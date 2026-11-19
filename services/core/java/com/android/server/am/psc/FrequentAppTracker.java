/*
 * Copyright (C) 2026 RisingOS mondrian (unofficial)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.server.am.psc;

import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.PackageManagerInternal;
import android.content.pm.ResolveInfo;
import android.os.Environment;
import android.os.Process;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.util.ArrayMap;
import android.util.ArraySet;
import android.util.AtomicFile;
import android.util.Slog;
import android.util.SparseArray;

import com.android.internal.annotations.GuardedBy;
import com.android.internal.os.BackgroundThread;
import com.android.server.LocalServices;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * Usage-aware cached-app protection.
 *
 * <p>Counts how often each launchable user app is used (each time it leaves the TOP state,
 * debounced) with an exponentially decaying score. The main processes of the N highest-scoring
 * eligible apps — plus the configured camera package without consuming a Top-N slot — get the
 * lowest cached oom_score_adj ({@link Constants#CACHED_APP_MIN_ADJ}) exclusively, so lmkd kills
 * every other cached process before them. They stay cached (frozen and compacted as usual).
 *
 * <p>{@code persist.sys.lmk.protect_frequent} = number of apps to protect (default 8, 0 = off).
 * Scores are persisted in {@code /data/system/frequent_apps.txt} so protection survives reboots.
 *
 * <p>All hot-path methods are cheap and only take this object's lock (a leaf lock); package
 * eligibility checks are performed asynchronously on {@link BackgroundThread}.
 */
final class FrequentAppTracker {
    private static final String TAG = "FrequentApps";

    static final String PROP_COUNT = "persist.sys.lmk.protect_frequent";
    private static final int DEFAULT_COUNT = 8;
    private static final int MAX_COUNT = 15;
    private static final String PROP_PRELOAD_COMPONENT = "ro.config.app_preload.component";
    private static final String DEFAULT_CAMERA_PACKAGE = "com.android.camera";

    /** Score half-life: a use 3 days ago counts half. */
    private static final double HALF_LIFE_MS = 3 * 24 * 3600_000.0;
    /** An app needs at least this (decayed) number of uses to be protected. */
    private static final double MIN_SCORE = 2.0;
    /** Leaving TOP again within this window does not count as another use. */
    private static final long DEBOUNCE_MS = 60_000;
    private static final long RECOMPUTE_INTERVAL_MS = 15_000;
    private static final long WRITE_DELAY_MS = 10 * 60_000;
    private static final int MAX_ENTRIES = 300;

    private static final class Entry {
        double score;
        long lastUseWall; // System.currentTimeMillis() of the last counted use
        String packageName;
    }

    private final Object mLock = new Object();
    @GuardedBy("mLock")
    private final SparseArray<Entry> mEntries = new SparseArray<>();
    @GuardedBy("mLock")
    private final ArrayMap<String, Boolean> mEligibleCache = new ArrayMap<>();
    @GuardedBy("mLock")
    private final ArraySet<String> mPendingEligibilityChecks = new ArraySet<>();
    private final AtomicFile mFile;
    private final String mCameraPackage;

    // Snapshot of protected uids, rebuilt at most every RECOMPUTE_INTERVAL_MS.
    @GuardedBy("mLock")
    private int[] mProtectedUids = new int[0];
    @GuardedBy("mLock")
    private long mLastComputeElapsed = -RECOMPUTE_INTERVAL_MS;
    @GuardedBy("mLock")
    private boolean mWriteScheduled;
    private volatile boolean mCameraProtectedSeen;

    FrequentAppTracker() {
        mCameraPackage = resolveCameraPackage();
        mFile = new AtomicFile(new File(Environment.getDataSystemDirectory(),
                "frequent_apps.txt"));
        load();
    }

    /** Called when a process leaves the TOP state. */
    void noteLeftTop(ProcessRecordInternal app) {
        if (app.isolated) return;
        final int uid = app.getApplicationUid();
        if (!isAppUid(uid)) return;
        final String pkg = app.getPackageName();
        if (pkg == null || !pkg.equals(app.processName)) return; // main process only
        final long now = System.currentTimeMillis();
        synchronized (mLock) {
            final Boolean eligible = mEligibleCache.get(pkg);
            if (Boolean.FALSE.equals(eligible)) {
                return;
            }
            if (eligible == null) {
                scheduleEligibilityCheckLocked(pkg, UserHandle.getUserId(uid));
            }
            Entry e = mEntries.get(uid);
            if (e == null) {
                if (mEntries.size() >= MAX_ENTRIES) pruneLocked(now);
                e = new Entry();
                mEntries.put(uid, e);
            } else if (now - e.lastUseWall < DEBOUNCE_MS && now >= e.lastUseWall) {
                return;
            }
            e.score = decayed(e, now) + 1.0;
            e.lastUseWall = now;
            e.packageName = pkg;
            scheduleWriteLocked();
        }
    }

    /** Whether this cached process should get the protected (lowest) cached adj. */
    boolean isProtected(ProcessRecordInternal app) {
        if (app.isolated) return false;
        final int uid = app.getApplicationUid();
        if (!isAppUid(uid)) return false;
        final String pkg = app.getPackageName();
        if (pkg == null || !pkg.equals(app.processName)) return false;
        if (getConfiguredCount() > 0 && mCameraPackage.equals(pkg)) {
            mCameraProtectedSeen = true;
            return true;
        }
        final int[] uids = getProtectedUids();
        if (uids.length == 0) return false;
        for (int u : uids) {
            if (u == uid) {
                return true;
            }
        }
        return false;
    }

    /** Whether any app is protected right now (others are then kept above the minimum adj). */
    boolean isActive() {
        return getProtectedUids().length > 0
                || (mCameraProtectedSeen && getConfiguredCount() > 0);
    }

    private static int getConfiguredCount() {
        final int count = SystemProperties.getInt(PROP_COUNT, DEFAULT_COUNT);
        return Math.max(0, Math.min(MAX_COUNT, count));
    }

    private static String resolveCameraPackage() {
        final String comp = SystemProperties.get(PROP_PRELOAD_COMPONENT, "");
        if (!comp.isEmpty()) {
            final ComponentName cn = ComponentName.unflattenFromString(comp);
            if (cn != null) {
                final String pkg = cn.getPackageName();
                if (pkg != null && pkg.toLowerCase(Locale.ROOT).contains("camera")) {
                    return pkg;
                }
            }
        }
        return DEFAULT_CAMERA_PACKAGE;
    }

    private int[] getProtectedUids() {
        final long nowElapsed = SystemClock.elapsedRealtime();
        synchronized (mLock) {
            if (nowElapsed - mLastComputeElapsed >= RECOMPUTE_INTERVAL_MS) {
                mLastComputeElapsed = nowElapsed;
                recomputeLocked();
            }
            return mProtectedUids;
        }
    }

    @GuardedBy("mLock")
    private void recomputeLocked() {
        final int count = getConfiguredCount();
        final long now = System.currentTimeMillis();
        final ArrayList<double[]> candidates = new ArrayList<>(); // {score, uid}
        boolean purged = false;
        for (int i = mEntries.size() - 1; i >= 0; i--) {
            final int uid = mEntries.keyAt(i);
            final Entry e = mEntries.valueAt(i);
            final String pkg = e.packageName;
            final Boolean eligible = mEligibleCache.get(pkg);
            if (Boolean.FALSE.equals(eligible)) {
                mEntries.removeAt(i);
                purged = true;
                continue;
            }
            if (eligible == null && pkg != null) {
                scheduleEligibilityCheckLocked(pkg, UserHandle.getUserId(uid));
            }
            // Camera is protected unconditionally in isProtected() without taking a Top-N slot.
            if (mCameraPackage.equals(pkg)) {
                continue;
            }
            final double s = decayed(e, now);
            if (s >= MIN_SCORE) candidates.add(new double[] {s, uid});
        }
        if (purged) {
            scheduleWriteLocked();
        }
        candidates.sort((a, b) -> Double.compare(b[0], a[0]));
        final int n = Math.min(count, candidates.size());
        final int[] result = new int[n];
        for (int i = 0; i < n; i++) result[i] = (int) candidates.get(i)[1];
        if (!Arrays.equals(result, mProtectedUids)) {
            final StringBuilder sb = new StringBuilder("protected:");
            for (int i = 0; i < n; i++) {
                final Entry entry = mEntries.get(result[i]);
                if (entry != null) {
                    sb.append(' ').append(entry.packageName).append('(')
                            .append(String.format("%.1f", candidates.get(i)[0])).append(')');
                }
            }
            Slog.i(TAG, sb.toString());
        }
        mProtectedUids = result;
    }

    @GuardedBy("mLock")
    private void scheduleEligibilityCheckLocked(String pkg, int userId) {
        if (pkg == null || pkg.isEmpty() || !mPendingEligibilityChecks.add(pkg)) {
            return;
        }
        BackgroundThread.getHandler().post(() -> resolveEligibility(pkg, userId));
    }

    private void resolveEligibility(String pkg, int userId) {
        final PackageManagerInternal pmi = LocalServices.getService(PackageManagerInternal.class);
        if (pmi == null) {
            synchronized (mLock) {
                mPendingEligibilityChecks.remove(pkg);
            }
            return;
        }

        boolean eligible = false;
        try {
            if (!pmi.isPackagePersistent(pkg)) {
                final long homeFlags = PackageManager.MATCH_DISABLED_COMPONENTS
                        | PackageManager.MATCH_DIRECT_BOOT_AWARE
                        | PackageManager.MATCH_DIRECT_BOOT_UNAWARE;
                final Intent homeIntent = new Intent(Intent.ACTION_MAIN)
                        .addCategory(Intent.CATEGORY_HOME)
                        .setPackage(pkg);
                final List<ResolveInfo> homes = pmi.queryIntentActivities(
                        homeIntent, null, homeFlags, Process.SYSTEM_UID, userId);
                if (homes == null || homes.isEmpty()) {
                    final long launchFlags = PackageManager.MATCH_DIRECT_BOOT_AWARE
                            | PackageManager.MATCH_DIRECT_BOOT_UNAWARE;
                    final Intent launchIntent = new Intent(Intent.ACTION_MAIN)
                            .addCategory(Intent.CATEGORY_LAUNCHER)
                            .setPackage(pkg);
                    final List<ResolveInfo> launchers = pmi.queryIntentActivities(
                            launchIntent, null, launchFlags, Process.SYSTEM_UID, userId);
                    eligible = launchers != null && !launchers.isEmpty();
                }
            }
        } catch (RuntimeException e) {
            synchronized (mLock) {
                mPendingEligibilityChecks.remove(pkg);
            }
            return;
        }

        synchronized (mLock) {
            mPendingEligibilityChecks.remove(pkg);
            mEligibleCache.put(pkg, eligible);
            if (!eligible) {
                boolean removed = false;
                for (int i = mEntries.size() - 1; i >= 0; i--) {
                    if (pkg.equals(mEntries.valueAt(i).packageName)) {
                        mEntries.removeAt(i);
                        removed = true;
                    }
                }
                if (removed) {
                    scheduleWriteLocked();
                    mLastComputeElapsed = SystemClock.elapsedRealtime();
                    recomputeLocked();
                }
            }
        }
    }

    private static double decayed(Entry e, long nowWall) {
        final long age = Math.max(0, nowWall - e.lastUseWall);
        return e.score * Math.pow(0.5, age / HALF_LIFE_MS);
    }

    private static boolean isAppUid(int uid) {
        final int appId = uid % 100000;
        return appId >= Process.FIRST_APPLICATION_UID && appId <= Process.LAST_APPLICATION_UID;
    }

    @GuardedBy("mLock")
    private void pruneLocked(long now) {
        int worst = -1;
        double worstScore = Double.MAX_VALUE;
        for (int i = 0; i < mEntries.size(); i++) {
            final double s = decayed(mEntries.valueAt(i), now);
            if (s < worstScore) {
                worstScore = s;
                worst = i;
            }
        }
        if (worst >= 0) mEntries.removeAt(worst);
    }

    @GuardedBy("mLock")
    private void scheduleWriteLocked() {
        if (mWriteScheduled) return;
        mWriteScheduled = true;
        BackgroundThread.getHandler().postDelayed(this::write, WRITE_DELAY_MS);
    }

    private void write() {
        final ArrayList<String> lines = new ArrayList<>();
        synchronized (mLock) {
            mWriteScheduled = false;
            for (int i = 0; i < mEntries.size(); i++) {
                final Entry e = mEntries.valueAt(i);
                lines.add(mEntries.keyAt(i) + " " + e.score + " " + e.lastUseWall + " "
                        + e.packageName);
            }
        }
        FileOutputStream out = null;
        try {
            out = mFile.startWrite();
            final PrintWriter pw = new PrintWriter(new OutputStreamWriter(out,
                    StandardCharsets.UTF_8));
            for (String l : lines) pw.println(l);
            pw.flush();
            mFile.finishWrite(out);
        } catch (IOException | RuntimeException ex) {
            Slog.w(TAG, "write failed", ex);
            if (out != null) mFile.failWrite(out);
        }
    }

    private void load() {
        if (!mFile.exists()) return;
        try (BufferedReader r = new BufferedReader(new InputStreamReader(mFile.openRead(),
                StandardCharsets.UTF_8))) {
            String line;
            synchronized (mLock) {
                while ((line = r.readLine()) != null && mEntries.size() < MAX_ENTRIES) {
                    final String[] f = line.trim().split(" ");
                    if (f.length < 4) continue;
                    try {
                        final int uid = Integer.parseInt(f[0]);
                        if (!isAppUid(uid)) continue;
                        final Entry e = new Entry();
                        e.score = Double.parseDouble(f[1]);
                        e.lastUseWall = Long.parseLong(f[2]);
                        e.packageName = f[3];
                        if (!(e.score > 0) || e.score > 1e6) continue;
                        mEntries.put(uid, e);
                    } catch (NumberFormatException ignored) {
                    }
                }
            }
        } catch (IOException | RuntimeException ex) {
            Slog.w(TAG, "load failed", ex);
        }
    }
}
