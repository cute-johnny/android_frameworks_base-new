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

package com.android.server.am;

import android.app.ActivityManager;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Debug;
import android.os.Handler;
import android.os.SystemClock;
import android.os.SystemProperties;
import android.os.UserHandle;
import android.util.Slog;

import com.android.internal.os.BackgroundThread;

import java.util.List;

/**
 * Starts one app's process in the background when the screen turns on, so its next launch
 * is warm instead of cold (e.g. the lock-screen camera shortcut).
 *
 * <p>The device opts in by naming a broadcast receiver of the app that only starts the
 * process (no UI):
 * <ul>
 *   <li>{@code ro.config.app_preload.component} = {@code pkg/.Receiver} (unset = feature off)
 *   <li>{@code ro.config.app_preload.action} = intent action the receiver accepts
 *   <li>{@code ro.config.app_preload.min_avail_mb} = minimum MemAvailable (default 1536)
 *   <li>{@code persist.sys.app_preload} = runtime kill switch (default true)
 * </ul>
 * The process is not started if it is already running, if MemAvailable is low, if the package
 * is force-stopped (the broadcast is not delivered to stopped packages), or more often than
 * once per {@link #MIN_INTERVAL_MS}. Once started it is an ordinary cached process: lmkd may
 * kill it like any other.
 */
final class AppPreloader {
    private static final String TAG = "AppPreloader";

    private static final String PROP_COMPONENT = "ro.config.app_preload.component";
    private static final String PROP_ACTION = "ro.config.app_preload.action";
    private static final String PROP_MIN_AVAIL_MB = "ro.config.app_preload.min_avail_mb";
    private static final String PROP_ENABLED = "persist.sys.app_preload";

    /** Wait after screen-on so a direct launch (camera gesture) wins and is not raced. */
    private static final long DELAY_MS = 1500;
    private static final long MIN_INTERVAL_MS = 30_000;

    private final Context mContext;
    private final Handler mHandler = BackgroundThread.getHandler();
    private ComponentName mComponent;
    private String mAction;
    private long mMinAvailKb;
    private long mLastAttempt = -MIN_INTERVAL_MS;

    AppPreloader(Context context) {
        mContext = context;
    }

    void onSystemReady() {
        final String comp = SystemProperties.get(PROP_COMPONENT, "");
        final String action = SystemProperties.get(PROP_ACTION, "");
        if (comp.isEmpty() || action.isEmpty()) return;
        mComponent = ComponentName.unflattenFromString(comp);
        if (mComponent == null) {
            Slog.w(TAG, "bad " + PROP_COMPONENT + ": " + comp);
            return;
        }
        mAction = action;
        mMinAvailKb = SystemProperties.getLong(PROP_MIN_AVAIL_MB, 1536) * 1024;
        mHandler.post(() -> {
            final IntentFilter filter = new IntentFilter(Intent.ACTION_SCREEN_ON);
            mContext.registerReceiver(new BroadcastReceiver() {
                @Override
                public void onReceive(Context context, Intent intent) {
                    mHandler.removeCallbacks(mPreload);
                    mHandler.postDelayed(mPreload, DELAY_MS);
                }
            }, filter, null, mHandler);
            Slog.i(TAG, "enabled for " + mComponent.flattenToShortString());
        });
    }

    private final Runnable mPreload = this::maybePreload;

    private void maybePreload() {
        if (!SystemProperties.getBoolean(PROP_ENABLED, true)) return;
        final long now = SystemClock.elapsedRealtime();
        if (now - mLastAttempt < MIN_INTERVAL_MS) return;

        final int userId = ActivityManager.getCurrentUser();
        final String pkg = mComponent.getPackageName();
        try {
            final PackageManager pm = mContext.getPackageManager();
            pm.getReceiverInfo(mComponent, PackageManager.ComponentInfoFlags.of(0));
            final ApplicationInfo ai = pm.getApplicationInfoAsUser(pkg, 0, userId);
            if ((ai.flags & ApplicationInfo.FLAG_STOPPED) != 0) return;
        } catch (PackageManager.NameNotFoundException | IllegalArgumentException e) {
            return; // app or receiver missing
        }

        final ActivityManager am = mContext.getSystemService(ActivityManager.class);
        final List<ActivityManager.RunningAppProcessInfo> procs = am.getRunningAppProcesses();
        if (procs != null) {
            for (ActivityManager.RunningAppProcessInfo p : procs) {
                if (pkg.equals(p.processName) && UserHandle.getUserId(p.uid) == userId) return;
            }
        }

        final long[] info = new long[Debug.MEMINFO_COUNT];
        Debug.getMemInfo(info);
        final long availKb = info[Debug.MEMINFO_AVAILABLE];
        if (availKb > 0 && availKb < mMinAvailKb) {
            Slog.i(TAG, "skip: MemAvailable " + (availKb / 1024) + " MB");
            return;
        }

        mLastAttempt = now;
        final Intent intent = new Intent(mAction).setComponent(mComponent)
                .addFlags(Intent.FLAG_RECEIVER_FOREGROUND);
        mContext.sendBroadcastAsUser(intent, UserHandle.of(userId));
        Slog.i(TAG, "preloading " + pkg + " (MemAvailable " + (availKb / 1024) + " MB)");
    }
}
