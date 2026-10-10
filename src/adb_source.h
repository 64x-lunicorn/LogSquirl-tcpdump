/*
 * Copyright (C) 2026 LogSquirl Contributors
 *
 * This file is part of logsquirl-tcpdump.
 *
 * logsquirl-tcpdump is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * logsquirl-tcpdump is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with logsquirl-tcpdump.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file adb_source.h
 * @brief The Android source: live capture on a phone or an emulator through
 *        adb, with the device's own tcpdump, as root or through su.
 *
 * The Android source finds adb (PATH, the SDK's platform-tools below
 * ANDROID_HOME or ANDROID_SDK_ROOT, where the SDK and package managers put
 * it), lists the devices of `adb devices -l` (an unauthorized or offline
 * one with what to do), and for a device asks its shell, in one
 * `adb -s <serial> shell <probe>`, for
 *
 *   - its user: root when adbd runs as root (an emulator or a userdebug
 *     build after `adb root`, which the plugin never runs itself),
 *   - whether `su -c` gives root without a prompt (stdin is the null device,
 *     and a timeout bounds a su manager's prompt on the phone),
 *   - where tcpdump is (PATH, /system/bin, /system/xbin, or pushed to
 *     /data/local/tmp),
 *   - its interfaces (`ip -o link`, else /sys/class/net), after "any".
 *
 * It captures with
 *
 *     adb -s <serial> exec-out '<script>'
 *
 * exec-out because its stdout is binary-clean (no pty, no CR/LF
 * translation); it merges stderr into stdout, so the device's tcpdump writes
 * its stderr to a file on the device, read back when the capture fails.
 * The script, run by the device's shell (through `su -c` when that is how
 * root is had), is (adbCaptureScript())
 *
 *     tcpdump -i '<if>' -s <snaplen> -U -w - '<filter>' 2>'<err>' & p=$!;
 *     echo $p >'<pid>'; [ -e '<stop>' ] && kill $p; wait $p;
 *     [ -e '<stop>' ] && rm -f '<err>'; rm -f '<pid>' '<stop>'
 *
 * every word from the user single-quoted for that shell (shellQuote()), so
 * that a filter is one argument of tcpdump and never shell syntax.  Stop
 * ends tcpdump on the device, not only the local adb (adbStopScript(),
 * through su if it runs as root): it leaves the stop mark, then kills the
 * pid the script left, if it is there yet; a script that leaves its pid
 * only after that finds the mark and ends its tcpdump itself.  The files go
 * on every path: the script removes the pid and the mark as it ends, Stop
 * or the end of the capture the stderr file (adbCleanupScript()).
 *
 * If LogSquirl crashes or is killed during a capture, nothing on the device
 * is told: tcpdump runs on until it next writes to the closed adb stream
 * (a packet it captures), and the capture's .pid and .err files stay in
 * the device's temporary directory (/data/local/tmp/logsquirl-*), to be
 * removed by hand.
 */

#pragma once

#include "live_source.h"
#include "local_source.h"

#include <QString>
#include <QStringList>

#include <vector>

namespace tcpdump {

/// The devices of `adb devices -l` output @p out: serial, model (else
/// product or device) as the description, and a problem for a device that is
/// not in the state "device" (unauthorized, offline, no permissions, …).
std::vector<LiveTarget> parseAdbDevices( const QString& out );

/// The interfaces of `ip -o link` output @p out ("2: wlan0: <UP,…> …", the
/// flags their description, "@ifN" dropped), or of a list of names, one a
/// line (/sys/class/net).
std::vector<LiveTarget> parseDeviceInterfaces( const QString& out );

/// The files on the device of a capture tagged @p tag: its tcpdump's pid and
/// stderr, and the mark a Stop leaves for a script that has not left the pid
/// yet; in the device's temporary directory.
struct AdbCaptureFiles {
    QString pid;
    QString err;
    QString stop;

    static AdbCaptureFiles of( const QString& tempDir, const QString& tag );
};

/// The device script running @p tcpdump, a command line, in the background
/// with its stderr in a file, leaving its pid, ending it if a Stop came
/// first, and removing the pid and the stop mark as it ends.
QString adbCaptureScript( const QString& tcpdump, const AdbCaptureFiles& files );

/// The device script a Stop runs while the capture runs: leave the stop
/// mark, kill tcpdump by its pid if it is there, remove the files.
QString adbStopScript( const AdbCaptureFiles& files );

/// The device script run after the capture has ended: kill tcpdump if it
/// still runs, remove the files.
QString adbCleanupScript( const AdbCaptureFiles& files );

/// What the device's shell said about capturing there (AdbSourceKind::probe()).
struct AdbDeviceAccess {
    /// adbd runs as root (`id -u` is 0): tcpdump runs as it is.
    bool root = false;
    /// `su -c` gives root without a prompt: tcpdump runs through it.
    bool su = false;
    /// Where tcpdump is on the device; empty: nowhere.
    QString tcpdump;
    /// The interfaces, if they were asked for.
    std::vector<LiveTarget> interfaces;
};

/// What to do so that adb can capture as root.
QString adbRootGuidance();
/// What to do about a device without tcpdump.
QString adbTcpdumpGuidance();
/// What to do about a device adb does not see or that is offline.
QString adbConnectGuidance();
/// What to do about an unauthorized device.
QString adbAuthorizeGuidance();
/// Where to get adb.
QString adbInstallHint();

/// Where the Android source looks for adb, and where it leaves its files on
/// the device.
struct AdbPrograms {
    CaptureOs os = runningCaptureOs(); ///< ".exe" on Windows.
    QStringList searchPath;            ///< The directories of PATH, searched first.
    /// The directories adb is installed in besides, in order: the SDK's
    /// platform-tools below ANDROID_HOME and ANDROID_SDK_ROOT, then the usual
    /// SDK and package manager locations of the OS.
    QStringList installed;
    /// The device's directory for a capture's pid and stderr files, where a
    /// pushed tcpdump is looked for too.
    QString deviceTempDir = QStringLiteral( "/data/local/tmp" );

    /// This computer's.
    static AdbPrograms forThisComputer();
};

/// Live capture on an Android device through adb.
class AdbSourceKind : public LiveSourceKind {
public:
    explicit AdbSourceKind( AdbPrograms where = AdbPrograms::forThisComputer() );

    /// adb's path, empty if it is not found; looked for anew on each call.
    QString adb() const;

    /// Ask @p serial's shell how it can capture (and its interfaces if
    /// @p withInterfaces), at most @p timeout; on a worker thread.  Throws
    /// std::runtime_error, saying why, if adb fails.
    AdbDeviceAccess probe( const QString& serial, bool withInterfaces,
                           std::chrono::milliseconds timeout ) const;

    /// The adb command capturing @p choice with @p access, its pid and stderr
    /// files on the device named after @p tag.
    ProcessCommand captureCommand( const LiveChoice& choice, const AdbDeviceAccess& access,
                                   const QString& tag ) const;

    QString id() const override;
    QString displayName() const override;
    LiveAvailability availability() const override;
    Devices devices() const override;
    LiveListing listDevices( std::chrono::milliseconds timeout ) const override;
    LiveListing listInterfaces( const QString& device,
                                std::chrono::milliseconds timeout ) const override;
    QString validate( const LiveChoice& choice ) const override;
    /// The capture of @p choice as adbd runs as root, with tcpdump on the
    /// device's PATH; makeSource() asks the device first.
    ProcessCommand command( const LiveChoice& choice ) const override;
    /// Asks the device how to capture (probe()) on the capture's worker
    /// thread, then runs captureCommand(); the stream ends tcpdump on the
    /// device when it goes.
    LiveCapture::SourceFactory makeSource( const LiveChoice& choice ) const override;
    QString explainFailure( const QString& error ) const override;

private:
    AdbPrograms where_;
};

} // namespace tcpdump
