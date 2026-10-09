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
 * @file local_source.h
 * @brief The Local source: live capture on this computer with Wireshark's
 *        dumpcap or tcpdump, and what to do about missing capture
 *        permissions on each OS.
 *
 * The Local source prefers dumpcap (Wireshark's capture program: every OS,
 * pcapng, and on Linux a group that may capture), and falls back to
 * tcpdump; it looks for them on PATH and where their installers put them.
 * It lists interfaces with `<program> -D` and captures with
 *
 *     dumpcap -i <if> -s <snaplen> -q [-f <filter>] -w -
 *     tcpdump -i <if> -s <snaplen> -U -w - [<filter>]
 *
 * the filter one argument (tcpdump joins its trailing arguments into the
 * filter, so one argument is the whole filter).  It never runs sudo or
 * anything that asks for a password: capturing needs permissions the user
 * gives the program once, and when a listing or a capture fails for want of
 * them (or a listing is empty, or, on macOS, /dev/bpf0 cannot be read) it
 * says how, for the OS it runs on: capturePermissionGuidance().
 */

#pragma once

#include "live_source.h"

#include <QString>
#include <QStringList>

namespace tcpdump {

/// The OSes the Local source gives guidance for.
enum class CaptureOs {
    MacOS,
    Linux,
    Windows,
};

/// The OS this plugin runs on (any Unix but macOS counts as Linux).
CaptureOs runningCaptureOs();

/// What to do on @p os so that the capture program @p program (its path:
/// dumpcap or tcpdump) may capture without root: the exact command or
/// download, which the plugin never runs itself.
QString capturePermissionGuidance( CaptureOs os, const QString& program );

/// Where to get a capture program on @p os, for a Local source that found none.
QString captureInstallHint( CaptureOs os );

/// Whether @p error (a capture program's message) says it may not capture:
/// permission denied, an operation not permitted, no interface to capture
/// on, Npcap missing.
bool isCapturePermissionError( const QString& error );

/// Where the Local source looks for its programs.
struct LocalPrograms {
    CaptureOs os = runningCaptureOs(); ///< Whose guidance and hints are given.
    QStringList searchPath;            ///< The directories of PATH, searched first.
    QStringList dumpcap;               ///< Where dumpcap is installed besides, in order.
    QStringList tcpdump;               ///< Where tcpdump is installed besides, in order.
    /// On macOS, a BPF device the program must read to capture; empty: not checked.
    QString bpfDevice;

    /// This computer's: PATH, and the install locations of its OS
    /// (/Applications/Wireshark.app, /usr/bin, /usr/sbin, Program Files).
    static LocalPrograms forThisComputer();
};

/// Live capture on this computer with dumpcap or tcpdump.
class LocalSourceKind : public LiveSourceKind {
public:
    explicit LocalSourceKind( LocalPrograms where = LocalPrograms::forThisComputer() );

    /// The capture program found, if any.
    struct Program {
        QString path;           ///< Empty: neither dumpcap nor tcpdump was found.
        bool isDumpcap = false; ///< dumpcap, not tcpdump.
    };
    /// dumpcap if it is found, else tcpdump; looked for anew on each call.
    Program program() const;

    QString id() const override;
    QString displayName() const override;
    LiveAvailability availability() const override;
    LiveListing listInterfaces( const QString& device,
                                std::chrono::milliseconds timeout ) const override;
    ProcessCommand command( const LiveChoice& choice ) const override;
    QString explainFailure( const QString& error ) const override;

private:
    /// The guidance for the program found (or dumpcap, if none was).
    QString guidance() const;

    LocalPrograms where_;
};

} // namespace tcpdump
