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
 * @file live_source.h
 * @brief Live Source Kinds: where a live capture can come from, and the one
 *        place they are registered.
 *
 * A Live Source Kind is a way to capture live: on this computer (tcpdump,
 * dumpcap), on an Android device (adb), on a server (ssh), through a
 * Wireshark extcap, or with a command the user wrote.  The live capture UI
 * (live_capture_form.h) knows none of them: it talks to each through
 * LiveSourceKind, which
 *
 *   - says whether the kind can be used here, and why not ("adb not found"),
 *   - lists its devices (phones, hosts) and their interfaces, on a worker
 *     thread, each listing bounded by a timeout,
 *   - checks a choice before it starts,
 *   - makes the capture's stream for a choice: by default a Process Source
 *     running the command the kind builds from {device, interface, capture
 *     filter, snaplen},
 *   - explains a failure the user can fix (missing capture permissions).
 *
 * The capture filter is BPF, handed to the capture program as one argument
 * (or quoted for a remote shell by a kind that needs one): never through a
 * local shell.  The plugin never asks for or stores a password.
 *
 * builtInLiveSources() is the one place a kind is registered.
 */

#pragma once

#include "live_capture.h"
#include "process_source.h"

#include <QString>
#include <QStringList>

#include <chrono>
#include <memory>
#include <vector>

namespace tcpdump {

/// The snaplen a live capture asks for unless the user chooses another:
/// dumpcap's and tcpdump's default, every packet whole.
constexpr int kDefaultSnaplen = 262144;
/// The most the snaplen may be set to.
constexpr int kMaxSnaplen = 262144;

/// What the user chose to capture: one choice of the live capture UI, as
/// settings.ini remembers it.
struct LiveChoice {
    QString source;    ///< The kind's id(); empty: none chosen.
    QString device;    ///< The device (a phone's serial, user@host); empty for none.
    QString interface; ///< The interface's id; empty: the kind's default, if it has one.
    QString filter;    ///< The capture filter, BPF; empty: everything.
    int snaplen = kDefaultSnaplen; ///< Bytes kept of each packet.

    bool operator==( const LiveChoice& other ) const
    {
        return source == other.source && device == other.device
               && interface == other.interface && filter == other.filter
               && snaplen == other.snaplen;
    }
    bool operator!=( const LiveChoice& other ) const
    {
        return !( *this == other );
    }
};

/// A device or an interface a kind listed.
struct LiveTarget {
    QString id;          ///< What a LiveChoice holds: "en0", a serial.
    QString description; ///< What the user is shown besides: "Wi-Fi", a model.
    /// Why it cannot be captured on, e.g. an Android device "unauthorized:
    /// accept the prompt on the phone"; empty if it can.  Listed, not chosen.
    QString problem;
};

/// What a listing found, or why it found nothing.
struct LiveListing {
    std::vector<LiveTarget> targets;
    QString error; ///< Why the listing failed; empty if it did not.
};

/// Whether a kind can be used on this computer.
struct LiveAvailability {
    bool available = true;
    /// Why not, and what to do: "adb not found: install the Android SDK
    /// Platform-Tools"; empty if it is available.
    QString reason;

    static LiveAvailability unavailable( const QString& reason )
    {
        return { false, reason };
    }
};

/**
 * A way to capture live.  The UI calls availability(), validate(),
 * makeSource() and explainFailure() on the UI thread, listDevices() and
 * listInterfaces() on a worker thread: a kind holds no state that changes
 * (its listings and commands depend on their arguments and the system
 * alone), so both may run at once.
 */
class LiveSourceKind {
public:
    /// How the user names a device, if the kind has devices at all.
    enum class Devices {
        None,   ///< No devices: interfaces of this computer, say.
        Listed, ///< Chosen from listDevices(): Android devices.
        Typed,  ///< Typed by the user, e.g. user@host; listDevices() may suggest.
    };

    /// How long a listing may take before it is given up; a kind passes it
    /// to the programs it runs (runListing()).
    static constexpr std::chrono::milliseconds kListTimeout{ 10000 };

    virtual ~LiveSourceKind() = default;

    /// The kind's name in settings.ini: "local", "adb", "ssh", …; never changes.
    virtual QString id() const = 0;
    /// The kind's name in the source picker: "Local", "Android", ….
    virtual QString displayName() const = 0;

    /// Whether the kind can be used here, and why not.  Called on the UI
    /// thread whenever the source picker is shown: it may look for a
    /// program, but not run one (that is what a listing does).
    virtual LiveAvailability availability() const
    {
        return {};
    }

    /// How the user names a device.
    virtual Devices devices() const
    {
        return Devices::None;
    }
    /// What a device is called in the UI: "Device", "Host".
    virtual QString deviceLabel() const
    {
        return QStringLiteral( "Device" );
    }
    /// The devices, at most @p timeout; on a worker thread.
    virtual LiveListing listDevices( std::chrono::milliseconds timeout ) const
    {
        (void)timeout;
        return {};
    }
    /// The interfaces of @p device (empty for a kind without devices), at
    /// most @p timeout; on a worker thread.
    virtual LiveListing listInterfaces( const QString& device,
                                        std::chrono::milliseconds timeout ) const = 0;

    /// Why @p choice cannot be captured, kind-specific (the capture filter's
    /// syntax and the snaplen's range are checked before: captureFilterProblem());
    /// empty if it can.  By default an interface must be chosen.
    virtual QString validate( const LiveChoice& choice ) const;

    /// The capture program for @p choice: e.g. `tcpdump -i <if> -s <snaplen>
    /// -U -w - <filter>`, the filter one argument.  For makeSource().
    virtual ProcessCommand command( const LiveChoice& choice ) const = 0;

    /// What captures @p choice, made on the capture's worker thread.  By
    /// default a Process Source running command(); a kind that reads a FIFO
    /// or a socket (an extcap) makes its own.
    virtual LiveCapture::SourceFactory makeSource( const LiveChoice& choice ) const
    {
        return LiveCapture::processSource( command( choice ) );
    }

    /// What the user can do about the failure @p error of a capture of this
    /// kind (it names the program's last stderr lines), e.g. how to get
    /// capture permissions on this OS; empty if the kind knows nothing to add.
    virtual QString explainFailure( const QString& error ) const
    {
        (void)error;
        return {};
    }
};

/// The kinds the UI offers, in the order the source picker lists them.
class LiveSourceRegistry {
public:
    /// Add @p kind after the others; one whose id() is taken replaces it.
    void add( std::shared_ptr<const LiveSourceKind> kind );

    /// The kind of @p id, or null.
    std::shared_ptr<const LiveSourceKind> find( const QString& id ) const;

    /// All kinds, in order.
    const std::vector<std::shared_ptr<const LiveSourceKind>>& kinds() const
    {
        return kinds_;
    }

private:
    std::vector<std::shared_ptr<const LiveSourceKind>> kinds_;
};

/// The kinds the plugin ships: the one place a new kind is registered.
std::shared_ptr<const LiveSourceRegistry> builtInLiveSources();

/// Why @p filter is not a capture filter the UI hands on, for the hint below
/// the field; empty if it is (an empty filter captures everything).  The
/// filter is not compiled (that needs libpcap, which the capture program
/// has): what is caught is what would be misread before it reaches it, a
/// line break, a leading '-' (an option to tcpdump), unbalanced parentheses,
/// and a Wireshark display filter field such as ip.addr.
QString captureFilterProblem( const QString& filter );

/// What a listing program printed, or why it did not finish.
struct ListingOutput {
    QString out;       ///< Its stdout, as UTF-8.
    QString err;       ///< Its stderr, as UTF-8.
    int exitCode = -1; ///< Its exit code, if it exited.
    /// Why it did not finish: could not be started, crashed, or ran out of
    /// time (and was killed); empty if it exited, with any code.
    QString error;
};

/**
 * Run @p command (devices --list, `tcpdump -D`, `adb devices -l`) and wait
 * for it, at most @p timeout: for a kind's listings, on a worker thread; no
 * event loop is needed.  stdin is the null device, so a program that would
 * ask (a password, a host key) fails instead of waiting.  A program still
 * running at the timeout is killed with what it started.
 */
ListingOutput runListing( const ProcessCommand& command, std::chrono::milliseconds timeout );

/// A file name for a capture of @p choice: its interface, after its device
/// if it has one, with anything but letters, digits, '.', '-' and '_'
/// replaced by '_'; "live" if neither is set.
QString liveCaptureName( const LiveChoice& choice );

} // namespace tcpdump
