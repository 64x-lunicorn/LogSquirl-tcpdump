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
 * @file file_conversion_session.h
 * @brief The File Conversion session: opening one capture file at a time,
 *        from its start to its outcome.
 *
 * The session decides what opening a capture file does, the sidebar only
 * shows it:
 *
 *   - a start: refused while the Activity rule refuses opening a file (a
 *     conversion or a live capture runs), with a notification; the
 *     conversion options are read from settings.ini as it starts, so that a
 *     change of them applies to the next file;
 *   - the conversion, run as a Background Job (background_job.h) on a
 *     worker thread of its own, into a private directory below the output
 *     root, its progress told as it goes;
 *   - Cancel: the cancel wins even over a conversion that was done when it
 *     came, and the directory it wrote is taken back;
 *   - the outcome: a converted capture is kept in the capture catalog,
 *     which opens its tab, and is the one in front; a cancelled or failed
 *     one leaves nothing behind.  The outcome carries what the sidebar's
 *     summary says of it, what was logged and what the user was told.
 *
 * It reaches LogSquirl (a notification) through a SessionHost
 * (session_host.h), as the Live Capture Session does, and keeps the
 * converted capture in a CaptureCatalog (capture_catalog.h).  A test may
 * convert with a converter of its own (setConverter()), which is run on the
 * worker as convertPcap() is, so that a cancel and a progress come when the
 * test says; the result is delivered through the event loop.
 *
 * Destroying the session cancels a running conversion and waits for its
 * worker: no code of the plugin runs on it afterwards, and the host may
 * unload the library.
 */

#pragma once

#include "background_job.h"
#include "capture_catalog.h"
#include "pcap_converter.h"
#include "session_host.h"

#include <QObject>
#include <QString>

#include <atomic>
#include <functional>
#include <optional>

namespace tcpdump {

/// What opening a capture file came to.
struct FileConversionOutcome {
    enum class Status {
        /// Converted: its text file is kept in the catalog and opened in a
        /// tab, which shows its summary.
        Opened,
        /// Cancelled: nothing is left behind.
        Cancelled,
        /// It failed, with error: nothing is left behind.
        Failed,
    };

    Status status = Status::Failed;
    QString filePath; ///< The capture file opened.
    QString textPath; ///< Its text file, opened in a tab; empty unless Opened.
    QString error;    ///< Why it failed.
    /// What the sidebar's summary says of it, as rich text: "Cancelled.",
    /// "Error: …"; empty when Opened, as its tab shows its summary.
    QString label;
    QString log; ///< What was written to the host's log.
    /// What the user was told in a notification; empty if nothing.
    QString notification;
};

/**
 * One capture file opened at a time, from its start to its outcome (see the
 * file comment).  On the UI thread, which runs an event loop: the outcome
 * is delivered through it.
 */
class FileConversionSession : public QObject {
    Q_OBJECT

public:
    enum class State {
        Idle,       ///< No conversion runs.
        Converting, ///< A capture file is being converted.
        Cancelling, ///< A conversion was cancelled, and has not ended yet.
    };

    /// Converts @p filePath into a private directory below @p outputRoot,
    /// with @p options, checking @p cancel and reporting @p progress as it
    /// goes; on the worker thread.  convertPcap() in the app.
    using Converter = std::function<ConversionResult(
        const QString& filePath, const QString& outputRoot, const std::atomic_bool* cancel,
        const std::function<void( int permille )>& progress, const ConversionOptions& options )>;

    /// A session telling the user on @p host and keeping what it converts
    /// in, and opening tabs through, @p catalog, both outliving it.
    FileConversionSession( SessionHost& host, CaptureCatalog& catalog, QObject* parent = nullptr );
    /// Cancels a running conversion and waits for its worker; what it wrote
    /// goes, and nothing is told.
    ~FileConversionSession() override;

    FileConversionSession( const FileConversionSession& ) = delete;
    FileConversionSession& operator=( const FileConversionSession& ) = delete;

    /// Where conversions write their private directories.
    void setOutputRoot( const QString& root )
    {
        outputRoot_ = root;
    }
    /// Convert with @p converter instead of convertPcap() (tests).
    void setConverter( Converter converter )
    {
        convert_ = std::move( converter );
    }

    /// Why no capture file can be opened now, as the Activity rule says;
    /// empty if one can.
    QString refusal() const;

    /**
     * Open the capture file @p filePath: convert it in the background, with
     * the options saved in settings.ini now, and keep it in the catalog when
     * it is done.  False, with a notification, while the Activity rule
     * refuses opening a file (refusal()).
     */
    bool start( const QString& filePath );

    /// Ask the running conversion to stop (Cancelling); it comes to
    /// Cancelled, and nothing is opened.
    void cancel();

    State state() const
    {
        return state_;
    }
    /// Whether a conversion runs, cancelled or not.
    bool isBusy() const
    {
        return state_ != State::Idle;
    }
    /// The capture file being converted, or the last.
    const QString& filePath() const
    {
        return filePath_;
    }
    /// The share of the running conversion done, in permille.
    int progress() const
    {
        return progress_;
    }
    /// What the sidebar's summary says of the session now, as rich text:
    /// "Reading <file>…" while it converts, "Cancelling…" once cancelled,
    /// the last outcome's label after, or empty.
    QString label() const;
    /// What the last conversion came to; none while one runs.
    const std::optional<FileConversionOutcome>& outcome() const
    {
        return outcome_;
    }

signals:
    /// state() changed.
    void stateChanged();
    /// The running conversion reports @p permille of it done (progress()).
    void progressed( int permille );
    /// The conversion ended with @p outcome (outcome()), after the catalog
    /// kept it and the user was told.
    void finished( const tcpdump::FileConversionOutcome& outcome );

private:
    /// The conversion's @p result is delivered: keep it, or tell why not.
    void finish( ConversionResult result );
    void setState( State state );

    SessionHost& host_;
    CaptureCatalog& catalog_;
    QString outputRoot_;
    Converter convert_;

    State state_ = State::Idle;
    QString filePath_;
    int progress_ = 0;
    std::optional<FileConversionOutcome> outcome_;

    /// The conversion, on a worker thread of its own; cancelled and waited
    /// for when the session goes.  Last, so that it goes first.
    BackgroundJob<ConversionResult> job_{ "conversion" };
};

} // namespace tcpdump
