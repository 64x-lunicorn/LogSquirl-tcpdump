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
 * @file export_session.h
 * @brief The Export session: exporting the packets of the selected lines,
 *        one export at a time, from its start to its outcome.
 *
 * The session decides what Export packets… does, the sidebar only shows it:
 *
 *   - a start: refused, with a notification, while the Activity rule
 *     refuses an export (another export runs), when the tab in front shows
 *     no capture of the plugin, on a host that does not tell the selected
 *     lines, or when it told no line (Selected Packet Line's reason);
 *   - the packets of the selected lines are confirmed or changed by the
 *     user (the confirmer: the Export dialog), who chooses where they go
 *     (the file chooser: a save dialog); a selection the host told only
 *     the first lines of is truncated, which matters only when the
 *     selection's packets are exported;
 *   - the export, run as a Background Job (background_job.h) on a worker
 *     thread of its own, its progress told as it goes;
 *   - Cancel: the export stops before its file replaces the one chosen;
 *     once it has, the cancel comes too late, and the export stands, as
 *     removing it would lose both (#166);
 *   - the outcome: what was logged and what the user was told.
 *
 * It reaches LogSquirl (a notification) through a SessionHost
 * (session_host.h), as the other sessions do, and reads the capture in
 * front from a CaptureCatalog (capture_catalog.h).  The selected lines are
 * read from the host (selected_packet_line.h).  A test may confirm, choose
 * and export with its own (setConfirmer(), setFileChooser(),
 * setExporter()); the exporter runs on the worker as exportPackets() does,
 * and the result is delivered through the event loop.
 *
 * Destroying the session cancels a running export and waits for its
 * worker, telling nothing: an export that has written its file keeps it.
 */

#pragma once

#include "background_job.h"
#include "capture_catalog.h"
#include "export_dialog.h"
#include "packet_export.h"
#include "session_host.h"

#include <QObject>
#include <QString>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>

namespace tcpdump {

/// What an export came to.
struct ExportOutcome {
    enum class Status {
        /// Its file was written, also when a cancel came after that.
        Exported,
        /// Cancelled before its file was written: the file chosen is as it
        /// was.  So is one that failed while cancelled.
        Cancelled,
        /// It failed, with error: the file chosen is as it was.
        Failed,
    };

    Status status = Status::Failed;
    ExportRequest request; ///< What was exported, and where to.
    uint32_t packets = 0;  ///< Packets written.
    QString error;         ///< Why it failed.
    /// What the session's label() says of it, as plain text: the
    /// notification of an export, "Cancelled.", "Error: …".
    QString label;
    QString log; ///< What was written to the host's log.
    /// What the user was told in a notification; empty if nothing.
    QString notification;
};

/**
 * One export of packets at a time, from its start to its outcome (see the
 * file comment).  On the UI thread, which runs an event loop: the outcome
 * is delivered through it.
 */
class ExportSession : public QObject {
    Q_OBJECT

public:
    enum class State {
        Idle,       ///< No export runs.
        Exporting,  ///< Packets are being exported.
        Cancelling, ///< An export was cancelled, and has not ended yet.
    };

    /// Writes @p numbers of the capture @p index points into to
    /// @p outputPath, checking @p cancel and reporting @p progress as it
    /// goes; on the worker thread.  exportPackets() in the app.
    using Exporter = std::function<ExportResult(
        std::shared_ptr<const CaptureIndex> index, const PacketNumbers& numbers,
        const QString& outputPath, const std::atomic_bool* cancel,
        const std::function<void( int permille )>& progress )>;
    /// Asks the user to confirm or change the packets of @p request; false
    /// if the user does not want them exported.
    using Confirmer = std::function<bool( ExportRequest& request )>;
    /// Asks where to write the packets of @p request: the path chosen, or
    /// an empty one.
    using FileChooser = std::function<QString( const ExportRequest& request )>;

    /// A session telling the user on @p host and exporting from the capture
    /// in front of @p catalog, both outliving it.  It asks nobody until
    /// setConfirmer() and setFileChooser(): every start ends unconfirmed.
    ExportSession( SessionHost& host, const CaptureCatalog& catalog, QObject* parent = nullptr );
    /// Cancels a running export and waits for its worker; nothing is told.
    ~ExportSession() override;

    ExportSession( const ExportSession& ) = delete;
    ExportSession& operator=( const ExportSession& ) = delete;

    /// Ask with @p confirmer (the Export dialog in the app).
    void setConfirmer( Confirmer confirmer )
    {
        confirm_ = std::move( confirmer );
    }
    /// Ask with @p chooser (a save dialog in the app).
    void setFileChooser( FileChooser chooser )
    {
        chooseFile_ = std::move( chooser );
    }
    /// Export with @p exporter instead of exportPackets() (tests).
    void setExporter( Exporter exporter )
    {
        export_ = std::move( exporter );
    }

    /// Why no export can start now, as the Activity rule says; empty if one
    /// can.
    QString refusal() const;

    /**
     * Export the packets of the lines selected in the tab in front: ask the
     * user to confirm them and where to write them, and write them in the
     * background.  False, with a notification, while the Activity rule
     * refuses an export (refusal()), or there are no lines to read; false,
     * telling nothing, if the user did not confirm.  The confirmer and the
     * file chooser may run an event loop, in which the session may be
     * destroyed: then nothing starts.
     */
    bool start();

    /// Ask the running export to stop (Cancelling); it comes to Cancelled,
    /// unless it has written its file.
    void cancel();

    State state() const
    {
        return state_;
    }
    /// Whether an export runs, cancelled or not.
    bool isBusy() const
    {
        return state_ != State::Idle;
    }
    /// What the running export, or the last, was asked to do.
    const ExportRequest& request() const
    {
        return request_;
    }
    /// The share of the running export done, in permille.
    int progress() const
    {
        return progress_;
    }
    /// What the session says of itself now, as plain text: "Exporting N
    /// packets…" while it exports, "Cancelling…" once cancelled, the last
    /// outcome's label after, or empty.
    QString label() const;
    /// What the last export came to; none while one runs.
    const std::optional<ExportOutcome>& outcome() const
    {
        return outcome_;
    }

signals:
    /// state() changed.
    void stateChanged();
    /// The running export reports @p permille of it done (progress()).
    void progressed( int permille );
    /// The export ended with @p outcome (outcome()), after the user was told.
    void finished( const tcpdump::ExportOutcome& outcome );

private:
    /// The export's @p result is delivered: tell what it came to.
    void finish( ExportResult result );
    void setState( State state );

    SessionHost& host_;
    const CaptureCatalog& catalog_;
    Confirmer confirm_;
    FileChooser chooseFile_;
    Exporter export_;

    State state_ = State::Idle;
    ExportRequest request_;
    int progress_ = 0;
    std::optional<ExportOutcome> outcome_;

    /// The export, on a worker thread of its own, apart from the
    /// conversion's; cancelled and waited for when the session goes.  Last,
    /// so that it goes first.
    BackgroundJob<ExportResult> job_{ "export" };
};

} // namespace tcpdump
