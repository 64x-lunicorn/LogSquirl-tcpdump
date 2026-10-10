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
 * @file live_capture_session.h
 * @brief The Live Capture Session: one live capture at a time, from its
 *        start to its outcome.
 *
 * The session decides what a live capture does, the sidebar only shows it:
 *
 *   - a start: refused while a capture runs, or when the choice cannot
 *     start (liveChoiceProblem()), with a notification; a kind that must
 *     ask first (an extcap's arguments not asked this session) is asked on
 *     a worker thread, and the choice checked again;
 *   - each text file of the capture (a ring buffer's, one per raw file),
 *     kept in the capture catalog and opened in a tab, and its summary and
 *     index as the snapshots and the outcome replace them;
 *   - Stop, and the pending start of Start live capture…, which waits until
 *     the running capture's program has ended, so two never capture at once;
 *   - the outcome: a capture with packets keeps its tabs, with the final
 *     summary and a notice of the stop condition that ended it; one without
 *     packets has its files removed; a failure is told with what the kind
 *     says to do about it (its Guidance), keeping what was captured.
 *
 * It reaches LogSquirl (a tab, a notification) through a LiveCaptureHost
 * and the summaries the sidebar keeps through a LiveCaptureCatalog, and
 * runs a capture through a LiveRun: in the app a LiveCapture on a worker
 * thread, in a test a run the test scripts, so that what the session does
 * with each event is tested without a widget or an event loop.
 *
 * Nothing cancels a live capture: its outcome is never Cancelled.
 */

#pragma once

#include "live_capture.h"
#include "live_source.h"
#include "pcap_converter.h"

#include <QElapsedTimer>
#include <QObject>
#include <QString>
#include <QStringList>
#include <QThreadPool>

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

namespace tcpdump {

/// @p bytes as "1.5 MB", "2.0 KB" or "12 B", as the sidebar shows sizes.
QString formatBytes( uint64_t bytes );

/// @p seconds as m:ss, or h:mm:ss from an hour on.
QString clockTime( qint64 seconds );

/// What the user is told of a live capture @p name that @p condition of
/// @p limits stopped: "The capture eth0 stopped after 1,000 packets."
QString liveStopText( const QString& name, StopCondition condition, const LiveLimits& limits );

/// Where a Live Capture Session opens tabs and tells the user: LogSquirl,
/// through the sidebar, in the app; a fake in tests.
class LiveCaptureHost {
public:
    virtual ~LiveCaptureHost() = default;

    /// Open the text file @p logPath in a tab, following it; on the UI thread.
    virtual void openTab( const QString& logPath ) = 0;
    /// Tell the user @p message in a notification.
    virtual void notify( const QString& message ) = 0;
    /// Why no capture can start now for something outside the session, e.g.
    /// a capture file being read; empty if one can.
    virtual QString busyElsewhere() const
    {
        return {};
    }
};

/// Where a Live Capture Session keeps what the tab of each text file of a
/// capture shows: the sidebar's summaries and indices, by text file, in the
/// app; a fake in tests.
class LiveCaptureCatalog {
public:
    virtual ~LiveCaptureCatalog() = default;

    /// The text file @p logPath of the capture @p name, written from the raw
    /// file @p rawPath, is about to open in a tab: keep it.
    virtual void addFile( const QString& logPath, const QString& rawPath, const QString& name ) = 0;
    /// What the text file @p logPath shows from now on: @p summary, the
    /// capture's @p index (null: the one it has) and the size of its raw
    /// capture, @p fileSize; so far, or final.
    virtual void updateFile( const QString& logPath, const CaptureSummary& summary,
                             std::shared_ptr<const CaptureIndex> index, qint64 fileSize ) = 0;
    /// The capture of the text file @p logPath failed with @p error; what it
    /// captured is kept.
    virtual void setFileError( const QString& logPath, const QString& error ) = 0;
};

/// What a capture is run with.
struct LiveRunRequest {
    QString name;       ///< Its files are <name>.log and the raw <name>.pcap or .pcapng.
    QString outputRoot; ///< Where its private directory is made.
    ConversionOptions options;
    LiveCapture::SourceFactory makeSource; ///< Makes its stream, on the worker thread.
    LiveLimits limits;                     ///< When it stops by itself; its ring buffer.
    LiveClock clock;                       ///< Measures the limits; empty: the steady clock.
};

/// A capture running for a Live Capture Session: a LiveCapture on a worker
/// thread (runOnWorker()), or a test's script.
class LiveRun {
public:
    /// What a run tells, on the session's thread, as LiveCapture's signals:
    /// readyToOpen once per text file, snapshots, stderr lines, then
    /// finished once and done once its source is gone.
    struct Listener {
        std::function<void( const QString& logPath, const QString& rawPath )> readyToOpen;
        std::function<void( const LiveSnapshot& snapshot )> snapshot;
        std::function<void( const QString& line )> stderrLine;
        std::function<void( const ConversionResult& result )> finished;
        std::function<void()> done;
    };

    /// Lets go of a run that may still go on without waiting for it, and
    /// without telling its listener anything more.
    virtual ~LiveRun() = default;

    /// Start the capture, telling @p listener; once only.
    virtual void start( Listener listener ) = 0;
    /// End the capture and keep what was captured: finished follows.
    virtual void stop() = 0;
    /// Whether it is done: its source is gone (done was told), or it never started.
    virtual bool isDone() const = 0;
};

/// Makes the run of @p request.
using LiveRunFactory = std::function<std::unique_ptr<LiveRun>( LiveRunRequest request )>;

/// The app's run of @p request: a LiveCapture on a worker thread of its own,
/// handed to retireLiveCapture() when the run is let go of.
std::unique_ptr<LiveRun> runOnWorker( LiveRunRequest request );

/// What a live capture came to.
struct LiveOutcome {
    enum class Status {
        /// Packets were captured: their tabs show the final summary.  A stop
        /// condition that ended it is stoppedBy.
        Captured,
        /// It ended without packets: no tab was opened, its files are gone.
        Empty,
        /// Stopped before its capture header came: nothing was captured,
        /// nothing is left behind.  Not a failure.
        Stopped,
        /// It failed: error and guidance; files keep what was captured, if
        /// a packet came.
        Failed,
    };

    Status status = Status::Failed;
    QString name;     ///< The capture's.
    QString error;    ///< Why it failed.
    QString guidance; ///< What its kind says to do about the failure; empty if nothing.
    StopCondition stoppedBy = StopCondition::None;
    QStringList files; ///< The text files opened in tabs, oldest first.
};

/// What the user is told of @p outcome when it left nothing to show,
/// Stopped or Empty: "The capture eth0 ended without packets."; empty for
/// one that Captured or Failed.
QString liveOutcomeText( const LiveOutcome& outcome );

/**
 * One live capture at a time, from its start to its outcome (see the file
 * comment).  On the UI thread; a capture runs through a LiveRun.
 */
class LiveCaptureSession : public QObject {
    Q_OBJECT

public:
    enum class State {
        Idle,      ///< No capture runs; one may still be ending its program.
        Checking,  ///< A choice's kind is being asked before it starts.
        Capturing, ///< A capture runs.
        Stopping,  ///< A capture was told to stop, and has not ended yet.
    };

    /// A session opening tabs on @p host and keeping summaries in @p
    /// catalog, both outliving it.
    LiveCaptureSession( LiveCaptureHost& host, LiveCaptureCatalog& catalog,
                        QObject* parent = nullptr );
    /// Lets go of a capture that may still run (its run is retired, not
    /// waited for), and cancels and waits for a check that runs.
    ~LiveCaptureSession() override;

    LiveCaptureSession( const LiveCaptureSession& ) = delete;
    LiveCaptureSession& operator=( const LiveCaptureSession& ) = delete;

    /// The kinds a choice is started with.
    void setSources( std::shared_ptr<const LiveSourceRegistry> sources )
    {
        sources_ = std::move( sources );
    }
    /// Where captures write their private directories.
    void setOutputRoot( const QString& root )
    {
        outputRoot_ = root;
    }
    /// Run captures with @p factory instead of on a worker (tests).
    void setRunFactory( LiveRunFactory factory )
    {
        makeRun_ = std::move( factory );
    }
    /// Measure the limits' durations with @p clock (tests).
    void setClock( LiveClock clock )
    {
        clock_ = std::move( clock );
    }

    /**
     * Capture @p choice: its kind makes the stream, named after its device
     * and interface (liveCaptureName()), and the choice is saved in
     * settings.ini as it starts.  False, with a notification, while a
     * capture runs or something else is busy, or when the choice cannot
     * start (liveChoiceProblem()).  A kind that must ask first is asked on a
     * worker thread (Checking): the choice is checked again then, and
     * refused with a notification, or started.
     */
    bool start( const LiveChoice& choice );

    /**
     * Capture from the stream @p makeSource makes, named @p name, as @p
     * limits say; a failure is explained by @p kind, if it is given.  False,
     * with a notification, while a capture runs or something else is busy.
     */
    bool start( const QString& name, LiveCapture::SourceFactory makeSource,
                const LiveLimits& limits = {}, std::shared_ptr<const LiveSourceKind> kind = {} );

    /// Start @p choice once no capture runs: a running one is stopped, and
    /// @p choice starts when its program has ended (the pending start); a
    /// check that runs is dropped for it.
    void startWhenIdle( const LiveChoice& choice );

    /// End the running capture and keep what was captured; a check that
    /// runs is dropped, and nothing starts.
    void stop();

    State state() const
    {
        return state_;
    }
    /// Whether a capture runs, or a choice is being checked to start.
    bool isBusy() const
    {
        return state_ != State::Idle;
    }
    /// Whether a choice waits to start once the running capture has ended.
    bool hasPendingStart() const
    {
        return pending_.has_value();
    }

    /// The capture's name, running or the last.
    const QString& name() const
    {
        return name_;
    }
    /// The choice of the capture, running, being checked, or the last; none
    /// for one started by name.
    const std::optional<LiveChoice>& choice() const
    {
        return choice_;
    }
    /// The capture's stop conditions and ring buffer.
    const LiveLimits& limits() const
    {
        return limits_;
    }
    /// The capture's latest snapshot, its counts only (no summary or index).
    const LiveSnapshot& progress() const
    {
        return progress_;
    }
    /// The time since the capture started, in milliseconds.
    qint64 elapsedMs() const
    {
        return clockStarted_.isValid() ? clockStarted_.elapsed() : 0;
    }
    /// The capture's text files opened in tabs so far, oldest first.
    const QStringList& files() const
    {
        return files_;
    }
    /// What the last capture came to; none while it runs.
    const std::optional<LiveOutcome>& outcome() const
    {
        return outcome_;
    }

signals:
    /// isBusy(), state() or hasPendingStart() changed.
    void stateChanged();
    /// A capture started: name(), choice() and limits() are its.
    void started();
    /// The capture's text file @p logPath was kept and opened in a tab.
    void fileOpened( const QString& logPath );
    /// A snapshot came: progress(), and the catalog's summaries.
    void progressed();
    /// A line the capture program wrote to stderr.
    void stderrLine( const QString& line );
    /// The capture ended with @p outcome (outcome()), after its catalog
    /// entries were final and the user was told.
    void finished( const tcpdump::LiveOutcome& outcome );

private:
    /// Start @p choice, checked: saved, and run with its kind's source.
    bool startChecked( const LiveChoice& choice );
    /// Run @p request, its failures explained by @p kind.
    void run( LiveRunRequest request, std::shared_ptr<const LiveSourceKind> kind );
    /// Why nothing can start now, said in a notification; false if it can.
    bool refuseWhileBusy();
    /// The kind of @p choice was asked (check @p check): check it again and
    /// start it, or refuse it.
    void checked( const LiveChoice& choice, unsigned check );
    void setState( State state );

    // What the run tells; @p run is the run's number, of runs_.
    void openFile( unsigned run, const QString& logPath, const QString& rawPath );
    void takeSnapshot( unsigned run, const LiveSnapshot& snapshot );
    void finish( unsigned run, const ConversionResult& result );
    void runDone( unsigned run );

    LiveCaptureHost& host_;
    LiveCaptureCatalog& catalog_;
    std::shared_ptr<const LiveSourceRegistry> sources_;
    QString outputRoot_;
    LiveRunFactory makeRun_;
    LiveClock clock_;

    State state_ = State::Idle;
    std::unique_ptr<LiveRun> run_;               ///< Running, or the last: it may still be ending.
    unsigned runs_ = 0;                          ///< The number of the last run made.
    std::shared_ptr<const LiveSourceKind> kind_; ///< Explains the run's failure; may be null.
    QString name_;
    std::optional<LiveChoice> choice_;
    LiveLimits limits_;
    LiveSnapshot progress_;
    QElapsedTimer clockStarted_;
    QStringList files_;
    std::vector<QString> rawFiles_; ///< The raw file of each of files_.
    std::optional<LiveOutcome> outcome_;
    std::optional<LiveChoice> pending_; ///< Starts once the run is done.

    /// The check of a choice's kind: its number (a later one, or Stop,
    /// drops it), and the flag that cancels its listings.
    unsigned checks_ = 0;
    std::shared_ptr<std::atomic_bool> cancelCheck_;
    QThreadPool checkPool_;
};

} // namespace tcpdump
