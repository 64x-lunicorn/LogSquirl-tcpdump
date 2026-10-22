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
 * @file live_capture.h
 * @brief A Live Capture: a capture source converted on a worker thread while
 *        it is written, reported on the UI thread.
 *
 * The Converter converts a stream live (convertStream()) and tells on its
 * own thread; LogSquirl and Qt widgets may only be called on the UI thread.
 * A LiveCapture runs the conversion on a worker thread of its own and posts
 * everything it is told to the thread the LiveCapture belongs to, as
 * signals: the text file is ready to open, a snapshot of the summary, the
 * lines the capture program wrote to stderr, the outcome.
 *
 * Stderr lines come in batches, at most one each kStderrBatchInterval and
 * of at most kStderrBatchLines (the latest; older ones are counted as
 * dropped): a program that prints without end holds one event in the UI
 * thread's queue, not one a line.
 *
 * The source is made on the worker thread by a SourceFactory, as a
 * ProcessSource must be (its QProcess belongs to the thread that reads it).
 * Stop ends the stream and finalises: the last lines are flushed, the raw
 * capture is closed, the summary is final.  A stop condition of its
 * LiveLimits, reached, ends it the same way.  Nothing cancels a live
 * capture: what it wrote is kept for its tabs, or removed by the Live
 * Capture Session (live_capture_session.h) when no tab opened.  The
 * outcome is posted before the source is destroyed, so that a
 * capture program that takes its time to end (ProcessSource::terminate())
 * does not hold it up; done() follows once the source is gone.
 *
 * The UI thread never waits for a worker: a LiveCapture that may still run
 * is handed to retireLiveCapture(), which stops it and keeps it until its
 * worker is done, and the plugin's shutdown joins what is left
 * (joinLiveCaptures()), the one place that waits, as the library is
 * unloaded next.
 */

#pragma once

#include "pcap_converter.h"
#include "process_source.h"

#include <QObject>
#include <QString>
#include <QThreadPool>

#include <QStringList>

#include <atomic>
#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>

namespace tcpdump {

class LiveCapture : public QObject {
    Q_OBJECT

public:
    /// The most stderr lines a batch holds: the latest, older ones dropped.
    static constexpr size_t kStderrBatchLines = 200;
    /// The least time between two batches of stderr lines.
    static constexpr std::chrono::milliseconds kStderrBatchInterval{ 100 };

    /// Makes the capture's stream, on the worker thread.  @p stop ends it
    /// (StreamSource's stop flag); @p onStderrLine, if the source has one,
    /// takes each line its program writes to stderr.  Null: the source
    /// could not be made.
    using SourceFactory = std::function<std::unique_ptr<ByteSource>(
        const std::atomic_bool* stop, std::function<void( const QString& )> onStderrLine )>;

    /// The factory of a ProcessSource running @p command.
    static SourceFactory processSource( const ProcessCommand& command );

    /// A capture named @p name (its files are <name>.log and <name>.pcap or
    /// .pcapng), written below @p outputRoot with @p options.
    LiveCapture( const QString& name, const QString& outputRoot, const ConversionOptions& options,
                 SourceFactory makeSource, QObject* parent = nullptr );
    /// Stops a capture that still runs, as stop() does, and waits for the
    /// worker: no code of the plugin runs on it afterwards.  What would have
    /// been posted is dropped.  On the UI thread, destroy one only once it
    /// isDone(), or never started; hand others to retireLiveCapture().
    ~LiveCapture() override;

    LiveCapture( const LiveCapture& ) = delete;
    LiveCapture& operator=( const LiveCapture& ) = delete;

    /// Stop by itself, and split the raw capture, as @p limits say; before
    /// start().  Any live source's capture can be limited.
    void setLimits( const LiveLimits& limits )
    {
        limits_ = limits;
    }
    const LiveLimits& limits() const
    {
        return limits_;
    }

    /// Measure the limits' durations and the flush and snapshot cadence with
    /// @p clock (a test's); before start().
    void setClock( LiveClock clock )
    {
        clock_ = std::move( clock );
    }

    /// Start the capture; once only.
    void start();
    /// End the capture and keep what was captured: finished() follows.
    void stop();

    /// Whether the capture was started and has not finished yet.
    bool isRunning() const
    {
        return running_;
    }

    /// Whether its worker is done, its source gone (done() was emitted), or
    /// it was never started: destroying it then waits for nothing.
    bool isDone() const
    {
        return !started_ || done_;
    }

    const QString& name() const
    {
        return name_;
    }

signals:
    /// The text file holds its header and the first packet line: open it,
    /// following it.  @p rawPath is the raw capture next to it.
    void readyToOpen( const QString& logPath, const QString& rawPath );
    /// What was converted so far (LiveObserver::snapshot).
    void snapshotTaken( const tcpdump::LiveSnapshot& snapshot );
    /// Lines the capture program wrote to stderr, the latest last, after
    /// @p dropped lines it wrote since the last batch that are not handed on.
    void stderrLines( const QStringList& lines, quint64 dropped );
    /// The capture ended: Converted (stopped, or its stream closed), Failed
    /// (keeping what was captured, if a packet came), or Stopped before its
    /// capture header had come (nothing was captured).  Never Cancelled.
    void finished( const tcpdump::ConversionResult& result );
    /// After finished(): the source is gone too, its capture program ended.
    void done();

private:
    /// Run @p work on this object's thread, unless it is gone by then.
    void post( std::function<void()> work );
    /// Take a stderr line, on the worker thread: a batch is posted unless
    /// one is on its way.
    void takeStderrLine( const QString& line );
    /// Emit the pending stderr lines, if any; on this object's thread.
    bool emitStderrLines();
    /// Emit the pending stderr lines, and look again after an interval; or
    /// let the next line post a batch, if there are none.
    void flushStderrLines();

    QString name_;
    QString outputRoot_;
    ConversionOptions options_;
    SourceFactory makeSource_;
    LiveLimits limits_;
    LiveClock clock_;
    bool running_ = false;
    bool started_ = false;
    bool done_ = false;
    /// Ends the stream.
    std::shared_ptr<std::atomic_bool> stop_ = std::make_shared<std::atomic_bool>( false );
    /// One worker thread, owned here so that it can be waited for.
    QThreadPool pool_;
    /// The stderr lines not handed on yet, shared with the worker.
    struct PendingStderr {
        std::mutex mutex;
        std::deque<QString> lines;
        quint64 dropped = 0;
        bool posted = false; ///< A flush is queued or timed: no need to post one.
    } pendingStderr_;
};

/// Stop @p capture and keep it until its worker is done, then let it go:
/// on the UI thread, instead of destroying a capture that may still run.
/// Its signals are disconnected; nothing waits.
void retireLiveCapture( std::unique_ptr<LiveCapture> capture );

/// Stop every retired capture and wait for their workers: the plugin's
/// shutdown, after cancelListings() (a worker may be listing) and with the
/// capture programs ended (terminateCaptureProcesses()), as the library is
/// unloaded next.  On the UI thread.
void joinLiveCaptures();

/// The retired captures whose workers are not done yet.
size_t retiredLiveCaptures();

} // namespace tcpdump
