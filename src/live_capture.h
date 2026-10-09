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
 * signals: the text file is ready to open, a snapshot of the summary, a line
 * the capture program wrote to stderr, the outcome.
 *
 * The source is made on the worker thread by a SourceFactory, as a
 * ProcessSource must be (its QProcess belongs to the thread that reads it).
 * Stop ends the stream and finalises: the last lines are flushed, the raw
 * capture is closed, the summary is final.  Cancel also removes what was
 * written.  The outcome is posted before the source is destroyed, so that a
 * capture program that takes its time to end (ProcessSource::terminate())
 * does not hold it up.
 */

#pragma once

#include "pcap_converter.h"
#include "process_source.h"

#include <QObject>
#include <QString>
#include <QThreadPool>

#include <atomic>
#include <functional>
#include <memory>

namespace tcpdump {

class LiveCapture : public QObject {
    Q_OBJECT

public:
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
    /// been posted is dropped.
    ~LiveCapture() override;

    LiveCapture( const LiveCapture& ) = delete;
    LiveCapture& operator=( const LiveCapture& ) = delete;

    /// Start the capture; once only.
    void start();
    /// End the capture and keep what was captured: finished() follows.
    void stop();
    /// End the capture and remove what was written: finished() follows.
    void cancel();

    /// Whether the capture was started and has not finished yet.
    bool isRunning() const
    {
        return running_;
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
    /// A line the capture program wrote to stderr.
    void stderrLine( const QString& line );
    /// The capture ended: Converted (stopped, or its stream closed), Failed
    /// (keeping what was captured, if a packet came), Cancelled, or Stopped
    /// before its capture header had come (nothing was captured).
    void finished( const tcpdump::ConversionResult& result );

private:
    /// Run @p work on this object's thread, unless it is gone by then.
    void post( std::function<void()> work );

    QString name_;
    QString outputRoot_;
    ConversionOptions options_;
    SourceFactory makeSource_;
    bool running_ = false;
    bool started_ = false;
    /// Ends the stream (Stop and Cancel), and removes what was written (Cancel).
    std::shared_ptr<std::atomic_bool> stop_ = std::make_shared<std::atomic_bool>( false );
    std::shared_ptr<std::atomic_bool> cancel_ = std::make_shared<std::atomic_bool>( false );
    /// One worker thread, owned here so that it can be waited for.
    QThreadPool pool_;
};

} // namespace tcpdump
