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
 * @file process_source.h
 * @brief The Process Source: a capture program's stdout as a capture stream.
 *
 * tcpdump, dumpcap, adb, ssh, an extcap or a user's command writes a
 * capture to its stdout and its complaints to its stderr.  A ProcessSource
 * runs such a program and is the StreamSource over its stdout; stderr is
 * kept apart, as text in the stream would corrupt the capture, and handed
 * over line by line.  The program is started from an argument list, never
 * through a shell, unless a custom command asks for one (ProcessCommand::shell).
 *
 * The program runs in a process group of its own (on Windows: in a job
 * object), so that ending it ends what it started too: ssh's or adb's
 * helpers, a wrapper script's tcpdump.  Ending it is SIGTERM to the group
 * and, after kTerminateGrace, SIGKILL; a job object is terminated.  Every
 * running program is known to terminateCaptureProcesses(), which the plugin
 * calls when it is shut down, so that none outlives LogSquirl or the plugin.
 */

#pragma once

#include "capture_source.h"

#include <QByteArray>
#include <QString>
#include <QStringList>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <deque>
#include <functional>
#include <memory>

class QProcess;

namespace tcpdump {

struct ProcessGroup;

/// A capture program and its arguments, as the user or a source chose them.
struct ProcessCommand {
    QString program;       ///< The executable, a path or a name found on PATH.
    QStringList arguments; ///< Passed as they are, each one argument.
    /// What messages call the program; empty: the program's file name.
    QString name;
    /// program is a command line for the system's shell, not an executable.
    bool viaShell = false;
    /// The capture comes another way than stdout (an extcap writes it to a
    /// FIFO the plugin made): stdout goes to the null device, and the
    /// stream is not read from it (see ProcessSource::waitForEnd()).
    bool discardStdout = false;

    /// A custom command line run by the system's shell (/bin/sh -c, or
    /// cmd.exe /c on Windows), for a user who wants pipes or quoting: the
    /// only way a shell is involved.  Messages call it by its first word.
    static ProcessCommand shell( const QString& commandLine );

    /// What messages call the program.
    QString displayName() const;
};

/**
 * The lines a program wrote to stderr: each one is handed on as it is
 * complete, and the last kKept are kept for a message.  Bytes are decoded as
 * UTF-8, line ends ("\n", "\r\n") dropped, empty lines skipped.
 */
class StderrLines {
public:
    /// The lines kept for a message, the latest last.
    static constexpr size_t kKept = 10;

    explicit StderrLines( std::function<void( const QString& )> onLine = {} )
        : onLine_( std::move( onLine ) )
    {
    }

    /// Take the next bytes of stderr; complete lines are handed on.
    void append( const QByteArray& bytes );
    /// The stream has ended: a last line without a line end is complete too.
    void finish();

    /// The last kKept lines, the latest last.
    QStringList last() const;

private:
    void complete( const QByteArray& line );

    std::function<void( const QString& )> onLine_;
    QByteArray partial_;
    std::deque<QString> last_;
};

/**
 * The StreamSource over a capture program's stdout.  It starts the program
 * when it is constructed, and ends it (with what it started) when it is
 * destroyed, if it has not ended by itself: the stream is read, and the
 * program owned, on the thread that constructs it, which needs no event
 * loop (the QProcess belongs to it).
 *
 * The stream ends when the program has exited (or a stop was requested).
 * A program that could not be started, exited with a code other than 0 or
 * crashed breaks the stream off: error() names the program, the code and
 * its last lines on stderr, so that "permission denied" or "no such device"
 * reaches the user, and convertStream() ends Failed with it.  A program
 * ended by terminate() or terminateCaptureProcesses() did not fail: the
 * stream reads as stopped().
 */
class ProcessSource : public StreamSource {
public:
    /// How long a program has to end on SIGTERM before it is killed.
    static constexpr std::chrono::milliseconds kTerminateGrace{ 2000 };

    /// @param stop    If set, ends the stream (Stop or Cancel); must outlive
    ///                the source.  The program runs on until terminate() or
    ///                the source's end.
    /// @param onLine  If set, called with each line of stderr, on this
    ///                thread, while the stream is read.
    explicit ProcessSource( const ProcessCommand& command, const std::atomic_bool* stop = nullptr,
                            std::function<void( const QString& )> onLine = {} );
    ~ProcessSource() override;

    ProcessSource( const ProcessSource& ) = delete;
    ProcessSource& operator=( const ProcessSource& ) = delete;

    /// Whether the program was started.
    bool started() const;

    /// The program's process id, 0 if it was not started.
    qint64 processId() const;

    /// The program's last lines on stderr, the latest last.
    QStringList lastStderrLines() const;

    /// End the program and every process it started and that is still in
    /// its group (job): SIGTERM, and SIGKILL to what is left after
    /// kTerminateGrace; on Windows the job is terminated.  Returns when they
    /// are gone.  Does nothing if the program was not started or has
    /// been ended.
    void terminate();

    /// For a program whose capture comes another way than stdout
    /// (ProcessCommand::discardStdout), read by whoever reads that: wait at
    /// most @p timeout (0: not at all) for the program to end, handing on
    /// what it writes to stderr meanwhile; whether it has ended (or was
    /// never started).
    bool waitForEnd( std::chrono::milliseconds timeout );

    /// Why the program ended, if it failed: empty if it runs, exited with 0
    /// or was ended on purpose.
    QString failure() const;

    /// Whether the program was ended by terminate() or
    /// terminateCaptureProcesses().
    bool endedOnPurpose() const override;

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override;
    bool available() override;

private:
    void drainStderr();

    QString name_;
    std::unique_ptr<QProcess> process_;
    std::unique_ptr<DeviceSource> stdout_;
    /// The program's group (job), also known to terminateCaptureProcesses().
    std::shared_ptr<ProcessGroup> group_;
    StderrLines stderr_;
    bool started_ = false;
    QString startError_; ///< Why it could not be started.
    qint64 pid_ = 0;
};

/// End every capture program that is running (ProcessSource::terminate()),
/// whichever thread reads it; returns when all are gone.  Called when the
/// plugin is shut down, as LogSquirl quits or the plugin is disabled.
void terminateCaptureProcesses();

} // namespace tcpdump
