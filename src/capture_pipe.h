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
 * @file capture_pipe.h
 * @brief A pipe the plugin makes for a capture program to write into (a
 *        FIFO, or a named pipe on Windows), and the Capture Source over it.
 *
 * A Wireshark extcap does not write its capture to stdout: it is given
 * `--fifo <path>` and opens that path for writing.  The plugin makes it:
 *
 *   - on Unix, a FIFO (mkfifo, mode 0600) in a directory of its own
 *     (mkdtemp, mode 0700) in the plugin's temporary root, named as its
 *     other temporary directories are, so that one a crash left behind is
 *     removed with them;
 *   - on Windows, a named pipe `\\.\pipe\logsquirl-tcpdump-<pid>-<random>`
 *     (CreateNamedPipe: inbound, one instance, the first of its name, no
 *     remote clients), read with overlapped I/O so that a read can wait in
 *     slices.
 *
 * On Unix the plugin holds a write end of the FIFO itself, so that it does
 * not read as ended before the program has opened it, or between two
 * opens: the stream ends when the program has ended, after what it wrote
 * is read.
 *
 * A PipeSource runs the program with the pipe's path (a Process Source
 * whose stdout is discarded: its process group, stderr lines and failure
 * are the same as a capture program's) and is the StreamSource over the
 * pipe; it ends the program, then removes the pipe, when it goes.
 */

#pragma once

#include "capture_source.h"
#include "process_source.h"

#include <QString>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace tcpdump {

/// A pipe a capture program writes into and the plugin reads from.
class CapturePipe {
public:
    /// Make the pipe; error() says why if it could not be made.
    CapturePipe();
    /// Closes and removes the pipe (and its directory).
    ~CapturePipe();

    CapturePipe( const CapturePipe& ) = delete;
    CapturePipe& operator=( const CapturePipe& ) = delete;

    /// The path the writer opens: a FIFO's, or `\\.\pipe\…`; empty if the
    /// pipe could not be made.
    const QString& path() const
    {
        return path_;
    }

    /// Why the pipe could not be made; empty if it was.
    const QString& error() const
    {
        return error_;
    }

    /// Wait at most @p timeout for bytes and read up to @p n of them into
    /// @p dst.  Returns how many were read, -1 if none came in time, or 0
    /// if the pipe has ended: its writer closed it (on Windows; on Unix the
    /// plugin's own write end keeps it open), or it broke, which @p error
    /// then says.
    std::ptrdiff_t read( uint8_t* dst, size_t n, std::chrono::milliseconds timeout,
                         std::string& error );

    /// Whether bytes, or the end, can be read without waiting.
    bool available();

private:
    QString path_;
    QString error_;
#ifdef _WIN32
    struct Windows;
    std::unique_ptr<Windows> win_;
#else
    QString dir_;     ///< The FIFO's private directory.
    int readFd_ = -1; ///< What the plugin reads.
    int holdFd_ = -1; ///< The plugin's own write end.
#endif
};

/**
 * The StreamSource over a CapturePipe that a program writes into.  The
 * program is started when the source is constructed, with the command
 * @p command makes of the pipe's path, its stdout discarded; it runs in a
 * group of its own (Stop and the plugin's shutdown end it, as a Process
 * Source's).  The stream ends when the program has ended and what it wrote
 * is read; a program that could not be started, or exited with a code
 * other than 0, breaks it off with its last lines on stderr.
 */
class PipeSource : public StreamSource {
public:
    /// @param command  The program to run, given the pipe's path.
    /// @param stop     If set, ends the stream (Stop or Cancel); must outlive
    ///                 the source.
    /// @param onLine   If set, called with each line of the program's
    ///                 stderr, on this thread, while the stream is read.
    PipeSource( const std::function<ProcessCommand( const QString& pipePath )>& command,
                const std::atomic_bool* stop = nullptr,
                std::function<void( const QString& )> onLine = {} );
    /// Ends the program (with what it started), then removes the pipe.
    ~PipeSource() override;

    PipeSource( const PipeSource& ) = delete;
    PipeSource& operator=( const PipeSource& ) = delete;

    /// The pipe's path; empty if it could not be made.
    QString pipePath() const;

    /// The program, if the pipe was made; null if not.
    ProcessSource* process() const
    {
        return process_.get();
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override;
    bool available() override;
    bool endedOnPurpose() const override;

private:
    std::unique_ptr<CapturePipe> pipe_;
    std::unique_ptr<ProcessSource> process_;
    QString name_;           ///< The program's name, for messages.
    bool pipeEnded_ = false; ///< Its writer closed the pipe.
};

} // namespace tcpdump
