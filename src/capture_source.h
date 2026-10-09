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
 * @file capture_source.h
 * @brief Capture Sources: ByteSources over a capture that is still being written.
 *
 * A file holds all of its capture when it is opened; a pipe, a FIFO, a
 * socket or a process's stdout holds what has been written so far, and
 * more comes later or never.  A StreamSource reads such a stream for a
 * CaptureReader: it waits for data in slices of at most kWaitSlice, so that
 * a stop request ends a wait promptly even when nothing is written, and it
 * reads as ended when the writer closes the stream (the process exited, the
 * pipe was closed) or a stop was requested.  A CaptureReader reads it like
 * a file that ends there: a record cut off at the end is truncated().
 *
 * Every live source (a local tcpdump or dumpcap, adb, ssh, an extcap, a
 * custom command) hands its stream to the Converter as one of these:
 * FdSource for a file descriptor, DeviceSource for a QIODevice such as a
 * QProcess or a QLocalSocket (a Windows named pipe).
 */

#pragma once

#include "pcap_parser.h"

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>

class QIODevice;

namespace tcpdump {

/**
 * A ByteSource over a stream that is still being written.
 *
 * read() waits until at least one byte has come and returns what has, or 0
 * once the stream has ended: closed by its writer, broken by an error
 * (error() says which), or stopped.  The stop flag is checked before every
 * wait, and no wait is longer than kWaitSlice, so a read returns within
 * kWaitSlice of the flag being set.  Once ended, a source stays ended.
 */
class StreamSource : public ByteSource {
public:
    /// The longest a read waits before it checks the stop flag again.
    static constexpr std::chrono::milliseconds kWaitSlice{ 50 };

    /// @param stop  If set, ends the stream (Stop or Cancel); must outlive
    ///              the source.
    explicit StreamSource( const std::atomic_bool* stop = nullptr )
        : stop_( stop )
    {
    }

    size_t read( uint8_t* dst, size_t n ) final;
    bool ready() final;

    /// Whether the stream ended because a stop was requested, not because
    /// its writer closed it.
    bool stopped() const
    {
        return stopped_;
    }

    /// Why the stream broke off; empty if it ended normally or was stopped.
    const std::string& error() const
    {
        return error_;
    }

protected:
    /// Wait at most @p timeout for data, and read up to @p n bytes of it into
    /// @p dst.  Returns how many were read, 0 if the stream has ended (on an
    /// error, error_ says why), or -1 if nothing came in time.
    virtual std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) = 0;

    /// Whether data, or the end, can be read without waiting.
    virtual bool available() = 0;

    std::string error_;

private:
    bool stopRequested() const
    {
        return stop_ != nullptr && stop_->load();
    }

    const std::atomic_bool* stop_;
    bool ended_ = false;
    bool stopped_ = false;
};

#ifndef _WIN32
/**
 * A StreamSource over an open file descriptor of a pipe, a FIFO or a
 * socket, waited on with poll().  The descriptor stays the caller's to
 * close, after the source is done with it.  Unix only; on Windows a pipe is
 * read through a DeviceSource.
 */
class FdSource : public StreamSource {
public:
    explicit FdSource( int fd, const std::atomic_bool* stop = nullptr )
        : StreamSource( stop )
        , fd_( fd )
    {
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override;
    bool available() override;

private:
    int fd_;
};
#endif

/**
 * A StreamSource over an open QIODevice that can wait for data
 * (waitForReadyRead()): a QProcess's stdout, a QLocalSocket (a Windows named
 * pipe), a QTcpSocket.  It is used on the thread the device belongs to,
 * which needs no event loop.  The stream ends when the device has nothing
 * left and stops waiting before the timeout, as a finished process or a
 * closed socket does.  A QFile cannot wait: a FIFO is read with an FdSource.
 */
class DeviceSource : public StreamSource {
public:
    explicit DeviceSource( QIODevice& device, const std::atomic_bool* stop = nullptr )
        : StreamSource( stop )
        , device_( device )
    {
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override;
    bool available() override;

private:
    friend class ProcessSource; // reads its stdout through one

    QIODevice& device_;
};

} // namespace tcpdump
