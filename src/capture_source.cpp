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
 * @file capture_source.cpp
 * @brief Waiting for a stream's bytes in slices, so that a stop is seen.
 */

#include "capture_source.h"

#include <QDeadlineTimer>
#include <QIODevice>

#ifndef _WIN32
#include <cerrno>
#include <cstring>
#include <poll.h>
#include <unistd.h>
#endif

namespace tcpdump {

// ── StreamSource ─────────────────────────────────────────────────────────

size_t StreamSource::read( uint8_t* dst, size_t n )
{
    if ( n == 0 ) {
        return 0;
    }
    while ( !ended_ ) {
        if ( stopRequested() ) {
            stopped_ = true;
            ended_ = true;
            break;
        }
        const auto got = readFor( dst, n, kWaitSlice );
        if ( got > 0 ) {
            return static_cast<size_t>( got );
        }
        ended_ = got == 0;
    }
    return 0;
}

bool StreamSource::ready()
{
    return ended_ || stopRequested() || available();
}

#ifndef _WIN32

// ── FdSource ─────────────────────────────────────────────────────────────

std::ptrdiff_t FdSource::readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout )
{
    pollfd wait{ fd_, POLLIN, 0 };
    const int polled = ::poll( &wait, 1, static_cast<int>( timeout.count() ) );
    if ( polled == 0 || ( polled < 0 && errno == EINTR ) ) {
        return -1;
    }
    if ( polled < 0 ) {
        error_ = std::strerror( errno );
        return 0;
    }
    // Readable, closed (POLLHUP) or broken: read() tells which.
    const auto got = ::read( fd_, dst, n );
    if ( got >= 0 ) {
        return got; // 0: the writer closed the stream
    }
    if ( errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK ) {
        return -1;
    }
    error_ = std::strerror( errno );
    return 0;
}

bool FdSource::available()
{
    pollfd wait{ fd_, POLLIN, 0 };
    return ::poll( &wait, 1, 0 ) > 0;
}

#endif

// ── DeviceSource ─────────────────────────────────────────────────────────

std::ptrdiff_t DeviceSource::readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout )
{
    if ( device_.bytesAvailable() <= 0 ) {
        const QDeadlineTimer deadline( timeout );
        if ( !device_.waitForReadyRead( static_cast<int>( timeout.count() ) )
             && device_.bytesAvailable() <= 0 ) {
            // Given up before the time was up: there is nothing left to wait for.
            return deadline.hasExpired() ? -1 : 0;
        }
    }
    const auto got = device_.read( reinterpret_cast<char*>( dst ), static_cast<qint64>( n ) );
    if ( got < 0 ) {
        error_ = device_.errorString().toStdString();
        return 0;
    }
    return got > 0 ? static_cast<std::ptrdiff_t>( got ) : -1;
}

bool DeviceSource::available()
{
    return device_.bytesAvailable() > 0 || !device_.isOpen();
}

} // namespace tcpdump
