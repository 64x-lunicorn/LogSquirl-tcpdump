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
 * @file capture_pipe.cpp
 * @brief Making a FIFO or a named pipe, reading it in slices, and running
 *        the program that writes into it.
 */

#include "capture_pipe.h"

#include "tempdirs.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QRandomGenerator>

#include <algorithm>
#include <cstring>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tcpdump {

#ifdef _WIN32

// ── CapturePipe on Windows: a named pipe ─────────────────────────────────

namespace {

/// The size of the pipe's buffer, and of each read.
constexpr DWORD kPipeBuffer = 1 << 16;

/// The text of the Windows error @p code.
std::string windowsError( DWORD code )
{
    wchar_t* text = nullptr;
    const auto length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, 0, reinterpret_cast<wchar_t*>( &text ), 0, nullptr );
    auto message = length > 0
                       ? QString::fromWCharArray( text, static_cast<int>( length ) ).trimmed()
                       : QStringLiteral( "error %1" ).arg( code );
    if ( text ) {
        LocalFree( text );
    }
    return message.toStdString();
}

} // namespace

/**
 * The pipe and the one overlapped operation that may be pending on it: the
 * connect of its writer, then one read after another into buffer, from
 * which a read hands out what it got.
 */
struct CapturePipe::Windows {
    enum class State {
        Connecting, ///< Waiting for the writer to open the pipe.
        Idle,       ///< Connected, no read pending.
        Reading,    ///< A read is pending.
        Ended,      ///< The writer closed it, or it broke.
    };

    HANDLE pipe = INVALID_HANDLE_VALUE;
    HANDLE event = nullptr;
    OVERLAPPED overlapped{};
    State state = State::Connecting;
    std::vector<uint8_t> buffer = std::vector<uint8_t>( kPipeBuffer );
    size_t at = 0;   ///< The next byte of buffer to hand out.
    size_t have = 0; ///< The bytes buffer holds.

    ~Windows()
    {
        if ( pipe != INVALID_HANDLE_VALUE ) {
            if ( state == State::Connecting || state == State::Reading ) {
                // The buffer must not be written after it is gone.
                CancelIoEx( pipe, &overlapped );
                DWORD ignored = 0;
                GetOverlappedResult( pipe, &overlapped, &ignored, TRUE );
            }
            CloseHandle( pipe );
        }
        if ( event ) {
            CloseHandle( event );
        }
    }

    /// Wait at most @p timeout for the pending operation; whether it is done.
    bool wait( std::chrono::milliseconds timeout ) const
    {
        return WaitForSingleObject( event, static_cast<DWORD>( timeout.count() ) ) == WAIT_OBJECT_0;
    }

    /// The pending connect is done, or it failed (@p error says why).
    void connected( std::string& error )
    {
        DWORD ignored = 0;
        if ( GetOverlappedResult( pipe, &overlapped, &ignored, FALSE )
             || GetLastError() == ERROR_PIPE_CONNECTED ) {
            state = State::Idle;
            return;
        }
        error = windowsError( GetLastError() );
        state = State::Ended;
    }

    /// Start a read into buffer; it may be done at once.
    void startRead( std::string& error )
    {
        ResetEvent( event );
        overlapped = OVERLAPPED{};
        overlapped.hEvent = event;
        if ( ReadFile( pipe, buffer.data(), kPipeBuffer, nullptr, &overlapped )
             || GetLastError() == ERROR_IO_PENDING ) {
            state = State::Reading;
            return;
        }
        ended( GetLastError(), error );
    }

    /// The pending read is done: its bytes are in buffer.
    void finishRead( std::string& error )
    {
        DWORD got = 0;
        if ( !GetOverlappedResult( pipe, &overlapped, &got, FALSE ) ) {
            ended( GetLastError(), error );
            return;
        }
        at = 0;
        have = got;
        state = State::Idle;
    }

    /// The pipe ended with @p code: closed by its writer, or broken.
    void ended( DWORD code, std::string& error )
    {
        state = State::Ended;
        if ( code != ERROR_BROKEN_PIPE && code != ERROR_PIPE_NOT_CONNECTED ) {
            error = windowsError( code );
        }
    }
};

CapturePipe::CapturePipe()
    : win_( std::make_unique<Windows>() )
{
    const auto name
        = QStringLiteral( "\\\\.\\pipe\\logsquirl-tcpdump-%1-%2" )
              .arg( QCoreApplication::applicationPid() )
              .arg( QRandomGenerator::system()->generate64(), 16, 16, QLatin1Char( '0' ) );
    win_->pipe = CreateNamedPipeW(
        reinterpret_cast<LPCWSTR>( name.utf16() ),
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 0,
        kPipeBuffer, 0, nullptr );
    if ( win_->pipe == INVALID_HANDLE_VALUE ) {
        error_ = QString::fromStdString( windowsError( GetLastError() ) );
        return;
    }
    win_->event = CreateEventW( nullptr, TRUE, FALSE, nullptr );
    if ( !win_->event ) {
        error_ = QString::fromStdString( windowsError( GetLastError() ) );
        return;
    }
    // Listening before the writer is started: it can open the pipe at once.
    win_->overlapped.hEvent = win_->event;
    if ( ConnectNamedPipe( win_->pipe, &win_->overlapped ) ) {
        win_->state = Windows::State::Idle;
    }
    else if ( GetLastError() == ERROR_PIPE_CONNECTED ) {
        win_->state = Windows::State::Idle;
    }
    else if ( GetLastError() != ERROR_IO_PENDING ) {
        error_ = QString::fromStdString( windowsError( GetLastError() ) );
        return;
    }
    path_ = name;
}

CapturePipe::~CapturePipe() = default;

std::ptrdiff_t CapturePipe::read( uint8_t* dst, size_t n, std::chrono::milliseconds timeout,
                                  std::string& error )
{
    auto& win = *win_;
    if ( !error_.isEmpty() ) {
        error = error_.toStdString();
        return 0;
    }
    if ( win.at == win.have ) {
        if ( win.state == Windows::State::Connecting ) {
            if ( !win.wait( timeout ) ) {
                return -1;
            }
            win.connected( error );
        }
        if ( win.state == Windows::State::Idle ) {
            win.startRead( error );
        }
        if ( win.state == Windows::State::Reading ) {
            if ( !win.wait( timeout ) ) {
                return -1;
            }
            win.finishRead( error );
        }
        if ( win.state == Windows::State::Ended ) {
            return 0;
        }
        if ( win.at == win.have ) {
            return -1; // a read of nothing
        }
    }
    const auto count = std::min( n, win.have - win.at );
    std::memcpy( dst, win.buffer.data() + win.at, count );
    win.at += count;
    return static_cast<std::ptrdiff_t>( count );
}

bool CapturePipe::available()
{
    auto& win = *win_;
    return !error_.isEmpty() || win.at < win.have || win.state == Windows::State::Ended
           || ( ( win.state == Windows::State::Connecting || win.state == Windows::State::Reading )
                && win.wait( std::chrono::milliseconds( 0 ) ) );
}

#else

// ── CapturePipe on Unix: a FIFO ──────────────────────────────────────────

namespace {

/// The text of errno.
QString errnoText()
{
    return QString::fromLocal8Bit( std::strerror( errno ) );
}

} // namespace

CapturePipe::CapturePipe()
{
    // Readable by this user alone: mkdtemp makes the directory 0700.
    auto dirTemplate = QFile::encodeName( tempDirTemplate( tempRoot() ) );
    if ( !QDir().mkpath( tempRoot() ) || ::mkdtemp( dirTemplate.data() ) == nullptr ) {
        error_ = QStringLiteral( "Cannot make a directory for the FIFO in %1: %2" )
                     .arg( tempRoot(), errnoText() );
        return;
    }
    dir_ = QFile::decodeName( dirTemplate );
    const auto fifo = dir_ + QStringLiteral( "/capture.fifo" );
    const auto encoded = QFile::encodeName( fifo );
    if ( ::mkfifo( encoded.constData(), 0600 ) != 0 ) {
        error_ = QStringLiteral( "Cannot make the FIFO %1: %2" ).arg( fifo, errnoText() );
        return;
    }
    // Non-blocking: opening a FIFO waits for the other end otherwise.
    readFd_ = ::open( encoded.constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC );
    if ( readFd_ >= 0 ) {
        holdFd_ = ::open( encoded.constData(), O_WRONLY | O_NONBLOCK | O_CLOEXEC );
    }
    if ( readFd_ < 0 || holdFd_ < 0 ) {
        error_ = QStringLiteral( "Cannot open the FIFO %1: %2" ).arg( fifo, errnoText() );
        return;
    }
    path_ = fifo;
}

CapturePipe::~CapturePipe()
{
    for ( const auto fd : { holdFd_, readFd_ } ) {
        if ( fd >= 0 ) {
            ::close( fd );
        }
    }
    if ( !dir_.isEmpty() ) {
        QDir( dir_ ).removeRecursively();
    }
}

std::ptrdiff_t CapturePipe::read( uint8_t* dst, size_t n, std::chrono::milliseconds timeout,
                                  std::string& error )
{
    if ( !error_.isEmpty() ) {
        error = error_.toStdString();
        return 0;
    }
    pollfd wait{ readFd_, POLLIN, 0 };
    const int polled = ::poll( &wait, 1, static_cast<int>( timeout.count() ) );
    if ( polled == 0 || ( polled < 0 && errno == EINTR ) ) {
        return -1;
    }
    if ( polled < 0 ) {
        error = std::strerror( errno );
        return 0;
    }
    const auto got = ::read( readFd_, dst, n );
    if ( got > 0 ) {
        return got;
    }
    if ( got < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK ) {
        error = std::strerror( errno );
        return 0;
    }
    // Nothing yet (the plugin's own write end keeps the FIFO from ending).
    return -1;
}

bool CapturePipe::available()
{
    if ( !error_.isEmpty() ) {
        return true;
    }
    pollfd wait{ readFd_, POLLIN, 0 };
    return ::poll( &wait, 1, 0 ) > 0;
}

#endif

// ── PipeSource ───────────────────────────────────────────────────────────

PipeSource::PipeSource( const std::function<ProcessCommand( const QString& pipePath )>& command,
                        const std::atomic_bool* stop, std::function<void( const QString& )> onLine )
    : StreamSource( stop )
    , pipe_( std::make_unique<CapturePipe>() )
{
    if ( !pipe_->error().isEmpty() ) {
        return;
    }
    auto run = command( pipe_->path() );
    run.discardStdout = true;
    name_ = run.displayName();
    process_ = std::make_unique<ProcessSource>( run, nullptr, std::move( onLine ) );
}

PipeSource::~PipeSource()
{
    // The writer first: it must not find the pipe gone while it runs.
    process_.reset();
    pipe_.reset();
}

QString PipeSource::pipePath() const
{
    return pipe_->path();
}

std::ptrdiff_t PipeSource::readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout )
{
    if ( !process_ ) {
        error_ = pipe_->error().toStdString();
        return 0;
    }
    if ( !process_->started() ) {
        error_ = process_->failure().toStdString();
        return 0;
    }
    if ( !pipeEnded_ ) {
        std::string broken;
        const auto got = pipe_->read( dst, n, timeout, broken );
        // stderr is taken in on every read, so that the program never
        // waits for it to be read.
        const bool ended = process_->waitForEnd( std::chrono::milliseconds( 0 ) );
        if ( got > 0 ) {
            return got;
        }
        if ( got == 0 && !broken.empty() ) {
            error_ = QStringLiteral( "Reading the pipe of %1 failed: %2" )
                         .arg( name_, QString::fromStdString( broken ) )
                         .toStdString();
            return 0;
        }
        pipeEnded_ = got == 0;
        if ( !ended ) {
            return -1;
        }
        if ( !pipeEnded_ ) {
            // What it wrote before it ended is still in the pipe.
            const auto last = pipe_->read( dst, n, std::chrono::milliseconds( 0 ), broken );
            if ( last > 0 ) {
                return last;
            }
        }
    }
    else if ( !process_->waitForEnd( timeout ) ) {
        // The writer closed the pipe; the stream ends with the program.
        return -1;
    }
    error_ = process_->failure().toStdString();
    return 0;
}

bool PipeSource::available()
{
    return !process_ || !process_->started() || pipe_->available()
           || process_->waitForEnd( std::chrono::milliseconds( 0 ) );
}

bool PipeSource::endedOnPurpose() const
{
    return process_ && process_->endedOnPurpose();
}

} // namespace tcpdump
