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
 * @file process_source.cpp
 * @brief Running a capture program, reading its stdout, ending its group.
 */

#include "process_source.h"

#include <QFileInfo>
#include <QProcess>

#include <algorithm>
#include <mutex>
#include <thread>
#include <vector>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <unistd.h>
#endif

namespace tcpdump {

using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

// ── ProcessCommand ───────────────────────────────────────────────────────

ProcessCommand ProcessCommand::shell( const QString& commandLine )
{
    ProcessCommand command;
    command.program = commandLine;
    command.viaShell = true;
    command.name
        = QFileInfo( commandLine.section( QLatin1Char( ' ' ), 0, 0, QString::SectionSkipEmpty ) )
              .fileName();
    return command;
}

QString ProcessCommand::displayName() const
{
    if ( !name.isEmpty() ) {
        return name;
    }
    return QFileInfo( program ).fileName();
}

// ── StderrLines ──────────────────────────────────────────────────────────

namespace {

/// A line longer than this without a line end is handed on as it is: a
/// program that writes binary to stderr must not fill the memory.
constexpr qsizetype kMaxLineBytes = 4096;

} // namespace

void StderrLines::append( const QByteArray& bytes )
{
    partial_ += bytes;
    qsizetype from = 0;
    for ( qsizetype end = partial_.indexOf( '\n' ); end >= 0;
          end = partial_.indexOf( '\n', from ) ) {
        complete( partial_.mid( from, end - from ) );
        from = end + 1;
    }
    partial_.remove( 0, from );
    while ( partial_.size() > kMaxLineBytes ) {
        complete( partial_.left( kMaxLineBytes ) );
        partial_.remove( 0, kMaxLineBytes );
    }
}

void StderrLines::finish()
{
    complete( partial_ );
    partial_.clear();
}

QStringList StderrLines::last() const
{
    return QStringList( last_.begin(), last_.end() );
}

void StderrLines::complete( const QByteArray& bytes )
{
    auto line = QString::fromUtf8( bytes );
    while ( line.endsWith( QLatin1Char( '\r' ) ) ) {
        line.chop( 1 );
    }
    if ( line.trimmed().isEmpty() ) {
        return;
    }
    last_.push_back( line );
    if ( last_.size() > kKept ) {
        last_.pop_front();
    }
    if ( onLine_ ) {
        onLine_( line );
    }
}

// ── Process groups ───────────────────────────────────────────────────────

/**
 * A program and what it started, ended together: a process group whose id
 * is the program's pid, or a Windows job object.  `ended` is set by whoever
 * ends it first, before any signal, so that the program's exit is not taken
 * for a failure.
 */
struct ProcessGroup {
#ifdef Q_OS_WIN
    HANDLE job = nullptr;

    ~ProcessGroup()
    {
        if ( job ) {
            CloseHandle( job ); // kills what is left: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        }
    }
#else
    pid_t id = 0;
#endif
    std::atomic_bool ended{ false };
};

namespace {

/// The groups of every running ProcessSource, for terminateCaptureProcesses().
std::mutex registryMutex;
std::vector<std::shared_ptr<ProcessGroup>> registry;

void enroll( const std::shared_ptr<ProcessGroup>& group )
{
    const std::lock_guard<std::mutex> lock( registryMutex );
    registry.push_back( group );
}

void withdraw( const std::shared_ptr<ProcessGroup>& group )
{
    const std::lock_guard<std::mutex> lock( registryMutex );
    registry.erase( std::remove( registry.begin(), registry.end(), group ), registry.end() );
}

/// Whether any process of @p group is still there.
bool alive( const ProcessGroup& group )
{
#ifdef Q_OS_WIN
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
    return group.job
           && QueryInformationJobObject( group.job, JobObjectBasicAccountingInformation, &info,
                                         sizeof info, nullptr )
           && info.ActiveProcesses > 0;
#else
    // EPERM: there is one, run by another user (behind sudo).
    return group.id > 0 && ( ::kill( -group.id, 0 ) == 0 || errno == EPERM );
#endif
}

/// Ask @p group to end (@p hard: make it), every process in it.
void signalGroup( const ProcessGroup& group, bool hard )
{
#ifdef Q_OS_WIN
    Q_UNUSED( hard ); // a console program has no request to end
    if ( group.job ) {
        TerminateJobObject( group.job, 1 );
    }
#else
    if ( group.id > 0 ) {
        ::kill( -group.id, hard ? SIGKILL : SIGTERM );
    }
#endif
}

/// Wait until @p group is gone or @p deadline has come; reaps @p leader, the
/// program, if it is given (only on the thread it belongs to).
bool waitUntilGone( const ProcessGroup& group, QProcess* leader, Clock::time_point deadline )
{
    const auto left = [ deadline ] {
        return static_cast<int>( std::max<Clock::rep>(
            0, std::chrono::duration_cast<milliseconds>( deadline - Clock::now() ).count() ) );
    };
    if ( leader && leader->state() != QProcess::NotRunning ) {
        leader->waitForFinished( left() );
    }
    while ( alive( group ) && Clock::now() < deadline ) {
        std::this_thread::sleep_for( milliseconds( 10 ) );
    }
    return !alive( group );
}

/// End @p group: SIGTERM, and SIGKILL after the grace; see ProcessSource::terminate().
void endGroup( ProcessGroup& group, QProcess* leader )
{
    if ( !group.ended.exchange( true ) ) {
        signalGroup( group, false );
    }
    if ( waitUntilGone( group, leader, Clock::now() + ProcessSource::kTerminateGrace ) ) {
        return;
    }
    signalGroup( group, true );
    // A process of another user cannot be killed: give up on it after a second.
    waitUntilGone( group, leader, Clock::now() + milliseconds( 1000 ) );
}

} // namespace

void terminateCaptureProcesses()
{
    std::vector<std::shared_ptr<ProcessGroup>> running;
    {
        const std::lock_guard<std::mutex> lock( registryMutex );
        running = registry;
    }
    // Every group is asked first, so that they end in parallel.
    for ( const auto& group : running ) {
        if ( !group->ended.exchange( true ) ) {
            signalGroup( *group, false );
        }
    }
    for ( const auto& group : running ) {
        endGroup( *group, nullptr );
    }
}

// ── ProcessSource ────────────────────────────────────────────────────────

ProcessSource::ProcessSource( const ProcessCommand& command, const std::atomic_bool* stop,
                              std::function<void( const QString& )> onLine )
    : StreamSource( stop )
    , name_( command.displayName() )
    , process_( std::make_unique<QProcess>() )
    , group_( std::make_shared<ProcessGroup>() )
    , stderr_( std::move( onLine ) )
{
    // stdout is the capture, and nothing else may get into it.
    process_->setProcessChannelMode( QProcess::SeparateChannels );
    process_->setReadChannel( QProcess::StandardOutput );
    process_->setStandardInputFile( QProcess::nullDevice() );
#ifdef Q_OS_WIN
    // A console program gets no console window.
    process_->setCreateProcessArgumentsModifier(
        []( QProcess::CreateProcessArguments* args ) { args->flags |= CREATE_NO_WINDOW; } );
    if ( command.viaShell ) {
        process_->setProgram( qEnvironmentVariable( "COMSPEC", QStringLiteral( "cmd.exe" ) ) );
        process_->setNativeArguments( QStringLiteral( "/d /s /c \"%1\"" ).arg( command.program ) );
    }
#else
    // A group of its own, which Stop ends as a whole.  setpgid() is
    // async-signal-safe, as the child requires.
    process_->setChildProcessModifier( [] { ::setpgid( 0, 0 ); } );
    if ( command.viaShell ) {
        process_->setProgram( QStringLiteral( "/bin/sh" ) );
        process_->setArguments( { QStringLiteral( "-c" ), command.program } );
    }
#endif
    if ( !command.viaShell ) {
        process_->setProgram( command.program );
        process_->setArguments( command.arguments );
    }
    process_->start();
    started_ = process_->waitForStarted();
    if ( started_ ) {
        pid_ = process_->processId();
#ifdef Q_OS_WIN
        // Assigned once it runs, so what it starts from now on is in the job
        // too; closing the job's last handle, even as LogSquirl crashes,
        // kills whatever is left in it.
        group_->job = CreateJobObjectW( nullptr, nullptr );
        if ( group_->job ) {
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject( group_->job, JobObjectExtendedLimitInformation, &limits,
                                     sizeof limits );
            if ( HANDLE handle = OpenProcess( PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE,
                                              static_cast<DWORD>( pid_ ) ) ) {
                AssignProcessToJobObject( group_->job, handle );
                CloseHandle( handle );
            }
        }
#else
        group_->id = static_cast<pid_t>( pid_ );
#endif
        enroll( group_ );
    }
    else {
        startError_ = process_->errorString();
    }
    stdout_ = std::make_unique<DeviceSource>( *process_ );
}

ProcessSource::~ProcessSource()
{
    terminate();
    withdraw( group_ );
}

bool ProcessSource::started() const
{
    return started_;
}

qint64 ProcessSource::processId() const
{
    return pid_;
}

QStringList ProcessSource::lastStderrLines() const
{
    return stderr_.last();
}

void ProcessSource::terminate()
{
    if ( started_ ) {
        endGroup( *group_, process_.get() );
        drainStderr();
    }
}

std::ptrdiff_t ProcessSource::readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout )
{
    const auto got = stdout_->readFor( dst, n, timeout );
    drainStderr();
    if ( got != 0 ) {
        return got;
    }
    if ( !stdout_->error_.empty() ) {
        error_ = stdout_->error_;
        return 0;
    }
    // stdout has closed; the stream ends with the program, which may still
    // be writing to stderr.
    if ( process_->state() != QProcess::NotRunning
         && !process_->waitForFinished( static_cast<int>( timeout.count() ) ) ) {
        drainStderr();
        return -1;
    }
    drainStderr();
    stderr_.finish();
    error_ = failure().toStdString();
    return 0;
}

bool ProcessSource::available()
{
    return process_->bytesAvailable() > 0 || process_->state() == QProcess::NotRunning;
}

bool ProcessSource::endedOnPurpose() const
{
    return started_ && group_->ended;
}

std::string ProcessSource::writerSaid()
{
    if ( !started_ ) {
        return failure().toStdString();
    }
    if ( process_->state() != QProcess::NotRunning
         && process_->waitForFinished( static_cast<int>( kSaidGrace.count() ) ) ) {
        // Ended by itself: a last line without a line end is complete.
        drainStderr();
        stderr_.finish();
    }
    drainStderr();
    if ( process_->state() == QProcess::NotRunning ) {
        if ( const auto failed = failure(); !failed.isEmpty() ) {
            return failed.toStdString();
        }
    }
    const auto lines = stderr_.last();
    if ( lines.isEmpty() ) {
        return {};
    }
    return QStringLiteral( "%1 wrote on stderr:\n%2" )
        .arg( name_, lines.join( QLatin1Char( '\n' ) ) )
        .toStdString();
}

QString ProcessSource::failure() const
{
    if ( !started_ ) {
        return QStringLiteral( "Cannot start %1: %2" ).arg( name_, startError_ );
    }
    if ( group_->ended ) {
        return {}; // ended on purpose
    }
    QString message;
    if ( process_->exitStatus() == QProcess::CrashExit ) {
        message = QStringLiteral( "%1 crashed (exit code %2)" )
                      .arg( name_ )
                      .arg( process_->exitCode() );
    }
    else if ( process_->exitCode() != 0 ) {
        message
            = QStringLiteral( "%1 exited with code %2" ).arg( name_ ).arg( process_->exitCode() );
    }
    else {
        return {};
    }
    const auto lines = stderr_.last();
    if ( !lines.isEmpty() ) {
        message += QStringLiteral( ":\n" ) + lines.join( QLatin1Char( '\n' ) );
    }
    return message;
}

void ProcessSource::drainStderr()
{
    stderr_.append( process_->readAllStandardError() );
}

} // namespace tcpdump
