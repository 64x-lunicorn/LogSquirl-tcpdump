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
// After windows.h, which it needs.
#include <tlhelp32.h>
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

// ── Batch files ──────────────────────────────────────────────────────────

QString batchArgumentProblem( const ProcessCommand& command )
{
    if ( command.viaShell ) {
        return {}; // the user's own command line for the shell
    }
    const auto suffix = QFileInfo( command.program ).suffix().toLower();
    if ( suffix != QLatin1String( "bat" ) && suffix != QLatin1String( "cmd" ) ) {
        return {};
    }
    static const QString kRead = QStringLiteral( "%!^&|<>()\"" );
    for ( const auto& argument : command.arguments ) {
        for ( const auto c : argument ) {
            if ( kRead.contains( c ) || c.category() == QChar::Other_Control ) {
                return QStringLiteral( "%1 is a batch file, which cmd.exe runs: it would read the "
                                       "%2 in the argument %3 as its own syntax. Leave out "
                                       "%, !, ^, &, |, <, >, (, ), \" and line breaks." )
                    .arg( command.displayName(),
                          c.category() == QChar::Other_Control ? QStringLiteral( "line break" )
                                                               : QStringLiteral( "'%1'" ).arg( c ),
                          argument.left( 80 ) );
            }
        }
    }
    return {};
}

// ── Process groups ───────────────────────────────────────────────────────

struct ProcessGroup {
#ifdef Q_OS_WIN
    HANDLE job = nullptr;
    /// The program, for alive() and ending its tree without a job.
    HANDLE process = nullptr;
    DWORD pid = 0;
    /// Qt's PROCESS_INFORMATION of the program started suspended, set by
    /// the CreateProcess modifier; read once, right after the start.
    Q_PROCESS_INFORMATION* started = nullptr;

    ~ProcessGroup()
    {
        if ( process ) {
            CloseHandle( process );
        }
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

#ifdef Q_OS_WIN

/// Why the last Windows call failed, as a message.
QString lastWindowsError()
{
    return QStringLiteral( "Windows error %1" ).arg( GetLastError() );
}

/// The processes whose parent is @p root, and theirs, as a snapshot sees them.
std::vector<DWORD> descendantsOf( DWORD root )
{
    std::vector<DWORD> found;
    const HANDLE snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    if ( snapshot == INVALID_HANDLE_VALUE ) {
        return found;
    }
    std::vector<std::pair<DWORD, DWORD>> all; // pid, parent
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof entry;
    for ( bool more = Process32FirstW( snapshot, &entry ); more;
          more = Process32NextW( snapshot, &entry ) ) {
        all.emplace_back( entry.th32ProcessID, entry.th32ParentProcessID );
    }
    CloseHandle( snapshot );
    std::vector<DWORD> parents{ root };
    while ( !parents.empty() ) {
        const auto parent = parents.back();
        parents.pop_back();
        for ( const auto& [ pid, ppid ] : all ) {
            if ( ppid == parent && pid != root
                 && std::find( found.begin(), found.end(), pid ) == found.end() ) {
                found.push_back( pid );
                parents.push_back( pid );
            }
        }
    }
    return found;
}

#endif

/// Whether any process of @p group is still there.
bool alive( const ProcessGroup& group )
{
#ifdef Q_OS_WIN
    if ( group.job ) {
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info{};
        return QueryInformationJobObject( group.job, JobObjectBasicAccountingInformation, &info,
                                          sizeof info, nullptr )
               && info.ActiveProcesses > 0;
    }
    // Without a job: the program itself.
    return group.process && WaitForSingleObject( group.process, 0 ) == WAIT_TIMEOUT;
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
        return;
    }
    if ( group.pid == 0 ) {
        return;
    }
    // Without a job: the program's tree, children first, as taskkill /T.
    const auto children = descendantsOf( group.pid );
    for ( auto pid = children.rbegin(); pid != children.rend(); ++pid ) {
        if ( HANDLE child = OpenProcess( PROCESS_TERMINATE, FALSE, *pid ) ) {
            TerminateProcess( child, 1 );
            CloseHandle( child );
        }
    }
    if ( group.process ) {
        TerminateProcess( group.process, 1 );
    }
#else
    // Never 0 or less: kill(-0) would signal LogSquirl's own group.
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

} // namespace

std::shared_ptr<ProcessGroup> newProcessGroup()
{
    return std::make_shared<ProcessGroup>();
}

ProcessStart startProcess( QProcess& process, const ProcessCommand& command, ProcessGroup& group,
                           std::chrono::milliseconds timeout )
{
    ProcessStart start;
    // stdout is the capture (or the listing), and nothing else may get into it.
    process.setProcessChannelMode( QProcess::SeparateChannels );
    process.setReadChannel( QProcess::StandardOutput );
    // Nothing to answer a prompt with: a program that asks fails at once.
    if ( !command.stdinPipe ) {
        process.setStandardInputFile( QProcess::nullDevice() );
    }
    if ( command.discardStdout ) {
        process.setStandardOutputFile( QProcess::nullDevice() );
    }
#ifdef Q_OS_WIN
    if ( const auto refused = batchArgumentProblem( command ); !refused.isEmpty() ) {
        start.error = refused;
        return start;
    }
    // A job that ends what the program starts, even as LogSquirl crashes
    // (its last handle closed kills what is in it).
    group.job = CreateJobObjectW( nullptr, nullptr );
    if ( group.job ) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if ( !SetInformationJobObject( group.job, JobObjectExtendedLimitInformation, &limits,
                                       sizeof limits ) ) {
            start.warning = QStringLiteral( "Cannot set up a job object for %1 (%2)" )
                                .arg( command.displayName(), lastWindowsError() );
            CloseHandle( group.job );
            group.job = nullptr;
        }
    }
    else {
        start.warning = QStringLiteral( "Cannot create a job object for %1 (%2)" )
                            .arg( command.displayName(), lastWindowsError() );
    }
    // No console window; suspended until it is in the job, so that nothing
    // it starts escapes it.
    const bool suspended = group.job != nullptr;
    process.setCreateProcessArgumentsModifier(
        [ &group, suspended ]( QProcess::CreateProcessArguments* args ) {
            args->flags |= CREATE_NO_WINDOW;
            if ( suspended ) {
                args->flags |= CREATE_SUSPENDED;
                group.started = args->processInformation;
            }
        } );
    if ( command.viaShell ) {
        process.setProgram( qEnvironmentVariable( "COMSPEC", QStringLiteral( "cmd.exe" ) ) );
        process.setNativeArguments( QStringLiteral( "/d /s /c \"%1\"" ).arg( command.program ) );
    }
#else
    // A group of its own, which ending it ends as a whole.  setpgid() is
    // async-signal-safe, as the child requires.
    process.setChildProcessModifier( [] { ::setpgid( 0, 0 ); } );
    if ( command.viaShell ) {
        process.setProgram( QStringLiteral( "/bin/sh" ) );
        process.setArguments( { QStringLiteral( "-c" ), command.program } );
    }
#endif
    if ( !command.viaShell ) {
        process.setProgram( command.program );
        process.setArguments( command.arguments );
    }
    process.start();
    start.started = process.waitForStarted( static_cast<int>( timeout.count() ) );
#ifdef Q_OS_WIN
    if ( suspended && group.started && group.started->hProcess ) {
        // Created, if not started (it is suspended): put it in the job and
        // let it run, or end it.
        if ( !AssignProcessToJobObject( group.job, group.started->hProcess ) ) {
            start.warning = QStringLiteral( "Cannot put %1 in a job object (%2): ending it may "
                                            "leave what it started running" )
                                .arg( command.displayName(), lastWindowsError() );
            CloseHandle( group.job );
            group.job = nullptr;
        }
        if ( ResumeThread( group.started->hThread ) == static_cast<DWORD>( -1 ) ) {
            TerminateProcess( group.started->hProcess, 1 );
            start.started = false;
            start.error = QStringLiteral( "Cannot start %1: it could not be resumed (%2)" )
                              .arg( command.displayName(), lastWindowsError() );
        }
    }
    group.started = nullptr;
#endif
    if ( !start.started ) {
        if ( start.error.isEmpty() ) {
            start.error = QStringLiteral( "Cannot start %1: %2" )
                              .arg( command.displayName(), process.errorString() );
        }
        process.kill();
        process.waitForFinished( 1000 );
        return start;
    }
    const auto pid = process.processId();
#ifdef Q_OS_WIN
    group.pid = static_cast<DWORD>( pid );
    group.process = OpenProcess(
        SYNCHRONIZE | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, group.pid );
#else
    // A program that has exited already has been reaped: its pid is 0.
    group.id = pid > 0 ? static_cast<pid_t>( pid ) : 0;
#endif
    return start;
}

void endProcessGroup( ProcessGroup& group, QProcess* leader, std::chrono::milliseconds grace )
{
    if ( !group.ended.exchange( true ) ) {
        signalGroup( group, grace.count() == 0 );
    }
    if ( waitUntilGone( group, leader, Clock::now() + grace ) ) {
        return;
    }
    signalGroup( group, true );
    // A process of another user cannot be killed: give up on it after a second.
    waitUntilGone( group, leader, Clock::now() + milliseconds( 1000 ) );
}

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
        endProcessGroup( *group, nullptr, ProcessSource::kTerminateGrace );
    }
}

// ── ProcessSource ────────────────────────────────────────────────────────

ProcessSource::ProcessSource( const ProcessCommand& command, const std::atomic_bool* stop,
                              std::function<void( const QString& )> onLine )
    : StreamSource( stop )
    , name_( command.displayName() )
    , process_( std::make_unique<QProcess>() )
    , group_( newProcessGroup() )
    , stderr_( std::move( onLine ) )
{
    const auto start = startProcess( *process_, command, *group_, kStartTimeout );
    started_ = start.started;
    if ( started_ ) {
        pid_ = process_->processId();
        enroll( group_ );
        if ( !start.warning.isEmpty() ) {
            stderr_.append( ( start.warning + QLatin1Char( '\n' ) ).toUtf8() );
        }
    }
    else {
        startError_ = start.error;
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
        // A remote command that ends with its stdin (ssh's watchdog) ends
        // first, before ssh is.
        if ( process_->state() != QProcess::NotRunning ) {
            process_->closeWriteChannel();
        }
        endProcessGroup( *group_, process_.get(), kTerminateGrace );
        drainStderr();
    }
}

bool ProcessSource::waitForEnd( std::chrono::milliseconds timeout )
{
    if ( !started_ ) {
        return true;
    }
    if ( process_->state() != QProcess::NotRunning ) {
        // Takes in stderr while it waits; 0 looks once.
        process_->waitForFinished( static_cast<int>( timeout.count() ) );
    }
    drainStderr();
    if ( process_->state() != QProcess::NotRunning ) {
        return false;
    }
    stderr_.finish();
    return true;
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
        return startError_;
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
