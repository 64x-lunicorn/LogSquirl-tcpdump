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
 * @file live_source.cpp
 * @brief The registry of Live Source Kinds, and what every kind shares:
 *        checking a capture filter, running a listing program.
 */

#include "live_source.h"

#include "command_source.h"
#include "local_source.h"
#include "ssh_source.h"

#include <QElapsedTimer>
#include <QProcess>
#include <QRegularExpression>

#include <algorithm>
#include <mutex>
#include <vector>

#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

namespace tcpdump {

QString LiveSourceKind::validate( const LiveChoice& choice ) const
{
    if ( choice.networkInterface.trimmed().isEmpty() ) {
        return QStringLiteral( "Choose an interface." );
    }
    return {};
}

void LiveSourceRegistry::add( std::shared_ptr<const LiveSourceKind> kind )
{
    if ( !kind ) {
        return;
    }
    const auto id = kind->id();
    const auto taken = std::find_if( kinds_.begin(), kinds_.end(),
                                     [ &id ]( const auto& known ) { return known->id() == id; } );
    if ( taken != kinds_.end() ) {
        *taken = std::move( kind );
        return;
    }
    kinds_.push_back( std::move( kind ) );
}

std::shared_ptr<const LiveSourceKind> LiveSourceRegistry::find( const QString& id ) const
{
    const auto found = std::find_if( kinds_.begin(), kinds_.end(),
                                     [ &id ]( const auto& kind ) { return kind->id() == id; } );
    return found == kinds_.end() ? nullptr : *found;
}

std::shared_ptr<const LiveSourceRegistry> builtInLiveSources()
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    // Each source ticket adds its kind here, in the order the picker lists
    // them: Local (#72), Android (#73), SSH (#74), Wireshark extcap (#75),
    // Custom command (#76).
    registry->add( std::make_shared<LocalSourceKind>() );
    registry->add( std::make_shared<SshSourceKind>() );
    registry->add( std::make_shared<CustomCommandSourceKind>() );
    return registry;
}

QString captureFilterProblem( const QString& filter )
{
    const auto trimmed = filter.trimmed();
    if ( trimmed.isEmpty() ) {
        return {};
    }
    for ( const auto c : trimmed ) {
        if ( c.category() == QChar::Other_Control ) {
            return QStringLiteral( "A capture filter is one line, without control characters." );
        }
    }
    if ( trimmed.startsWith( QLatin1Char( '-' ) ) ) {
        return QStringLiteral( "A capture filter cannot start with '-': the capture program "
                               "would read it as an option." );
    }
    int depth = 0;
    for ( const auto c : trimmed ) {
        if ( c == QLatin1Char( '(' ) ) {
            ++depth;
        }
        else if ( c == QLatin1Char( ')' ) && --depth < 0 ) {
            return QStringLiteral( "A ')' has no '(' before it." );
        }
    }
    if ( depth > 0 ) {
        return QStringLiteral( "A '(' is not closed." );
    }
    // Wireshark's fields (ip.addr, tcp.port) are display filters; BPF says
    // "host" and "port", and reads a protocol's bytes as ip[…].
    static const QRegularExpression displayField( QStringLiteral(
        "(?<![\\w.])(eth|frame|ip|ipv6|tcp|udp|icmp|arp|dns|http|tls|sip|mqtt)\\.[a-z_]+" ) );
    const auto field = displayField.match( trimmed );
    if ( field.hasMatch() ) {
        return QStringLiteral( "%1 is a Wireshark display filter field; a capture filter is BPF, "
                               "e.g. host 10.0.0.1 and tcp port 443." )
            .arg( field.captured( 0 ) );
    }
    return {};
}

namespace {

/// The cancel flags of the listings running now, for cancelListings().
std::mutex listingsMutex;
std::vector<std::shared_ptr<std::atomic_bool>> runningListings;

/// The flag of the ListingCancelScope of this thread, if there is one.
thread_local std::shared_ptr<const std::atomic_bool> scopeCancel;

/// How often a listing looks whether it was cancelled.
constexpr int kCancelPollMs = 20;

/// Kill @p process and, on Unix, every process of its group.
void killListing( QProcess& process )
{
#ifndef Q_OS_WIN
    // Again until the group is gone: a process forking as the first
    // signal comes may leave a child that did not get it.
    const auto group = -static_cast<pid_t>( process.processId() );
    QElapsedTimer killing;
    killing.start();
    while ( ::kill( group, SIGKILL ) == 0 && killing.elapsed() < 1000 ) {
        process.waitForFinished( 10 );
    }
#endif
    process.kill();
    process.waitForFinished( 1000 );
}

} // namespace

ListingCancelScope::ListingCancelScope( std::shared_ptr<const std::atomic_bool> cancel )
{
    scopeCancel = std::move( cancel );
}

ListingCancelScope::~ListingCancelScope()
{
    scopeCancel.reset();
}

void cancelListings()
{
    const std::lock_guard<std::mutex> lock( listingsMutex );
    for ( const auto& cancel : runningListings ) {
        cancel->store( true );
    }
}

ListingOutput runListing( const ProcessCommand& command, std::chrono::milliseconds timeout )
{
    ListingOutput output;
    const auto cancel = std::make_shared<std::atomic_bool>( false );
    const auto cancelled = [ &cancel ] { return *cancel || ( scopeCancel && *scopeCancel ); };
    {
        const std::lock_guard<std::mutex> lock( listingsMutex );
        runningListings.push_back( cancel );
    }
    struct Withdraw {
        std::shared_ptr<std::atomic_bool> cancel;
        ~Withdraw()
        {
            const std::lock_guard<std::mutex> lock( listingsMutex );
            runningListings.erase(
                std::remove( runningListings.begin(), runningListings.end(), cancel ),
                runningListings.end() );
        }
    } withdraw{ cancel };
    if ( cancelled() ) {
        output.error = QStringLiteral( "Listing with %1 cancelled" ).arg( command.displayName() );
        return output;
    }

    QProcess process;
    process.setProcessChannelMode( QProcess::SeparateChannels );
    // Nothing to answer a prompt with: a program that asks fails at once.
    process.setStandardInputFile( QProcess::nullDevice() );
#ifdef Q_OS_WIN
    process.setCreateProcessArgumentsModifier(
        []( QProcess::CreateProcessArguments* args ) { args->flags |= CREATE_NO_WINDOW; } );
    if ( command.viaShell ) {
        process.setProgram( qEnvironmentVariable( "COMSPEC", QStringLiteral( "cmd.exe" ) ) );
        process.setNativeArguments( QStringLiteral( "/d /s /c \"%1\"" ).arg( command.program ) );
    }
#else
    // A group of its own, so that a timeout ends what it started too.
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
    QElapsedTimer clock;
    clock.start();
    process.start();
    if ( !process.waitForStarted( static_cast<int>( timeout.count() ) ) ) {
        output.error = QStringLiteral( "Cannot start %1: %2" )
                           .arg( command.displayName(), process.errorString() );
        return output;
    }
    // In slices, to see a cancel in time.
    bool finished = false;
    while ( !finished && !cancelled() && clock.elapsed() < timeout.count() ) {
        const auto left = timeout.count() - clock.elapsed();
        finished = process.waitForFinished(
            static_cast<int>( std::min<qint64>( kCancelPollMs, std::max<qint64>( 1, left ) ) ) );
        finished = finished || process.state() == QProcess::NotRunning;
    }
    if ( !finished ) {
        killListing( process );
        output.error
            = cancelled()
                  ? QStringLiteral( "Listing with %1 cancelled" ).arg( command.displayName() )
                  : QStringLiteral( "%1 did not answer within %2 s" )
                        .arg( command.displayName() )
                        .arg( static_cast<double>( timeout.count() ) / 1000.0 );
    }
    else if ( process.exitStatus() == QProcess::CrashExit ) {
        output.error = QStringLiteral( "%1 crashed" ).arg( command.displayName() );
    }
    output.out = QString::fromUtf8( process.readAllStandardOutput() );
    output.err = QString::fromUtf8( process.readAllStandardError() );
    output.exitCode = output.error.isEmpty() ? process.exitCode() : -1;
    return output;
}

QString liveCaptureName( const LiveChoice& choice )
{
    QStringList parts;
    for ( const auto& part : { choice.device.trimmed(), choice.networkInterface.trimmed() } ) {
        if ( !part.isEmpty() ) {
            parts << part;
        }
    }
    if ( parts.isEmpty() ) {
        return QStringLiteral( "live" );
    }
    auto name = parts.join( QLatin1Char( '-' ) );
    static const QRegularExpression unsafe( QStringLiteral( "[^A-Za-z0-9._-]" ) );
    name.replace( unsafe, QStringLiteral( "_" ) );
    // Not "." or "..", nor hidden.
    if ( name.startsWith( QLatin1Char( '.' ) ) ) {
        name.prepend( QLatin1Char( '_' ) );
    }
    return name;
}

} // namespace tcpdump
