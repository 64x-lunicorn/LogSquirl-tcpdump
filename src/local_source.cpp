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
 * @file local_source.cpp
 * @brief The Local source: finding dumpcap or tcpdump, listing interfaces,
 *        the capture command, and the guidance for capture permissions.
 */

#include "local_source.h"

#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

namespace tcpdump {

namespace {

const QString kWiresharkDownload = QStringLiteral( "https://www.wireshark.org/download.html" );

/// The program at @p path, if it is one that can be run.
bool runnable( const QString& path )
{
    const QFileInfo file( path );
    return file.isFile() && file.isExecutable();
}

/// The program @p name on @p where's PATH, else at its install locations
/// @p installed; empty if it is nowhere.
QString find( const LocalPrograms& where, const QString& name, const QStringList& installed )
{
    const auto fileName = where.os == CaptureOs::Windows ? name + QStringLiteral( ".exe" ) : name;
    for ( const auto& dir : where.searchPath ) {
        if ( dir.isEmpty() ) {
            continue;
        }
        const auto path = QDir( dir ).filePath( fileName );
        if ( runnable( path ) ) {
            return path;
        }
    }
    for ( const auto& path : installed ) {
        if ( runnable( path ) ) {
            return path;
        }
    }
    return {};
}

/// One interface of a `-D` listing: "1. en0 (Wi-Fi)" (dumpcap), "1.en0 [Up,
/// Running]" or "3.any (Pseudo-device …) [Up, Running]" (tcpdump); none if
/// @p line is not one.
bool parseInterface( const QString& line, LiveTarget& target )
{
    static const QRegularExpression numbered( QStringLiteral( "^\\s*\\d+\\.\\s*(\\S+)(.*)$" ) );
    const auto match = numbered.match( line );
    if ( !match.hasMatch() ) {
        return false;
    }
    target.id = match.captured( 1 );
    auto rest = match.captured( 2 ).trimmed();
    QString flags;
    if ( rest.endsWith( QLatin1Char( ']' ) ) ) {
        const auto open = rest.lastIndexOf( QLatin1Char( '[' ) );
        if ( open >= 0 ) {
            flags = rest.mid( open + 1, rest.size() - open - 2 ).trimmed();
            rest = rest.left( open ).trimmed();
        }
    }
    QString description;
    if ( rest.startsWith( QLatin1Char( '(' ) ) && rest.endsWith( QLatin1Char( ')' ) ) ) {
        description = rest.mid( 1, rest.size() - 2 ).trimmed();
    }
    target.description = description.isEmpty() ? flags : description;
    return true;
}

} // namespace

CaptureOs runningCaptureOs()
{
#if defined( Q_OS_WIN )
    return CaptureOs::Windows;
#elif defined( Q_OS_MACOS )
    return CaptureOs::MacOS;
#else
    return CaptureOs::Linux;
#endif
}

QString capturePermissionGuidance( CaptureOs os, const QString& program )
{
    const QString never = QStringLiteral(
        " LogSquirl never runs sudo or asks for a password: run the command in a terminal "
        "yourself." );
    switch ( os ) {
    case CaptureOs::MacOS:
        return QStringLiteral( "Capturing needs read access to /dev/bpf*, which macOS gives root "
                               "alone. Install ChmodBPF from the Wireshark disk image (%1, "
                               "\"Install ChmodBPF.pkg\"): it lets the group access_bpf read "
                               "/dev/bpf* and adds you to it. If ChmodBPF is installed but you "
                               "are not in the group: sudo dseditgroup -o edit -a \"$USER\" -t "
                               "user access_bpf, then log out and log in again." )
                   .arg( kWiresharkDownload )
               + never;
    case CaptureOs::Linux: {
        const auto path = program.isEmpty() ? QStringLiteral( "/usr/bin/dumpcap" ) : program;
        const auto setcap
            = QStringLiteral( "sudo setcap cap_net_raw,cap_net_admin=eip %1" ).arg( path );
        if ( QFileInfo( path ).fileName().startsWith( QStringLiteral( "dumpcap" ) ) ) {
            return QStringLiteral( "Capturing needs the capabilities CAP_NET_RAW and "
                                   "CAP_NET_ADMIN. Either join the wireshark group, which may "
                                   "run dumpcap (on Debian and Ubuntu first: sudo "
                                   "dpkg-reconfigure wireshark-common, answering Yes): sudo "
                                   "usermod -aG wireshark \"$USER\", then log out and log in "
                                   "again; or give dumpcap the capabilities: %1." )
                       .arg( setcap )
                   + never;
        }
        return QStringLiteral( "Capturing needs the capabilities CAP_NET_RAW and CAP_NET_ADMIN. "
                               "Give them to tcpdump: %1 (or install Wireshark's dumpcap, which "
                               "members of the group wireshark may run)." )
                   .arg( setcap )
               + never;
    }
    case CaptureOs::Windows:
        return QStringLiteral(
            "Capturing on Windows needs Npcap: install it from https://npcap.com/#download "
            "(Wireshark's installer offers it too), leaving \"Restrict Npcap driver's access to "
            "Administrators only\" unchecked, so that LogSquirl need not run as administrator." );
    }
    return {};
}

QString captureInstallHint( CaptureOs os )
{
    switch ( os ) {
    case CaptureOs::MacOS:
        return QStringLiteral( "Neither dumpcap nor tcpdump was found: install Wireshark (%1) for "
                               "dumpcap; tcpdump comes with macOS, in /usr/sbin." )
            .arg( kWiresharkDownload );
    case CaptureOs::Linux:
        return QStringLiteral( "Neither dumpcap nor tcpdump was found: install your "
                               "distribution's tcpdump, or Wireshark's dumpcap (Debian and "
                               "Ubuntu: wireshark-common, Fedora: wireshark-cli)." );
    case CaptureOs::Windows:
        return QStringLiteral( "dumpcap was not found: install Wireshark (%1), with Npcap." )
            .arg( kWiresharkDownload );
    }
    return {};
}

bool isCapturePermissionError( const QString& error )
{
    static const QRegularExpression denied(
        QStringLiteral( "permission|not permitted|access is denied|cannot open bpf device|"
                        "no interfaces on which a capture can be done|npcap|winpcap|wpcap\\.dll|"
                        "npf driver" ),
        QRegularExpression::CaseInsensitiveOption );
    return denied.match( error ).hasMatch();
}

LocalPrograms LocalPrograms::forThisComputer()
{
    LocalPrograms where;
    where.os = runningCaptureOs();
    where.searchPath
        = qEnvironmentVariable( "PATH" ).split( QDir::listSeparator(), Qt::SkipEmptyParts );
    switch ( where.os ) {
    case CaptureOs::MacOS:
        where.dumpcap = { QStringLiteral( "/Applications/Wireshark.app/Contents/MacOS/dumpcap" ),
                          QStringLiteral( "/usr/local/bin/dumpcap" ),
                          QStringLiteral( "/opt/homebrew/bin/dumpcap" ) };
        where.tcpdump = { QStringLiteral( "/usr/sbin/tcpdump" ) };
        where.bpfDevice = QStringLiteral( "/dev/bpf0" );
        break;
    case CaptureOs::Linux:
        where.dumpcap
            = { QStringLiteral( "/usr/bin/dumpcap" ), QStringLiteral( "/usr/sbin/dumpcap" ),
                QStringLiteral( "/usr/local/bin/dumpcap" ) };
        where.tcpdump
            = { QStringLiteral( "/usr/sbin/tcpdump" ), QStringLiteral( "/usr/bin/tcpdump" ),
                QStringLiteral( "/usr/local/sbin/tcpdump" ) };
        break;
    case CaptureOs::Windows:
        for ( const auto* variable : { "ProgramFiles", "ProgramW6432", "ProgramFiles(x86)" } ) {
            const auto dir = qEnvironmentVariable( variable );
            if ( !dir.isEmpty() ) {
                const auto path = QDir( dir ).filePath( QStringLiteral( "Wireshark/dumpcap.exe" ) );
                if ( !where.dumpcap.contains( path ) ) {
                    where.dumpcap << path;
                }
            }
        }
        break;
    }
    return where;
}

LocalSourceKind::LocalSourceKind( LocalPrograms where )
    : where_( std::move( where ) )
{
}

LocalSourceKind::Program LocalSourceKind::program() const
{
    if ( auto dumpcap = find( where_, QStringLiteral( "dumpcap" ), where_.dumpcap );
         !dumpcap.isEmpty() ) {
        return { std::move( dumpcap ), true };
    }
    if ( where_.os == CaptureOs::Windows ) {
        return {};
    }
    return { find( where_, QStringLiteral( "tcpdump" ), where_.tcpdump ), false };
}

QString LocalSourceKind::id() const
{
    return QStringLiteral( "local" );
}

QString LocalSourceKind::displayName() const
{
    return QStringLiteral( "Local" );
}

LiveAvailability LocalSourceKind::availability() const
{
    if ( program().path.isEmpty() ) {
        return LiveAvailability::unavailable( captureInstallHint( where_.os ) );
    }
    return {};
}

LiveListing LocalSourceKind::listInterfaces( const QString& device,
                                             std::chrono::milliseconds timeout ) const
{
    (void)device;
    LiveListing listing;
    const auto found = program();
    if ( found.path.isEmpty() ) {
        listing.error = captureInstallHint( where_.os );
        return listing;
    }
    const auto name = found.isDumpcap ? QStringLiteral( "dumpcap" ) : QStringLiteral( "tcpdump" );
    const auto output = runListing( { found.path, { QStringLiteral( "-D" ) }, name }, timeout );
    if ( !output.error.isEmpty() ) {
        listing.error = output.error;
        return listing;
    }
    for ( const auto& line : output.out.split( QLatin1Char( '\n' ), Qt::SkipEmptyParts ) ) {
        LiveTarget target;
        if ( parseInterface( line, target ) ) {
            listing.targets.push_back( std::move( target ) );
        }
    }
    const auto err = output.err.trimmed();
    if ( output.exitCode != 0 ) {
        listing.error
            = QStringLiteral( "%1 -D exited with code %2" ).arg( name ).arg( output.exitCode );
        if ( !err.isEmpty() ) {
            listing.error += QStringLiteral( ":\n" ) + err;
        }
        if ( isCapturePermissionError( err ) ) {
            listing.error += QStringLiteral( "\n\n" ) + guidance();
        }
    }
    else if ( listing.targets.empty() ) {
        listing.error
            = QStringLiteral(
                  "%1 -D listed no interfaces: it may lack the permission to capture.\n\n" )
                  .arg( name )
              + guidance();
    }
    else if ( where_.os == CaptureOs::MacOS && !where_.bpfDevice.isEmpty() ) {
        // tcpdump and dumpcap list without it; capturing fails then.
        const QFileInfo bpf( where_.bpfDevice );
        if ( bpf.exists() && !bpf.isReadable() ) {
            listing.error = QStringLiteral( "%1 cannot be read, so %2 cannot capture.\n\n" )
                                .arg( where_.bpfDevice, name )
                            + guidance();
        }
    }
    return listing;
}

ProcessCommand LocalSourceKind::command( const LiveChoice& choice ) const
{
    const auto found = program();
    ProcessCommand command;
    command.program = found.path.isEmpty() ? QStringLiteral( "dumpcap" ) : found.path;
    command.name = found.isDumpcap || found.path.isEmpty() ? QStringLiteral( "dumpcap" )
                                                           : QStringLiteral( "tcpdump" );
    command.arguments = { QStringLiteral( "-i" ), choice.networkInterface, QStringLiteral( "-s" ),
                          QString::number( choice.snaplen ) };
    if ( command.name == QStringLiteral( "dumpcap" ) ) {
        // -q: no packet counts on stderr; pcapng, dumpcap's own, to stdout.
        command.arguments << QStringLiteral( "-q" );
        if ( !choice.filter.isEmpty() ) {
            command.arguments << QStringLiteral( "-f" ) << choice.filter;
        }
        command.arguments << QStringLiteral( "-w" ) << QStringLiteral( "-" );
    }
    else {
        // -U: each packet written as it comes, not when a buffer is full.
        command.arguments << QStringLiteral( "-U" ) << QStringLiteral( "-w" )
                          << QStringLiteral( "-" );
        if ( !choice.filter.isEmpty() ) {
            command.arguments << choice.filter;
        }
    }
    return command;
}

QString LocalSourceKind::explainFailure( const QString& error ) const
{
    return isCapturePermissionError( error ) ? guidance() : QString();
}

QString LocalSourceKind::guidance() const
{
    return capturePermissionGuidance( where_.os, program().path );
}

} // namespace tcpdump
