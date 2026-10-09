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
 * @file ssh_source.cpp
 * @brief The SSH source: the ssh command, the remote command line and its
 *        quoting, the hosts of ~/.ssh/config, and what to do when ssh, sudo
 *        or tcpdump fail.
 */

#include "ssh_source.h"

#include "live_capture_form.h"
#include "local_source.h"

#include <QCheckBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QVBoxLayout>

#include <algorithm>
#include <set>

namespace tcpdump {

namespace {

/// ssh's options for every run: never a prompt, a bounded connect, no tty.
const QStringList kSshOptions{ QStringLiteral( "-T" ), QStringLiteral( "-o" ),
                               QStringLiteral( "BatchMode=yes" ), QStringLiteral( "-o" ),
                               QStringLiteral( "ConnectTimeout=10" ) };

/// What lists the server's interfaces.
const QString kRemoteListing = QStringLiteral( "tcpdump -D" );

/// The exit code with which ssh reports its own failure (not the remote command's).
constexpr int kSshFailed = 255;

/// Whether the option @p name of @p options is on; both are on by default.
bool optionOn( const LiveOptions& options, const QString& name )
{
    return options.value( name ) != QStringLiteral( "false" );
}

bool hasControl( const QString& text )
{
    return std::any_of( text.begin(), text.end(),
                        []( QChar c ) { return c.category() == QChar::Other_Control; } );
}

/// One interface of `tcpdump -D`: "1.eth0 [Up, Running]", "2.any
/// (Pseudo-device …) [Up, Running]"; none if @p line is not one.
bool parseInterface( const QString& line, LiveTarget& target )
{
    static const QRegularExpression numbered(
        QStringLiteral( "^\\s*\\d+\\.\\s*(\\S+)\\s*(?:\\((.*)\\))?\\s*(?:\\[(.*)\\])?\\s*$" ) );
    const auto match = numbered.match( line );
    if ( !match.hasMatch() ) {
        return false;
    }
    target.id = match.captured( 1 );
    const auto description = match.captured( 2 ).trimmed();
    target.description = description.isEmpty() ? match.captured( 3 ).trimmed() : description;
    return true;
}

/// The guidance for tcpdump that may not capture on the server.
QString remotePermissionGuidance()
{
    return QStringLiteral(
        "tcpdump on the server may not capture as this user: turn on \"Use sudo -n\" (with "
        "a sudo rule that lets you run tcpdump without a password), or give tcpdump the "
        "capture capabilities on the server: sudo setcap cap_net_raw,cap_net_admin=eip "
        "$(command -v tcpdump)." );
}

/// A widget of the SSH source's options: two checkboxes.
class SshOptionsWidget : public LiveOptionsWidget {
public:
    SshOptionsWidget()
    {
        auto* layout = new QVBoxLayout( this );
        layout->setContentsMargins( 0, 0, 0, 0 );
        sudo_ = new QCheckBox( QStringLiteral( "Run tcpdump with sudo -n" ) );
        sudo_->setObjectName( QStringLiteral( "sshSudo" ) );
        sudo_->setToolTip( QStringLiteral(
            "Capture as root with sudo -n, which never asks for a password: sudo must allow "
            "tcpdump without one (a NOPASSWD rule). Off: tcpdump runs as the SSH user, who "
            "needs the capture capabilities" ) );
        excludeOwn_ = new QCheckBox( QStringLiteral( "Exclude this SSH connection" ) );
        excludeOwn_->setObjectName( QStringLiteral( "sshExcludeOwn" ) );
        excludeOwn_->setToolTip( QStringLiteral(
            "Add not (host <this computer> and tcp port <SSH port>) to the capture filter, so "
            "that the capture does not capture its own transport" ) );
        layout->addWidget( sudo_ );
        layout->addWidget( excludeOwn_ );
        setOptions( {} );
        connect( sudo_, &QCheckBox::toggled, this, &LiveOptionsWidget::changed );
        connect( excludeOwn_, &QCheckBox::toggled, this, &LiveOptionsWidget::changed );
    }

    void setOptions( const LiveOptions& options ) override
    {
        sudo_->setChecked( optionOn( options, kSshSudoOption ) );
        excludeOwn_->setChecked( optionOn( options, kSshExcludeOwnOption ) );
    }
    LiveOptions options() const override
    {
        const auto text
            = []( bool on ) { return on ? QStringLiteral( "true" ) : QStringLiteral( "false" ); };
        return { { kSshSudoOption, text( sudo_->isChecked() ) },
                 { kSshExcludeOwnOption, text( excludeOwn_->isChecked() ) } };
    }

private:
    QCheckBox* sudo_ = nullptr;
    QCheckBox* excludeOwn_ = nullptr;
};

} // namespace

SshDestination SshDestination::parse( const QString& device )
{
    SshDestination parsed;
    const auto text = device.trimmed();
    if ( text.isEmpty() ) {
        parsed.problem = QStringLiteral( "Enter a host: [user@]host[:port], or a Host of "
                                         "~/.ssh/config." );
        return parsed;
    }
    if ( hasControl( text ) || text.contains( QRegularExpression( QStringLiteral( "\\s" ) ) ) ) {
        parsed.problem = QStringLiteral( "A host has no spaces: [user@]host[:port]." );
        return parsed;
    }
    // ssh, too, splits at the last '@'.
    auto host = text;
    const auto at = text.lastIndexOf( QLatin1Char( '@' ) );
    if ( at >= 0 ) {
        parsed.user = text.left( at );
        host = text.mid( at + 1 );
    }
    QString port;
    if ( host.startsWith( QLatin1Char( '[' ) ) ) {
        const auto close = host.indexOf( QLatin1Char( ']' ) );
        if ( close < 0 ) {
            parsed.problem = QStringLiteral( "A '[' of the host is not closed." );
            return parsed;
        }
        const auto rest = host.mid( close + 1 );
        if ( !rest.isEmpty() && !rest.startsWith( QLatin1Char( ':' ) ) ) {
            parsed.problem = QStringLiteral( "After [address] only :port may follow." );
            return parsed;
        }
        port = rest.mid( 1 );
        if ( rest.startsWith( QLatin1Char( ':' ) ) && port.isEmpty() ) {
            port = QStringLiteral( "?" ); // "[::1]:" names no port
        }
        host = host.mid( 1, close - 1 );
    }
    else if ( host.count( QLatin1Char( ':' ) ) == 1 ) {
        const auto colon = host.indexOf( QLatin1Char( ':' ) );
        port = host.mid( colon + 1 );
        if ( port.isEmpty() ) {
            port = QStringLiteral( "?" );
        }
        host = host.left( colon );
    }
    // More than one ':' unbracketed: an IPv6 address, without a port.
    if ( host.isEmpty() || ( at >= 0 && parsed.user.isEmpty() ) ) {
        parsed.problem = QStringLiteral( "Enter a host: [user@]host[:port]." );
        return parsed;
    }
    if ( host.startsWith( QLatin1Char( '-' ) ) || parsed.user.startsWith( QLatin1Char( '-' ) ) ) {
        parsed.problem = QStringLiteral( "A host cannot start with '-'." );
        return parsed;
    }
    if ( !port.isEmpty() ) {
        bool ok = false;
        const auto number = port.toInt( &ok );
        if ( !ok || number < 1 || number > 65535 || port.startsWith( QLatin1Char( '+' ) ) ) {
            parsed.problem = QStringLiteral( "The port must be a number from 1 to 65535." );
            return parsed;
        }
        parsed.port = number;
    }
    parsed.host = host;
    return parsed;
}

QString SshDestination::destination() const
{
    return user.isEmpty() ? host : user + QLatin1Char( '@' ) + host;
}

std::vector<LiveTarget> sshConfigHosts( const QString& configText )
{
    std::vector<LiveTarget> hosts;
    struct Details {
        QString hostName, user, port;
    };
    std::vector<Details> details;
    std::vector<size_t> block; // the hosts of the current Host entry
    std::set<QString> seen;
    static const QRegularExpression keyword(
        QStringLiteral( "^\\s*([A-Za-z]+)\\s*(?:=\\s*|\\s+)(.*?)\\s*$" ) );
    for ( const auto& line : configText.split( QLatin1Char( '\n' ) ) ) {
        const auto trimmed = line.trimmed();
        if ( trimmed.isEmpty() || trimmed.startsWith( QLatin1Char( '#' ) ) ) {
            continue;
        }
        const auto match = keyword.match( trimmed );
        if ( !match.hasMatch() ) {
            continue;
        }
        const auto name = match.captured( 1 ).toLower();
        const auto value = match.captured( 2 );
        if ( name == QStringLiteral( "host" ) || name == QStringLiteral( "match" ) ) {
            block.clear();
            if ( name == QStringLiteral( "match" ) ) {
                continue;
            }
            for ( auto pattern : value.split( QRegularExpression( QStringLiteral( "\\s+" ) ),
                                              Qt::SkipEmptyParts ) ) {
                pattern.remove( QLatin1Char( '"' ) );
                if ( pattern.isEmpty() || pattern.contains( QRegularExpression( "[*?!]" ) )
                     || seen.count( pattern ) > 0 ) {
                    continue;
                }
                seen.insert( pattern );
                block.push_back( hosts.size() );
                hosts.push_back( { pattern, {}, {} } );
                details.emplace_back();
            }
            continue;
        }
        for ( const auto index : block ) {
            auto& detail = details[ index ];
            // The first value of each counts, as ssh reads it.
            if ( name == QStringLiteral( "hostname" ) && detail.hostName.isEmpty() ) {
                detail.hostName = value;
            }
            else if ( name == QStringLiteral( "user" ) && detail.user.isEmpty() ) {
                detail.user = value;
            }
            else if ( name == QStringLiteral( "port" ) && detail.port.isEmpty() ) {
                detail.port = value;
            }
        }
    }
    for ( size_t i = 0; i < hosts.size(); ++i ) {
        const auto& detail = details[ i ];
        if ( detail.hostName.isEmpty() && detail.user.isEmpty() && detail.port.isEmpty() ) {
            continue;
        }
        auto description = detail.hostName.isEmpty() ? hosts[ i ].id : detail.hostName;
        if ( !detail.user.isEmpty() ) {
            description.prepend( detail.user + QLatin1Char( '@' ) );
        }
        if ( !detail.port.isEmpty() ) {
            description += QLatin1Char( ':' ) + detail.port;
        }
        hosts[ i ].description = description;
    }
    return hosts;
}

QString sshRemoteCaptureCommand( const LiveChoice& choice )
{
    const bool excludeOwn = optionOn( choice.options, kSshExcludeOwnOption );
    QString filter;
    if ( excludeOwn ) {
        // $SSH_CLIENT is "<client address> <client port> <server port>": the
        // server's shell puts its first and last word between the quoted
        // parts, as one argument.
        const auto own = choice.filter.isEmpty()
                             ? QStringLiteral( "not (host " )
                             : QStringLiteral( "(%1) and not (host " ).arg( choice.filter );
        filter = shellQuote( own ) + QStringLiteral( "\"${SSH_CLIENT%% *}\"" )
                 + shellQuote( QStringLiteral( " and tcp port " ) )
                 + QStringLiteral( "\"${SSH_CLIENT##* }\"" ) + shellQuote( QStringLiteral( ")" ) );
    }
    else if ( !choice.filter.isEmpty() ) {
        filter = shellQuote( choice.filter );
    }

    QString line;
    if ( excludeOwn ) {
        line = QStringLiteral( "[ -n \"$SSH_CLIENT\" ] || { echo 'SSH_CLIENT is not set on the "
                               "server, so the SSH connection cannot be excluded' >&2; exit 2; "
                               "}; " );
    }
    line += QStringLiteral( "exec " );
    if ( optionOn( choice.options, kSshSudoOption ) ) {
        line += QStringLiteral( "sudo -n " );
    }
    // -U: each packet written as it comes, not when a buffer is full.
    line += QStringLiteral( "tcpdump -i %1 -s %2 -U -w -" )
                .arg( shellQuote( choice.networkInterface ) )
                .arg( choice.snaplen );
    if ( !filter.isEmpty() ) {
        line += QLatin1Char( ' ' ) + filter;
    }
    return line;
}

QString explainSshFailure( const QString& error )
{
    const auto has = [ &error ]( const char* pattern ) {
        return QRegularExpression( QString::fromLatin1( pattern ),
                                   QRegularExpression::CaseInsensitiveOption )
            .match( error )
            .hasMatch();
    };
    if ( has( "REMOTE HOST IDENTIFICATION HAS CHANGED|host key for .* has changed" ) ) {
        return QStringLiteral(
            "The server's host key is not the one ssh knows: the server was reinstalled, or "
            "someone is in between. Ask the server's administrator; if the new key is right, "
            "remove the old one (ssh-keygen -R <host>, or ssh-keygen -R '[<host>]:<port>' for "
            "another port) and connect once in a terminal to accept the new one. LogSquirl "
            "never accepts a host key for you." );
    }
    if ( has( "Host key verification failed|No \\S+ host key is known|host key is not known" ) ) {
        return QStringLiteral(
            "ssh does not know the server's host key, and LogSquirl never accepts one for you "
            "(it runs ssh with BatchMode=yes). Connect once in a terminal (ssh [-p <port>] "
            "<user>@<host>), check the key's fingerprint and answer yes; then Refresh." );
    }
    if ( has( "Permission denied \\((publickey|password|keyboard-interactive|gssapi|hostbased)"
              "|Too many authentication failures|no more authentication methods" ) ) {
        return QStringLiteral(
            "The server accepted none of the keys ssh offered. LogSquirl uses keys and the SSH "
            "agent alone, never a password or a passphrase prompt (BatchMode=yes): load your "
            "key into the agent (ssh-add), install your public key on the server (ssh-copy-id "
            "<user>@<host>), or name it with IdentityFile in ~/.ssh/config. ssh -v "
            "<user>@<host> in a terminal shows which keys are tried." );
    }
    if ( has( "sudo: (a password is required|a terminal is required|no tty present"
              "|sorry, you must have a tty)" ) ) {
        return QStringLiteral(
            "sudo on the server wants a password, which LogSquirl never gives (it runs sudo -n). "
            "Let your user run tcpdump without one: on the server, sudo visudo -f "
            "/etc/sudoers.d/tcpdump and add the line <user> ALL=(root) NOPASSWD: "
            "/usr/bin/tcpdump (the path command -v tcpdump prints). Or give tcpdump the capture "
            "capabilities (sudo setcap cap_net_raw,cap_net_admin=eip $(command -v tcpdump)) "
            "and turn off \"Run tcpdump with sudo -n\"." );
    }
    if ( has( "tcpdump: (command )?not found|command not found: tcpdump"
              "|tcpdump: No such file or directory" ) ) {
        return QStringLiteral(
            "tcpdump is not installed on the server, or not on the PATH of a non-interactive "
            "ssh session. Install it: sudo apt install tcpdump (Debian, Ubuntu), sudo dnf "
            "install tcpdump (Fedora, RHEL), sudo apk add tcpdump (Alpine)." );
    }
    if ( has( "sudo: (command )?not found|command not found: sudo" ) ) {
        return QStringLiteral( "sudo is not installed on the server: install it, or give "
                               "tcpdump the capture capabilities and turn off \"Run tcpdump "
                               "with sudo -n\"." );
    }
    if ( isCapturePermissionError( error ) ) {
        return remotePermissionGuidance();
    }
    if ( has( "Could not resolve hostname|Connection refused|Connection timed out|"
              "Operation timed out|No route to host|Network is unreachable|"
              "Connection closed by|kex_exchange_identification" ) ) {
        return QStringLiteral( "The server could not be reached over SSH: check the host and "
                               "port (a Host of ~/.ssh/config works too), and that ssh "
                               "<user>@<host> works in a terminal." );
    }
    return {};
}

SshPrograms SshPrograms::forThisComputer()
{
    SshPrograms where;
#ifdef Q_OS_WIN
    const auto root = qEnvironmentVariable( "SystemRoot", QStringLiteral( "C:\\Windows" ) );
    where.installed = { QDir( root ).filePath( QStringLiteral( "System32/OpenSSH/ssh.exe" ) ) };
#endif
    where.searchPath
        = qEnvironmentVariable( "PATH" ).split( QDir::listSeparator(), Qt::SkipEmptyParts );
#ifndef Q_OS_WIN
    where.searchPath << QStringLiteral( "/usr/bin" ) << QStringLiteral( "/usr/local/bin" );
#endif
    where.config = QDir::home().filePath( QStringLiteral( ".ssh/config" ) );
    return where;
}

SshSourceKind::SshSourceKind( SshPrograms where )
    : where_( std::move( where ) )
{
}

QString SshSourceKind::program() const
{
    for ( const auto& path : where_.installed ) {
        const QFileInfo file( path );
        if ( file.isFile() && file.isExecutable() ) {
            return path;
        }
    }
    if ( where_.searchPath.isEmpty() ) {
        return {};
    }
    return QStandardPaths::findExecutable( QStringLiteral( "ssh" ), where_.searchPath );
}

QStringList SshSourceKind::sshArguments( const SshDestination& device,
                                         const QString& remoteCommand )
{
    auto arguments = kSshOptions;
    if ( device.port > 0 ) {
        arguments << QStringLiteral( "-p" ) << QString::number( device.port );
    }
    // After "--" the destination cannot be read as an option.
    arguments << QStringLiteral( "--" ) << device.destination() << remoteCommand;
    return arguments;
}

QString SshSourceKind::id() const
{
    return QStringLiteral( "ssh" );
}

QString SshSourceKind::displayName() const
{
    return QStringLiteral( "SSH" );
}

LiveAvailability SshSourceKind::availability() const
{
    if ( program().isEmpty() ) {
#ifdef Q_OS_WIN
        return LiveAvailability::unavailable( QStringLiteral(
            "ssh not found: install the OpenSSH Client (Settings > System > Optional "
            "features)." ) );
#else
        return LiveAvailability::unavailable( QStringLiteral(
            "ssh not found: install the OpenSSH client (Debian, Ubuntu: openssh-client)." ) );
#endif
    }
    return {};
}

LiveSourceKind::Devices SshSourceKind::devices() const
{
    return Devices::Typed;
}

QString SshSourceKind::deviceLabel() const
{
    return QStringLiteral( "Host" );
}

LiveListing SshSourceKind::listDevices( std::chrono::milliseconds timeout ) const
{
    (void)timeout;
    LiveListing listing;
    QFile config( where_.config );
    if ( !where_.config.isEmpty() && config.open( QIODevice::ReadOnly | QIODevice::Text ) ) {
        listing.targets = sshConfigHosts( QString::fromUtf8( config.readAll() ) );
    }
    return listing;
}

LiveListing SshSourceKind::listInterfaces( const QString& device,
                                           std::chrono::milliseconds timeout ) const
{
    LiveListing listing;
    const auto destination = SshDestination::parse( device );
    if ( !destination.problem.isEmpty() ) {
        listing.error = destination.problem;
        return listing;
    }
    const auto ssh = program();
    if ( ssh.isEmpty() ) {
        listing.error = availability().reason;
        return listing;
    }
    const auto output = runListing(
        { ssh, sshArguments( destination, kRemoteListing ), QStringLiteral( "ssh" ) }, timeout );
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
        listing.error = output.exitCode == kSshFailed
                            ? QStringLiteral( "ssh to %1 failed" ).arg( destination.host )
                            : QStringLiteral( "tcpdump -D on %1 exited with code %2" )
                                  .arg( destination.host )
                                  .arg( output.exitCode );
        if ( !err.isEmpty() ) {
            listing.error += QStringLiteral( ":\n" ) + err;
        }
        if ( const auto hint = explainSshFailure( err ); !hint.isEmpty() ) {
            listing.error += QStringLiteral( "\n\n" ) + hint;
        }
    }
    else if ( listing.targets.empty() ) {
        listing.error = QStringLiteral( "tcpdump -D listed no interfaces on %1; type one (any "
                                        "captures on all).\n\n" )
                            .arg( destination.host )
                        + remotePermissionGuidance();
    }
    return listing;
}

QString SshSourceKind::validate( const LiveChoice& choice ) const
{
    if ( const auto problem = SshDestination::parse( choice.device ).problem; !problem.isEmpty() ) {
        return problem;
    }
    if ( hasControl( choice.networkInterface ) ) {
        return QStringLiteral( "An interface is one line, without control characters." );
    }
    return LiveSourceKind::validate( choice );
}

LiveOptionsWidget* SshSourceKind::makeOptionsWidget() const
{
    return new SshOptionsWidget;
}

ProcessCommand SshSourceKind::command( const LiveChoice& choice ) const
{
    const auto ssh = program();
    return { ssh.isEmpty() ? QStringLiteral( "ssh" ) : ssh,
             sshArguments( SshDestination::parse( choice.device ),
                           sshRemoteCaptureCommand( choice ) ),
             QStringLiteral( "ssh" ) };
}

QString SshSourceKind::explainFailure( const QString& error ) const
{
    return explainSshFailure( error );
}

} // namespace tcpdump
