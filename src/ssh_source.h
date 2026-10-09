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
 * @file ssh_source.h
 * @brief The SSH source: live capture on a server, with tcpdump run over the
 *        system's OpenSSH client, keys or the agent alone.
 *
 * The host is typed, `[user@]host[:port]` or a Host of ~/.ssh/config (whose
 * Host entries without wildcards are suggested).  Every ssh runs as
 *
 *     ssh -T -o BatchMode=yes -o ConnectTimeout=10 [-p <port>] -- <user@host> <remote command>
 *
 * with stdin the null device: BatchMode makes ssh fail instead of asking for
 * a password, a passphrase or whether to trust a host key, so only keys and
 * the SSH agent are used and the plugin never asks for or stores a secret.
 * The interfaces are what `tcpdump -D` lists on the server; the capture is
 *
 *     exec [sudo -n] tcpdump -i '<if>' -s <snaplen> -U -w - '<filter>'
 *
 * a command line for the server's (POSIX) shell, the interface and the
 * filter quoted in single quotes (shellQuote()), so that nothing in them is
 * read by that shell.  `sudo -n` never prompts: a sudo that wants a password
 * fails, and the source says how to allow tcpdump without one.  By default
 * the filter excludes the capture's own SSH connection, `not (host <client>
 * and tcp port <server port>)`, both read from $SSH_CLIENT on the server.
 *
 * What ssh, sudo and tcpdump write on failure (an unknown host key, a
 * refused key, a sudo that wants a password, tcpdump missing or lacking
 * permissions) comes with what to do: explainSshFailure().
 */

#pragma once

#include "live_source.h"

#include <QString>
#include <QStringList>

#include <vector>

namespace tcpdump {

/// The option "use sudo -n" (LiveChoice::options): "true" (the default) or "false".
inline const QString kSshSudoOption = QStringLiteral( "sudo" );
/// The option "exclude this SSH connection from the capture": "true" (the
/// default) or "false".
inline const QString kSshExcludeOwnOption = QStringLiteral( "excludeOwnConnection" );

/// A device of the SSH source, `[user@]host[:port]`, taken apart.  An IPv6
/// address with a port is written in brackets: `[fe80::1]:2222`.
struct SshDestination {
    QString user; ///< Empty: ssh's own (~/.ssh/config, or the local user).
    QString host; ///< A name, an address, or a Host of ~/.ssh/config.
    int port = 0; ///< 0: ssh's own (~/.ssh/config, or 22).
    /// Why the device is not one ssh can be given; empty if it is.
    QString problem;

    static SshDestination parse( const QString& device );

    /// What ssh is given: user@host, or host.
    QString destination() const;
};

/// @p text as one word for a POSIX shell: in single quotes, each "'" as '\''.
QString shellQuote( const QString& text );

/// The Host entries of the ssh config @p configText that name one host (no
/// '*', '?' or '!'), each with its HostName, User and Port as description,
/// e.g. "admin@10.0.0.5:2222"; in their order, each once.
std::vector<LiveTarget> sshConfigHosts( const QString& configText );

/// The command line the server's shell runs to capture @p choice: tcpdump
/// (behind `sudo -n` unless the option is off) writing pcap to stdout, the
/// interface and filter quoted, and, unless the option is off, the filter
/// excluding the SSH connection as $SSH_CLIENT names it.
QString sshRemoteCaptureCommand( const LiveChoice& choice );

/// What the user can do about @p error, what ssh, sudo or tcpdump wrote: an
/// unknown or changed host key, a refused key, a sudo that wants a
/// password, tcpdump missing or lacking permissions, a host that cannot be
/// reached; empty if it is none of them.
QString explainSshFailure( const QString& error );

/// Where the SSH source looks for ssh, and the ssh config it suggests hosts from.
struct SshPrograms {
    /// Paths tried first, in order (Windows: its own OpenSSH client).
    QStringList installed;
    QStringList searchPath; ///< The directories searched then for ssh.
    QString config;         ///< The ssh config file whose hosts are suggested.

    /// This computer's: System32\OpenSSH\ssh.exe on Windows, PATH (and
    /// /usr/bin) elsewhere, and ~/.ssh/config.
    static SshPrograms forThisComputer();
};

/// Live capture on a server over SSH.
class SshSourceKind : public LiveSourceKind {
public:
    explicit SshSourceKind( SshPrograms where = SshPrograms::forThisComputer() );

    /// The ssh client found; empty if there is none.  Looked for anew on each call.
    QString program() const;

    /// The arguments of ssh to run @p remoteCommand on @p device's host.
    static QStringList sshArguments( const SshDestination& device, const QString& remoteCommand );

    QString id() const override;
    QString displayName() const override;
    LiveAvailability availability() const override;
    Devices devices() const override;
    QString deviceLabel() const override;
    LiveListing listDevices( std::chrono::milliseconds timeout ) const override;
    LiveListing listInterfaces( const QString& device,
                                std::chrono::milliseconds timeout ) const override;
    QString validate( const LiveChoice& choice ) const override;
    LiveOptionsWidget* makeOptionsWidget() const override;
    ProcessCommand command( const LiveChoice& choice ) const override;
    QString explainFailure( const QString& error ) const override;

private:
    SshPrograms where_;
};

} // namespace tcpdump
