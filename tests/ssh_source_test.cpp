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
 * @file ssh_source_test.cpp
 * @brief BDD tests for the SSH source: the hosts it suggests, the exact ssh
 *        command it runs, the quoting of the remote command line, and live
 *        capture and its failures with a fake ssh that runs the remote
 *        command in a local shell, with fake sudo and tcpdump.
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "live_capture_form.h"
#include "sidebarwidget.h"
#include "ssh_source.h"
#include "stream_capture.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QPlainTextEdit>
#include <QProcess>
#include <QProcessEnvironment>
#include <QStandardPaths>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

SCENARIO( "A host of the SSH source is [user@]host[:port]", "[ssh_source]" )
{
    THEN( "user, host and port are taken apart" )
    {
        const auto plain = SshDestination::parse( "srv" );
        REQUIRE( plain.problem.isEmpty() );
        REQUIRE( plain.destination() == "srv" );
        REQUIRE( plain.port == 0 );

        const auto full = SshDestination::parse( " admin@srv.example.com:2222 " );
        REQUIRE( full.problem.isEmpty() );
        REQUIRE( full.user == "admin" );
        REQUIRE( full.host == "srv.example.com" );
        REQUIRE( full.port == 2222 );
        REQUIRE( full.destination() == "admin@srv.example.com" );

        const auto v6 = SshDestination::parse( "root@[fe80::1]:22" );
        REQUIRE( v6.problem.isEmpty() );
        REQUIRE( v6.destination() == "root@fe80::1" );
        REQUIRE( v6.port == 22 );

        const auto bareV6 = SshDestination::parse( "fe80::1" );
        REQUIRE( bareV6.problem.isEmpty() );
        REQUIRE( bareV6.host == "fe80::1" );
        REQUIRE( bareV6.port == 0 );

        // As ssh does, at the last '@'.
        REQUIRE( SshDestination::parse( "a@b@srv" ).user == "a@b" );
    }

    THEN( "what ssh could misread is refused" )
    {
        for ( const auto* device :
              { "", "  ", "-oProxyCommand=touch /tmp/x", "user@-oProxyCommand=x", "my host",
                "srv\nother", "srv:", "srv:0", "srv:65536", "srv:http", "@srv", "user@", "[fe80::1",
                "[fe80::1]x" } ) {
            CAPTURE( device );
            REQUIRE_FALSE( SshDestination::parse( device ).problem.isEmpty() );
        }
    }
}

SCENARIO( "The SSH source suggests the hosts of ~/.ssh/config", "[ssh_source]" )
{
    const auto hosts = sshConfigHosts( "# servers\n"
                                       "Host web1 web2\n"
                                       "    HostName 10.0.0.5\n"
                                       "    User admin\n"
                                       "    Port 2222\n"
                                       "Host *.internal !bastion\n"
                                       "    User ops\n"
                                       "host=db\n"
                                       "  hostname=db.example.com\n"
                                       "Host gw?\n"
                                       "Match host foo\n"
                                       "    User nobody\n"
                                       "Host plain web1\n" );

    THEN( "Host entries without wildcards, each once, with HostName, User and Port" )
    {
        REQUIRE( hosts.size() == 4 );
        REQUIRE( hosts[ 0 ].id == "web1" );
        REQUIRE( hosts[ 0 ].description == "admin@10.0.0.5:2222" );
        REQUIRE( hosts[ 1 ].id == "web2" );
        REQUIRE( hosts[ 1 ].description == "admin@10.0.0.5:2222" );
        REQUIRE( hosts[ 2 ].id == "db" );
        REQUIRE( hosts[ 2 ].description == "db.example.com" );
        REQUIRE( hosts[ 3 ].id == "plain" );
        REQUIRE( hosts[ 3 ].description.isEmpty() );
    }
}

SCENARIO( "The remote command line quotes the interface and the filter for the server's shell",
          "[ssh_source]" )
{
    THEN( "single quotes, each ' as '\\''" )
    {
        REQUIRE( shellQuote( "eth0" ) == "'eth0'" );
        REQUIRE( shellQuote( "" ) == "''" );
        REQUIRE( shellQuote( "it's" ) == "'it'\\''s'" );
    }

    LiveChoice choice{ "ssh", "admin@srv:2222", "eth0", "port 80", 1500, {} };

    THEN( "by default: sudo -n, and the SSH connection excluded as $SSH_CLIENT names it" )
    {
        const auto script = sshRemoteCaptureScript( choice );
        REQUIRE( script.startsWith( "[ -n \"$SSH_CLIENT\" ] || { echo 'SSH_CLIENT is not set on "
                                    "the server, so the SSH connection cannot be excluded' >&2; "
                                    "exit 2; }; set -- $SSH_CLIENT; exec 3<&0; " ) );
        REQUIRE( script.contains( "sudo -n tcpdump -i 'eth0' -s 1500 -U -w - '(port 80) and not "
                                  "(host '\"$1\"' and tcp port '\"$3\"')' 3<&- &" ) );
        REQUIRE( sshRemoteCaptureCommand( choice ) == "exec /bin/sh -c " + shellQuote( script ) );
    }

    THEN( "both options off: tcpdump as it is, the filter as it is" )
    {
        choice.options = { { kSshSudoOption, "false" }, { kSshExcludeOwnOption, "false" } };
        REQUIRE( sshRemoteCaptureScript( choice ).startsWith(
            "exec 3<&0; tcpdump -i 'eth0' -s 1500 -U -w - 'port 80' 3<&- &" ) );
        choice.filter.clear();
        REQUIRE( sshRemoteCaptureScript( choice ).startsWith(
            "exec 3<&0; tcpdump -i 'eth0' -s 1500 -U -w - 3<&- &" ) );
    }

    THEN( "the script ends tcpdump once its stdin closes, and exits with tcpdump's status" )
    {
        const auto script = sshRemoteCaptureScript( choice );
        REQUIRE( script.contains( "while IFS= read -r _; do :; done <&3; kill $pid;" ) );
        REQUIRE( script.endsWith( "wait $pid; status=$?; kill $watchdog 2>/dev/null; exit "
                                  "$status" ) );
    }
}

SCENARIO( "The SSH source runs ssh with BatchMode, a connect timeout and no tty", "[ssh_source]" )
{
    QTemporaryDir dir;
    SshPrograms where;
#ifdef Q_OS_WIN
    // Windows tells a program by its extension.
    where.installed = { dir.filePath( "ssh.exe" ) };
#else
    where.installed = { dir.filePath( "ssh" ) };
#endif
    where.config = dir.filePath( "config" );

    WHEN( "there is no ssh" )
    {
        const SshSourceKind kind( where );

        THEN( "the source is unavailable and says what to install" )
        {
            REQUIRE_FALSE( kind.availability().available );
            REQUIRE( kind.availability().reason.contains( "OpenSSH" ) );
        }
    }

    WHEN( "ssh is there" )
    {
        writeFile( where.installed.front(), {} );
        REQUIRE( QFile::setPermissions( where.installed.front(),
                                        QFileDevice::ReadOwner | QFileDevice::ExeOwner ) );
        const SshSourceKind kind( where );
        const LiveChoice choice{ "ssh", "admin@srv:2222", "eth0", "port 80", 1500, {} };

        THEN( "it is the SSH source, of typed hosts" )
        {
            REQUIRE( kind.availability().available );
            REQUIRE( kind.id() == "ssh" );
            REQUIRE( kind.displayName() == "SSH" );
            REQUIRE( kind.devices() == LiveSourceKind::Devices::Typed );
            REQUIRE( kind.deviceLabel() == "Host" );
            const auto registered = builtInLiveSources()->find( "ssh" );
            REQUIRE( registered );
            REQUIRE( registered->devices() == LiveSourceKind::Devices::Typed );
        }

        THEN( "the capture runs exactly this ssh: options, port, --, host, one remote command" )
        {
            const auto command = kind.command( choice );
            REQUIRE( command.program == where.installed.front() );
            REQUIRE( command.name == "ssh" );
            REQUIRE_FALSE( command.viaShell );
            REQUIRE( command.arguments
                     == QStringList{ "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-p",
                                     "2222", "--", "admin@srv",
                                     sshRemoteCaptureCommand( choice ) } );
        }

        THEN( "without a port there is no -p" )
        {
            auto plain = choice;
            plain.device = "srv";
            REQUIRE( kind.command( plain ).arguments.mid( 0, 7 )
                     == QStringList{ "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--",
                                     "srv" } );
        }

        THEN( "a choice needs a host and an interface" )
        {
            REQUIRE( kind.validate( choice ).isEmpty() );
            auto noHost = choice;
            noHost.device.clear();
            REQUIRE( kind.validate( noHost ).contains( "host" ) );
            auto optionLike = choice;
            optionLike.device = "-oProxyCommand=x";
            REQUIRE_FALSE( kind.validate( optionLike ).isEmpty() );
            auto noInterface = choice;
            noInterface.networkInterface.clear();
            REQUIRE_FALSE( kind.validate( noInterface ).isEmpty() );
        }

        THEN( "the hosts of the config file are suggested; without one, none" )
        {
            REQUIRE( kind.listDevices( LiveSourceKind::kListTimeout ).targets.empty() );
            QFile config( where.config );
            REQUIRE( config.open( QIODevice::WriteOnly ) );
            config.write( "Host web1\n  HostName 10.0.0.5\nHost *\n  User x\n" );
            config.close();
            const auto listing = kind.listDevices( LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.isEmpty() );
            REQUIRE( listing.targets.size() == 1 );
            REQUIRE( listing.targets[ 0 ].id == "web1" );
        }
    }
}

#ifdef Q_OS_UNIX

namespace {

/// A program at @p path that runs @p body.
void scriptAt( const QString& path, const QString& body )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( ( "#!/bin/sh\n" + body + "\n" ).toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
}

/// A server for the fake ssh: what its ssh, sudo and tcpdump do.
struct FakeServer {
    QTemporaryDir dir;
    /// Run by the fake ssh before the remote command, e.g. to fail as ssh does.
    QString sshPrelude;
    /// The body of the server's sudo; by default it runs its command after -n.
    QString sudo = "[ \"$1\" = -n ] || { echo 'fake sudo: -n missing' >&2; exit 97; }\n"
                   "shift; exec \"$@\"";
    bool tcpdump = true; ///< Whether the server has tcpdump.
    /// Whether a capture's tcpdump runs until it is killed, logging it.
    bool hang = false;
    /// Whether the remote command runs in a process group of its own, with
    /// ssh's stdin, as on a server: ending ssh does not end it.
    bool detached = false;

    QString remote() const
    {
        return dir.filePath( "remote" );
    }
    QString argvLog() const
    {
        return dir.filePath( "argv" );
    }
    QString tcpdumpLog() const
    {
        QFile file( dir.filePath( "tcpdump.log" ) );
        return file.open( QIODevice::ReadOnly ) ? QString::fromUtf8( file.readAll() ) : QString();
    }

    /// Write the fake ssh, sudo and tcpdump: ssh logs its arguments, one per
    /// line in brackets, fails without BatchMode=yes, and runs its last
    /// argument with /bin/sh as the server's shell would, $SSH_CLIENT set
    /// and the server's programs alone on PATH.  tcpdump -D lists two
    /// interfaces; a capture writes its arguments to stderr, one per line in
    /// brackets, and then a capture of one UDP datagram.
    SshPrograms write()
    {
        REQUIRE( QDir().mkpath( remote() ) );
        const auto pcap = dir.filePath( "synthetic.pcap" );
        writeFile( pcap,
                   pcapOf( { eth( EthertypeIpv4,
                                  ipv4( IpProtoUdp, udp( 40000, 9999, text( "live" ) ) ) ) } ) );
        scriptAt( dir.filePath( "ssh" ),
                  QString( "for a in \"$@\"; do printf '[%s]\\n' \"$a\"; done >> '%1'\n"
                           "batch=no\n"
                           "for a in \"$@\"; do [ \"$a\" = BatchMode=yes ] && batch=yes; done\n"
                           "[ $batch = yes ] || { echo 'fake ssh: no BatchMode=yes' >&2; exit "
                           "98; }\n"
                           "for a in \"$@\"; do cmd=$a; done\n"
                           "%2\n"
                           "%3" )
                      .arg( argvLog(), sshPrelude,
                            detached
                                ? QString( "exec 3<&0\n"
                                           "SSH_CLIENT='10.9.8.7 50123 2222' PATH='%1' '%2' -e "
                                           "'setpgrp(0,0); exec @ARGV or die' /bin/sh -c \"$cmd\" "
                                           "<&3 3<&- &\n"
                                           "wait $!" )
                                      .arg( remote(), QStandardPaths::findExecutable( "perl" ) )
                                : QString( "SSH_CLIENT='10.9.8.7 50123 2222' PATH='%1' exec "
                                           "/bin/sh -c \"$cmd\"" )
                                      .arg( remote() ) ) );
        scriptAt( QDir( remote() ).filePath( "sudo" ), sudo );
        if ( tcpdump ) {
            scriptAt( QDir( remote() ).filePath( "tcpdump" ),
                      QString( "if [ \"$1\" = -D ]; then printf '1.eth0 [Up, Running, "
                               "Connected]\\n2.any (Pseudo-device that captures on all "
                               "interfaces) [Up, Running]\\n'; exit 0; fi\n"
                               "for a in \"$@\"; do printf '[%s]\\n' \"$a\" >&2; done\n"
                               "/bin/cat '%1'\n"
                               "%2" )
                          .arg( pcap, hang ? QString( "trap 'echo killed >>\"%1\"; exit 0' TERM\n"
                                                      "echo running >>\"%1\"\n"
                                                      "while :; do /bin/sleep 0.05; done" )
                                                 .arg( dir.filePath( "tcpdump.log" ) )
                                           : QString() ) );
        }
        SshPrograms where;
        where.installed = { dir.filePath( "ssh" ) };
        where.config = dir.filePath( "config" );
        return where;
    }

    QString loggedArgv() const
    {
        QFile file( argvLog() );
        return file.open( QIODevice::ReadOnly ) ? QString::fromUtf8( file.readAll() ) : QString();
    }
};

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( std::shared_ptr<const LiveSourceKind> kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( std::move( kind ) );
    return registry;
}

/// What /bin/sh hands a program for the command line @p line: each
/// argument of `printf '[%s]\n'` standing in for tcpdump, in brackets.
QString argumentsAfterShell( const QString& line, const QString& binDir )
{
    QProcess shell;
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert( "PATH", binDir );
    environment.insert( "SSH_CLIENT", "10.9.8.7 50123 2222" );
    shell.setProcessEnvironment( environment );
    shell.start( "/bin/sh", { "-c", line } );
    REQUIRE( shell.waitForFinished( 10000 ) );
    return QString::fromUtf8( shell.readAllStandardError() );
}

} // namespace

SCENARIO( "Hostile interfaces and filters reach tcpdump as they are, run nothing", "[ssh_source]" )
{
    QTemporaryDir dir;
    const auto bin = dir.filePath( "bin" );
    REQUIRE( QDir().mkpath( bin ) );
    scriptAt( QDir( bin ).filePath( "sudo" ), "shift; exec \"$@\"" );
    scriptAt( QDir( bin ).filePath( "tcpdump" ),
              "for a in \"$@\"; do printf '[%s]\\n' \"$a\" >&2; done" );
    const auto pwned = dir.filePath( "pwned" );

    const QString hostileInterface = "eth0'; touch " + pwned + "; echo '";
    const QString filter = "host 10.0.0.1 and not port 22 \"$(touch " + pwned + ")\" `touch "
                           + pwned + "` $HOME ${PATH} \\ ' '' ; | & > " + pwned + " * ?";

    for ( const bool excludeOwn : { true, false } ) {
        CAPTURE( excludeOwn );
        LiveChoice choice{ "ssh", "srv", hostileInterface, filter, 96, {} };
        choice.options[ kSshExcludeOwnOption ] = excludeOwn ? "true" : "false";
        const auto arguments = argumentsAfterShell( sshRemoteCaptureCommand( choice ), bin );
        const auto expectedFilter
            = excludeOwn ? "(" + filter + ") and not (host 10.9.8.7 and tcp port 2222)" : filter;
        REQUIRE( arguments
                 == "[-i]\n[" + hostileInterface + "]\n[-s]\n[96]\n[-U]\n[-w]\n[-]\n["
                        + expectedFilter + "]\n" );
        REQUIRE_FALSE( QFileInfo::exists( pwned ) );
    }
}

SCENARIO( "The SSH source lists and captures on a server through a fake ssh", "[ssh_source]" )
{
    FakeServer server;
    const auto where = server.write();
    const auto kind = std::make_shared<SshSourceKind>( where );

    THEN( "the interfaces are what tcpdump -D lists on the server, over ssh in BatchMode" )
    {
        const auto listing = kind->listInterfaces( "admin@srv:2222", LiveSourceKind::kListTimeout );
        REQUIRE( listing.error.isEmpty() );
        REQUIRE( listing.targets.size() == 2 );
        REQUIRE( listing.targets[ 0 ].id == "eth0" );
        REQUIRE( listing.targets[ 0 ].description == "Up, Running, Connected" );
        REQUIRE( listing.targets[ 1 ].id == "any" );
        REQUIRE( listing.targets[ 1 ].description
                 == "Pseudo-device that captures on all interfaces" );
        REQUIRE( server.loggedArgv()
                 == "[-T]\n[-o]\n[BatchMode=yes]\n[-o]\n[ConnectTimeout=10]\n[-p]\n[2222]\n[--]\n"
                    "[admin@srv]\n[tcpdump -D]\n" );
    }

    THEN( "a typed host lists its interfaces in the form, which shows the options" )
    {
        LiveCaptureForm form;
        form.setSources( registryOf( kind ) );
        form.setChoice( LiveChoice{ "ssh", "srv", "", "", kDefaultSnaplen, {} } );
        auto* interfaces = form.findChild<QComboBox*>( "liveInterface" );
        REQUIRE( waitFor( [ & ] { return !form.isListing() && interfaces->count() == 2; } ) );
        REQUIRE( form.choice().networkInterface == "eth0" );

        auto* sudo = form.findChild<QCheckBox*>( "sshSudo" );
        auto* excludeOwn = form.findChild<QCheckBox*>( "sshExcludeOwn" );
        REQUIRE( sudo );
        REQUIRE( excludeOwn );
        REQUIRE( sudo->isChecked() );
        REQUIRE( excludeOwn->isChecked() );
        excludeOwn->setChecked( false );
        REQUIRE( form.choice().options.value( kSshExcludeOwnOption ) == "false" );
        REQUIRE( form.choice().options.value( kSshSudoOption ) == "true" );
        REQUIRE( form.problem().isEmpty() );
    }

    THEN( "a capture runs sudo -n tcpdump on the server and opens what it captured" )
    {
        FakeHost host;
        QTemporaryDir temp;
        SidebarWidget sidebar;
        sidebar.setTempRoot( temp.path() );
        sidebar.setLiveSources( registryOf( kind ) );
        REQUIRE( sidebar.startLiveCapture(
            LiveChoice{ "ssh", "admin@srv", "eth0", "udp port 9999", 96, {} } ) );
        REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
        REQUIRE( host.openedFiles.size() == 1 );
        REQUIRE( QFileInfo( host.openedFiles.first() ).fileName() == "admin_srv-eth0.log" );
        const auto stderrText = sidebar.findChild<QPlainTextEdit*>( "liveStderr" )->toPlainText();
        REQUIRE( stderrText.contains( "[eth0]" ) );
        REQUIRE( stderrText.contains( "[96]" ) );
        REQUIRE(
            stderrText.contains( "[(udp port 9999) and not (host 10.9.8.7 and tcp port 2222)]" ) );
        REQUIRE( sidebar.findChild<QLabel*>( "liveError" )->isHidden() );
    }
}

SCENARIO( "Stop ends tcpdump on the server, not only the local ssh", "[ssh_source]" )
{
    FakeServer server;
    server.hang = true;
    server.detached = true;
    const auto kind = std::make_shared<SshSourceKind>( server.write() );

    for ( const bool sudo : { true, false } ) {
        CAPTURE( sudo );
        QFile::remove( server.dir.filePath( "tcpdump.log" ) );
        FakeHost host;
        QTemporaryDir temp;
        SidebarWidget sidebar;
        sidebar.setTempRoot( temp.path() );
        sidebar.setLiveSources( registryOf( kind ) );
        LiveChoice choice{ "ssh", "admin@srv", "eth0", "", 96, {} };
        choice.options[ kSshSudoOption ] = sudo ? "true" : "false";
        REQUIRE( sidebar.startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return host.openedFiles.size() == 1; } ) );
        REQUIRE( waitFor( [ & ] { return server.tcpdumpLog().contains( "running" ); } ) );

        sidebar.stopLiveCapture();
        REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
        REQUIRE( waitFor( [ & ] { return server.tcpdumpLog().contains( "killed" ); } ) );
        REQUIRE( sidebar.findChild<QLabel*>( "liveError" )->isHidden() );
    }
}

SCENARIO( "What ssh, sudo and tcpdump fail with is reported with what to do", "[ssh_source]" )
{
    FakeServer server;

    GIVEN( "a server whose host key ssh does not know" )
    {
        server.sshPrelude = "echo 'No ED25519 host key is known for srv and you have requested "
                            "strict checking.' >&2\n"
                            "echo 'Host key verification failed.' >&2; exit 255";
        const SshSourceKind kind( server.write() );

        THEN( "the listing fails at once, saying to accept the key in a terminal" )
        {
            const auto listing = kind.listInterfaces( "srv", LiveSourceKind::kListTimeout );
            REQUIRE( listing.targets.empty() );
            REQUIRE( listing.error.contains( "ssh to srv failed" ) );
            REQUIRE( listing.error.contains( "Host key verification failed." ) );
            REQUIRE( listing.error.contains( "never accepts one for you" ) );
        }
    }

    GIVEN( "a server whose host key changed" )
    {
        server.sshPrelude = "echo '@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @' "
                            ">&2\necho 'Host key verification failed.' >&2; exit 255";
        const SshSourceKind kind( server.write() );

        THEN( "the listing says to check, then ssh-keygen -R" )
        {
            const auto error = kind.listInterfaces( "srv", LiveSourceKind::kListTimeout ).error;
            REQUIRE( error.contains( "ssh-keygen -R" ) );
        }
    }

    GIVEN( "a server that refuses the keys" )
    {
        server.sshPrelude
            = "echo 'admin@srv: Permission denied (publickey,password).' >&2; exit 255";
        const SshSourceKind kind( server.write() );

        THEN( "the listing names the agent and ssh-copy-id, never a password" )
        {
            const auto error
                = kind.listInterfaces( "admin@srv", LiveSourceKind::kListTimeout ).error;
            REQUIRE( error.contains( "Permission denied (publickey,password)." ) );
            REQUIRE( error.contains( "ssh-add" ) );
            REQUIRE( error.contains( "ssh-copy-id" ) );
        }
    }

    GIVEN( "a server without tcpdump" )
    {
        server.tcpdump = false;
        const SshSourceKind kind( server.write() );

        THEN( "the listing says to install it" )
        {
            const auto error = kind.listInterfaces( "srv", LiveSourceKind::kListTimeout ).error;
            REQUIRE( error.contains( "exited with code 127" ) );
            REQUIRE( error.contains( "tcpdump is not installed on the server" ) );
        }

        THEN( "so does a capture, behind sudo -n" )
        {
            REQUIRE( kind.explainFailure( "ssh exited with code 1:\nsudo: tcpdump: command not "
                                          "found" )
                         .contains( "apt install tcpdump" ) );
        }
    }

    GIVEN( "a sudo that wants a password" )
    {
        server.sudo = "echo 'sudo: a password is required' >&2; exit 1";
        const auto kind = std::make_shared<SshSourceKind>( server.write() );
        FakeHost host;
        QTemporaryDir temp;
        SidebarWidget sidebar;
        sidebar.setTempRoot( temp.path() );
        sidebar.setLiveSources( registryOf( kind ) );
        REQUIRE( sidebar.startLiveCapture( LiveChoice{ "ssh", "srv", "eth0", "", 96, {} } ) );
        REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

        THEN( "the capture fails, and the section says how to allow tcpdump without one" )
        {
            REQUIRE( host.openedFiles.isEmpty() );
            const auto error = sidebar.findChild<QLabel*>( "liveError" )->text();
            REQUIRE( error.contains( "sudo: a password is required" ) );
            REQUIRE( error.contains( "NOPASSWD" ) );
            REQUIRE( error.contains( "never gives" ) );
        }
    }

    THEN( "tcpdump without permission on the server suggests sudo -n or setcap" )
    {
        const SshSourceKind kind( server.write() );
        const auto hint = kind.explainFailure(
            "ssh exited with code 1:\ntcpdump: eth0: You don't have permission to capture on "
            "that device (socket: Operation not permitted)" );
        REQUIRE( hint.contains( "sudo -n" ) );
        REQUIRE( hint.contains( "setcap" ) );
        REQUIRE( kind.explainFailure( "tcpdump: syntax error" ).isEmpty() );
    }
}

SCENARIO( "The SSH source never waits for a prompt", "[ssh_source]" )
{
    FakeServer server;
    // An ssh that would ask: what it reads is what it got.
    server.sshPrelude = "read answer; echo \"answer=[$answer]\" >&2; exit 255";
    const SshSourceKind kind( server.write() );

    THEN( "stdin is empty, so a listing fails at once instead of hanging" )
    {
        QElapsedTimer clock;
        clock.start();
        const auto error = kind.listInterfaces( "srv", LiveSourceKind::kListTimeout ).error;
        REQUIRE( clock.elapsed() < 5000 );
        REQUIRE( error.contains( "answer=[]" ) );
    }

    THEN( "every ssh it runs is in BatchMode" )
    {
        const auto arguments
            = kind.command( LiveChoice{ "ssh", "srv", "eth0", "", 96, {} } ).arguments;
        REQUIRE( arguments.indexOf( "BatchMode=yes" ) == arguments.indexOf( "-o" ) + 1 );
        REQUIRE_FALSE( server.loggedArgv().contains( "fake ssh: no BatchMode" ) );
    }
}

#endif
