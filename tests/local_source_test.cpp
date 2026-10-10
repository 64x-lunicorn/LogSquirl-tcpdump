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
 * @file local_source_test.cpp
 * @brief BDD tests for the Local source: live capture on this computer with
 *        dumpcap or tcpdump, found on a test PATH as fake scripts, and the
 *        guidance for missing capture permissions per OS; captures run
 *        through a Live Capture Session.
 */

#include <catch2/catch.hpp>

#include "fake_live_session.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "live_capture_session.h"
#include "local_source.h"
#include "stream_capture.h"

#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

SCENARIO( "The guidance for missing capture permissions names what to do on each OS",
          "[local_source]" )
{
    THEN( "macOS: Wireshark's ChmodBPF or the access_bpf group, for /dev/bpf*" )
    {
        const auto text = capturePermissionGuidance( CaptureOs::MacOS,
                                                     "/Applications/Wireshark.app/Contents/MacOS/"
                                                     "dumpcap" );
        REQUIRE( text.contains( "/dev/bpf" ) );
        REQUIRE( text.contains( "ChmodBPF" ) );
        REQUIRE( text.contains( "access_bpf" ) );
        REQUIRE( text.contains( "https://www.wireshark.org/download.html" ) );
    }

    THEN( "Linux: setcap on the program, or the wireshark group for dumpcap" )
    {
        const auto dumpcap = capturePermissionGuidance( CaptureOs::Linux, "/usr/bin/dumpcap" );
        REQUIRE( dumpcap.contains( "setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap" ) );
        REQUIRE( dumpcap.contains( "usermod -aG wireshark" ) );
        REQUIRE( dumpcap.contains( "log in again" ) );

        const auto tcpdump = capturePermissionGuidance( CaptureOs::Linux, "/usr/sbin/tcpdump" );
        REQUIRE( tcpdump.contains( "setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump" ) );
        REQUIRE_FALSE( tcpdump.contains( "wireshark group" ) );
    }

    THEN( "Windows: Npcap, without restricting it to administrators" )
    {
        const auto text = capturePermissionGuidance( CaptureOs::Windows,
                                                     "C:/Program Files/Wireshark/dumpcap.exe" );
        REQUIRE( text.contains( "Npcap" ) );
        REQUIRE( text.contains( "https://npcap.com/#download" ) );
        REQUIRE( text.contains( "Administrators only" ) );
    }

    THEN( "the install hints name where to get a capture program" )
    {
        REQUIRE( captureInstallHint( CaptureOs::MacOS ).contains( "wireshark.org" ) );
        REQUIRE( captureInstallHint( CaptureOs::Linux ).contains( "tcpdump" ) );
        REQUIRE( captureInstallHint( CaptureOs::Windows ).contains( "Npcap" ) );
    }

    THEN( "permission errors of dumpcap, tcpdump and Npcap are told apart from others" )
    {
        for ( const auto* error :
              { "tcpdump: en0: You don't have permission to capture on that device\n"
                "((cannot open BPF device) /dev/bpf0: Permission denied)",
                "dumpcap: You don't have permission to capture on that device (socket: "
                "Operation not permitted)",
                "tcpdump: eth0: You don't have permission to perform this capture on that device",
                "dumpcap: There are no interfaces on which a capture can be done",
                "Unable to load Npcap or WinPcap (wpcap.dll); you will not be able to capture" } ) {
            CAPTURE( error );
            REQUIRE( isCapturePermissionError( error ) );
        }
        REQUIRE_FALSE( isCapturePermissionError( "tcpdump: syntax error in filter expression" ) );
        REQUIRE_FALSE(
            isCapturePermissionError( "dumpcap: The capture session could not be "
                                      "initiated on interface 'xyz0' (No such device)" ) );
    }
}

#ifdef Q_OS_UNIX

SCENARIO( "The Local source runs dumpcap or tcpdump without sudo and passes the filter whole",
          "[local_source]" )
{
    LocalPrograms where;
    where.os = CaptureOs::Linux;
    where.dumpcap = { "/opt/ws/dumpcap" };
    where.tcpdump = { "/opt/td/tcpdump" };
    const LiveChoice choice{ "local", "", "en0", "host 10.0.0.1 and not (port 22)", 1500 };

    THEN( "it is registered as Local" )
    {
        const auto kind = builtInLiveSources()->find( "local" );
        REQUIRE( kind );
        REQUIRE( kind->displayName() == "Local" );
        REQUIRE( kind->devices() == LiveSourceKind::Devices::None );
    }

    WHEN( "dumpcap is there" )
    {
        // Not executable files: found only as install locations that exist.
        QTemporaryDir dir;
        where.dumpcap = { dir.filePath( "dumpcap" ) };
        where.tcpdump = { dir.filePath( "tcpdump" ) };
        for ( const auto& path : { where.dumpcap.front(), where.tcpdump.front() } ) {
            QFile file( path );
            REQUIRE( file.open( QIODevice::WriteOnly ) );
            file.close();
            REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                          | QFileDevice::ExeOwner ) );
        }
        const LocalSourceKind kind( where );

        THEN( "dumpcap captures, as pcapng to stdout, quietly, the filter one argument" )
        {
            REQUIRE( kind.program().isDumpcap );
            const auto command = kind.command( choice );
            REQUIRE( command.program == where.dumpcap.front() );
            REQUIRE( command.name == "dumpcap" );
            REQUIRE_FALSE( command.viaShell );
            REQUIRE( command.arguments
                     == QStringList{ "-i", "en0", "-s", "1500", "-q", "-f",
                                     "host 10.0.0.1 and not (port 22)", "-w", "-" } );
        }

        THEN( "without a filter there is no -f" )
        {
            auto all = choice;
            all.filter.clear();
            REQUIRE( kind.command( all ).arguments
                     == QStringList{ "-i", "en0", "-s", "1500", "-q", "-w", "-" } );
        }
    }

    WHEN( "only tcpdump is there" )
    {
        QTemporaryDir dir;
        where.dumpcap = { dir.filePath( "dumpcap" ) };
        where.tcpdump = { dir.filePath( "tcpdump" ) };
        QFile file( where.tcpdump.front() );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.close();
        REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::ExeOwner ) );
        const LocalSourceKind kind( where );

        THEN( "tcpdump captures, packet-buffered to stdout, the filter its last argument" )
        {
            REQUIRE( kind.availability().available );
            REQUIRE_FALSE( kind.program().isDumpcap );
            const auto command = kind.command( choice );
            REQUIRE( command.program == where.tcpdump.front() );
            REQUIRE( command.arguments
                     == QStringList{ "-i", "en0", "-s", "1500", "-U", "-w", "-",
                                     "host 10.0.0.1 and not (port 22)" } );
        }
    }

    WHEN( "neither is there" )
    {
        QTemporaryDir dir;
        where.dumpcap = { dir.filePath( "dumpcap" ) };
        where.tcpdump = { dir.filePath( "tcpdump" ) };
        const LocalSourceKind kind( where );

        THEN( "the source is unavailable with an install hint for the OS" )
        {
            const auto availability = kind.availability();
            REQUIRE_FALSE( availability.available );
            REQUIRE( availability.reason == captureInstallHint( CaptureOs::Linux ) );
            REQUIRE( kind.program().path.isEmpty() );
        }
    }

    THEN( "no command of the source runs sudo or anything that asks for a password" )
    {
        const LocalSourceKind kind( where );
        for ( const auto& word :
              kind.command( choice ).arguments + QStringList{ kind.command( choice ).program } ) {
            for ( const auto* asker : { "sudo", "pkexec", "doas", "gksu", "runas", "osascript" } ) {
                REQUIRE_FALSE( word.contains( asker ) );
            }
        }
    }
}

namespace {

/// A fake capture program in @p dir named @p name: `-D` prints @p list, a
/// capture writes its arguments to stderr, one per line in brackets, and
/// then the capture @p pcapPath to stdout.
void fakeCaptureProgram( const QTemporaryDir& dir, const QString& name, const QString& list,
                         const QString& pcapPath )
{
    QFile file( dir.filePath( name ) );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( QString( "#!/bin/sh\n"
                         "if [ \"$1\" = -D ]; then printf '%1'; exit 0; fi\n"
                         "for a in \"$@\"; do printf '[%s]\\n' \"$a\" >&2; done\n"
                         "cat '%2'\n" )
                    .arg( list, pcapPath )
                    .toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
}

/// A program in @p dir named @p name that runs @p body.
void scriptProgram( const QTemporaryDir& dir, const QString& name, const QString& body )
{
    QFile file( dir.filePath( name ) );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( ( "#!/bin/sh\n" + body + "\n" ).toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
}

/// What the dumpcap and tcpdump of @p dir capture: one UDP datagram.
QString writeCapture( const QTemporaryDir& dir )
{
    const auto path = dir.filePath( "synthetic.pcap" );
    writeFile( path, pcapOf( { eth( EthertypeIpv4,
                                    ipv4( IpProtoUdp, udp( 40000, 9999, text( "live" ) ) ) ) } ) );
    return path;
}

/// Programs found on @p dir as PATH alone, on @p os.
LocalPrograms onTestPath( const QTemporaryDir& dir, CaptureOs os = runningCaptureOs() )
{
    LocalPrograms where;
    where.os = os;
    where.searchPath = { dir.path() };
    return where;
}

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( std::shared_ptr<const LiveSourceKind> kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( std::move( kind ) );
    return registry;
}

} // namespace

SCENARIO( "The Local source prefers dumpcap on the PATH and falls back to tcpdump",
          "[local_source]" )
{
    QTemporaryDir dir;
    const auto pcap = writeCapture( dir );

    GIVEN( "both on the PATH" )
    {
        fakeCaptureProgram( dir, "dumpcap", "1. en0 (Wi-Fi)\\n2. lo0 (Loopback)\\n", pcap );
        fakeCaptureProgram( dir, "tcpdump", "1.tcp0 [Up, Running]\\n", pcap );
        const LocalSourceKind kind( onTestPath( dir ) );

        THEN( "dumpcap is chosen, and lists the interfaces with their descriptions" )
        {
            REQUIRE( kind.availability().available );
            REQUIRE( kind.program().path == dir.filePath( "dumpcap" ) );
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.isEmpty() );
            REQUIRE( listing.targets.size() == 2 );
            REQUIRE( listing.targets[ 0 ].id == "en0" );
            REQUIRE( listing.targets[ 0 ].description == "Wi-Fi" );
            REQUIRE( listing.targets[ 1 ].id == "lo0" );
            REQUIRE( listing.targets[ 1 ].description == "Loopback" );
        }
    }

    GIVEN( "tcpdump alone on the PATH" )
    {
        fakeCaptureProgram( dir, "tcpdump",
                            "1.en0 [Up, Running, Wireless, Associated]\\n2.lo0 [Up, Running, "
                            "Loopback]\\n3.any (Pseudo-device that captures on all interfaces) "
                            "[Up, Running]\\n",
                            pcap );
        const LocalSourceKind kind( onTestPath( dir ) );

        THEN( "tcpdump lists the interfaces, its flags or description besides" )
        {
            REQUIRE( kind.program().path == dir.filePath( "tcpdump" ) );
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.isEmpty() );
            REQUIRE( listing.targets.size() == 3 );
            REQUIRE( listing.targets[ 0 ].id == "en0" );
            REQUIRE( listing.targets[ 0 ].description == "Up, Running, Wireless, Associated" );
            REQUIRE( listing.targets[ 2 ].id == "any" );
            REQUIRE( listing.targets[ 2 ].description
                     == "Pseudo-device that captures on all interfaces" );
        }
    }

    GIVEN( "a listing that is empty" )
    {
        fakeCaptureProgram( dir, "tcpdump", "", pcap );
        const LocalSourceKind kind( onTestPath( dir, CaptureOs::Linux ) );

        THEN( "it says the program may not capture, and what to do" )
        {
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.targets.empty() );
            REQUIRE( listing.error.contains( "no interfaces" ) );
            REQUIRE( listing.error.contains( "setcap cap_net_raw,cap_net_admin=eip "
                                             + dir.filePath( "tcpdump" ) ) );
        }
    }

    GIVEN( "a listing that fails for want of permissions" )
    {
        // As on Windows, where programs end in .exe.
        scriptProgram( dir, "dumpcap.exe",
                       "echo 'dumpcap: There are no interfaces on which a capture can be done' "
                       ">&2; exit 1" );
        const LocalSourceKind kind( onTestPath( dir, CaptureOs::Windows ) );

        THEN( "its error comes with the guidance" )
        {
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.contains( "no interfaces on which a capture can be done" ) );
            REQUIRE( listing.error.contains( "Npcap" ) );
        }
    }

    GIVEN( "a listing that fails otherwise" )
    {
        scriptProgram( dir, "tcpdump", "echo 'tcpdump: something broke' >&2; exit 2" );
        const LocalSourceKind kind( onTestPath( dir ) );

        THEN( "its error is shown without guidance" )
        {
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.contains( "tcpdump: something broke" ) );
            REQUIRE( listing.error.contains( "code 2" ) );
            REQUIRE_FALSE( listing.error.contains( "setcap" ) );
        }
    }

    GIVEN( "macOS, tcpdump listing, and a BPF device that cannot be read" )
    {
        fakeCaptureProgram( dir, "tcpdump", "1.en0 [Up, Running]\\n", pcap );
        auto where = onTestPath( dir, CaptureOs::MacOS );
        where.bpfDevice = dir.filePath( "bpf0" );
        writeFile( where.bpfDevice, {} );
        REQUIRE( QFile::setPermissions( where.bpfDevice, QFileDevice::WriteOwner ) );
        const LocalSourceKind kind( where );

        THEN( "the interfaces are listed, and the guidance shown before a capture fails" )
        {
            const auto listing = kind.listInterfaces( {}, LiveSourceKind::kListTimeout );
            REQUIRE( listing.targets.size() == 1 );
            if ( !QFileInfo( where.bpfDevice ).isReadable() ) { // not as root
                REQUIRE( listing.error.contains( "ChmodBPF" ) );
            }
        }

        AND_WHEN( "the device can be read" )
        {
            REQUIRE( QFile::setPermissions( where.bpfDevice,
                                            QFileDevice::ReadOwner | QFileDevice::WriteOwner ) );

            THEN( "there is nothing to say" )
            {
                REQUIRE( kind.listInterfaces( {}, LiveSourceKind::kListTimeout ).error.isEmpty() );
            }
        }
    }
}

SCENARIO( "The Local source captures live with a fake dumpcap or tcpdump", "[local_source]" )
{
    FakeHost host;
    QTemporaryDir dir;
    const auto pcap = writeCapture( dir );

    for ( const auto* name : { "dumpcap", "tcpdump" } ) {
        CAPTURE( name );
        QTemporaryDir path;
        fakeCaptureProgram( path, name, "1.en0 (Wi-Fi)\\n", pcap );
        const auto sources = registryOf( std::make_shared<LocalSourceKind>( onTestPath( path ) ) );

        LiveCaptureForm form;
        form.setSources( sources );
        form.setChoice( LiveChoice{ "local", "", "", "", kDefaultSnaplen, {} } );
        auto* interfaces = form.findChild<QComboBox*>( "liveInterface" );
        REQUIRE( waitFor( [ & ] { return !form.isListing() && interfaces->count() == 1; } ) );
        REQUIRE( interfaces->itemData( 0 ).toString() == "en0" );

        WorkerSession live( sources );
        REQUIRE( live.session.start( LiveChoice{ "local", "", "en0", "udp port 9999", 96 } ) );
        REQUIRE( live.waitForOutcome() );
        INFO( live.outcome().error.toStdString() );
        REQUIRE( live.outcome().status == LiveOutcome::Status::Captured );
        REQUIRE( live.outcome().error.isEmpty() );
        REQUIRE( live.outcome().files.size() == 1 );
        REQUIRE( live.outcome().files == live.adapters.openedTabs );
        REQUIRE( QFileInfo( live.outcome().files.first() ).fileName() == "en0.log" );
        REQUIRE( live.stderrText().contains( "[udp port 9999]" ) );
        REQUIRE( live.stderrText().contains( "[96]" ) );
    }
}

SCENARIO( "A capture that fails for want of permissions gets the guidance for this OS",
          "[local_source]" )
{
    FakeHost host;
    QTemporaryDir dir;
    scriptProgram( dir, "tcpdump",
                   "if [ \"$1\" = -D ]; then echo '1.en0 [Up, Running]'; exit 0; fi\n"
                   "echo 'tcpdump: en0: You don'\\''t have permission to capture on that device' "
                   ">&2\n"
                   "echo '((cannot open BPF device) /dev/bpf0: Permission denied)' >&2\n"
                   "exit 1" );
    const auto kind = std::make_shared<LocalSourceKind>( onTestPath( dir ) );
    WorkerSession live( registryOf( kind ) );

    REQUIRE( live.session.start( LiveChoice{ "local", "", "en0", "", 96 } ) );
    REQUIRE( live.waitForOutcome() );

    THEN( "the capture fails with the error and the Guidance of the running OS" )
    {
        REQUIRE( live.outcome().status == LiveOutcome::Status::Failed );
        REQUIRE( live.outcome().error.contains( "permission to capture" ) );
        const auto guidance
            = capturePermissionGuidance( runningCaptureOs(), dir.filePath( "tcpdump" ) );
        REQUIRE( kind->explainFailure( "tcpdump: en0: You don't have permission to capture" )
                 == guidance );
        REQUIRE( live.outcome().guidance == guidance );
        REQUIRE( live.outcome().files.isEmpty() );
        REQUIRE( live.adapters.openedTabs.isEmpty() );
    }

    THEN( "a failure that is not about permissions gets no guidance" )
    {
        REQUIRE( kind->explainFailure( "tcpdump: syntax error" ).isEmpty() );
    }
}

#endif
