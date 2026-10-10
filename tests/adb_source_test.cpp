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
 * @file adb_source_test.cpp
 * @brief BDD tests for the Android source: adb found where the SDK puts it,
 *        devices and interfaces, root through adb root or su, and live
 *        captures through a fake adb whose "device" is a shell on this
 *        computer with fake id, su, ip and tcpdump.
 */

#include <catch2/catch.hpp>

#include "adb_source.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "sidebarwidget.h"
#include "stream_capture.h"

#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QProcess>
#include <QStandardPaths>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

SCENARIO( "The Android source reads adb's device list and the device's interfaces", "[adb_source]" )
{
    THEN( "devices come with their model, and those adb cannot use with what to do" )
    {
        const auto devices = parseAdbDevices(
            "* daemon not running; starting now at tcp:5037\n"
            "* daemon started successfully\n"
            "List of devices attached\n"
            "emulator-5554          device product:sdk_gphone64_arm64 model:sdk_gphone64_arm64 "
            "device:emu64a transport_id:1\n"
            "R58M123ABC             unauthorized usb:1-1 transport_id:2\n"
            "192.168.1.20:5555      offline product:panther model:Pixel_7 device:panther\n"
            "0123456789ABCDEF       no permissions (missing udev rules? user is in the plugdev "
            "group); see [http://developer.android.com/tools/device.html] usb:1-2\n"
            "ZY22                   recovery product:foo\n"
            "\n" );
        REQUIRE( devices.size() == 5 );
        REQUIRE( devices[ 0 ].id == "emulator-5554" );
        REQUIRE( devices[ 0 ].description == "sdk gphone64 arm64" );
        REQUIRE( devices[ 0 ].problem.isEmpty() );
        REQUIRE( devices[ 1 ].id == "R58M123ABC" );
        REQUIRE( devices[ 1 ].problem.startsWith( "unauthorized" ) );
        REQUIRE( devices[ 1 ].problem.contains( "allow USB debugging" ) );
        REQUIRE( devices[ 2 ].description == "Pixel 7" );
        REQUIRE( devices[ 2 ].problem.startsWith( "offline" ) );
        REQUIRE( devices[ 3 ].problem.contains( "udev" ) );
        REQUIRE( devices[ 4 ].problem == "recovery: not ready for adb" );
    }

    THEN( "interfaces come from ip -o link, with their flags, or as bare names" )
    {
        const auto interfaces = parseDeviceInterfaces(
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT "
            "group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "9: eth0@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "rmnet_data0\n" );
        REQUIRE( interfaces.size() == 3 );
        REQUIRE( interfaces[ 0 ].id == "lo" );
        REQUIRE( interfaces[ 0 ].description == "LOOPBACK,UP,LOWER_UP" );
        REQUIRE( interfaces[ 1 ].id == "eth0" );
        REQUIRE( interfaces[ 2 ].id == "rmnet_data0" );
    }

    THEN( "a choice needs a device, and an interface that is a name" )
    {
        const AdbSourceKind kind( AdbPrograms{} );
        REQUIRE( kind.id() == "adb" );
        REQUIRE( kind.displayName() == "Android" );
        REQUIRE( kind.devices() == LiveSourceKind::Devices::Listed );
        REQUIRE( kind.validate( { "adb", "", "wlan0", "", 96 } ) == "Choose a device." );
        REQUIRE_FALSE( kind.validate( { "adb", "-x", "wlan0", "", 96 } ).isEmpty() );
        REQUIRE_FALSE( kind.validate( { "adb", "emulator-5554", "", "", 96 } ).isEmpty() );
        REQUIRE_FALSE( kind.validate( { "adb", "emulator-5554", "wlan0;id", "", 96 } ).isEmpty() );
        REQUIRE( kind.validate( { "adb", "192.168.1.20:5555", "rmnet_data0", "", 96 } ).isEmpty() );
    }

    THEN( "it is registered as Android" )
    {
        const auto kind = builtInLiveSources()->find( "adb" );
        REQUIRE( kind );
        REQUIRE( kind->displayName() == "Android" );
    }
}

SCENARIO( "The Android source's failures come with what to do", "[adb_source]" )
{
    const AdbSourceKind kind( AdbPrograms{} );
    REQUIRE( kind.explainFailure( "adb: error: device unauthorized.\nThis adb server's "
                                  "$ADB_VENDOR_KEYS is not set" )
             == adbAuthorizeGuidance() );
    REQUIRE( kind.explainFailure( "adb: device 'R58' not found" ) == adbConnectGuidance() );
    REQUIRE( kind.explainFailure( "adb: error: no devices/emulators found" )
             == adbConnectGuidance() );
    REQUIRE( kind.explainFailure( "error: device offline" ) == adbConnectGuidance() );
    REQUIRE( kind.explainFailure( "R58 gives adb no root, which capturing needs" )
             == adbRootGuidance() );
    REQUIRE( kind.explainFailure( "tcpdump: socket: Operation not permitted" )
             == adbRootGuidance() );
    REQUIRE( kind.explainFailure( "tcpdump was not found on R58" ) == adbTcpdumpGuidance() );
    REQUIRE( kind.explainFailure( "/system/bin/sh: tcpdump: inaccessible or not found" )
             == adbTcpdumpGuidance() );
    REQUIRE( kind.explainFailure( "tcpdump: syntax error in filter expression" ).isEmpty() );

    THEN( "the guidance names adb root, su, a static tcpdump, USB debugging" )
    {
        REQUIRE( adbRootGuidance().contains( "adb root" ) );
        REQUIRE( adbRootGuidance().contains( "never runs it" ) );
        REQUIRE( adbRootGuidance().contains( "userdebug" ) );
        REQUIRE( adbRootGuidance().contains( "Magisk" ) );
        REQUIRE( adbTcpdumpGuidance().contains( "adb push tcpdump /data/local/tmp/" ) );
        REQUIRE( adbConnectGuidance().contains( "USB debugging" ) );
        REQUIRE( adbInstallHint().contains( "Platform-Tools" ) );
    }
}

#ifdef Q_OS_UNIX

namespace {

/// Write @p body as the executable script @p path.
void writeScript( const QString& path, const QString& body )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( ( "#!/bin/sh\n" + body + "\n" ).toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
}

/// The text of the file @p path, empty if there is none.
QString readText( const QString& path )
{
    QFile file( path );
    return file.open( QIODevice::ReadOnly ) ? QString::fromUtf8( file.readAll() ) : QString();
}

/// The bytes of the file @p path.
Bytes readBytes( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto data = file.readAll();
    return Bytes( data.begin(), data.end() );
}

/// A UDP datagram whose payload holds CR, LF and CR LF, as a pty would mangle.
Bytes crlfCapture()
{
    return pcapOf(
        { eth( EthertypeIpv4,
               ipv4( IpProtoUdp, udp( 40000, 9999, text( "a\r\nb\nc\rd\n\r\x1a" ) ) ) ),
          eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999, text( "\r\n" ) ) ) ) } );
}

/**
 * A fake adb in a directory of its own, and its "device": `shell` and
 * `exec-out` run their command line with this computer's /bin/sh, with
 * PATH the device's directory alone (fake id, ip, su and tcpdump, and the
 * cat, rm and sleep of this computer), as adbd runs it with the device's
 * shell.  exec-out runs it in a process group of its own, as a device's
 * tcpdump is not ended with the local adb.  adb logs each call, the
 * device's tcpdump its arguments and a kill.
 */
struct FakeAdb {
    QTemporaryDir dir;
    QString serial = "emulator-5554";

    FakeAdb()
    {
        REQUIRE( dir.isValid() );
        REQUIRE( QDir( dir.path() ).mkpath( "device" ) );
        REQUIRE( QDir( dir.path() ).mkpath( "tmp" ) );
        const auto perl = QStandardPaths::findExecutable( "perl" );
        REQUIRE_FALSE( perl.isEmpty() );
        // A call's line is written at once: calls that run together (a
        // listing while a capture starts) do not mix their lines.
        writeScript( path( "adb" ),
                     QString( "d='%1'\n"
                              "l=; for a in \"$@\"; do l=\"$l[$a]\"; done\n"
                              "printf '%s\\n' \"$l\" >>\"$d/adb.log\"\n"
                              "if [ \"$1\" = -s ]; then\n"
                              "  if [ ! -f \"$d/serial-$2\" ]; then\n"
                              "    echo \"adb: device '$2' not found\" >&2; exit 1\n"
                              "  fi\n"
                              "  shift 2\n"
                              "fi\n"
                              "PATH=\"$d/device\"; export PATH\n"
                              "case \"$1\" in\n"
                              "devices) /bin/cat \"$d/devices.txt\"; exit 0 ;;\n"
                              "shell) exec /bin/sh -c \"$2\" ;;\n"
                              "exec-out) '%2' -e 'setpgrp(0,0); exec @ARGV or die' /bin/sh -c "
                              "\"$2\" &\n"
                              "  wait $!; exit 0 ;;\n"
                              "esac\n"
                              "echo \"adb: unknown command $1\" >&2; exit 1" )
                         .arg( dir.path(), perl ) );
        writeFile( path( "devices.txt" ),
                   text( "List of devices attached\n" + serial.toStdString()
                         + "\tdevice product:sdk model:Pixel_Emu device:emu64a\n" ) );
        writeFile( path( "serial-" + serial ), {} );
        for ( const auto* tool : { "cat", "rm", "sleep" } ) {
            const auto found = QStandardPaths::findExecutable( tool );
            REQUIRE_FALSE( found.isEmpty() );
            REQUIRE( QFile::link( found, path( QString( "device/" ) + tool ) ) );
        }
        writeScript( path( "device/id" ),
                     QString( "if [ -n \"$FAKE_ROOT\" ] || [ -f '%1/adb-root' ]; then u=0; else "
                              "u=2000; fi\n"
                              "if [ \"$1\" = -u ]; then echo $u; else echo \"uid=$u\"; fi" )
                         .arg( dir.path() ) );
        writeScript( path( "device/ip" ),
                     "echo '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue'\n"
                     "echo '3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq'\n"
                     "echo '9: eth0@if10: <BROADCAST,UP> mtu 1500'" );
        writeFile( path( "capture.pcap" ), crlfCapture() );
    }

    QString path( const QString& name ) const
    {
        return dir.filePath( name );
    }

    /// adbd runs as root, as after `adb root`.
    void adbRoot()
    {
        writeFile( path( "adb-root" ), {} );
    }

    /// su gives root to whoever asks, as a su manager that granted the shell.
    void suGrants()
    {
        writeScript( path( "device/su" ),
                     "[ \"$1\" = -c ] || exit 1\nFAKE_ROOT=1 exec /bin/sh -c \"$2\"" );
    }

    /// su refuses, as a su manager that denied the shell.
    void suDenies()
    {
        writeScript( path( "device/su" ), "echo 'Permission denied' >&2; exit 1" );
    }

    /// The device's tcpdump: logs its arguments (and whether it runs as
    /// root), writes the capture and, if @p hang, runs until it is killed.
    void tcpdump( bool hang = false )
    {
        writeScript( path( "device/tcpdump" ),
                     QString( "d='%1'\n"
                              "{ echo \"run uid=$(id -u)\"; for a in \"$@\"; do "
                              "printf '[%s]\\n' \"$a\"; done; } >>\"$d/tcpdump.log\"\n"
                              "trap 'echo killed >>\"$d/tcpdump.log\"; exit 0' TERM\n"
                              "echo 'tcpdump: listening on wlan0' >&2\n"
                              "cat \"$d/capture.pcap\"\n"
                              "%2" )
                         .arg( dir.path(), hang ? "while :; do sleep 0.05; done" : "" ) );
    }

    /// A device's tcpdump that fails with @p message.
    void failingTcpdump( const QString& message )
    {
        writeScript( path( "device/tcpdump" ), QString( "echo '%1' >&2; exit 1" ).arg( message ) );
    }

    /// The Android source with this adb, and the device's files in tmp/.
    std::shared_ptr<AdbSourceKind> kind() const
    {
        AdbPrograms where;
        where.os = CaptureOs::Linux;
        where.searchPath = { dir.path() };
        where.deviceTempDir = path( "tmp" );
        return std::make_shared<AdbSourceKind>( where );
    }

    QString adbLog() const
    {
        return readText( path( "adb.log" ) );
    }

    /// The adb calls that captured.
    QString captures() const
    {
        QStringList lines = adbLog().split( '\n' );
        lines = lines.filter( "[exec-out]" );
        return lines.join( '\n' );
    }

    QString tcpdumpLog() const
    {
        return readText( path( "tcpdump.log" ) );
    }

    /// The capture's files left on the device.
    QStringList deviceFiles() const
    {
        return QDir( path( "tmp" ) ).entryList( QDir::Files );
    }
};

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( std::shared_ptr<const LiveSourceKind> kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( std::move( kind ) );
    return registry;
}

/// A sidebar capturing with the Android source of @p adb, below @p tempRoot.
std::unique_ptr<SidebarWidget> sidebarFor( const FakeAdb& adb, const QTemporaryDir& tempRoot )
{
    auto sidebar = std::make_unique<SidebarWidget>();
    sidebar->setTempRoot( tempRoot.path() );
    sidebar->setLiveSources( registryOf( adb.kind() ) );
    REQUIRE( waitFor( [ & ] { return !sidebar->liveForm()->isListing(); } ) );
    return sidebar;
}

} // namespace

SCENARIO( "adb is found on PATH, below ANDROID_HOME, or not at all", "[adb_source]" )
{
    QTemporaryDir sdk;
    REQUIRE( QDir( sdk.path() ).mkpath( "platform-tools" ) );

    GIVEN( "an SDK in ANDROID_HOME" )
    {
        const auto before = qgetenv( "ANDROID_HOME" );
        qputenv( "ANDROID_HOME", sdk.path().toUtf8() );
        auto where = AdbPrograms::forThisComputer();
        if ( before.isNull() ) {
            qunsetenv( "ANDROID_HOME" );
        }
        else {
            qputenv( "ANDROID_HOME", before );
        }

        THEN( "its platform-tools come first after PATH" )
        {
            REQUIRE( where.installed.value( 0 )
                     == QDir( sdk.path() ).filePath( "platform-tools" ) );
            REQUIRE( where.deviceTempDir == "/data/local/tmp" );
        }

        AND_WHEN( "adb is there" )
        {
            writeScript( sdk.filePath( "platform-tools/adb" ), "exit 0" );
            where.searchPath.clear();
            const AdbSourceKind kind( where );

            THEN( "it is used" )
            {
                REQUIRE( kind.adb() == sdk.filePath( "platform-tools/adb" ) );
                REQUIRE( kind.availability().available );
            }
        }
    }

    GIVEN( "no adb anywhere" )
    {
        AdbPrograms where;
        where.searchPath = { sdk.path() };
        where.installed = { sdk.filePath( "platform-tools" ) };
        const AdbSourceKind kind( where );

        THEN( "the source is unavailable, and says where to get adb" )
        {
            const auto availability = kind.availability();
            REQUIRE_FALSE( availability.available );
            REQUIRE( availability.reason == adbInstallHint() );
            REQUIRE( kind.listDevices( LiveSourceKind::kListTimeout ).error == adbInstallHint() );
        }
    }
}

SCENARIO( "The Android source lists devices and interfaces, and finds root and tcpdump",
          "[adb_source]" )
{
    FakeAdb adb;
    const auto kind = adb.kind();
    REQUIRE( kind->availability().available );

    THEN( "the devices are adb's, an unauthorized one with what to do" )
    {
        writeFile( adb.path( "devices.txt" ),
                   text( "List of devices attached\nemulator-5554\tdevice model:Pixel_Emu\n"
                         "R58\tunauthorized usb:1-1\n" ) );
        const auto listing = kind->listDevices( LiveSourceKind::kListTimeout );
        REQUIRE( listing.error.isEmpty() );
        REQUIRE( listing.targets.size() == 2 );
        REQUIRE( listing.targets[ 0 ].description == "Pixel Emu" );
        REQUIRE( listing.targets[ 1 ].problem.startsWith( "unauthorized" ) );
        REQUIRE( adb.adbLog().contains( "[devices][-l]" ) );
    }

    THEN( "no device at all says how to connect one" )
    {
        writeFile( adb.path( "devices.txt" ), text( "List of devices attached\n\n" ) );
        const auto listing = kind->listDevices( LiveSourceKind::kListTimeout );
        REQUIRE( listing.targets.empty() );
        REQUIRE( listing.error.contains( "No Android device found" ) );
        REQUIRE( listing.error.contains( adbConnectGuidance() ) );
    }

    GIVEN( "adbd running as root and tcpdump on the device" )
    {
        adb.adbRoot();
        adb.tcpdump();

        THEN( "the interfaces are listed after any, without an error" )
        {
            const auto listing = kind->listInterfaces( adb.serial, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.isEmpty() );
            REQUIRE( listing.targets.size() == 4 );
            REQUIRE( listing.targets[ 0 ].id == "any" );
            REQUIRE( listing.targets[ 1 ].id == "lo" );
            REQUIRE( listing.targets[ 2 ].id == "wlan0" );
            REQUIRE( listing.targets[ 3 ].id == "eth0" );
            const auto access = kind->probe( adb.serial, false, LiveSourceKind::kListTimeout );
            REQUIRE( access.root );
            REQUIRE_FALSE( access.su );
            REQUIRE( access.tcpdump == adb.path( "device/tcpdump" ) );
            REQUIRE( access.interfaces.empty() );
        }
    }

    GIVEN( "a shell user and a su that grants root" )
    {
        adb.suGrants();
        adb.tcpdump();

        THEN( "root is had through su" )
        {
            const auto access = kind->probe( adb.serial, true, LiveSourceKind::kListTimeout );
            REQUIRE_FALSE( access.root );
            REQUIRE( access.su );
            REQUIRE(
                kind->listInterfaces( adb.serial, LiveSourceKind::kListTimeout ).error.isEmpty() );
        }
    }

    GIVEN( "a shell user and a su that denies" )
    {
        adb.suDenies();
        adb.tcpdump();

        THEN( "there is no root, and the listing says what to do" )
        {
            const auto access = kind->probe( adb.serial, true, LiveSourceKind::kListTimeout );
            REQUIRE_FALSE( access.root );
            REQUIRE_FALSE( access.su );
            const auto listing = kind->listInterfaces( adb.serial, LiveSourceKind::kListTimeout );
            REQUIRE( listing.targets.size() == 4 );
            REQUIRE( listing.error.contains( "no root" ) );
            REQUIRE( listing.error.contains( adbRootGuidance() ) );
        }
    }

    GIVEN( "a shell user without su" )
    {
        adb.tcpdump();

        THEN( "there is no root" )
        {
            const auto access = kind->probe( adb.serial, false, LiveSourceKind::kListTimeout );
            REQUIRE_FALSE( access.root );
            REQUIRE_FALSE( access.su );
        }
    }

    GIVEN( "root but no tcpdump on the device" )
    {
        adb.adbRoot();

        THEN( "the listing says how to push one" )
        {
            const auto listing = kind->listInterfaces( adb.serial, LiveSourceKind::kListTimeout );
            REQUIRE( listing.error.contains( "tcpdump was not found" ) );
            REQUIRE( listing.error.contains( adbTcpdumpGuidance() ) );
        }

        AND_WHEN( "one was pushed to the device's temporary directory" )
        {
            writeScript( adb.path( "tmp/tcpdump" ), "exit 0" );

            THEN( "it is found there" )
            {
                REQUIRE( kind->probe( adb.serial, false, LiveSourceKind::kListTimeout ).tcpdump
                         == adb.path( "tmp/tcpdump" ) );
            }
        }
    }

    THEN( "a device adb does not know says how to connect one" )
    {
        const auto listing = kind->listInterfaces( "gone", LiveSourceKind::kListTimeout );
        REQUIRE( listing.targets.empty() );
        REQUIRE( listing.error.contains( "device 'gone' not found" ) );
        REQUIRE( listing.error.contains( adbConnectGuidance() ) );
    }
}

SCENARIO( "A shell word is quoted so that the device's shell reads it as it is", "[adb_source]" )
{
    QTemporaryDir dir;
    const auto marker = dir.filePath( "pwned" );
    for ( const QString word :
          { QString( "plain" ), QString( "it's" ), QString( "'" ), QString( "''" ),
            QString( "$(touch %1)" ).arg( marker ), QString( "`touch %1`" ).arg( marker ),
            QString( "a; touch %1; b" ).arg( marker ),
            QString( "x' ; touch %1 ; echo '" ).arg( marker ),
            QString( "\"$HOME\" \\ * ? ~ & | > <" ), QString() } ) {
        CAPTURE( word );
        QProcess shell;
        shell.start( "/bin/sh", { "-c", "printf '%s' " + shellQuote( word ) } );
        REQUIRE( shell.waitForFinished() );
        REQUIRE( QString::fromUtf8( shell.readAllStandardOutput() ) == word );
        REQUIRE_FALSE( QFileInfo::exists( marker ) );
    }
}

SCENARIO( "The Android source captures live through a fake adb", "[adb_source]" )
{
    FakeHost host;
    FakeAdb adb;
    QTemporaryDir tempRoot;
    const LiveChoice choice{ "adb", adb.serial, "wlan0", "udp port 9999", 4096 };

    for ( const auto how : { "adb root", "su" } ) {
        CAPTURE( how );
        const bool viaSu = QString( how ) == "su";
        GIVEN( QString( "root through %1" ).arg( how ).toStdString() )
        {
            if ( viaSu ) {
                adb.suGrants();
            }
            else {
                adb.adbRoot();
            }
            adb.tcpdump();
            auto sidebar = sidebarFor( adb, tempRoot );
            REQUIRE( sidebar->startLiveCapture( choice ) );
            REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

            THEN( "the capture comes binary-clean through exec-out, CR and LF as they were" )
            {
                INFO( sidebar->findChild<QLabel*>( "liveError" )->text().toStdString() );
                REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
                REQUIRE( host.openedFiles.size() == 1 );
                const QFileInfo log( host.openedFiles.first() );
                REQUIRE( log.fileName() == "emulator-5554-wlan0.log" );
                REQUIRE( readBytes( log.dir().filePath( "emulator-5554-wlan0.pcap" ) )
                         == crlfCapture() );
                REQUIRE( adb.adbLog().contains( "[-s][emulator-5554][exec-out]" ) );
            }

            THEN( "tcpdump ran as root on the device, the filter one argument" )
            {
                const auto run = adb.tcpdumpLog();
                REQUIRE( run.contains( "run uid=0" ) );
                REQUIRE( run.contains( "[-i]\n[wlan0]\n[-s]\n[4096]\n[-U]\n[-w]\n[-]\n"
                                       "[udp port 9999]\n" ) );
                INFO( adb.adbLog().toStdString() );
                REQUIRE( adb.captures().contains( "su -c" ) == viaSu );
            }

            THEN( "tcpdump ended by itself, so nothing was killed, and its files are gone" )
            {
                REQUIRE( waitFor( [ & ] { return adb.deviceFiles().isEmpty(); } ) );
                REQUIRE_FALSE( adb.tcpdumpLog().contains( "killed" ) );
            }
        }
    }
}

SCENARIO( "A hostile capture filter reaches the device's tcpdump as one argument", "[adb_source]" )
{
    FakeHost host;
    FakeAdb adb;
    QTemporaryDir tempRoot;
    const auto marker = adb.path( "pwned" );
    const auto filter = QString( "host 10.0.0.1 or x' ; touch %1 ; echo 'y or $(touch %1) or "
                                 "`touch %1` or \"; touch %1\" or \\' ; touch %1" )
                            .arg( marker );
    REQUIRE( captureFilterProblem( filter ).isEmpty() );

    for ( const auto viaSu : { false, true } ) {
        CAPTURE( viaSu );
        if ( viaSu ) {
            adb.suGrants();
        }
        else {
            adb.adbRoot();
        }
        adb.tcpdump();
        QFile::remove( adb.path( "tcpdump.log" ) );
        auto sidebar = sidebarFor( adb, tempRoot );
        REQUIRE( sidebar->startLiveCapture( { "adb", adb.serial, "wlan0", filter, 96 } ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        REQUIRE( adb.tcpdumpLog().contains( "[-]\n[" + filter + "]\n" ) );
        REQUIRE_FALSE( QFileInfo::exists( marker ) );
        QFile::remove( adb.path( "adb-root" ) );
        sidebar.reset();
    }
}

SCENARIO( "Stop ends tcpdump on the device, not only the local adb", "[adb_source]" )
{
    FakeHost host;
    FakeAdb adb;
    QTemporaryDir tempRoot;

    for ( const auto viaSu : { false, true } ) {
        CAPTURE( viaSu );
        if ( viaSu ) {
            adb.suGrants();
        }
        else {
            adb.adbRoot();
        }
        adb.tcpdump( true );
        QFile::remove( adb.path( "tcpdump.log" ) );
        host.openedFiles.clear();
        auto sidebar = sidebarFor( adb, tempRoot );
        REQUIRE( sidebar->startLiveCapture( { "adb", adb.serial, "any", "", 96 } ) );
        const auto* error = sidebar->findChild<QLabel*>( "liveError" );
        REQUIRE( waitFor( [ & ] { return host.openedFiles.size() == 1 || !error->isHidden(); } ) );
        INFO( error->text().toStdString() );
        REQUIRE( host.openedFiles.size() == 1 );
        REQUIRE( waitFor( [ & ] { return adb.deviceFiles().size() == 2; } ) ); // pid, stderr

        sidebar->stopLiveCapture();
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );
        REQUIRE( waitFor( [ & ] { return adb.tcpdumpLog().contains( "killed" ); } ) );
        REQUIRE( adb.adbLog().contains( "kill $p" ) );
        REQUIRE( adb.adbLog().contains( "su -c ': >" ) == viaSu );
        REQUIRE( waitFor( [ & ] { return adb.deviceFiles().isEmpty(); } ) );
        INFO( sidebar->findChild<QLabel*>( "liveError" )->text().toStdString() );
        REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
        QFile::remove( adb.path( "adb-root" ) );
        sidebar.reset();
    }
}

SCENARIO( "A Stop before tcpdump has left its pid still ends it", "[adb_source]" )
{
    FakeAdb adb;
    adb.adbRoot();
    adb.tcpdump( true );
    const auto kind = adb.kind();
    AdbDeviceAccess access;
    access.root = true;
    access.tcpdump = "tcpdump";
    const auto files = AdbCaptureFiles::of( adb.path( "tmp" ), "race" );
    const auto capture
        = kind->captureCommand( { "adb", adb.serial, "any", "", 96 }, access, "race" );
    const auto shell = [ & ]( const QStringList& arguments ) {
        QProcess process;
        process.start( adb.path( "adb" ), arguments );
        REQUIRE( process.waitForStarted( 5000 ) );
        return process.waitForFinished( 10000 );
    };

    GIVEN( "a Stop that comes before the capture's script has left the pid" )
    {
        REQUIRE( shell( { "-s", adb.serial, "shell", adbStopScript( files ) } ) );

        WHEN( "the script runs after it" )
        {
            const bool ended = shell( capture.arguments );

            THEN( "it ends its tcpdump itself, and leaves no file behind" )
            {
                // It waits for tcpdump, which would otherwise run until killed.
                REQUIRE( ended );
                REQUIRE( waitFor( [ & ] { return adb.deviceFiles().isEmpty(); } ) );
            }
        }
    }

    THEN( "a capture that ended by itself is cleaned up without a stop mark" )
    {
        REQUIRE( adbCleanupScript( files ).contains( "rm -f" ) );
        REQUIRE_FALSE( adbCleanupScript( files ).contains( ": >" ) );
    }
}

SCENARIO( "A capture the device cannot make says why, and what to do", "[adb_source]" )
{
    FakeHost host;
    FakeAdb adb;
    QTemporaryDir tempRoot;
    const LiveChoice choice{ "adb", adb.serial, "wlan0", "", 96 };

    GIVEN( "no root" )
    {
        adb.suDenies();
        adb.tcpdump();
        auto sidebar = sidebarFor( adb, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "it fails before tcpdump runs, with the guidance for root" )
        {
            const auto text = sidebar->findChild<QLabel*>( "liveError" )->text();
            REQUIRE( text.contains( "no root" ) );
            REQUIRE( text.contains( adbRootGuidance().left( 40 ).toHtmlEscaped() ) );
            REQUIRE( adb.tcpdumpLog().isEmpty() );
            REQUIRE_FALSE( adb.adbLog().contains( "exec-out" ) );
        }
    }

    GIVEN( "a tcpdump on the device that fails" )
    {
        adb.adbRoot();
        adb.failingTcpdump( "tcpdump: wlan0: No such device exists" );
        auto sidebar = sidebarFor( adb, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "its stderr on the device is the error, and its files are gone" )
        {
            REQUIRE( sidebar->findChild<QLabel*>( "liveError" )
                         ->text()
                         .contains( "No such device exists" ) );
            REQUIRE( host.openedFiles.isEmpty() );
            REQUIRE( waitFor( [ & ] { return adb.deviceFiles().isEmpty(); } ) );
        }
    }

    GIVEN( "a device that went away" )
    {
        adb.adbRoot();
        adb.tcpdump();
        auto sidebar = sidebarFor( adb, tempRoot );
        QFile::remove( adb.path( "serial-" + adb.serial ) );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "adb's error comes with how to connect it" )
        {
            const auto text = sidebar->findChild<QLabel*>( "liveError" )->text();
            REQUIRE( text.contains( "not found" ) );
            REQUIRE( text.contains( adbConnectGuidance().left( 40 ).toHtmlEscaped() ) );
        }
    }
}

#endif
