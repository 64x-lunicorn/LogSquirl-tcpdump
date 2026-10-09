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
 * @file live_capture_test.cpp
 * @brief BDD tests for a live capture in the sidebar: its tab, its summary,
 *        its progress, Stop and Save capture….
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "live_capture.h"
#include "packet_panel.h"
#include "pcapbuilder.h"
#include "sidebarwidget.h"
#include "stream_capture.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A UDP datagram of conversation @p i.
Bytes datagram( int i )
{
    return eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( static_cast<uint16_t>( 40000 + i ), 9999,
                                                      text( "live" ) ) ) );
}

/// The bytes of the file @p path.
QByteArray fileContent( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return file.readAll();
}

QByteArray asByteArray( const Bytes& bytes )
{
    return QByteArray( reinterpret_cast<const char*>( bytes.data() ),
                       static_cast<qsizetype>( bytes.size() ) );
}

/// A source factory that hands out @p source, made by the test.
LiveCapture::SourceFactory
factoryOf( std::function<std::unique_ptr<ByteSource>( const std::atomic_bool* stop )> make )
{
    return [ make ]( const std::atomic_bool* stop, std::function<void( const QString& )> ) {
        return make( stop );
    };
}

} // namespace

SCENARIO( "The progress of a live capture is packets, bytes, packets/s and elapsed time",
          "[live_capture]" )
{
    LiveSnapshot snapshot;
    snapshot.summary.packets = 1234;
    snapshot.summary.bytes = 2048;
    snapshot.elapsed = std::chrono::milliseconds( 2000 );
    const auto text = liveProgressText( snapshot, 83000 );
    REQUIRE( text.contains( "Packets: " + QLocale().toString( 1234 ) ) );
    REQUIRE( text.contains( "Bytes: 2.0 KB" ) );
    REQUIRE( text.contains( "617.0 packets/s" ) );
    REQUIRE( text.contains( "Elapsed 1:23" ) );
    REQUIRE_FALSE( text.contains( "%" ) );
    REQUIRE( liveProgressText( {}, 3723000 ).contains( "Elapsed 1:02:03" ) );
}

#ifdef Q_OS_UNIX

SCENARIO( "A live capture opens its tab once a packet line is there, and Stop finalises it",
          "[live_capture]" )
{
    GIVEN( "the sidebar capturing from a pipe" )
    {
        FakeHost host;
        QTemporaryDir root;
        SidebarWidget sidebar;
        sidebar.setTempRoot( root.path() );
        auto pipe = std::make_shared<Pipe>();
        REQUIRE( sidebar.startLiveCapture(
            "eth0", factoryOf( [ pipe ]( const std::atomic_bool* stop ) {
                return std::make_unique<FdSource>( pipe->readEnd(), stop );
            } ) ) );
        auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
        auto* stop = sidebar.findChild<QPushButton*>( "stopButton" );
        auto* summary = sidebar.findChild<QLabel*>( "summary" );
        REQUIRE( sidebar.isCapturing() );
        REQUIRE( stop->isVisibleTo( &sidebar ) );
        REQUIRE( live->isVisibleTo( &sidebar ) );
        REQUIRE_FALSE( sidebar.findChild<QProgressBar*>( "progress" )->isVisibleTo( &sidebar ) );
        REQUIRE_FALSE( sidebar.startLiveCapture( "again", {} ) );
        REQUIRE( host.notifications.size() == 1 );
        host.notifications.clear();

        const auto header = pcapOf( {} );
        const auto whole = pcapOf( { datagram( 0 ), datagram( 1 ) } );
        const Bytes first( whole.begin(),
                           whole.begin() + 24 + 16
                               + static_cast<std::ptrdiff_t>( datagram( 0 ).size() ) );
        const Bytes second( whole.begin() + static_cast<std::ptrdiff_t>( first.size() ),
                            whole.end() );

        WHEN( "only the header has come" )
        {
            pipe->write( header );
            QElapsedTimer quiet;
            quiet.start();
            waitFor( [ & ] { return quiet.elapsed() > 300; } );

            THEN( "no tab is opened yet" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( summary->text().contains( "waiting for the first packet" ) );
            }
        }

        WHEN( "the header and a packet have come" )
        {
            pipe->write( first );
            REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
            const auto logPath = host.openedFiles.first();
            sidebar.showSummaryFor( logPath ); // the host brings the new tab to the front

            THEN( "its tab is opened once, following the file, on the UI thread" )
            {
                REQUIRE( host.openedFiles.size() == 1 );
                REQUIRE( host.openedFollowing == QList<bool>{ true } );
                REQUIRE_FALSE( host.openedOffUiThread );
                REQUIRE( QFileInfo( logPath ).fileName() == "eth0.log" );
                REQUIRE( readLines( logPath ).size() == 2 );
            }

            THEN( "the sidebar shows the summary so far and the progress, no percentage" )
            {
                REQUIRE( waitFor( [ & ] { return live->text().contains( "Packets: 1" ); } ) );
                REQUIRE( live->text().contains( "packets/s" ) );
                REQUIRE( live->text().contains( "Elapsed" ) );
                REQUIRE( summary->text().contains( "Capturing" ) );
                REQUIRE( summary->text().contains( "eth0.pcap" ) );
            }

            THEN( "the Packet Panel shows a selected packet while the capture runs" )
            {
                sidebar.show();
                auto* panel = sidebar.packetPanel();
                host.selectedLines = { readLines( logPath ).at( 1 ) };
                panel->refresh();
                REQUIRE( waitFor( [ & ] { return panel->shownPacket() == 1; } ) );

                AND_WHEN( "another packet comes and the capture is stopped" )
                {
                    pipe->write( second );
                    REQUIRE( waitFor( [ & ] { return readLines( logPath ).size() == 3; } ) );
                    stop->click();
                    REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

                    THEN( "it shows that packet too, from the final index" )
                    {
                        host.selectedLines = { readLines( logPath ).at( 2 ) };
                        panel->refresh();
                        REQUIRE( waitFor( [ & ] { return panel->shownPacket() == 2; } ) );
                        REQUIRE( panel->statusText() == "Packet 2" );
                    }
                }
            }

            AND_WHEN( "another packet comes and Stop is pressed" )
            {
                pipe->write( second );
                REQUIRE( waitFor( [ & ] { return readLines( logPath ).size() == 3; } ) );
                QElapsedTimer stopping;
                stopping.start();
                stop->click();
                REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
                const auto took = stopping.elapsed();

                THEN( "it ends within a second with the final summary, and nothing else opens" )
                {
                    REQUIRE( took < 1000 );
                    REQUIRE( host.openedFiles.size() == 1 );
                    REQUIRE( stop->isHidden() );
                    REQUIRE_FALSE( summary->text().contains( "Capturing" ) );
                    REQUIRE( summary->text().contains( "Packets: <b>2</b>" ) );
                }

                THEN( "Save capture… copies the raw capture, byte for byte" )
                {
                    auto* save = sidebar.findChild<QPushButton*>( "saveCaptureButton" );
                    REQUIRE_FALSE( save->isHidden() );
                    QTemporaryDir saved;
                    const auto target = saved.filePath( "kept.pcap" );
                    QString suggested;
                    sidebar.setSaveChooser( [ & ]( QWidget*, const QString& path ) {
                        suggested = path;
                        return target;
                    } );
                    save->click();
                    REQUIRE( QFileInfo( suggested ).fileName() == "eth0.pcap" );
                    REQUIRE( fileContent( target ) == asByteArray( whole ) );
                }
            }
        }

        WHEN( "Stop is pressed before the header has come" )
        {
            stop->click();
            REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

            THEN( "no tab is opened, it says it was stopped, not failed, and nothing is left" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( host.notifications.isEmpty() );
                REQUIRE( summary->text().contains( "stopped before anything was captured" ) );
                REQUIRE_FALSE( summary->text().contains( "Error" ) );
                REQUIRE(
                    host.logs.join( '\n' ).contains( "stopped before anything was captured" ) );
                REQUIRE( QDir( root.path() ).isEmpty() );
            }
        }

        WHEN( "the stream closes after the header alone" )
        {
            pipe->write( header );
            pipe->closeWrite();
            REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

            THEN( "no tab is opened, it says so, and nothing is left behind" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "without packets" ) );
                REQUIRE( summary->text().contains( "without packets" ) );
                REQUIRE( QDir( root.path() ).isEmpty() );
            }
        }
    }
}

#endif

SCENARIO( "A live capture whose source fails keeps its tab and says why", "[live_capture]" )
{
    FakeHost host;
    QTemporaryDir root;
    SidebarWidget sidebar;
    sidebar.setTempRoot( root.path() );
    const auto capture = pcapOf( { datagram( 0 ), datagram( 1 ), datagram( 2 ) } );
    REQUIRE( sidebar.startLiveCapture( "usb0", factoryOf( [ capture ]( const std::atomic_bool* ) {
                                           return std::make_unique<BreakingSource>(
                                               capture, "tcpdump exited with code 1" );
                                       } ) ) );
    REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
    REQUIRE( host.openedFiles.size() == 1 );
    sidebar.showSummaryFor( host.openedFiles.first() );

    auto* summary = sidebar.findChild<QLabel*>( "summary" );
    REQUIRE( summary->text().contains( "tcpdump exited with code 1" ) );
    REQUIRE( summary->text().contains( "Packets: <b>3</b>" ) );
    REQUIRE( host.notifications.size() == 1 );
    REQUIRE( host.notifications.first().contains( "tcpdump exited with code 1" ) );
    REQUIRE( readLines( host.openedFiles.first() ).size() == 4 );
}

SCENARIO( "A live capture's stderr lines reach the host's log from the UI thread",
          "[live_capture]" )
{
    FakeHost host;
    QTemporaryDir root;
    SidebarWidget sidebar;
    sidebar.setTempRoot( root.path() );
    REQUIRE( sidebar.startLiveCapture(
        "eth1", []( const std::atomic_bool*, std::function<void( const QString& )> onLine ) {
            onLine( "tcpdump: listening on eth1" );
            return std::make_unique<BreakingSource>( Bytes{}, "no capture" );
        } ) );
    REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
    REQUIRE( host.logs.contains( "eth1: tcpdump: listening on eth1" ) );
    REQUIRE( host.openedFiles.isEmpty() );
}
