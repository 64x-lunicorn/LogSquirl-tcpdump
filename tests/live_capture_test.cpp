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
 * @brief BDD tests for a live capture through the plugin's sessions, shown
 *        in the sidebar: its tab, its summary, its progress, Stop and Save
 *        capture….
 */

#include <catch2/catch.hpp>

#include "fake_live_source.h"
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
#include <thread>

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

    WHEN( "the capture has stop conditions and a ring buffer" )
    {
        LiveLimits limits;
        limits.duration = std::chrono::seconds( 600 );
        limits.packets = 10000;
        limits.bytes = 4 * 1024;
        limits.ringFiles = 5;
        limits.fileBytes = 1024;
        snapshot.rawBytes = 1024;
        snapshot.rawFile = 7;

        THEN( "it shows how far it is to each, and the ring buffer's file" )
        {
            const auto limited = liveProgressText( snapshot, 150000, limits );
            REQUIRE( limited.contains( "Stops after 10:00 (25%), or at "
                                       + QLocale().toString( 10000 ) + " packets (12%), or at "
                                       + "4.0 KB (25%)" ) );
            REQUIRE( limited.contains( "Ring buffer: file 7, keeping the last 5" ) );
        }
    }
}

SCENARIO( "A live capture that a stop condition ended says which", "[live_capture]" )
{
    LiveLimits limits;
    limits.duration = std::chrono::seconds( 90 );
    limits.packets = 1000;
    limits.bytes = 2 * 1024 * 1024;
    REQUIRE( liveStopText( "eth0", StopCondition::Duration, limits )
             == "The capture eth0 stopped after 1:30, as set." );
    REQUIRE( liveStopText( "eth0", StopCondition::Packets, limits )
             == "The capture eth0 stopped after " + QLocale().toString( 1000 )
                    + " packets, as set." );
    REQUIRE( liveStopText( "eth0", StopCondition::Bytes, limits )
             == "The capture eth0 stopped at 2.0 MB captured, as set." );
    REQUIRE( liveStopText( "eth0", StopCondition::PacketNumbers, limits )
             == "The capture eth0 stopped at packet " + QLocale().toString( 4294967295ull )
                    + ", the last one the No. column can number." );
}

namespace {

/// Hands out its bytes, then, until Stop, writes numbered lines to stderr
/// as fast as it can: "line 0", "line 1", ...
class StderrFloodSource : public ScriptedSource {
public:
    StderrFloodSource( Bytes bytes, const std::atomic_bool* stop,
                       std::function<void( const QString& )> onLine )
        : ScriptedSource( std::move( bytes ), {}, stop )
        , onLine_( std::move( onLine ) )
    {
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override
    {
        const auto got = ScriptedSource::readFor( dst, n, std::chrono::milliseconds( 0 ) );
        if ( got != -1 ) {
            return got;
        }
        Q_UNUSED( timeout );
        for ( int i = 0; i < 1000; ++i ) {
            onLine_( QStringLiteral( "line %1" ).arg( next_++ ) );
        }
        return -1;
    }

private:
    std::function<void( const QString& )> onLine_;
    qint64 next_ = 0;
};

/// What a LiveCapture handed on of its program's stderr: every batch, checked
/// as it comes for numbered lines ("line N", from 0) in order, none lost
/// without being counted.
struct StderrBatches {
    explicit StderrBatches( LiveCapture& capture )
    {
        clock.start();
        QObject::connect( &capture, &LiveCapture::stderrLines, &capture,
                          [ this ]( const QStringList& lines, quint64 dropped ) {
                              ++batches;
                              largest = std::max( largest, lines.size() );
                              this->dropped += dropped;
                              next += static_cast<qint64>( dropped );
                              for ( const auto& line : lines ) {
                                  inOrder
                                      = inOrder && line == QStringLiteral( "line %1" ).arg( next );
                                  ++next;
                              }
                          } );
    }

    QElapsedTimer clock;
    int batches = 0;
    qsizetype largest = 0;
    quint64 dropped = 0;
    qint64 next = 0; ///< The lines handed on or dropped.
    bool inOrder = true;
};

/// Check what @p capture handed on of a program that writes stderr without
/// end, until it has written @p lines, then stop it.
void checkFlood( LiveCapture& capture, StderrBatches& seen, qint64 lines )
{
    REQUIRE( waitFor( [ & ] { return seen.next >= lines; } ) );
    const auto elapsed = seen.clock.elapsed();
    // At most one batch an interval (the count can only come out lower on
    // a slow machine), none larger than kept: the UI thread's queue holds
    // one event for the flood, whatever its rate.
    REQUIRE( seen.batches <= elapsed / LiveCapture::kStderrBatchInterval.count() + 2 );
    REQUIRE( seen.largest <= static_cast<qsizetype>( LiveCapture::kStderrBatchLines ) );
    REQUIRE( seen.dropped > 0 );
    REQUIRE( seen.inOrder );
    capture.stop();
    REQUIRE( waitFor( [ & ] { return capture.isDone(); } ) );
}

} // namespace

SCENARIO( "A capture program printing stderr without end reaches the UI thread in bounded batches",
          "[live_capture]" )
{
    QTemporaryDir root;
    LiveCapture capture(
        "flood", root.path(), {},
        []( const std::atomic_bool* stop, std::function<void( const QString& )> onLine ) {
            return std::make_unique<StderrFloodSource>( pcapOf( { datagram( 0 ) } ), stop,
                                                        std::move( onLine ) );
        } );
    StderrBatches seen( capture );
    capture.start();
    checkFlood( capture, seen, 200000 );
}

#ifdef Q_OS_UNIX

namespace {

/// A source whose end, as a capture program's, takes its time.
class SlowEndingSource : public ScriptedSource {
public:
    SlowEndingSource( Bytes bytes, const std::atomic_bool* stop )
        : ScriptedSource( std::move( bytes ), {}, stop )
    {
    }
    ~SlowEndingSource() override
    {
        std::this_thread::sleep_for( kEnding );
    }

    static constexpr std::chrono::milliseconds kEnding{ 1500 };
};

} // namespace

SCENARIO( "The UI thread never waits for a live capture's source to end", "[live_capture]" )
{
    FakeHost host;
    QTemporaryDir root;
    const auto slow = factoryOf( []( const std::atomic_bool* stop ) {
        return std::make_unique<SlowEndingSource>( pcapOf( { datagram( 0 ) } ), stop );
    } );
    auto sessions = std::make_unique<CaptureSessions>();
    sessions->setTempRoot( root.path() );
    REQUIRE( sessions->liveSession().start( "slow", slow ) );
    REQUIRE( waitFor( [ & ] { return host.openedFiles.size() == 1; } ) );
    sessions->liveSession().stop();
    REQUIRE( waitFor( [ & ] { return !sessions->liveSession().isBusy(); } ) );

    WHEN( "the next capture starts while the last one's source is still ending" )
    {
        QElapsedTimer clock;
        clock.start();
        REQUIRE( sessions->liveSession().start( "next", slow ) );
        const auto took = clock.elapsed();

        THEN( "it starts at once, and the last one ends on its own" )
        {
            REQUIRE( took < 500 );
            REQUIRE( retiredLiveCaptures() == 1 );
            REQUIRE( waitFor( [ & ] { return retiredLiveCaptures() == 0; } ) );
        }
    }

    WHEN( "the plugin's sessions go while the source is still ending" )
    {
        QElapsedTimer clock;
        clock.start();
        sessions.reset();
        const auto took = clock.elapsed();

        THEN( "they go at once; the plugin's shutdown joins the worker" )
        {
            REQUIRE( took < 500 );
            REQUIRE( retiredLiveCaptures() == 1 );
            joinLiveCaptures();
            REQUIRE( retiredLiveCaptures() == 0 );
        }
    }
    sessions.reset();
    joinLiveCaptures();
}

SCENARIO( "A real capture program printing stderr without end is batched and ended",
          "[live_capture]" )
{
    QTemporaryDir root;
    const auto header = root.filePath( "header.pcap" );
    writeFile( header, pcapOf( {} ) );
    const auto program = root.filePath( "flood" );
    {
        QFile file( program );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write(
            "#!/bin/sh\ncat \"$1\"\ni=0\nwhile :; do echo \"line $i\" >&2; i=$((i+1)); done\n" );
        file.close();
        REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner ) );
    }
    LiveCapture capture( "flood", root.path(), {},
                         LiveCapture::processSource( { program, { header } } ) );
    StderrBatches seen( capture );
    capture.start();
    checkFlood( capture, seen, 20000 );
}

SCENARIO( "A live capture opens its tab once a packet line is there, and Stop finalises it",
          "[live_capture]" )
{
    GIVEN( "the sidebar capturing from a pipe" )
    {
        FakeHost host;
        QTemporaryDir root;
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        auto pipe = std::make_shared<Pipe>();
        REQUIRE( sessions.liveSession().start(
            "eth0", factoryOf( [ pipe ]( const std::atomic_bool* stop ) {
                return std::make_unique<FdSource>( pipe->readEnd(), stop );
            } ) ) );
        auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
        auto* stop = sidebar.findChild<QPushButton*>( "stopButton" );
        auto* summary = sidebar.findChild<QLabel*>( "summary" );
        REQUIRE( sessions.liveSession().isBusy() );
        REQUIRE( stop->isVisibleTo( &sidebar ) );
        REQUIRE( live->isVisibleTo( &sidebar ) );
        REQUIRE_FALSE( sidebar.findChild<QProgressBar*>( "progress" )->isVisibleTo( &sidebar ) );
        REQUIRE_FALSE( sessions.liveSession().start( "again", {} ) );
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
            sessions.catalog().setFront( logPath ); // the host brings the new tab to the front

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
                    REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

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
                REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
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
                    sessions.setSaveChooser( [ & ]( QWidget*, const QString& path ) {
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
            REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

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
            REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

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

SCENARIO( "A live capture with a ring buffer opens a tab for each file", "[live_capture]" )
{
    GIVEN( "the sidebar capturing from a pipe into a ring buffer of two files of two packets" )
    {
        FakeHost host;
        QTemporaryDir root;
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        sidebar.show();
        auto pipe = std::make_shared<Pipe>();
        LiveLimits limits;
        limits.ringFiles = 2;
        limits.fileBytes = 24 + 2 * ( 16 + datagram( 0 ).size() );
        REQUIRE( sessions.liveSession().start(
            "eth0", factoryOf( [ pipe ]( const std::atomic_bool* stop ) {
                return std::make_unique<FdSource>( pipe->readEnd(), stop );
            } ),
            limits ) );
        auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
        std::vector<Bytes> packets;
        for ( int i = 0; i < 6; ++i ) {
            packets.push_back( datagram( i ) );
        }
        const auto whole = pcapOf( packets );
        const auto firstEnd = 24 + 16 + static_cast<std::ptrdiff_t>( packets[ 0 ].size() );

        WHEN( "a packet comes and its line is selected" )
        {
            pipe->write( Bytes( whole.begin(), whole.begin() + firstEnd ) );
            REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
            const auto logPath = host.openedFiles.first();
            sessions.catalog().setFront( logPath );
            const auto firstLine = readLines( logPath ).at( 1 );

            AND_WHEN( "five more come, so that its file is deleted, and the capture is stopped" )
            {
                pipe->write( Bytes( whole.begin() + firstEnd, whole.end() ) );
                REQUIRE( waitFor( [ & ] { return live->text().contains( "file 3" ); } ) );
                REQUIRE( waitFor( [ & ] { return host.openedFiles.size() == 3; } ) );
                const auto lastLog = host.openedFiles.last();
                REQUIRE( waitFor( [ & ] { return readLines( lastLog ).size() == 3; } ) );
                sidebar.findChild<QPushButton*>( "stopButton" )->click();
                REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

                THEN( "each file's text is in a tab of its own, followed, opened in order" )
                {
                    REQUIRE( host.openedFollowing == QList<bool>{ true, true, true } );
                    REQUIRE_FALSE( host.openedOffUiThread );
                    for ( int i = 0; i < 3; ++i ) {
                        const auto lines = readLines( host.openedFiles.at( i ) );
                        REQUIRE( lines.size() == 3 );
                        REQUIRE( lines.at( 1 ).startsWith( QString::number( 2 * i + 1 ) + " " ) );
                        REQUIRE( lines.at( 2 ).startsWith( QString::number( 2 * i + 2 ) + " " ) );
                    }
                }

                THEN( "every tab shows the capture's final summary" )
                {
                    auto* summary = sidebar.findChild<QLabel*>( "summary" );
                    for ( const auto& opened : host.openedFiles ) {
                        CAPTURE( opened );
                        sessions.catalog().setFront( opened );
                        REQUIRE( summary->text().contains( "Packets: <b>6</b>" ) );
                    }
                }

                THEN( "the first tab stays as it was; its Packet Panel says rotated away" )
                {
                    REQUIRE( readLines( logPath ).at( 1 ) == firstLine );
                    auto* panel = sidebar.packetPanel();
                    host.selectedLines = { firstLine };
                    panel->refresh();
                    REQUIRE( waitFor(
                        [ & ] { return panel->statusText().contains( "Rotated away" ); } ) );
                    REQUIRE( panel->shownPacket() == 0 );
                }

                THEN( "the last tab's Packet Panel shows its packets" )
                {
                    sessions.catalog().setFront( lastLog );
                    auto* panel = sidebar.packetPanel();
                    host.selectedLines = { readLines( lastLog ).at( 1 ) };
                    panel->refresh();
                    REQUIRE( waitFor( [ & ] { return panel->shownPacket() == 5; } ) );
                }

                THEN( "Save capture… writes the files kept as one capture of packets 3 to 6" )
                {
                    QTemporaryDir saved;
                    const auto target = saved.filePath( "kept.pcap" );
                    QString suggested;
                    sessions.setSaveChooser( [ & ]( QWidget*, const QString& path ) {
                        suggested = path;
                        return target;
                    } );
                    sidebar.findChild<QPushButton*>( "saveCaptureButton" )->click();
                    REQUIRE( QFileInfo( suggested ).fileName() == "eth0.pcap" );
                    const auto third
                        = 24 + 2 * ( 16 + static_cast<std::ptrdiff_t>( packets[ 0 ].size() ) );
                    REQUIRE( fileContent( target )
                             == asByteArray( Bytes( whole.begin(), whole.begin() + 24 )
                                             + Bytes( whole.begin() + third, whole.end() ) ) );
                }
            }
        }
    }
}

#endif

SCENARIO( "A live capture whose source fails keeps its tab and says why", "[live_capture]" )
{
    FakeHost host;
    QTemporaryDir root;
    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sessions.setTempRoot( root.path() );
    const auto capture = pcapOf( { datagram( 0 ), datagram( 1 ), datagram( 2 ) } );
    REQUIRE( sessions.liveSession().start(
        "usb0", factoryOf( [ capture ]( const std::atomic_bool* ) {
            return std::make_unique<BreakingSource>( capture, "tcpdump exited with code 1" );
        } ) ) );
    REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
    REQUIRE( host.openedFiles.size() == 1 );
    sessions.catalog().setFront( host.openedFiles.first() );

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
    CaptureSessions sessions;
    sessions.setTempRoot( root.path() );
    REQUIRE( sessions.liveSession().start(
        "eth1", []( const std::atomic_bool*, std::function<void( const QString& )> onLine ) {
            onLine( "tcpdump: listening on eth1" );
            return std::make_unique<BreakingSource>( Bytes{}, "no capture" );
        } ) );
    REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
    REQUIRE( host.logs.contains( "eth1: tcpdump: listening on eth1" ) );
    REQUIRE( host.openedFiles.isEmpty() );
}
