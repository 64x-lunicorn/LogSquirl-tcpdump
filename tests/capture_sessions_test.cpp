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
 * @file capture_sessions_test.cpp
 * @brief BDD tests for the plugin's sessions and what the user starts them
 *        with, without a sidebar: Open pcap…, Start and Stop live capture,
 *        Export packets… and Save capture….
 */

#include <catch2/catch.hpp>

#include "activity.h"
#include "capture_sessions.h"
#include "fake_live_session.h"
#include "fakehost.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QWidget>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A capture of @p count UDP packets, written as @p name in @p dir.
QString writeCapture( const QTemporaryDir& dir, const QString& name, int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back( eth(
            EthertypeIpv4,
            ipv4( IpProtoUdp, udp( 40000, static_cast<uint16_t>( 1000 + i ), text( "data" ) ) ) ) );
    }
    const auto content = pcapOf( packets );
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( content.data() ),
                static_cast<qint64>( content.size() ) );
    return path;
}

/// A converter that converts, then holds its result until cancelled.
FileConversionSession::Converter heldConverter()
{
    return []( const QString& filePath, const QString& outputRoot, const std::atomic_bool* cancel,
               const std::function<void( int )>&, const ConversionOptions& options ) {
        auto result = convertPcap( filePath, outputRoot, nullptr, {}, options );
        while ( !cancel->load() ) {
            std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        }
        return result;
    };
}

} // namespace

SCENARIO( "Open pcap… asks for a capture and opens it through the File Conversion session",
          "[capture_sessions]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    const auto capture = writeCapture( dir, "small.pcap", 3 );
    QWidget parent;
    sessions.setDialogParent( &parent );
    QWidget* shownOver = nullptr;
    QStringList startedIn;
    sessions.setFileChooser( [ & ]( QWidget* over, const QString& in ) {
        shownOver = over;
        startedIn << in;
        return capture;
    } );

    WHEN( "it is chosen" )
    {
        sessions.chooseAndOpen();

        THEN( "the dialog is shown over the dialog parent, and the capture opened in a tab" )
        {
            REQUIRE( shownOver == &parent );
            REQUIRE( sessions.conversionSession().isBusy() );
            REQUIRE( sessions.runningActivities().converting );
            REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
            REQUIRE( host.openedFiles.size() == 1 );
            REQUIRE( host.openedFollowing == QList<bool>{ false } );
            REQUIRE( sessions.catalog().isFront( host.openedFiles.first() ) );
        }

        AND_WHEN( "it is chosen again" )
        {
            REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
            sessions.chooseAndOpen();

            THEN( "the dialog starts in the directory of the capture opened last" )
            {
                REQUIRE( startedIn.size() == 2 );
                REQUIRE( QDir( startedIn.last() ) == QDir( dir.path() ) );
                REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
            }
        }
    }

    WHEN( "the dialog parent is gone" )
    {
        auto* gone = new QWidget;
        sessions.setDialogParent( gone );
        delete gone;
        sessions.chooseAndOpen();

        THEN( "the dialog is shown over no window" )
        {
            REQUIRE( shownOver == nullptr );
            REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
        }
    }

    WHEN( "no capture is chosen" )
    {
        sessions.setFileChooser( []( QWidget*, const QString& ) { return QString(); } );
        sessions.chooseAndOpen();

        THEN( "nothing is opened" )
        {
            REQUIRE_FALSE( sessions.conversionSession().isBusy() );
            REQUIRE( host.openedFiles.isEmpty() );
        }
    }

    WHEN( "a live capture runs" )
    {
        ScriptedRuns runs;
        sessions.liveSession().setRunFactory( runs.factory() );
        REQUIRE( sessions.liveSession().start( "eth0", {} ) );
        sessions.chooseAndOpen();

        THEN( "only a notification says why, with the Activity rule's reason" )
        {
            REQUIRE( startedIn.isEmpty() );
            REQUIRE( host.notifications
                     == QStringList{ refusalMessage( ActivityRefusal::Capturing ) } );
            REQUIRE_FALSE( sessions.conversionSession().isBusy() );
        }
    }
}

SCENARIO( "Start live capture… starts the choice asked for, one capture at a time",
          "[capture_sessions]" )
{
    QTemporaryDir tempRoot;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    ScriptedRuns runs;
    sessions.liveSession().setRunFactory( runs.factory() );
    auto local = std::make_shared<LiveSourceRegistry>();
    sessions.setLiveSources( local );
    QWidget parent;
    sessions.setDialogParent( &parent );
    int asked = 0;
    int stopsAsked = 0;
    QWidget* askedOver = nullptr;
    bool stopIt = false;
    sessions.setLiveChoiceAsker( [ & ]( QWidget* over, LiveChoice& ) {
        ++asked;
        askedOver = over;
        return false;
    } );
    sessions.setStopConfirmer( [ & ]( QWidget*, const QString& running ) {
        ++stopsAsked;
        REQUIRE( running == "eth0" );
        return stopIt;
    } );

    WHEN( "nothing runs and it is chosen" )
    {
        sessions.chooseAndStartLiveCapture();

        THEN( "the dialog is asked over the dialog parent, and no stop is offered" )
        {
            REQUIRE( asked == 1 );
            REQUIRE( askedOver == &parent );
            REQUIRE( stopsAsked == 0 );
            REQUIRE_FALSE( sessions.liveSession().isBusy() );
        }
    }

    WHEN( "a capture runs and it is chosen" )
    {
        REQUIRE( sessions.liveSession().start( "eth0", {} ) );
        REQUIRE( sessions.runningActivities().capturing );

        AND_WHEN( "the user keeps the running capture" )
        {
            sessions.chooseAndStartLiveCapture();

            THEN( "it runs on, and no dialog is shown" )
            {
                REQUIRE( stopsAsked == 1 );
                REQUIRE( asked == 0 );
                REQUIRE_FALSE( runs.last().stopped );
            }
        }

        AND_WHEN( "the user stops it, but cancels the dialog" )
        {
            stopIt = true;
            sessions.chooseAndStartLiveCapture();

            THEN( "the dialog was asked, and the capture runs on" )
            {
                REQUIRE( stopsAsked == 1 );
                REQUIRE( asked == 1 );
                REQUIRE_FALSE( runs.last().stopped );
                REQUIRE_FALSE( sessions.liveSession().hasPendingStart() );
            }
        }
    }

    WHEN( "a capture file is being read and it is chosen" )
    {
        QTemporaryDir dir;
        sessions.conversionSession().setConverter( heldConverter() );
        REQUIRE( sessions.conversionSession().start( writeCapture( dir, "a.pcap", 1 ) ) );
        sessions.chooseAndStartLiveCapture();

        THEN( "only a notification says why, with the Activity rule's reason" )
        {
            REQUIRE( asked == 0 );
            REQUIRE( host.notifications
                     == QStringList{ refusalMessage( ActivityRefusal::Converting ) } );
            sessions.conversionSession().cancel();
            REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
        }
    }
}

SCENARIO( "Stop live capture stops the running capture, or says none runs", "[capture_sessions]" )
{
    QTemporaryDir tempRoot;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    ScriptedRuns runs;
    sessions.liveSession().setRunFactory( runs.factory() );

    WHEN( "a capture runs" )
    {
        REQUIRE( sessions.liveSession().start( "eth0", {} ) );
        sessions.stopLiveCapture();

        THEN( "it is told to stop" )
        {
            REQUIRE( runs.last().stopped );
            REQUIRE( sessions.liveSession().state() == LiveCaptureSession::State::Stopping );
            REQUIRE( host.notifications.isEmpty() );
        }
    }

    WHEN( "none runs" )
    {
        sessions.stopLiveCapture();

        THEN( "a notification says so" )
        {
            REQUIRE( host.notifications == QStringList{ "No live capture is running." } );
        }
    }
}

SCENARIO( "Export packets… starts the Export session", "[capture_sessions]" )
{
    FakeHost host;
    CaptureSessions sessions;

    WHEN( "the tab in front shows no capture" )
    {
        sessions.exportSelectedPackets();

        THEN( "the Export session refuses it with a notification" )
        {
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().startsWith( "Export packets: the tab in front" ) );
            REQUIRE_FALSE( sessions.runningActivities().exporting );
        }
    }
}

SCENARIO( "Save capture… with nothing to save asks nothing", "[capture_sessions]" )
{
    FakeHost host;
    CaptureSessions sessions;
    int asked = 0;
    sessions.setSaveChooser( [ & ]( QWidget*, const QString& ) {
        ++asked;
        return QString();
    } );
    sessions.saveCapture();
    REQUIRE( asked == 0 );
    REQUIRE( host.notifications.isEmpty() );
}

SCENARIO( "The sessions end with the plugin", "[capture_sessions]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    FakeHost host;
    auto sessions = std::make_unique<CaptureSessions>();
    sessions->setTempRoot( tempRoot.path() );
    sessions->conversionSession().setConverter( heldConverter() );
    REQUIRE( sessions->conversionSession().start( writeCapture( dir, "small.pcap", 3 ) ) );

    WHEN( "they are destroyed while a capture file is being read" )
    {
        sessions.reset();
        QCoreApplication::processEvents();

        THEN( "the conversion is stopped first, no tab is opened, and its directory goes" )
        {
            REQUIRE( host.openedFiles.isEmpty() );
            REQUIRE( QDir( tempRoot.path() ).isEmpty() );
        }
    }
}
