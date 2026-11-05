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
 * @file host_converter_test.cpp
 * @brief BDD tests for converting a capture LogSquirl opened itself: what
 *        convertForHost() writes into the host's file, what it tells the
 *        host's control and the sink, and what it leaves behind; which files
 *        the plugin's converter entry points take, and the catalog entry the
 *        tab LogSquirl opens finds.
 *
 * The host's control is a fake that records the thread each call came on:
 * the API allows the thread convert_ex() runs on only.
 */

#include <catch2/catch.hpp>

#include "capture_sessions.h"
#include "fakehost.h"
#include "host_converter.h"
#include "pcapbuilder.h"
#include "settings.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

extern "C" {
int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
const char* logsquirl_converter_get_extensions( void );
int logsquirl_converter_convert_ex( const char* input_path, const char* output_path,
                                    const LogSquirlConvertControl* control );
int logsquirl_converter_convert( const char* input_path, const char* output_path );
int logsquirl_converter_claims( const char* file_path, const unsigned char* head,
                                size_t head_length );
}

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr auto kHangGuard = std::chrono::seconds( 60 );

/// The file @p name in @p dir, holding @p content.
QString writeFile( const QTemporaryDir& dir, const QString& name, const Bytes& content )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( content.data() ),
                static_cast<qint64>( content.size() ) );
    return path;
}

/// A capture of @p count UDP packets.
Bytes captureOf( int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back(
            eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 53, text( "x" ) ) ) ) );
    }
    return pcapOf( packets );
}

/// The lines of the text file @p path.
QStringList linesOf( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    return QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
}

/// The entries of @p dir, but . and ..
QStringList entriesOf( const QTemporaryDir& dir )
{
    return QDir( dir.path() ).entryList( QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden );
}

/// The host's control, recording what it was told and on which thread.
struct FakeControl {
    std::atomic_bool cancelled{ false };
    std::mutex mutex;
    std::vector<std::pair<uint64_t, uint64_t>> progress;
    std::vector<std::thread::id> threads;

    HostConvertControl control()
    {
        HostConvertControl c;
        c.reportProgress = [ this ]( uint64_t done, uint64_t total ) {
            const std::lock_guard<std::mutex> lock( mutex );
            progress.emplace_back( done, total );
            threads.push_back( std::this_thread::get_id() );
        };
        c.isCancelled = [ this ] {
            const std::lock_guard<std::mutex> lock( mutex );
            threads.push_back( std::this_thread::get_id() );
            return cancelled.load();
        };
        return c;
    }

    bool onlyOn( std::thread::id thread )
    {
        const std::lock_guard<std::mutex> lock( mutex );
        for ( const auto& t : threads ) {
            if ( t != thread ) {
                return false;
            }
        }
        return !threads.empty();
    }
};

/// What the sink was handed.
struct Kept {
    int calls = 0;
    QString logPath;
    QString capturePath;
    CaptureSummary summary;
    std::shared_ptr<const CaptureIndex> index;

    ConvertedCaptureSink sink()
    {
        return [ this ]( const QString& log, const QString& capture, const CaptureSummary& s,
                         std::shared_ptr<const CaptureIndex> i ) {
            ++calls;
            logPath = log;
            capturePath = capture;
            summary = s;
            index = std::move( i );
        };
    }
};

/// A conversion that runs until it is cancelled, then ends Cancelled, as
/// convertPcap() does when its cancel flag is set between packets.
ConversionResult untilCancelled( const QString&, const QString&, const std::atomic_bool* cancel,
                                 const std::function<void( int )>& progress,
                                 const ConversionOptions& )
{
    progress( 250 );
    const auto start = std::chrono::steady_clock::now();
    while ( !cancel->load() && std::chrono::steady_clock::now() - start < kHangGuard ) {
        std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
    }
    ConversionResult result;
    result.status = ConversionResult::Status::Cancelled;
    return result;
}

/// The control a host passes, around @p fake.
struct HostControl {
    LogSquirlConvertControl table{};
    explicit HostControl( FakeControl& fake )
    {
        table.size = sizeof( LogSquirlConvertControl );
        table.host = &fake;
        table.report_progress
            = []( const LogSquirlConvertControl* c, uint64_t done, uint64_t total ) {
                  static_cast<FakeControl*>( c->host )->control().reportProgress( done, total );
              };
        table.is_cancelled = []( const LogSquirlConvertControl* c ) {
            return static_cast<FakeControl*>( c->host )->control().isCancelled() ? 1 : 0;
        };
    }
};

} // namespace

SCENARIO( "A capture LogSquirl opened is converted into the host's file", "[host_converter]" )
{
    GIVEN( "a capture of five packets and the file the host created for its text" )
    {
        QTemporaryDir files;
        QTemporaryDir outputRoot;
        const auto capture = writeFile( files, "trace.pcap", captureOf( 5 ) );
        // What the host's temporary file may hold: it is written over.
        const auto output = writeFile( files, "trace.pcap.txt", text( "left over" ) );
        FakeControl fake;
        Kept kept;

        WHEN( "it is converted for the host" )
        {
            const auto code = convertForHost( capture, output, outputRoot.path(), {},
                                              fake.control(), kept.sink() );

            THEN( "the host's file holds the column header and a line per packet" )
            {
                REQUIRE( code == kHostConverted );
                const auto lines = linesOf( output );
                REQUIRE( lines.size() == 6 );
                REQUIRE_FALSE( lines.join( '\n' ).contains( "left over" ) );
            }

            THEN( "the capture, its summary and index went to the sink, for the host's file" )
            {
                REQUIRE( kept.calls == 1 );
                REQUIRE( kept.logPath == output );
                REQUIRE( kept.capturePath == capture );
                REQUIRE( kept.summary.packets == 5 );
                REQUIRE( kept.index );
            }

            THEN( "the plugin's private directory is gone" )
            {
                REQUIRE( entriesOf( outputRoot ).isEmpty() );
            }

            THEN( "the host was told the whole of its progress, on the thread it called on" )
            {
                REQUIRE_FALSE( fake.progress.empty() );
                REQUIRE( fake.progress.back()
                         == std::make_pair( kHostProgressTotal, kHostProgressTotal ) );
                REQUIRE( fake.onlyOn( std::this_thread::get_id() ) );
            }
        }
    }
}

SCENARIO( "A conversion for the host stops when the host cancels it", "[host_converter]" )
{
    GIVEN( "a conversion that runs until it is cancelled" )
    {
        QTemporaryDir files;
        QTemporaryDir outputRoot;
        const auto capture = writeFile( files, "big.pcap", captureOf( 1 ) );
        const auto output = writeFile( files, "big.pcap.txt", {} );
        FakeControl fake;
        Kept kept;

        WHEN( "the host's Cancel is pressed" )
        {
            std::thread press( [ &fake ] {
                std::this_thread::sleep_for( kHostConvertPoll * 3 );
                fake.cancelled = true;
            } );
            const auto code = convertForHost( capture, output, outputRoot.path(), {},
                                              fake.control(), kept.sink(), &untilCancelled );
            press.join();

            THEN( "the conversion hears it and the host is told it was cancelled" )
            {
                REQUIRE( code == kHostConvertCancelled );
            }

            THEN( "nothing went to the sink, and nothing of the plugin's is left" )
            {
                REQUIRE( kept.calls == 0 );
                REQUIRE( entriesOf( outputRoot ).isEmpty() );
            }

            THEN( "the progress so far and the polls came on the host's thread only" )
            {
                REQUIRE( std::find( fake.progress.begin(), fake.progress.end(),
                                    std::make_pair( uint64_t{ 250 }, kHostProgressTotal ) )
                         != fake.progress.end() );
                REQUIRE( fake.onlyOn( std::this_thread::get_id() ) );
            }
        }
    }

    GIVEN( "a capture whose conversion is done when the host's Cancel comes" )
    {
        QTemporaryDir files;
        QTemporaryDir outputRoot;
        const auto capture = writeFile( files, "trace.pcap", captureOf( 3 ) );
        const auto output = writeFile( files, "trace.pcap.txt", {} );
        FakeControl fake;
        fake.cancelled = true;
        Kept kept;

        WHEN( "it is converted for the host" )
        {
            const auto code = convertForHost( capture, output, outputRoot.path(), {},
                                              fake.control(), kept.sink() );

            THEN( "the cancel wins: nothing is kept, and nothing of the plugin's is left" )
            {
                REQUIRE( code == kHostConvertCancelled );
                REQUIRE( kept.calls == 0 );
                REQUIRE( entriesOf( outputRoot ).isEmpty() );
            }
        }
    }
}

SCENARIO( "A file that is no capture fails to convert for the host", "[host_converter]" )
{
    GIVEN( "a text file" )
    {
        QTemporaryDir files;
        QTemporaryDir outputRoot;
        const auto input = writeFile( files, "notes.pcap", text( "just some notes\n" ) );
        const auto output = writeFile( files, "notes.pcap.txt", {} );
        FakeControl fake;
        Kept kept;

        WHEN( "it is converted for the host" )
        {
            const auto code = convertForHost( input, output, outputRoot.path(), {}, fake.control(),
                                              kept.sink() );

            THEN( "it fails, nothing is kept, and nothing of the plugin's is left" )
            {
                REQUIRE( code == kHostConvertFailed );
                REQUIRE( kept.calls == 0 );
                REQUIRE( entriesOf( outputRoot ).isEmpty() );
            }
        }
    }
}

SCENARIO( "The plugin claims a file LogSquirl opens by its first bytes", "[host_converter]" )
{
    const Pcapng le;

    THEN( "pcap and pcapng captures are claimed, also behind tcpdump's stderr" )
    {
        const auto pcap = captureOf( 1 );
        REQUIRE( isCaptureHead( pcap.data(), pcap.size() ) );
        const auto pcapng = le.shb() + le.idb( DltEthernet );
        REQUIRE( isCaptureHead( pcapng.data(), pcapng.size() ) );
        const auto adb = text( "tcpdump: listening on wlan0\n" ) + pcap;
        REQUIRE( isCaptureHead( adb.data(), adb.size() ) );
    }

    THEN( "a text log, an empty file and a gzip file are not" )
    {
        const auto log = text( "2026-11-05 12:00:00 INFO started\n" );
        REQUIRE_FALSE( isCaptureHead( log.data(), log.size() ) );
        REQUIRE_FALSE( isCaptureHead( log.data(), 0 ) );
        REQUIRE_FALSE( isCaptureHead( nullptr, 0 ) );
        const Bytes gzip{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 };
        REQUIRE_FALSE( isCaptureHead( gzip.data(), gzip.size() ) );
    }

    THEN( "the extensions listed are .pcap and .pcapng, or none when the option is off" )
    {
        REQUIRE( QString( hostConverterExtensions( true ) ) == ".pcap;.pcapng" );
        REQUIRE( QString( hostConverterExtensions( false ) ).isEmpty() );
    }
}

SCENARIO( "The plugin converts the captures LogSquirl opens while its option is on",
          "[host_converter][plugin]" )
{
    QTemporaryDir files;
    QTemporaryDir tempRoot;
    g_state.tempRoot = tempRoot.path();
    const auto capture = writeFile( files, "trace.pcap", captureOf( 4 ) );
    const auto head = captureOf( 4 );

    GIVEN( "the plugin in a host, with the default options" )
    {
        FakeHost host;
        REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

        THEN( "it lists .pcap and .pcapng and claims a capture by its bytes" )
        {
            REQUIRE( QString( logsquirl_converter_get_extensions() ) == ".pcap;.pcapng" );
            REQUIRE(
                logsquirl_converter_claims( capture.toUtf8().constData(), head.data(), head.size() )
                == 1 );
        }

        WHEN( "the host has it convert a capture it opened, then brings its tab to the front" )
        {
            const auto output = writeFile( files, "trace.pcap.txt", {} );
            FakeControl fake;
            const HostControl control( fake );
            const auto code = logsquirl_converter_convert_ex(
                capture.toUtf8().constData(), output.toUtf8().constData(), &control.table );
            QCoreApplication::processEvents();
            host.activateFile( output );

            THEN( "it converted it, and the catalog shows the capture for the host's file" )
            {
                REQUIRE( code == kHostConverted );
                const auto* front = g_state.sessions->catalog().front();
                REQUIRE( front );
                REQUIRE( front->fileName == "trace.pcap" );
                REQUIRE( front->summary.packets == 4 );
                REQUIRE( front->index );
            }

            THEN( "nothing of the plugin's is left in its temporary directory" )
            {
                REQUIRE( entriesOf( tempRoot ).isEmpty() );
            }
        }

        WHEN( "the host converts without a control, as plain convert() does" )
        {
            const auto output = writeFile( files, "plain.pcap.txt", {} );
            const auto code = logsquirl_converter_convert( capture.toUtf8().constData(),
                                                           output.toUtf8().constData() );

            THEN( "it converts all the same" )
            {
                REQUIRE( code == kHostConverted );
                REQUIRE( linesOf( output ).size() == 5 );
            }
        }

        WHEN( "it is shut down" )
        {
            logsquirl_plugin_shutdown();

            THEN( "it lists no extension and claims nothing" )
            {
                REQUIRE( QString( logsquirl_converter_get_extensions() ).isEmpty() );
                REQUIRE( logsquirl_converter_claims( "", head.data(), head.size() ) == 0 );
            }
        }
    }

    GIVEN( "the plugin in a host whose saved options turn converting opened captures off" )
    {
        FakeHost host;
        ConversionOptions options;
        options.convertOpenedCaptures = false;
        REQUIRE( saveConversionOptions( host.configDir(), options ) );
        REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

        THEN( "it lists no extension and claims no capture: LogSquirl opens it as before" )
        {
            REQUIRE( QString( logsquirl_converter_get_extensions() ).isEmpty() );
            REQUIRE(
                logsquirl_converter_claims( capture.toUtf8().constData(), head.data(), head.size() )
                == 0 );
        }
    }

    g_state.tempRoot.clear();
}
