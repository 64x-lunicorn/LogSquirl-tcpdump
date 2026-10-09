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
 * @file live_conversion_test.cpp
 * @brief BDD tests for converting a capture live, while it is written.
 *
 * A scripted writer sends a capture into a pipe record by record, with
 * pauses, as tcpdump does; the test watches the text file grow, the
 * snapshots come and the raw capture next to it.
 */

#include <catch2/catch.hpp>

#include <QtGlobal>

#include "capture_source.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "stream_capture.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

namespace {

/// The bytes of the file @p path.
Bytes fileBytes( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto all = file.readAll();
    return Bytes( all.begin(), all.end() );
}

/// Lines of @p path now, 0 if it cannot be read (yet).
int lineCount( const QString& path )
{
    QFile file( path );
    if ( !file.open( QIODevice::ReadOnly ) ) {
        return 0;
    }
    return static_cast<int>( file.readAll().count( '\n' ) );
}

/// @p count UDP datagrams of distinct conversations.
std::vector<Bytes> datagrams( int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back( eth(
            EthertypeIpv4,
            ipv4( IpProtoUdp, udp( static_cast<uint16_t>( 40000 + i ), 9999, text( "live" ) ) ) ) );
    }
    return packets;
}

/// A pcap of @p packets in pieces as a capture program writes it: the
/// global header, then one record after another.
std::vector<Bytes> pcapPieces( const std::vector<Bytes>& packets )
{
    const auto whole = pcapOf( packets );
    std::vector<Bytes> pieces;
    size_t at = 0;
    size_t end = 24;
    for ( size_t i = 0; i <= packets.size(); ++i ) {
        pieces.emplace_back( whole.begin() + static_cast<std::ptrdiff_t>( at ),
                             whole.begin() + static_cast<std::ptrdiff_t>( end ) );
        at = end;
        if ( i < packets.size() ) {
            end += 16 + packets[ i ].size();
        }
    }
    REQUIRE( at == whole.size() );
    return pieces;
}

/// Wait until @p condition holds, at most @p limit; whether it does.
bool within( milliseconds limit, const std::function<bool()>& condition )
{
    const auto until = Clock::now() + limit;
    while ( !condition() ) {
        if ( Clock::now() > until ) {
            return false;
        }
        std::this_thread::sleep_for( milliseconds( 1 ) );
    }
    return true;
}

#ifdef Q_OS_UNIX

/// A live conversion of what a test writes into a pipe, run on a thread of
/// its own, recording what it tells.
class LiveRun {
public:
    explicit LiveRun( const QString& outputRoot )
    {
        LiveObserver observer;
        observer.firstPacket = [ this ]( const QString& logPath, const QString& rawPath ) {
            std::lock_guard<std::mutex> lock( mutex_ );
            ++firstPacketCalls_;
            logPath_ = logPath;
            rawPath_ = rawPath;
            linesAtFirstPacket_ = lineCount( logPath );
        };
        observer.snapshot = [ this ]( const LiveSnapshot& snapshot ) {
            std::lock_guard<std::mutex> lock( mutex_ );
            snapshots_.push_back( snapshot );
        };
        thread_ = std::thread( [ this, outputRoot, observer ] {
            FdSource source( pipe.readEnd(), &stop );
            result_ = convertStream( source, QStringLiteral( "live" ), outputRoot, nullptr, {},
                                     observer );
            done = true;
        } );
    }
    ~LiveRun()
    {
        stop = true;
        if ( thread_.joinable() ) {
            thread_.join();
        }
    }
    LiveRun( const LiveRun& ) = delete;
    LiveRun& operator=( const LiveRun& ) = delete;

    /// Wait for the conversion to end; its result.
    ConversionResult finish()
    {
        thread_.join();
        return result_;
    }

    int firstPacketCalls()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return firstPacketCalls_;
    }
    QString logPath()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return logPath_;
    }
    QString rawPath()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return rawPath_;
    }
    int linesAtFirstPacket()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return linesAtFirstPacket_;
    }
    std::vector<LiveSnapshot> snapshots()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return snapshots_;
    }

    Pipe pipe;
    std::atomic_bool stop{ false };
    std::atomic_bool done{ false };

private:
    std::mutex mutex_;
    int firstPacketCalls_ = 0;
    QString logPath_;
    QString rawPath_;
    int linesAtFirstPacket_ = 0;
    std::vector<LiveSnapshot> snapshots_;
    ConversionResult result_;
    std::thread thread_;
};

#endif

} // namespace

#ifdef Q_OS_UNIX

SCENARIO( "A live capture's lines are in the file while the capture runs", "[live]" )
{
    GIVEN( "a writer that sends a pcap record by record, pausing after each" )
    {
        const auto pieces = pcapPieces( datagrams( 4 ) );
        QTemporaryDir out;
        LiveRun run( out.path() );

        WHEN( "it has sent the header and the first record" )
        {
            run.pipe.write( pieces[ 0 ] );
            run.pipe.write( pieces[ 1 ] );

            THEN( "the file is to be opened, once its header and first line are in it" )
            {
                REQUIRE( within( milliseconds( 2000 ), [ & ] { return run.firstPacketCalls(); } ) );
                REQUIRE( run.linesAtFirstPacket() == 2 );
                REQUIRE( QFileInfo( run.logPath() ).fileName() == "live.log" );
                REQUIRE( QFileInfo( run.rawPath() ).fileName() == "live.pcap" );

                AND_THEN( "each further record's line is readable at once, not at the end" )
                {
                    for ( size_t i = 2; i < pieces.size(); ++i ) {
                        std::this_thread::sleep_for( milliseconds( 150 ) );
                        const auto sent = Clock::now();
                        run.pipe.write( pieces[ i ] );
                        const auto lines = static_cast<int>( i ) + 1;
                        // The stream pauses after the record, and what was
                        // written is flushed before the wait: well within
                        // kLiveFlushInterval, which a slow runner gets on top.
                        REQUIRE( within( kLiveFlushInterval * 3,
                                         [ & ] { return lineCount( run.logPath() ) == lines; } ) );
                        INFO( "visible after "
                              << std::chrono::duration_cast<milliseconds>( Clock::now() - sent )
                                     .count()
                              << " ms" );
                        REQUIRE_FALSE( run.done );
                    }
                    run.pipe.closeWrite();
                    const auto result = run.finish();
                    REQUIRE( result.status == ConversionResult::Status::Converted );
                    REQUIRE( run.firstPacketCalls() == 1 );
                    REQUIRE( readLines( result.outputPath )
                             == linesFromFile( pcapOf( datagrams( 4 ) ) ) );
                }
            }
        }
    }

    GIVEN( "a writer that sends only a header and closes the stream" )
    {
        QTemporaryDir out;
        LiveRun run( out.path() );
        run.pipe.write( pcapPieces( {} )[ 0 ] );
        run.pipe.closeWrite();
        const auto result = run.finish();

        THEN( "the capture is converted without packets, and nothing is to be opened" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == 0 );
            REQUIRE( run.firstPacketCalls() == 0 );
            REQUIRE( run.snapshots().empty() );
        }
    }
}

SCENARIO( "A live capture's summary comes in snapshots, and the final one is the raw file's",
          "[live]" )
{
    const std::pair<const char*, Bytes> formats[] = {
        { "pcap", {} },
        { "pcapng", {} },
    };
    for ( const auto& [ format, unused ] : formats ) {
        GIVEN( std::string( "a writer that sends a " ) + format
               + " a record every 50 ms for over two seconds" )
        {
            const auto packets = datagrams( 48 );
            std::vector<Bytes> pieces;
            if ( std::string( format ) == "pcap" ) {
                pieces = pcapPieces( packets );
            }
            else {
                Pcapng le;
                pieces.push_back( le.shb() + le.idb( DltEthernet, 9 ) );
                uint64_t ts = 1000000000000;
                for ( const auto& p : packets ) {
                    pieces.push_back( le.epb( 0, ts, p ) );
                    ts += 50000;
                }
            }
            Bytes sent;
            QTemporaryDir out;
            LiveRun run( out.path() );
            for ( const auto& piece : pieces ) {
                run.pipe.write( piece );
                sent = sent + piece;
                std::this_thread::sleep_for( milliseconds( 50 ) );
            }
            run.pipe.closeWrite();
            const auto result = run.finish();
            REQUIRE( result.status == ConversionResult::Status::Converted );

            THEN( "snapshots came at most once a second, each with what was converted so far" )
            {
                const auto snapshots = run.snapshots();
                REQUIRE( snapshots.size() >= 2 );
                REQUIRE( snapshots.front().summary.packets == 1 );
                for ( size_t i = 1; i < snapshots.size(); ++i ) {
                    REQUIRE( snapshots[ i ].elapsed - snapshots[ i - 1 ].elapsed
                             >= kLiveSnapshotInterval );
                    REQUIRE( snapshots[ i ].summary.packets > snapshots[ i - 1 ].summary.packets );
                    REQUIRE( snapshots[ i ].rawBytes > snapshots[ i - 1 ].rawBytes );
                }
                REQUIRE( snapshots.back().summary.packets <= packets.size() );
            }

            THEN( "the raw file next to the text is what the writer sent, byte for byte" )
            {
                REQUIRE( QFileInfo( result.rawPath ).absolutePath()
                         == QFileInfo( result.outputPath ).absolutePath() );
                REQUIRE( QFileInfo( result.rawPath ).fileName() == QString( "live." ) + format );
                REQUIRE( fileBytes( result.rawPath ) == sent );
            }

            THEN( "the final summary is that of converting the raw file" )
            {
                QTemporaryDir again;
                const auto fromRaw = convertPcap( result.rawPath, again.path() );
                REQUIRE( fromRaw.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.packets == packets.size() );
                REQUIRE( result.summary == fromRaw.summary );
                REQUIRE( readLines( result.outputPath ) == readLines( fromRaw.outputPath ) );
            }
        }
    }
}

SCENARIO( "Stop finalises a live capture at once", "[live]" )
{
    GIVEN( "a capture that has sent two packets and goes quiet, its stream open" )
    {
        const auto pieces = pcapPieces( datagrams( 2 ) );
        QTemporaryDir out;
        LiveRun run( out.path() );
        Bytes sent;
        for ( const auto& piece : pieces ) {
            run.pipe.write( piece );
            sent = sent + piece;
        }
        REQUIRE( within( milliseconds( 2000 ), [ & ] {
            return run.firstPacketCalls() && lineCount( run.logPath() ) == 3;
        } ) );

        WHEN( "Stop is pressed" )
        {
            const auto pressed = Clock::now();
            run.stop = true;
            const auto result = run.finish();
            const auto took = Clock::now() - pressed;

            THEN( "it ends Converted within a second, with every line and byte kept" )
            {
                REQUIRE( took < milliseconds( 1000 ) );
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.packets == 2 );
                REQUIRE( lineCount( result.outputPath ) == 3 );
                REQUIRE( fileBytes( result.rawPath ) == sent );
            }
        }
    }
}

#endif

SCENARIO( "A live capture whose source fails keeps what was captured", "[live]" )
{
    GIVEN( "a source that sends three packets and breaks off with an error" )
    {
        const auto capture = pcapOf( datagrams( 3 ) );
        BreakingSource source( capture, "tcpdump exited with code 1: device went away" );
        QTemporaryDir out;
        int opened = 0;
        LiveObserver observer;
        observer.firstPacket = [ & ]( const QString&, const QString& ) { ++opened; };
        const auto result
            = convertStream( source, QStringLiteral( "eth0" ), out.path(), nullptr, {}, observer );

        THEN( "it ends Failed with the message, and the text, raw file and summary stay" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "device went away" ) );
            REQUIRE( opened == 1 );
            REQUIRE( result.summary.packets == 3 );
            REQUIRE( lineCount( result.outputPath ) == 4 );
            REQUIRE( fileBytes( result.rawPath ) == capture );
        }
    }

    GIVEN( "a source that breaks off before its first packet" )
    {
        auto header = pcapOf( {} );
        BreakingSource source( header, "permission denied" );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "eth0" ), out.path() );

        THEN( "it ends Failed and leaves nothing behind" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "permission denied" ) );
            REQUIRE( result.outputPath.isEmpty() );
            REQUIRE( QDir( out.path() ).isEmpty() );
        }
    }

    GIVEN( "a source cancelled after three packets" )
    {
        const auto capture = pcapOf( datagrams( 3 ) );
        BreakingSource source( capture, "never seen" );
        QTemporaryDir out;
        std::atomic_bool cancel{ false };
        LiveObserver observer;
        observer.firstPacket = [ & ]( const QString&, const QString& ) { cancel = true; };
        const auto result
            = convertStream( source, QStringLiteral( "eth0" ), out.path(), &cancel, {}, observer );

        THEN( "it ends Cancelled, and neither the text nor the raw file stays" )
        {
            REQUIRE( result.status == ConversionResult::Status::Cancelled );
            REQUIRE( QDir( out.path() ).isEmpty() );
        }
    }
}
