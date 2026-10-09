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
 * @file live_limits_test.cpp
 * @brief BDD tests for a live capture's stop conditions and ring buffer.
 *
 * A FeedSource hands out what the test fed it and waits for more, as a
 * capture program waiting for traffic does; a FakeClock is the clock the
 * durations are measured with, moved on by the test.
 */

#include <catch2/catch.hpp>

#include "capture_index.h"
#include "capture_source.h"
#include "packet_export.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "raw_capture.h"
#include "stream_capture.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <future>
#include <mutex>
#include <thread>

using namespace tcpdump;
using namespace tcpdump_test;
using std::chrono::milliseconds;
using std::chrono::seconds;

namespace {

/// Hands out the bytes fed to it, then waits for more until the feed ends.
class FeedSource : public StreamSource {
public:
    explicit FeedSource( const std::atomic_bool* stop = nullptr )
        : StreamSource( stop )
    {
    }

    void feed( const Bytes& bytes )
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        bytes_.insert( bytes_.end(), bytes.begin(), bytes.end() );
    }
    void end()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        ended_ = true;
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, milliseconds timeout ) override
    {
        {
            std::lock_guard<std::mutex> lock( mutex_ );
            if ( at_ < bytes_.size() ) {
                n = std::min( n, bytes_.size() - at_ );
                std::copy_n( bytes_.begin() + static_cast<std::ptrdiff_t>( at_ ), n, dst );
                at_ += n;
                return static_cast<std::ptrdiff_t>( n );
            }
            if ( ended_ ) {
                return 0;
            }
        }
        std::this_thread::sleep_for( std::min( timeout, milliseconds( 2 ) ) );
        return -1;
    }
    bool available() override
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return at_ < bytes_.size() || ended_;
    }

private:
    std::mutex mutex_;
    Bytes bytes_;
    size_t at_ = 0;
    bool ended_ = false;
};

/// A clock that stands still until the test moves it on.
struct FakeClock {
    std::atomic<int64_t> ms{ 0 };
    std::atomic<int> reads{ 0 }; ///< Times it was read.
    LiveClock clock()
    {
        return [ this ] {
            ++reads;
            return std::chrono::steady_clock::time_point( milliseconds( ms.load() ) );
        };
    }
};

/// @p count UDP datagrams of the same size, of distinct conversations.
std::vector<Bytes> datagrams( int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back( eth(
            EthertypeIpv4,
            ipv4( IpProtoUdp, udp( static_cast<uint16_t>( 40000 + i ), 9999, text( "ring" ) ) ) ) );
    }
    return packets;
}

/// The bytes of a pcap record of datagram @p packet.
size_t recordSize( const Bytes& packet )
{
    return 16 + packet.size();
}

/// The pcap of @p packets' records @p first, @p first + 1, … (all the
/// rest without @p count), as in the pcap of all of them: its global header
/// and those records.
Bytes pcapSlice( const std::vector<Bytes>& packets, size_t first, size_t count = SIZE_MAX )
{
    const auto whole = pcapOf( packets );
    size_t at = 24;
    for ( size_t i = 0; i < first; ++i ) {
        at += recordSize( packets[ i ] );
    }
    auto end = at;
    for ( size_t i = first; i < packets.size() && i - first < count; ++i ) {
        end += recordSize( packets[ i ] );
    }
    return Bytes( whole.begin(), whole.begin() + 24 )
           + Bytes( whole.begin() + static_cast<std::ptrdiff_t>( at ),
                    whole.begin() + static_cast<std::ptrdiff_t>( end ) );
}

Bytes fileBytes( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto all = file.readAll();
    return Bytes( all.begin(), all.end() );
}

/// A live conversion of a FeedSource on a thread of its own.
class LimitedRun {
public:
    explicit LimitedRun( const QString& outputRoot, const LiveLimits& limits,
                         const LiveClock& clock = {}, const ConversionOptions& options = {} )
    {
        LiveObserver observer;
        observer.snapshot = [ this ]( const LiveSnapshot& snapshot ) {
            std::lock_guard<std::mutex> lock( mutex_ );
            snapshots_.push_back( snapshot );
        };
        observer.firstPacket = [ this ]( const QString& logPath, const QString& rawPath ) {
            std::lock_guard<std::mutex> lock( mutex_ );
            texts_.emplace_back( logPath, rawPath );
            opened = true;
        };
        result_ = std::async(
            std::launch::async, [ this, outputRoot, options, observer, limits, clock ] {
                return convertStream( source, QStringLiteral( "live" ), outputRoot, nullptr,
                                      options, observer, limits, clock );
            } );
    }
    ~LimitedRun()
    {
        stop = true;
        source.end();
    }
    LimitedRun( const LimitedRun& ) = delete;
    LimitedRun& operator=( const LimitedRun& ) = delete;

    /// Whether it ended within @p limit.
    bool endsWithin( milliseconds limit )
    {
        return result_.wait_for( limit ) == std::future_status::ready;
    }
    ConversionResult finish()
    {
        return result_.get();
    }
    std::vector<LiveSnapshot> snapshots()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return snapshots_;
    }
    /// The text files to open, each with its raw file, in order.
    std::vector<std::pair<QString, QString>> texts()
    {
        std::lock_guard<std::mutex> lock( mutex_ );
        return texts_;
    }

    std::atomic_bool stop{ false };
    std::atomic_bool opened{ false };
    FeedSource source{ &stop };

private:
    std::mutex mutex_;
    std::vector<LiveSnapshot> snapshots_;
    std::vector<std::pair<QString, QString>> texts_;
    std::future<ConversionResult> result_;
};

/// Wait until @p condition holds, at most 5 s; whether it does.
bool soon( const std::function<bool()>& condition )
{
    const auto until = std::chrono::steady_clock::now() + seconds( 5 );
    while ( !condition() ) {
        if ( std::chrono::steady_clock::now() > until ) {
            return false;
        }
        std::this_thread::sleep_for( milliseconds( 1 ) );
    }
    return true;
}

} // namespace

SCENARIO( "A live capture stops by itself at a packet count or a size", "[live_limits]" )
{
    const auto packets = datagrams( 6 );
    const auto whole = pcapOf( packets );
    QTemporaryDir out;

    GIVEN( "a capture program that has sent six packets and waits for more" )
    {
        WHEN( "the capture is to stop after three packets" )
        {
            LiveLimits limits;
            limits.packets = 3;
            LimitedRun run( out.path(), limits );
            run.source.feed( whole );

            THEN( "it ends Converted with the third, as with Stop" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.stoppedBy == StopCondition::Packets );
                REQUIRE( result.summary.packets == 3 );
                REQUIRE_FALSE( result.summary.endsInsideRecord );
                REQUIRE( readLines( result.outputPath ).size() == 4 );
                REQUIRE( fileBytes( result.rawPath )
                         == pcapOf( { packets[ 0 ], packets[ 1 ], packets[ 2 ] } ) );
            }
        }

        WHEN( "the capture is to stop once two packets' bytes were read" )
        {
            LiveLimits limits;
            limits.bytes = 24 + recordSize( packets[ 0 ] ) * 2;
            LimitedRun run( out.path(), limits );
            run.source.feed( whole );

            THEN( "the packet that reaches the size is the last" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.stoppedBy == StopCondition::Bytes );
                REQUIRE( result.summary.packets == 2 );
            }
        }

        WHEN( "the size is a byte past two packets" )
        {
            LiveLimits limits;
            limits.bytes = 24 + recordSize( packets[ 0 ] ) * 2 + 1;
            LimitedRun run( out.path(), limits );
            run.source.feed( whole );

            THEN( "the packet that goes past it is the last" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                REQUIRE( run.finish().summary.packets == 3 );
            }
        }

        WHEN( "the capture has no stop condition" )
        {
            LimitedRun run( out.path(), {} );
            run.source.feed( whole );

            THEN( "it goes on until Stop" )
            {
                REQUIRE_FALSE( run.endsWithin( milliseconds( 300 ) ) );
                run.stop = true;
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.stoppedBy == StopCondition::None );
                REQUIRE( result.summary.packets == 6 );
            }
        }
    }
}

SCENARIO( "A live capture stops by itself after a duration, by the clock it is given",
          "[live_limits]" )
{
    const auto packets = datagrams( 3 );
    const auto whole = pcapOf( packets );
    const Bytes header( whole.begin(), whole.begin() + 24 );
    QTemporaryDir out;
    FakeClock fake;
    LiveLimits limits;
    limits.duration = seconds( 60 );

    GIVEN( "a capture to stop after a minute that has sent a packet and waits" )
    {
        LimitedRun run( out.path(), limits, fake.clock() );
        run.source.feed( Bytes( whole.begin(),
                                whole.begin() + 24
                                    + static_cast<std::ptrdiff_t>( recordSize( packets[ 0 ] ) ) ) );
        REQUIRE( soon( [ & ] { return run.opened.load(); } ) );

        WHEN( "59 s have passed" )
        {
            fake.ms = 59000;

            THEN( "it goes on" )
            {
                REQUIRE_FALSE( run.endsWithin( milliseconds( 200 ) ) );
            }
        }

        WHEN( "a minute has passed, though nothing more comes" )
        {
            fake.ms = 60000;

            THEN( "it ends Converted with what it captured" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.stoppedBy == StopCondition::Duration );
                REQUIRE( result.summary.packets == 1 );
                REQUIRE_FALSE( result.summary.endsInsideRecord );
            }
        }
    }

    GIVEN( "a capture to stop after a minute whose packets keep coming" )
    {
        LimitedRun run( out.path(), limits, fake.clock() );
        run.source.feed( Bytes( whole.begin(),
                                whole.begin() + 24
                                    + static_cast<std::ptrdiff_t>( recordSize( packets[ 0 ] ) ) ) );
        REQUIRE( soon( [ & ] { return run.opened.load(); } ) );

        WHEN( "the minute is over as the next packet comes" )
        {
            fake.ms = 60000;
            run.source.feed( Bytes( whole.begin() + 24
                                        + static_cast<std::ptrdiff_t>( recordSize( packets[ 0 ] ) ),
                                    whole.end() ) );

            THEN( "it ends, with no more than that packet" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.stoppedBy == StopCondition::Duration );
                REQUIRE( result.summary.packets <= 2 );
            }
        }
    }

    GIVEN( "a capture to stop after a minute that has sent its header only" )
    {
        LimitedRun run( out.path(), limits, fake.clock() );
        run.source.feed( header );
        REQUIRE( soon( [ & ] { return fake.reads > 0; } ) ); // it started

        WHEN( "the minute is over" )
        {
            fake.ms = 60000;

            THEN( "it ends Converted without packets" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.stoppedBy == StopCondition::Duration );
                REQUIRE( result.summary.packets == 0 );
            }
        }
    }

    GIVEN( "a capture to stop after a minute that has sent nothing" )
    {
        LimitedRun run( out.path(), limits, fake.clock() );
        REQUIRE( soon( [ & ] { return fake.reads > 0; } ) ); // it started

        WHEN( "the minute is over" )
        {
            fake.ms = 60000;

            THEN( "it ends Stopped, not failed, and leaves nothing behind" )
            {
                REQUIRE( run.endsWithin( seconds( 5 ) ) );
                const auto result = run.finish();
                REQUIRE( result.status == ConversionResult::Status::Stopped );
                REQUIRE( result.stoppedBy == StopCondition::Duration );
                REQUIRE( QDir( out.path() ).isEmpty() );
            }
        }
    }
}

SCENARIO( "A ring buffer keeps the newest files, each a capture of its own", "[live_limits]" )
{
    const auto packets = datagrams( 10 );
    const auto whole = pcapOf( packets );
    QTemporaryDir out;

    GIVEN( "a ring buffer of three files of two packets each" )
    {
        LiveLimits limits;
        limits.ringFiles = 3;
        limits.fileBytes = 24 + 2 * recordSize( packets[ 0 ] );
        ConversionOptions options;
        options.checkpointInterval = 3;
        LimitedRun run( out.path(), limits, {}, options );

        WHEN( "ten packets come and the capture is stopped" )
        {
            run.source.feed( whole );
            REQUIRE( soon( [ & ] {
                const auto snapshots = run.snapshots();
                return !snapshots.empty() && snapshots.back().rawFile == 5;
            } ) );
            std::this_thread::sleep_for( milliseconds( 100 ) );
            run.stop = true;
            REQUIRE( run.endsWithin( seconds( 5 ) ) );
            const auto result = run.finish();
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == 10 );
            const auto parts = result.index->parts();
            const QDir dir = QFileInfo( result.outputPath ).absoluteDir();

            THEN( "the files 3 to 5 are kept, named by number and time, the rest deleted" )
            {
                REQUIRE( parts.size() == 3 );
                const QRegularExpression name( "^live_0000([345])_\\d{14}\\.pcap$" );
                QStringList captures = dir.entryList( { "*.pcap" }, QDir::Files, QDir::Name );
                REQUIRE( captures.size() == 3 );
                for ( int i = 0; i < 3; ++i ) {
                    const auto match = name.match( captures[ i ] );
                    REQUIRE( match.hasMatch() );
                    REQUIRE( match.captured( 1 ).toInt() == i + 3 );
                    REQUIRE( QFileInfo( parts[ static_cast<size_t>( i ) ].path ).fileName()
                             == captures[ i ] );
                }
                REQUIRE( QFileInfo( result.rawPath ).fileName() == captures.last() );
            }

            THEN( "each file is a capture of its own with its two packets" )
            {
                for ( size_t i = 0; i < parts.size(); ++i ) {
                    const auto first = 4 + 2 * i;
                    REQUIRE( parts[ i ].packetsBefore == first );
                    REQUIRE( fileBytes( parts[ i ].path ) == pcapSlice( packets, first, 2 ) );
                    REQUIRE( parse( fileBytes( parts[ i ].path ) ).packets.size() == 2 );
                }
            }

            THEN( "each file has a text of its own, opened at its first line, never rewritten" )
            {
                const auto all = linesFromFile( whole );
                const auto texts = run.texts();
                REQUIRE( texts.size() == 5 );
                const QRegularExpression name( "^live_0000([1-5])_\\d{14}\\.log$" );
                for ( size_t i = 0; i < texts.size(); ++i ) {
                    const auto& [ logPath, rawPath ] = texts[ i ];
                    CAPTURE( logPath );
                    const auto match = name.match( QFileInfo( logPath ).fileName() );
                    REQUIRE( match.hasMatch() );
                    REQUIRE( match.captured( 1 ).toInt() == static_cast<int>( i ) + 1 );
                    REQUIRE( QFileInfo( logPath ).completeBaseName()
                             == QFileInfo( rawPath ).completeBaseName() );
                    // The header and the lines of its two packets, also of a
                    // file deleted since.
                    const auto first = static_cast<qsizetype>( 1 + 2 * i );
                    REQUIRE( readLines( logPath )
                             == QStringList{ all.at( 0 ), all.at( first ), all.at( first + 1 ) } );
                }
                REQUIRE( result.outputPath == texts.back().first );
                REQUIRE( dir.entryList( { "*.log" }, QDir::Files ).size() == 5 );
            }

            THEN( "the index keeps the checkpoints of the files kept only" )
            {
                const auto& checkpoints = result.index->checkpoints();
                REQUIRE_FALSE( checkpoints.empty() );
                REQUIRE( checkpoints.front().packetsBefore > result.index->rotatedAway() );
            }

            THEN( "a packet kept is read from its file; one rotated away says so" )
            {
                CaptureCursor cursor( result.index );
                CapturedPacket packet;
                for ( uint32_t number = 5; number <= 10; ++number ) {
                    REQUIRE( cursor.read( number, packet ) );
                    REQUIRE( packet.record.number == number );
                    REQUIRE( packet.bytes == packets[ number - 1 ] );
                }
                REQUIRE( cursor.read( 6, packet ) ); // back again, past a checkpoint
                REQUIRE( packet.bytes == packets[ 5 ] );
                REQUIRE_FALSE( cursor.read( 4, packet ) );
                REQUIRE( cursor.error().contains( "Rotated away" ) );
                REQUIRE( result.index->rotatedAway() == 4 );
            }

            THEN( "an index taken before the oldest files went says so too" )
            {
                const auto snapshots = run.snapshots();
                const auto older = std::find_if(
                    snapshots.begin(), snapshots.end(), []( const LiveSnapshot& snapshot ) {
                        return snapshot.index && snapshot.index->parts().size() == 2;
                    } );
                REQUIRE( older != snapshots.end() );
                CaptureCursor cursor( older->index );
                CapturedPacket packet;
                REQUIRE_FALSE( cursor.read( 1, packet ) );
                REQUIRE( cursor.error().contains( "Rotated away" ) );
            }

            THEN( "Save capture… writes the files kept as one capture" )
            {
                QTemporaryDir saved;
                const auto target = saved.filePath( "kept.pcap" );
                QString error;
                REQUIRE( saveCaptureParts( parts, target, error ) );
                REQUIRE( fileBytes( target ) == pcapSlice( packets, 4 ) );
            }

            THEN( "packets of two files export as one capture" )
            {
                QTemporaryDir saved;
                const auto target = saved.filePath( "some.pcap" );
                const auto exported = exportPackets( result.index, { 6, 9 }, target );
                REQUIRE( exported.status == ExportResult::Status::Exported );
                const auto ninth = pcapSlice( packets, 8, 1 );
                REQUIRE( fileBytes( target )
                         == pcapSlice( packets, 5, 1 ) + Bytes( ninth.begin() + 24, ninth.end() ) );
            }
        }
    }

    GIVEN( "a ring buffer of two files of a minute each" )
    {
        FakeClock fake;
        LiveLimits limits;
        limits.ringFiles = 2;
        limits.fileDuration = seconds( 60 );
        LimitedRun run( out.path(), limits, fake.clock() );
        size_t at = 0;
        auto send = [ & ]( size_t record ) {
            const auto end = 24 + ( record + 1 ) * recordSize( packets[ 0 ] );
            run.source.feed( Bytes( whole.begin() + static_cast<std::ptrdiff_t>( at ),
                                    whole.begin() + static_cast<std::ptrdiff_t>( end ) ) );
            at = end;
        };

        WHEN( "two packets come in the first minute and one after it" )
        {
            send( 0 );
            send( 1 );
            REQUIRE( soon( [ & ] {
                const auto snapshots = run.snapshots();
                return !snapshots.empty() && snapshots.back().summary.packets >= 1;
            } ) );
            std::this_thread::sleep_for( milliseconds( 100 ) );
            fake.ms = 61000;
            send( 2 );
            REQUIRE( soon( [ & ] {
                const auto snapshots = run.snapshots();
                return !snapshots.empty() && snapshots.back().rawFile == 2;
            } ) );
            run.stop = true;
            REQUIRE( run.endsWithin( seconds( 5 ) ) );
            const auto result = run.finish();

            THEN( "the third starts the second file" )
            {
                const auto parts = result.index->parts();
                REQUIRE( parts.size() == 2 );
                REQUIRE( fileBytes( parts[ 0 ].path ) == pcapOf( { packets[ 0 ], packets[ 1 ] } ) );
                REQUIRE( parts[ 1 ].packetsBefore == 2 );
                REQUIRE( parse( fileBytes( parts[ 1 ].path ) ).packets.size() == 1 );
            }
        }
    }
}

SCENARIO( "A pcapng ring buffer repeats the section header and interfaces in every file",
          "[live_limits]" )
{
    Pcapng le;
    const auto packets = datagrams( 6 );
    // A second interface is declared after the second packet, in the
    // second file; packets 5 and 6 are on it.
    Bytes stream = le.shb() + le.idb( DltEthernet );
    std::vector<Bytes> blocks;
    for ( size_t i = 0; i < packets.size(); ++i ) {
        blocks.push_back( le.epb( i < 4 ? 0 : 1, 1000000 + i, packets[ i ] ) );
    }
    const auto secondInterface = le.idb( DltRaw );
    QTemporaryDir out;

    GIVEN( "a ring buffer of two files of two packets each, a checkpoint per packet" )
    {
        LiveLimits limits;
        limits.ringFiles = 2;
        limits.fileBytes = stream.size() + 2 * blocks[ 0 ].size();
        ConversionOptions options;
        options.checkpointInterval = 1;
        LimitedRun run( out.path(), limits, {}, options );

        WHEN( "six packets come" )
        {
            Bytes all = stream;
            for ( size_t i = 0; i < blocks.size(); ++i ) {
                if ( i == 2 ) {
                    all = all + secondInterface;
                }
                all = all + blocks[ i ];
            }
            run.source.feed( all );
            run.source.end();
            REQUIRE( run.endsWithin( seconds( 5 ) ) );
            const auto result = run.finish();
            REQUIRE( result.status == ConversionResult::Status::Converted );
            const auto parts = result.index->parts();

            THEN( "the two files kept are captures with both interfaces" )
            {
                REQUIRE( parts.size() == 2 );
                for ( size_t i = 0; i < parts.size(); ++i ) {
                    const auto parsed = parse( fileBytes( parts[ i ].path ) );
                    REQUIRE( parsed.ok );
                    REQUIRE( parsed.linkTypes.size() == 2 );
                    REQUIRE( parsed.packets.size() == 2 );
                    REQUIRE( parsed.packets[ 0 ].timestampNsec
                             == ( 1000000 + 2 + 2 * i ) % 1000000 * 1000 );
                }
            }

            THEN( "a packet of the last file reads from a checkpoint, and exports with its "
                  "interface" )
            {
                CaptureCursor cursor( result.index );
                CapturedPacket packet;
                REQUIRE( cursor.read( 6, packet ) );
                REQUIRE( packet.bytes == packets[ 5 ] );
                REQUIRE( cursor.read( 3, packet ) );
                REQUIRE( packet.bytes == packets[ 2 ] );
                REQUIRE_FALSE( cursor.read( 2, packet ) );

                QTemporaryDir saved;
                const auto target = saved.filePath( "some.pcapng" );
                const auto exported = exportPackets( result.index, { 3, 6 }, target );
                REQUIRE( exported.status == ExportResult::Status::Exported );
                const auto parsed = parse( fileBytes( target ) );
                REQUIRE( parsed.ok );
                REQUIRE( parsed.packets.size() == 2 );
            }

            THEN( "Save capture… writes them as one capture of packets 3 to 6" )
            {
                QTemporaryDir saved;
                const auto target = saved.filePath( "kept.pcapng" );
                QString error;
                REQUIRE( saveCaptureParts( parts, target, error ) );
                const auto parsed = parse( fileBytes( target ) );
                REQUIRE( parsed.ok );
                REQUIRE( parsed.packets.size() == 4 );
                REQUIRE( parsed.linkTypes.size() == 2 );
            }
        }
    }
}
