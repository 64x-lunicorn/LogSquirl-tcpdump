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
 * @file live_output_test.cpp
 * @brief BDD tests for the Live Output, through its interface: which stop
 *        condition ends a live capture, when its lines are flushed and its
 *        snapshots go out, and when a ring buffer's next file starts,
 *        packet by packet on a fake clock.  No thread, sleep or file: the
 *        test hands it packet counts and sizes, a capture read from memory
 *        and fake files, and moves the clock on.
 */

#include <catch2/catch.hpp>

#include "capture_reader.h"
#include "live_output.h"
#include "pcapbuilder.h"

#include <QBuffer>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>

using namespace tcpdump;
using namespace tcpdump_test;
using std::chrono::milliseconds;
using std::chrono::seconds;

namespace {

/// A clock that stands still until the test moves it on.
struct FakeClock {
    int64_t ms = 0;
    LiveClock clock()
    {
        return [ this ] { return std::chrono::steady_clock::time_point( milliseconds( ms ) ); };
    }
};

/// The files of a test's Live Output: no file, but what it was told.
class FakeFiles : public LiveFiles {
public:
    /// A raw file started: where the one before it was cut, and the packets
    /// and the header records it was told.
    struct Start {
        uint64_t cut = 0;
        uint32_t packetsBefore = 0;
        size_t headers = 0;
    };

    FakeFiles()
    {
        text_.open( QIODevice::WriteOnly );
    }

    QIODevice& text() override
    {
        return text_;
    }
    bool writeRaw( const uint8_t* /*data*/, size_t n ) override
    {
        rawSize += n;
        return true;
    }
    bool flush() override
    {
        return true;
    }
    uint64_t rawFileSize() const override
    {
        return rawSize;
    }
    bool startNext( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers ) override
    {
        if ( failing ) {
            return false;
        }
        starts.push_back( { cut, packetsBefore, headers.records.size() } );
        rawSize = 0;
        return true;
    }
    bool close() override
    {
        return true;
    }
    const std::vector<CapturePart>& parts() const override
    {
        return parts_;
    }
    uint32_t fileNumber() const override
    {
        return static_cast<uint32_t>( starts.size() ) + 1;
    }
    QString textPath() const override
    {
        return {};
    }
    QString rawPath() const override
    {
        return {};
    }
    QString error() const override
    {
        return QStringLiteral( "The next file cannot be started" );
    }

    uint64_t rawSize = 0;      ///< Bytes of the raw file written, as the test says.
    bool failing = false;      ///< The next file cannot be started.
    std::vector<Start> starts; ///< The raw files started after the first.

private:
    QBuffer text_;
    std::vector<CapturePart> parts_;
};

/// A pcap of datagrams of one size, read packet by packet as the Converter
/// reads a live capture.
class Capture {
public:
    explicit Capture( int count )
        : bytes_( pcapOf( datagrams( count ) ) )
        , memory_( bytes_.data(), bytes_.size() )
        , head_( memory_ )
        , reader_( makeCaptureReader( head_ ) )
    {
        REQUIRE( reader_->open() );
    }

    /// Read the next packet.
    void next()
    {
        PacketRecord pkt;
        REQUIRE( reader_->next( pkt ) );
    }

    const CaptureReader& reader() const
    {
        return *reader_;
    }

    /// Where the record of packet @p number ends in the capture.
    static uint64_t endOf( uint32_t number )
    {
        return kPcapHeaderBytes + number * ( kRecordHeaderBytes + datagrams( 1 )[ 0 ].size() );
    }

private:
    static constexpr uint64_t kPcapHeaderBytes = 24;
    static constexpr uint64_t kRecordHeaderBytes = 16;

    static std::vector<Bytes> datagrams( int count )
    {
        return std::vector<Bytes>(
            static_cast<size_t>( count ),
            eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999, text( "ring" ) ) ) ) );
    }

    Bytes bytes_;
    MemorySource memory_;
    HeadSource head_;
    std::unique_ptr<CaptureReader> reader_;
};

/// Bytes of the capture header and of each packet's record, as a test
/// counts the bytes read.
constexpr uint64_t kHeaderBytes = 24;
constexpr uint64_t kRecordBytes = 100;

/// The bytes read once @p packets packets came.
uint64_t bytesAfter( uint64_t packets )
{
    return kHeaderBytes + packets * kRecordBytes;
}

} // namespace

SCENARIO( "The Live Output stops a capture at a packet count or a size", "[live_output]" )
{
    FakeClock fake;

    GIVEN( "a capture to stop after three packets" )
    {
        LiveLimits limits;
        limits.packets = 3;
        LiveOutput output( limits, fake.clock() );

        THEN( "the third packet is the last" )
        {
            REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::None );
            REQUIRE( output.packet( 2, bytesAfter( 2 ) ).stop == StopCondition::None );
            REQUIRE( output.packet( 3, bytesAfter( 3 ) ).stop == StopCondition::Packets );
        }
    }

    GIVEN( "a capture to stop once two packets' bytes were read" )
    {
        LiveLimits limits;
        limits.bytes = bytesAfter( 2 );
        LiveOutput output( limits, fake.clock() );

        THEN( "the packet that reaches the size is the last" )
        {
            REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::None );
            REQUIRE( output.packet( 2, bytesAfter( 2 ) ).stop == StopCondition::Bytes );
        }
    }

    GIVEN( "a capture to stop a byte past two packets" )
    {
        LiveLimits limits;
        limits.bytes = bytesAfter( 2 ) + 1;
        LiveOutput output( limits, fake.clock() );

        THEN( "the packet that goes past it is the last" )
        {
            REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::None );
            REQUIRE( output.packet( 2, bytesAfter( 2 ) ).stop == StopCondition::None );
            REQUIRE( output.packet( 3, bytesAfter( 3 ) ).stop == StopCondition::Bytes );
        }
    }

    GIVEN( "a capture without stop conditions" )
    {
        LiveOutput output( {}, fake.clock() );

        THEN( "no packet, size or time ends it" )
        {
            for ( uint64_t n = 1; n <= 1000; ++n ) {
                fake.ms += 60000;
                REQUIRE( output.packet( n, bytesAfter( n ) * 1000000 ).stop
                         == StopCondition::None );
                REQUIRE_FALSE( output.durationOver() );
            }
        }
    }
}

SCENARIO( "The Live Output stops a capture after a duration, by the clock it is given",
          "[live_output]" )
{
    FakeClock fake;
    fake.ms = 5000; // the clock does not start at 0
    LiveLimits limits;
    limits.duration = seconds( 60 );
    LiveOutput output( limits, fake.clock() );

    GIVEN( "a capture to stop after a minute" )
    {
        WHEN( "59 s have passed" )
        {
            fake.ms += 59000;

            THEN( "it goes on, at a packet and while it waits" )
            {
                REQUIRE_FALSE( output.durationOver() );
                REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::None );
            }
        }

        WHEN( "a minute has passed" )
        {
            fake.ms += 60000;

            THEN( "the duration is over while it waits, and the next packet is the last" )
            {
                REQUIRE( output.durationOver() );
                REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::Duration );
            }
        }
    }
}

SCENARIO( "The Live Output stops a capture with the last packet it can number", "[live_output]" )
{
    FakeClock fake;

    GIVEN( "a capture whose last packet number is four" )
    {
        LiveOutput output( {}, fake.clock(), 4 );

        THEN( "the fourth packet is the last, as at a stop condition" )
        {
            for ( uint64_t n = 1; n <= 3; ++n ) {
                REQUIRE( output.packet( n, bytesAfter( n ) ).stop == StopCondition::None );
            }
            REQUIRE( output.packet( 4, bytesAfter( 4 ) ).stop == StopCondition::PacketNumbers );
        }
    }

    GIVEN( "a capture of the default last number" )
    {
        LiveOutput output( {}, fake.clock() );

        THEN( "the packet of kMaxPacketNumber is the last" )
        {
            REQUIRE( output.packet( kMaxPacketNumber - 1, 0 ).stop == StopCondition::None );
            REQUIRE( output.packet( kMaxPacketNumber, 0 ).stop == StopCondition::PacketNumbers );
        }
    }
}

SCENARIO( "The first stop condition the Live Output sees reached ends the capture",
          "[live_output]" )
{
    FakeClock fake;
    LiveLimits limits;
    limits.packets = 3;
    limits.bytes = bytesAfter( 2 );
    limits.duration = seconds( 60 );

    GIVEN( "a size that the second packet reaches before the count" )
    {
        LiveOutput output( limits, fake.clock() );
        REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::None );

        THEN( "the size ends it, before the count could" )
        {
            REQUIRE( output.packet( 2, bytesAfter( 2 ) ).stop == StopCondition::Bytes );
        }
    }

    GIVEN( "a minute that is over before the size is reached" )
    {
        LiveOutput output( limits, fake.clock() );
        fake.ms = 60000;

        THEN( "the duration ends it" )
        {
            REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::Duration );
        }
    }

    GIVEN( "a packet that reaches every condition at once" )
    {
        limits.bytes = bytesAfter( 3 );
        LiveOutput output( limits, fake.clock(), 3 );
        output.packet( 1, bytesAfter( 1 ) );
        output.packet( 2, bytesAfter( 2 ) );
        fake.ms = 60000;

        THEN( "the count comes first, then the size, the duration and the numbers" )
        {
            REQUIRE( output.packet( 3, bytesAfter( 3 ) ).stop == StopCondition::Packets );
        }
    }

    GIVEN( "a packet that reaches the size, the duration and the numbers at once" )
    {
        limits.packets = 0;
        LiveOutput output( limits, fake.clock(), 2 );
        output.packet( 1, bytesAfter( 1 ) );
        fake.ms = 60000;

        THEN( "the size comes first" )
        {
            REQUIRE( output.packet( 2, bytesAfter( 2 ) ).stop == StopCondition::Bytes );
        }
    }

    GIVEN( "a packet that reaches the duration and the numbers at once" )
    {
        limits.packets = 0;
        limits.bytes = 0;
        LiveOutput output( limits, fake.clock(), 1 );
        fake.ms = 60000;

        THEN( "the duration comes first" )
        {
            REQUIRE( output.packet( 1, bytesAfter( 1 ) ).stop == StopCondition::Duration );
        }
    }
}

SCENARIO( "The Live Output opens a text at its first packet and flushes it every 100 ms",
          "[live_output]" )
{
    FakeClock fake;
    LiveOutput output( {}, fake.clock() );

    GIVEN( "a capture's first packet" )
    {
        const auto first = output.packet( 1, bytesAfter( 1 ) );

        THEN( "its line is flushed, the text can be opened, and a snapshot goes out" )
        {
            REQUIRE( first.flush );
            REQUIRE( first.firstOfText );
            REQUIRE( first.snapshot );
        }

        WHEN( "packets follow in a stream that does not pause" )
        {
            fake.ms = 50;
            const auto soon = output.packet( 2, bytesAfter( 2 ) );
            fake.ms = 99;
            const auto beforeFlush = output.packet( 3, bytesAfter( 3 ) );
            fake.ms = 100;
            const auto atFlush = output.packet( 4, bytesAfter( 4 ) );
            fake.ms = 150;
            const auto after = output.packet( 5, bytesAfter( 5 ) );
            fake.ms = 200;
            const auto next = output.packet( 6, bytesAfter( 6 ) );

            THEN( "their lines are flushed every kLiveFlushInterval, and no text opens again" )
            {
                REQUIRE_FALSE( soon.flush );
                REQUIRE_FALSE( beforeFlush.flush );
                REQUIRE( atFlush.flush );
                REQUIRE_FALSE( after.flush );
                REQUIRE( next.flush );
                for ( const auto& step : { soon, beforeFlush, atFlush, after, next } ) {
                    REQUIRE_FALSE( step.firstOfText );
                    REQUIRE_FALSE( step.snapshot );
                }
            }
        }

        WHEN( "the stream pauses" )
        {
            fake.ms = 10;
            const auto wait = output.beforeWait();

            THEN( "what was written is flushed before the wait" )
            {
                REQUIRE( wait.flush );
                REQUIRE_FALSE( wait.snapshot );
            }

            AND_WHEN( "the next packet comes less than 100 ms after that flush" )
            {
                fake.ms = 105;

                THEN( "its line waits for the next flush" )
                {
                    REQUIRE_FALSE( output.packet( 2, bytesAfter( 2 ) ).flush );
                }
            }
        }
    }
}

SCENARIO( "The Live Output sends a snapshot with the first packet, then at most every second",
          "[live_output]" )
{
    FakeClock fake;
    fake.ms = 7000; // the capture starts 7 s into the clock
    LiveOutput output( {}, fake.clock() );

    GIVEN( "a capture whose first packet came 2 s after it started" )
    {
        fake.ms += 2000;
        REQUIRE( output.packet( 1, bytesAfter( 1 ) ).snapshot );

        THEN( "the snapshot says how long the capture has run, by the clock" )
        {
            REQUIRE( output.elapsed() == milliseconds( 2000 ) );
        }

        WHEN( "packets keep coming for two seconds" )
        {
            std::vector<int64_t> snapshotAt;
            for ( uint64_t n = 2; n <= 41; ++n ) {
                fake.ms += 50;
                const auto step = output.packet( n, bytesAfter( n ) );
                if ( step.snapshot ) {
                    REQUIRE( step.flush ); // a snapshot's index points into flushed bytes
                    snapshotAt.push_back( fake.ms );
                }
            }

            THEN( "a snapshot goes out once every kLiveSnapshotInterval" )
            {
                REQUIRE( snapshotAt == std::vector<int64_t>{ 10000, 11000 } );
                REQUIRE( output.elapsed() == milliseconds( 4000 ) );
            }
        }

        WHEN( "a burst's last packets came, and the stream pauses" )
        {
            fake.ms += 300;
            REQUIRE_FALSE( output.packet( 2, bytesAfter( 2 ) ).snapshot );
            const auto wait = output.beforeWait();

            THEN( "the snapshot is not due yet, but waits for its turn" )
            {
                REQUIRE( wait.flush );
                REQUIRE_FALSE( wait.snapshot );
                REQUIRE( output.snapshotWaits() );
            }

            AND_WHEN( "its turn comes while the stream stays idle" )
            {
                fake.ms += 700;

                THEN( "it no longer waits, and goes out after the wait" )
                {
                    REQUIRE_FALSE( output.snapshotWaits() );
                    const auto waited = output.beforeWait();
                    REQUIRE( waited.snapshot );
                    REQUIRE_FALSE( output.snapshotWaits() );
                    REQUIRE_FALSE( output.beforeWait().snapshot );
                }
            }
        }

        WHEN( "the stream pauses with no packet since the snapshot" )
        {
            fake.ms += 5000;

            THEN( "no snapshot is waited for or sent" )
            {
                REQUIRE_FALSE( output.snapshotWaits() );
                REQUIRE_FALSE( output.beforeWait().snapshot );
            }
        }
    }
}

namespace {

/// A live capture of @p capture's packets into fake files, as the Converter
/// runs one: each packet is read, the Live Output asked before its line and
/// after it.
struct RingRun {
    RingRun( const LiveLimits& limits, FakeClock& fake, int count )
        : capture( count )
        , output( limits, fake.clock() )
    {
        auto owned = std::make_unique<FakeFiles>();
        files = owned.get();
        output.open( std::move( owned ), capture.reader() );
    }

    /// The next packet comes, its record filling the raw file to
    /// @p rawSize: what the Live Output said before its line (nothing if
    /// the next file could not start) and after it.
    std::pair<std::optional<LiveStep>, LiveStep> packet( uint64_t rawSize )
    {
        capture.next();
        auto before = output.beforePacket();
        if ( !before ) {
            return { before, {} };
        }
        ++packets;
        files->rawSize = rawSize;
        return { before, output.packet( packets, bytesAfter( packets ) ) };
    }

    Capture capture;
    LiveOutput output;
    FakeFiles* files = nullptr;
    uint32_t packets = 0;
};

} // namespace

SCENARIO( "The Live Output starts a ring buffer's next file after the packet that filled one",
          "[live_output]" )
{
    FakeClock fake;
    LiveLimits limits;
    limits.ringFiles = 3;
    limits.fileBytes = 1000;

    GIVEN( "a ring buffer whose second packet fills the first file" )
    {
        RingRun run( limits, fake, 4 );
        REQUIRE_FALSE( run.packet( 500 ).first->snapshot );
        fake.ms = 300;
        const auto [ before, after ] = run.packet( 1000 );

        THEN( "the packet that filled it is still in it" )
        {
            REQUIRE( before );
            REQUIRE_FALSE( before->snapshot );
            REQUIRE_FALSE( after.snapshot );
            REQUIRE( run.files->starts.empty() );
        }

        WHEN( "the third packet comes, 400 ms after the last snapshot" )
        {
            fake.ms = 400;
            const auto [ started, third ] = run.packet( 600 );

            THEN( "the next file starts before it, cut after the second's record" )
            {
                REQUIRE( started );
                REQUIRE( run.files->starts.size() == 1 );
                const auto& start = run.files->starts.front();
                REQUIRE( start.cut == Capture::endOf( 2 ) );
                REQUIRE( start.packetsBefore == 2 );
                REQUIRE( start.headers == 1 ); // the pcap's global header
            }

            THEN( "a snapshot goes out at once, for the index to follow the files" )
            {
                REQUIRE( started->snapshot );
                REQUIRE( started->flush );
                REQUIRE_FALSE( started->firstOfText );
            }

            THEN( "the third packet opens the new text, and the fourth stays in that file" )
            {
                REQUIRE( third.firstOfText );
                REQUIRE( third.flush );
                REQUIRE( third.snapshot );
                fake.ms = 450;
                const auto [ notStarted, fourth ] = run.packet( 900 );
                REQUIRE( notStarted );
                REQUIRE_FALSE( notStarted->snapshot );
                REQUIRE_FALSE( fourth.firstOfText );
                REQUIRE( run.files->starts.size() == 1 );
            }
        }
    }

    GIVEN( "a ring buffer whose file is full, and a capture that stops" )
    {
        limits.packets = 2;
        RingRun run( limits, fake, 4 );
        run.packet( 500 );
        const auto last = run.packet( 1000 ).second;

        THEN( "it stops with the packet that filled the file, and starts no next one" )
        {
            REQUIRE( last.stop == StopCondition::Packets );
            REQUIRE( run.files->starts.empty() );
        }
    }

    GIVEN( "a ring buffer whose next file cannot be started" )
    {
        RingRun run( limits, fake, 2 );
        run.packet( 1000 );
        run.files->failing = true;

        THEN( "the next packet is not recorded, for the Converter to fail with the files' error" )
        {
            REQUIRE_FALSE( run.packet( 100 ).first );
            REQUIRE( run.packets == 1 );
        }
    }
}

SCENARIO( "The Live Output starts a ring buffer's next file once one is old, by the clock",
          "[live_output]" )
{
    FakeClock fake;
    fake.ms = 5000; // the clock does not start at 0
    LiveLimits limits;
    limits.ringFiles = 2;
    limits.fileDuration = seconds( 60 );

    GIVEN( "a ring buffer of a minute per file, whose first packets came in the first minute" )
    {
        RingRun run( limits, fake, 6 );
        run.packet( 100 );
        fake.ms += 59000;
        run.packet( 200 );
        REQUIRE( run.files->starts.empty() );

        WHEN( "the next packet comes after the minute" )
        {
            fake.ms += 2000;
            run.packet( 100 );

            THEN( "the next file starts before it, after the record of the last one before" )
            {
                REQUIRE( run.files->starts.size() == 1 );
                REQUIRE( run.files->starts.front().cut == Capture::endOf( 2 ) );
                REQUIRE( run.files->starts.front().packetsBefore == 2 );
            }

            THEN( "the new file's minute counts from when it started" )
            {
                fake.ms += 59999;
                run.packet( 200 );
                REQUIRE( run.files->starts.size() == 1 );
                fake.ms += 1;
                run.packet( 100 );
                REQUIRE( run.files->starts.size() == 2 );
                REQUIRE( run.files->starts.back().packetsBefore == 4 );
            }
        }
    }

    GIVEN( "a ring buffer whose first packet comes after the minute" )
    {
        RingRun run( limits, fake, 2 );
        fake.ms += 120000;

        THEN( "the first file is not left empty: the packet goes into it" )
        {
            REQUIRE( run.packet( 100 ).second.firstOfText );
            REQUIRE( run.files->starts.empty() );
        }
    }

    GIVEN( "a ring buffer of a minute or 1000 bytes, whichever comes first" )
    {
        limits.fileBytes = 1000;
        RingRun run( limits, fake, 4 );
        run.packet( 1000 );

        THEN( "a full file starts the next before its minute is over" )
        {
            fake.ms += 1000;
            run.packet( 100 );
            REQUIRE( run.files->starts.size() == 1 );
        }
    }
}

SCENARIO( "The Live Output starts no next file without a ring buffer", "[live_output]" )
{
    FakeClock fake;

    GIVEN( "a file size and duration, but no files to keep" )
    {
        LiveLimits limits;
        limits.fileBytes = 1000;
        limits.fileDuration = seconds( 60 );
        RingRun run( limits, fake, 3 );

        THEN( "a full or old file goes on" )
        {
            run.packet( 5000 );
            fake.ms += 120000;
            run.packet( 10000 );
            run.packet( 15000 );
            REQUIRE( run.files->starts.empty() );
        }
    }

    GIVEN( "files to keep, but neither a size nor a duration" )
    {
        LiveLimits limits;
        limits.ringFiles = 3;
        RingRun run( limits, fake, 3 );

        THEN( "one file is written" )
        {
            run.packet( 5000 );
            fake.ms += 120000;
            run.packet( 10000 );
            run.packet( 15000 );
            REQUIRE( run.files->starts.empty() );
        }
    }
}
