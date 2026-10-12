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
 *        condition ends a live capture, and when its lines are flushed and
 *        its snapshots go out, packet by packet on a fake clock.  No
 *        thread, sleep or file: the test hands it packet counts and sizes
 *        and moves the clock on.
 */

#include <catch2/catch.hpp>

#include "live_output.h"

#include <chrono>
#include <cstdint>

using namespace tcpdump;
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

SCENARIO( "The Live Output starts a ring buffer's next text with a snapshot", "[live_output]" )
{
    FakeClock fake;
    LiveOutput output( {}, fake.clock() );
    REQUIRE( output.packet( 1, bytesAfter( 1 ) ).firstOfText );
    fake.ms = 300;
    REQUIRE_FALSE( output.packet( 2, bytesAfter( 2 ) ).snapshot );

    GIVEN( "a new text started 400 ms after the last snapshot" )
    {
        fake.ms = 400;
        const auto started = output.textStarted();

        THEN( "a snapshot goes out at once, for the index to follow the files" )
        {
            REQUIRE( started.snapshot );
            REQUIRE_FALSE( started.firstOfText );
        }

        THEN( "the next packet opens the new text" )
        {
            fake.ms = 450;
            const auto next = output.packet( 3, bytesAfter( 3 ) );
            REQUIRE( next.firstOfText );
            REQUIRE( next.flush );
            REQUIRE( next.snapshot );
            fake.ms = 500;
            REQUIRE_FALSE( output.packet( 4, bytesAfter( 4 ) ).firstOfText );
        }
    }
}
