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
 * @file tcp_analysis_test.cpp
 * @brief BDD tests for the TCP Analysis: relative sequence numbers.
 */

#include <catch2/catch.hpp>

#include "packet_formatter.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kPshAck = 0x18;

constexpr uint16_t kClient = 40000;
constexpr uint16_t kServer = 80;

/// A segment from the client to the server, or back when @p fromServer.
Bytes segment( bool fromServer, uint8_t flags, uint32_t seq, uint32_t ack,
               const Bytes& payload = {} )
{
    auto addresses = Ipv4Options{};
    if ( fromServer ) {
        std::swap( addresses.src, addresses.dst );
    }
    return eth( EthertypeIpv4,
                ipv4( IpProtoTcp,
                      fromServer ? tcp( kServer, kClient, payload, 5, flags, seq, ack )
                                 : tcp( kClient, kServer, payload, 5, flags, seq, ack ),
                      addresses ) );
}

/// The Info of each segment, after the TCP Analysis followed them in order.
std::vector<std::string> infoOf( const std::vector<Bytes>& segments,
                                 StreamTracker tracker = StreamTracker() )
{
    auto packets = parse( pcapOf( segments ) ).packets;
    REQUIRE( packets.size() == segments.size() );
    std::vector<std::string> infos;
    for ( auto& pkt : packets ) {
        analyseTcp( pkt, tracker.track( pkt ) );
        infos.push_back( pkt.info );
    }
    return infos;
}

/// Whether @p info shows @p numbers ("Seq=1 Ack=1") right after the flags.
bool shows( const std::string& info, const std::string& numbers )
{
    return info.find( "] " + numbers + " Win=" ) != std::string::npos;
}

} // namespace

SCENARIO( "TCP sequence and acknowledgement numbers are shown relative per direction",
          "[tcp_analysis]" )
{
    GIVEN( "a handshake and an exchange of data with random initial sequence numbers" )
    {
        const uint32_t client = 3000000000u;
        const uint32_t server = 123456789u;
        const auto infos = infoOf( {
            segment( false, kSyn, client, 0 ),
            segment( true, kSyn | kAck, server, client + 1 ),
            segment( false, kAck, client + 1, server + 1 ),
            segment( false, kPshAck, client + 1, server + 1, text( "hello" ) ),
            segment( true, kPshAck, server + 1, client + 6, text( "hi" ) ),
            segment( false, kAck, client + 6, server + 3 ),
        } );

        THEN( "each direction counts from its SYN, which is Seq=0" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=0 Ack=0" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=0 Ack=1" ) );
            REQUIRE( shows( infos[ 2 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=1 Ack=6" ) );
            REQUIRE( shows( infos[ 5 ], "Seq=6 Ack=3" ) );
        }

        THEN( "the rest of Info is kept" )
        {
            REQUIRE( infos[ 3 ]
                     == "40000 \xe2\x86\x92 80 [ACK, PSH] Seq=1 Ack=1 Win=65535 Len=5 | hello" );
        }
    }

    GIVEN( "a SYN whose acknowledgement field is not zero" )
    {
        const auto infos = infoOf( { segment( false, kSyn, 1000, 777 ) } );

        THEN( "Ack is 0: without the ACK flag the field acknowledges nothing" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=0 Ack=0" ) );
        }
    }

    GIVEN( "a stream whose handshake was not captured" )
    {
        const auto infos = infoOf( {
            segment( true, kPshAck, 5000, 9000, text( "data" ) ),
            segment( false, kAck, 9000, 5004 ),
            segment( true, kPshAck, 5004, 9000, text( "more" ) ),
        } );

        THEN( "the first segment seen sets the base of both directions, as after a handshake" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=1 Ack=5" ) );
            REQUIRE( shows( infos[ 2 ], "Seq=5 Ack=1" ) );
        }
    }

    GIVEN( "a stream whose first segment carries no ACK" )
    {
        const auto infos = infoOf( {
            segment( false, 0x08, 5000, 0, text( "x" ) ),
            segment( true, kAck, 7000, 5001 ),
        } );

        THEN( "the other direction takes its base from its own first segment" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1 Ack=0" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=1 Ack=2" ) );
        }
    }

    GIVEN( "sequence numbers that wrap past 2^32" )
    {
        const uint32_t client = 0xFFFFFFF0u;
        const auto infos = infoOf( {
            segment( false, kSyn, client, 0 ),
            segment( true, kSyn | kAck, 100, client + 1 ),
            segment( false, kPshAck, client + 1, 101, Bytes( 20, 'a' ) ),
            segment( false, kPshAck, client + 21, 101, Bytes( 20, 'a' ) ),
            segment( true, kAck, 101, client + 41 ),
        } );

        THEN( "the relative numbers go on counting" )
        {
            REQUIRE( shows( infos[ 2 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=21 Ack=1" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=1 Ack=41" ) );
        }
    }

    GIVEN( "a new connection that reuses the addresses and ports of an earlier one" )
    {
        const auto infos = infoOf( {
            segment( false, kSyn, 1000, 0 ),
            segment( true, kSyn | kAck, 2000, 1001 ),
            segment( false, kAck, 1001, 2001 ),
            segment( false, kSyn, 50000, 0 ),
            segment( true, kSyn | kAck, 90000, 50001 ),
            segment( false, kAck, 50001, 90001 ),
        } );

        THEN( "its SYN starts counting afresh in both directions" )
        {
            REQUIRE( shows( infos[ 3 ], "Seq=0 Ack=0" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=0 Ack=1" ) );
            REQUIRE( shows( infos[ 5 ], "Seq=1 Ack=1" ) );
        }
    }

    GIVEN( "a retransmitted SYN" )
    {
        const auto infos = infoOf( {
            segment( false, kSyn, 1000, 0 ),
            segment( true, kSyn | kAck, 2000, 1001 ),
            segment( false, kSyn, 1000, 0 ),
            segment( false, kAck, 1001, 2001 ),
        } );

        THEN( "it keeps the stream's bases" )
        {
            REQUIRE( shows( infos[ 2 ], "Seq=0 Ack=0" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=1 Ack=1" ) );
        }
    }

    GIVEN( "a stream past the stream cap" )
    {
        const auto infos = infoOf(
            {
                segment( false, kSyn, 1000, 0 ),
            },
            StreamTracker( 0 ) );

        THEN( "its numbers are shown as they are, without a state to count from" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1000 Ack=0" ) );
        }
    }
}

SCENARIO( "The whole-capture formatter shows relative numbers too", "[tcp_analysis]" )
{
    GIVEN( "a SYN with a random initial sequence number" )
    {
        const auto packets = parse( pcapOf( { segment( false, kSyn, 3000000000u, 0 ) } ) ).packets;

        THEN( "its line shows Seq=0" )
        {
            REQUIRE( shows( formatAllPackets( packets ).at( 1 ), "Seq=0 Ack=0" ) );
        }
    }
}
