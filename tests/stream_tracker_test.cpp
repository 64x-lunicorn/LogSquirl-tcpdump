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
 * @file stream_tracker_test.cpp
 * @brief BDD tests for the Stream Tracker.
 */

#include <catch2/catch.hpp>

#include <algorithm>

#include "capture_stats.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A packet from @p src:@p srcPort to 10.0.0.1:@p dstPort over @p transport.
PacketRecord packetOver( std::optional<Transport> transport, const std::string& src,
                         uint16_t srcPort, uint16_t dstPort = 80 )
{
    PacketRecord pkt;
    pkt.transport = transport;
    pkt.srcIp = src;
    pkt.dstIp = "10.0.0.1";
    pkt.srcPort = srcPort;
    pkt.dstPort = dstPort;
    return pkt;
}

/// The reply to @p pkt: the same conversation, the other direction.
PacketRecord replyTo( PacketRecord pkt )
{
    std::swap( pkt.srcIp, pkt.dstIp );
    std::swap( pkt.srcPort, pkt.dstPort );
    return pkt;
}

} // namespace

SCENARIO( "The Stream Tracker numbers TCP and UDP conversations", "[stream_tracker]" )
{
    StreamTracker tracker;

    GIVEN( "a TCP conversation in both directions" )
    {
        const auto syn = packetOver( Transport::Tcp, "10.0.0.2", 1000 );

        THEN( "both directions share stream 0" )
        {
            REQUIRE( tracker.track( syn ).id == 0 );
            REQUIRE( tracker.track( replyTo( syn ) ).id == 0 );
            REQUIRE( tracker.track( syn ).id == 0 );
        }
    }

    GIVEN( "two TCP conversations between the same hosts" )
    {
        THEN( "they are told apart by their ports" )
        {
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1000 ) ).id == 0 );
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1001 ) ).id == 1 );
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1000 ) ).id == 0 );
        }
    }

    GIVEN( "TCP and UDP conversations interleaved" )
    {
        THEN( "each transport is numbered on its own, from 0, like tcp.stream and udp.stream" )
        {
            REQUIRE( tracker.track( packetOver( Transport::Udp, "10.0.0.2", 53 ) ).id == 0 );
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1000 ) ).id == 0 );
            REQUIRE( tracker.track( packetOver( Transport::Udp, "10.0.0.3", 53 ) ).id == 1 );
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.3", 1000 ) ).id == 1 );
        }

        THEN( "the same addresses and ports over TCP and over UDP are two streams" )
        {
            const auto overTcp = tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 53 ) );
            const auto overUdp = tracker.track( packetOver( Transport::Udp, "10.0.0.2", 53 ) );
            REQUIRE( overTcp.id == 0 );
            REQUIRE( overUdp.id == 0 );
            REQUIRE( overTcp.state != overUdp.state );
        }
    }

    GIVEN( "a packet without a TCP or UDP header" )
    {
        // ICMP, ARP, an IP fragment after the first, a truncated TCP header:
        // the parser sets no transport for any of them.
        auto icmp = packetOver( std::nullopt, "10.0.0.2", 0, 0 );
        icmp.protocol = "ICMP";
        PacketRecord arp;
        arp.protocol = "ARP";
        arp.srcIp = "10.0.0.2";
        arp.dstIp = "10.0.0.1";

        THEN( "it has no stream, and numbers none" )
        {
            REQUIRE( tracker.track( icmp ).id == kNoStream );
            REQUIRE( tracker.track( icmp ).state == nullptr );
            REQUIRE( tracker.track( arp ).id == kNoStream );
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1000 ) ).id == 0 );
        }
    }
}

SCENARIO( "Each stream has a state slot", "[stream_tracker]" )
{
    StreamTracker tracker;
    const auto first = packetOver( Transport::Tcp, "10.0.0.2", 1000 );

    GIVEN( "a slot written through the first packet of a stream" )
    {
        auto* state = tracker.track( first ).state;
        REQUIRE( state != nullptr );

        THEN( "every later packet of the stream, in either direction, gets that same slot" )
        {
            // Many more streams in between must not move it.
            for ( uint16_t port = 1; port < 2000; ++port ) {
                tracker.track( packetOver( Transport::Udp, "10.0.0.3", port ) );
                tracker.track( packetOver( Transport::Tcp, "10.0.0.3", port ) );
            }
            REQUIRE( tracker.track( replyTo( first ) ).state == state );
            REQUIRE( tracker.track( first ).state == state );
        }

        THEN( "another stream gets another slot" )
        {
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1001 ) ).state
                     != state );
        }
    }
}

SCENARIO( "The Stream Tracker stops numbering at its cap", "[stream_tracker]" )
{
    GIVEN( "a tracker that numbers at most two streams" )
    {
        StreamTracker tracker( 2 );

        THEN( "a third conversation is unnumbered, while known ones keep their number" )
        {
            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1 ) ).id == 0 );
            REQUIRE( tracker.track( packetOver( Transport::Udp, "10.0.0.2", 2 ) ).id == 0 );
            REQUIRE_FALSE( tracker.limitReached() );

            const auto third = tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 3 ) );
            REQUIRE( third.id == kUnnumbered );
            REQUIRE( third.state == nullptr );
            REQUIRE( tracker.limitReached() );

            REQUIRE( tracker.track( packetOver( Transport::Tcp, "10.0.0.2", 1 ) ).id == 0 );
            REQUIRE( tracker.track( packetOver( Transport::Udp, "10.0.0.2", 2 ) ).id == 0 );
        }

        THEN( "packets without a stream do not count towards the cap" )
        {
            REQUIRE( tracker.track( packetOver( std::nullopt, "10.0.0.2", 0, 0 ) ).id
                     == kNoStream );
            REQUIRE_FALSE( tracker.limitReached() );
        }
    }
}

SCENARIO( "IPv6 conversations pair both directions in compressed form", "[stream_tracker]" )
{
    GIVEN( "a TCP segment from fe80::1 to fe80::2 and its reply" )
    {
        auto request = ipv6( IpProtoTcp, tcp( 40000, 22 ) );
        auto reply = ipv6( IpProtoTcp, tcp( 22, 40000 ) );
        std::swap_ranges( reply.begin() + 8, reply.begin() + 24, reply.begin() + 24 );
        const auto result
            = parse( pcapOf( { eth( EthertypeIpv6, request ), eth( EthertypeIpv6, reply ) } ) );
        REQUIRE( result.packets.size() == 2 );

        THEN( "both directions share one stream and each address counts both packets" )
        {
            REQUIRE( result.packets[ 0 ].srcIp == "fe80::1" );
            REQUIRE( result.packets[ 1 ].srcIp == "fe80::2" );

            StreamTracker tracker;
            CaptureStats stats;
            for ( const auto& pkt : result.packets ) {
                REQUIRE( tracker.track( pkt ).id == 0 );
                stats.add( pkt );
            }
            REQUIRE( stats.endpointPackets.size() == 2 );
            REQUIRE( stats.endpointPackets.at( "fe80::1" ) == 2 );
            REQUIRE( stats.endpointPackets.at( "fe80::2" ) == 2 );
        }
    }
}
