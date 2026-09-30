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
 * @file pcap_layers_test.cpp
 * @brief BDD tests for how the parser walks link, network and transport layers.
 */

#include <catch2/catch.hpp>

#include "pcapbuilder.h"

using namespace tcpdump;
using namespace tcpdump_test;

SCENARIO( "The IP length fields bound the transport data", "[pcap_parser]" )
{
    const auto payload = text( "0123456789" );

    GIVEN( "an Ethernet frame padded behind a short IPv4 packet" )
    {
        auto file = pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001 ) ) ) + Bytes( 6, 0 ) } );

        THEN( "the padding is not counted as payload" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].payloadLen == 0 );
        }
    }

    GIVEN( "an outgoing TSO packet captured with IPv4 total length 0" )
    {
        Ipv4Options o;
        o.totalLength = 0;
        auto file = pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, payload ), o ) ) } );

        THEN( "its captured bytes are taken as the packet, like Wireshark does" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].payloadLen == payload.size() );
            REQUIRE( result.packets[ 0 ].info.find( "Len=10" ) != std::string::npos );
        }
    }

    GIVEN( "an IPv4 total length smaller than the IPv4 header" )
    {
        Ipv4Options o;
        o.totalLength = 12;
        auto file = pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, payload ), o ) ) } );

        THEN( "the transport layer is still parsed from the captured bytes" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].protocol == "TCP" );
            REQUIRE( result.packets[ 0 ].srcPort == 40000 );
            REQUIRE( result.packets[ 0 ].payloadLen == payload.size() );
        }
    }

    GIVEN( "an IPv6 packet with payload length 0 (TSO or jumbogram)" )
    {
        auto file = pcapOf(
            { eth( EthertypeIpv6, ipv6( IpProtoTcp, tcp( 40000, 40001, payload ), 0 ) ) } );

        THEN( "its captured bytes are taken as the payload" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].protocol == "TCP" );
            REQUIRE( result.packets[ 0 ].payloadLen == payload.size() );
        }
    }

    GIVEN( "a padded IPv6 frame" )
    {
        auto file = pcapOf(
            { eth( EthertypeIpv6, ipv6( IpProtoUdp, udp( 40000, 40001 ) ) ) + Bytes( 4, 0 ) } );

        THEN( "the padding is not counted as payload" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].payloadLen == 0 );
        }
    }
}
