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

#include <algorithm>

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

SCENARIO( "Payload previews are capped", "[pcap_parser]" )
{
    GIVEN( "a TCP segment with 1000 bytes of text" )
    {
        const std::string longText( 1000, 'x' );
        auto file = pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, text( longText ) ) ) ) } );

        THEN( "the preview shows the first 200 characters and an ellipsis" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& info = result.packets[ 0 ].info;
            const auto preview = info.substr( info.find( " | " ) + 3 );
            REQUIRE( preview == std::string( 200, 'x' ) + "\xe2\x80\xa6" );
        }
    }

    GIVEN( "a text payload of exactly 200 characters" )
    {
        const std::string exact( 200, 'y' );
        auto file = pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 40001, text( exact ) ) ) ) } );

        THEN( "it is shown without an ellipsis" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& info = result.packets[ 0 ].info;
            REQUIRE( info.substr( info.find( " | " ) + 3 ) == exact );
        }
    }

    GIVEN( "a mostly binary payload with a little text in front" )
    {
        auto payload = text( "GET" ) + Bytes( 5000, 0x00 );
        auto file
            = pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, payload ) ) ) } );

        THEN( "no preview is shown" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].info.find( " | " ) == std::string::npos );
        }
    }
}

SCENARIO( "Payload text never breaks the one-line-per-packet format", "[pcap_parser]" )
{
    auto noControlChars = []( const std::string& s ) {
        return std::none_of( s.begin(), s.end(),
                             []( char c ) { return static_cast<unsigned char>( c ) < 0x20; } );
    };

    GIVEN( "a DNS query for a name with a newline and an escape character in a label" )
    {
        Bytes dns{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        dns = dns + Bytes{ 5, 'a', '\n', 'b', 0x1B, 'c', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1 };
        auto file = pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 53, dns ) ) ) } );

        THEN( "the name is shown with the control characters escaped" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& info = result.packets[ 0 ].info;
            REQUIRE( noControlChars( info ) );
            REQUIRE( info.find( "Query a\\x0Ab\\x1Bc.com" ) != std::string::npos );
        }
    }

    GIVEN( "an HTTP request line with a control character" )
    {
        auto file = pcapOf( { eth(
            EthertypeIpv4,
            ipv4( IpProtoTcp, tcp( 40000, 80, text( "GET /\x1b[2J HTTP/1.1\r\n\r\n" ) ) ) ) } );

        THEN( "the control character is escaped" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& info = result.packets[ 0 ].info;
            REQUIRE( noControlChars( info ) );
            REQUIRE( info.find( "GET /\\x1B[2J HTTP/1.1" ) != std::string::npos );
        }
    }

    GIVEN( "an NMEA sentence with a tab and a byte above 0x7F" )
    {
        auto file = pcapOf(
            { eth( EthertypeIpv4,
                   ipv4( IpProtoUdp, udp( 40000, 10110, text( "$GPGGA,1\t2,\xff*47\r\n" ) ) ) ) } );

        THEN( "both are escaped" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& info = result.packets[ 0 ].info;
            REQUIRE( noControlChars( info ) );
            REQUIRE( info.find( "$GPGGA,1\\x092,\\xFF*47" ) != std::string::npos );
        }
    }
}
