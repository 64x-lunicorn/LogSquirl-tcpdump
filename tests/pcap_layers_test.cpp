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

#include "packet_formatter.h"
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

SCENARIO( "Captures with nanosecond timestamps are read", "[pcap_parser]" )
{
    const auto packet = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 1, 2 ) ) );

    for ( const bool bigEndian : { false, true } ) {
        GIVEN( std::string( "a nanosecond capture in " ) + ( bigEndian ? "big" : "little" )
               + "-endian byte order" )
        {
            FileOptions o;
            o.nanoseconds = true;
            o.bigEndian = bigEndian;
            auto file = pcapFile( { { packet, 1000, 5 }, { packet, 1000, 123456789 } }, o );

            THEN( "its packets are parsed with their nanoseconds" )
            {
                auto result = parse( file );
                REQUIRE( result.ok );
                REQUIRE( result.header.nanoseconds );
                REQUIRE( result.packets.size() == 2 );
                REQUIRE( result.packets[ 1 ].timestampSec == 1000 );
                REQUIRE( result.packets[ 1 ].timestampNsec == 123456789 );
                REQUIRE( result.packets[ 1 ].srcPort == 1 );
            }

            THEN( "the relative time is shown to the nanosecond" )
            {
                auto result = parse( file );
                PacketFormatter formatter( result.header.nanoseconds );
                formatter.format( result.packets[ 0 ] );
                const auto line = formatter.format( result.packets[ 1 ] );
                REQUIRE( line.find( " 0.123456784 " ) != std::string::npos );
                REQUIRE( formatter.header().find( "Time" ) != std::string::npos );
            }
        }
    }

    GIVEN( "a microsecond capture" )
    {
        auto file = pcapFile( { { packet, 1000, 5 }, { packet, 1001, 250000 } } );

        THEN( "timestamps are kept in nanoseconds and shown to the microsecond" )
        {
            auto result = parse( file );
            REQUIRE_FALSE( result.header.nanoseconds );
            REQUIRE( result.packets[ 1 ].timestampNsec == 250000000 );
            PacketFormatter formatter( false );
            formatter.format( result.packets[ 0 ] );
            REQUIRE( formatter.format( result.packets[ 1 ] ).find( " 1.249995 " )
                     != std::string::npos );
        }
    }

    GIVEN( "a packet earlier than the first one" )
    {
        auto file = pcapFile( { { packet, 1000, 500000 }, { packet, 999, 900000 } } );

        THEN( "its relative time is negative instead of wrapping or reading zero" )
        {
            auto result = parse( file );
            PacketFormatter formatter( false );
            formatter.format( result.packets[ 0 ] );
            REQUIRE( formatter.format( result.packets[ 1 ] ).find( " -0.600000 " )
                     != std::string::npos );
        }
    }
}

SCENARIO( "BSD loopback captures are read in the capture's byte order", "[pcap_parser]" )
{
    const auto v4 = ipv4( IpProtoUdp, udp( 1, 2 ) );
    const auto v6 = ipv6( IpProtoUdp, udp( 3, 4 ) );

    auto loopback = []( uint32_t family, bool bigEndian, const Bytes& payload ) {
        Bytes b;
        bigEndian ? putBE32( b, family ) : putLE32( b, family );
        return b + payload;
    };

    for ( const bool bigEndian : { false, true } ) {
        GIVEN( std::string( "a DLT_NULL capture in " ) + ( bigEndian ? "big" : "little" )
               + "-endian byte order" )
        {
            FileOptions o;
            o.linkType = DltNull;
            o.bigEndian = bigEndian;
            std::vector<Record> records{ { loopback( 2, bigEndian, v4 ) } };
            for ( const uint32_t af6 : { 24u, 28u, 30u } ) {
                records.push_back( { loopback( af6, bigEndian, v6 ) } );
            }
            records.push_back( { loopback( 99, bigEndian, v4 ) } );

            THEN( "AF_INET is IPv4, the BSD AF_INET6 values are IPv6, others are unknown" )
            {
                auto result = parse( pcapFile( records, o ) );
                REQUIRE( result.packets.size() == 5 );
                REQUIRE( result.packets[ 0 ].srcPort == 1 );
                REQUIRE( result.packets[ 0 ].etherType == EthertypeIpv4 );
                for ( size_t i = 1; i <= 3; ++i ) {
                    REQUIRE( result.packets[ i ].srcPort == 3 );
                    REQUIRE( result.packets[ i ].etherType == EthertypeIpv6 );
                }
                REQUIRE( result.packets[ 4 ].srcIp.empty() );
                REQUIRE( result.packets[ 4 ].info == "Address family 99" );
            }
        }
    }

    GIVEN( "a DLT_NULL capture whose family is in the other byte order than the file" )
    {
        FileOptions o;
        o.linkType = DltNull;
        auto file = pcapFile( { { loopback( 2, true, v4 ) } }, o );

        THEN( "the family is still recognised" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].srcPort == 1 );
        }
    }

    GIVEN( "a DLT_LOOP capture, whose family is always big-endian" )
    {
        FileOptions o;
        o.linkType = DltLoop;
        auto file = pcapFile( { { loopback( 30, true, v6 ) } }, o );

        THEN( "it is read" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].srcPort == 3 );
        }
    }
}

SCENARIO( "IPv6 extension headers are walked to the transport layer", "[pcap_parser]" )
{
    auto parseOne = []( const Bytes& ipPacket ) {
        auto result = parse( pcapOf( { eth( EthertypeIpv6, ipPacket ) } ) );
        REQUIRE( result.packets.size() == 1 );
        return result.packets[ 0 ];
    };

    GIVEN( "a UDP packet behind a hop-by-hop options header" )
    {
        auto pkt
            = parseOne( ipv6( 0, ipv6Options( IpProtoUdp, udp( 5353, 5353, text( "abc" ) ) ) ) );

        THEN( "the UDP layer is found" )
        {
            REQUIRE( pkt.ipProtocol == IpProtoUdp );
            REQUIRE( pkt.srcPort == 5353 );
            REQUIRE( pkt.payloadLen == 3 );
        }
    }

    GIVEN( "a TCP segment behind hop-by-hop, destination options, routing and AH headers" )
    {
        Bytes ah{ IpProtoTcp, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0 }; // (2+2)*4 = 16 bytes
        auto inner = ipv6Options(
            60, ipv6Options( 43, ipv6Options( 51, ah + tcp( 40000, 22, text( "hi" ) ) ) ) );
        auto pkt = parseOne( ipv6( 0, inner ) );

        THEN( "the TCP layer and its payload are found" )
        {
            REQUIRE( pkt.srcPort == 40000 );
            REQUIRE( pkt.dstPort == 22 );
            REQUIRE( pkt.payloadLen == 2 );
        }
    }

    GIVEN( "an extension header that claims more bytes than there are" )
    {
        Bytes bogus{ IpProtoUdp, 200, 0, 0, 0, 0, 0, 0 };
        auto pkt = parseOne( ipv6( 0, bogus ) );

        THEN( "it is reported as truncated" )
        {
            REQUIRE( pkt.protocol == "IPv6" );
            REQUIRE( pkt.info.find( "Truncated" ) != std::string::npos );
        }
    }

    GIVEN( "the first fragment of a UDP datagram" )
    {
        auto pkt
            = parseOne( ipv6( 44, ipv6Fragment( IpProtoUdp, 0, true, udp( 1, 2, text( "x" ) ) ) ) );

        THEN( "its UDP header is parsed" )
        {
            REQUIRE( pkt.protocol == "UDP" );
            REQUIRE( pkt.srcPort == 1 );
        }
    }

    GIVEN( "a later fragment, whose data merely looks like a UDP header" )
    {
        auto pkt = parseOne(
            ipv6( 44, ipv6Fragment( IpProtoUdp, 185, false, udp( 1, 2, text( "x" ) ) ) ) );

        THEN( "it is shown as a fragment, without ports" )
        {
            REQUIRE( pkt.protocol == "IPv6" );
            REQUIRE( pkt.srcPort == 0 );
            REQUIRE( pkt.info == "Fragment of IP protocol 17 (offset 1480, ID 0x0000CAFE)" );
        }
    }
}

SCENARIO( "IPv4 fragments after the first are not parsed as TCP or UDP", "[pcap_parser]" )
{
    auto parseOne = []( const Bytes& ipPacket ) {
        auto result = parse( pcapOf( { eth( EthertypeIpv4, ipPacket ) } ) );
        REQUIRE( result.packets.size() == 1 );
        return result.packets[ 0 ];
    };

    GIVEN( "the first fragment of a TCP segment (more fragments, offset 0)" )
    {
        Ipv4Options o;
        o.fragment = 0x2000;
        auto pkt = parseOne( ipv4( IpProtoTcp, tcp( 40000, 80 ), o ) );

        THEN( "its TCP header is parsed" )
        {
            REQUIRE( pkt.srcPort == 40000 );
        }
    }

    GIVEN( "a later fragment of a TCP segment" )
    {
        Ipv4Options o;
        o.fragment = 185; // 1480 bytes
        auto pkt = parseOne( ipv4( IpProtoTcp, tcp( 40000, 80 ), o ) );

        THEN( "it is shown as a fragment, without ports" )
        {
            REQUIRE( pkt.protocol == "IPv4" );
            REQUIRE( pkt.srcPort == 0 );
            REQUIRE( pkt.srcIp == "192.168.1.1" );
            REQUIRE( pkt.info == "Fragment of IP protocol 6 (offset 1480, ID 0x1234)" );
        }
    }
}

SCENARIO( "A TCP header shorter than 20 bytes is malformed", "[pcap_parser]" )
{
    GIVEN( "a TCP segment whose data offset says 12 bytes" )
    {
        auto file = pcapOf(
            { eth( EthertypeIpv4,
                   ipv4( IpProtoTcp, tcp( 40000, 80, text( "GET / HTTP/1.1\r\n" ), 3 ) ) ) } );

        THEN( "no header bytes are taken for payload, and the length is flagged" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            const auto& pkt = result.packets[ 0 ];
            REQUIRE( pkt.srcPort == 40000 );
            REQUIRE( pkt.payloadLen == 0 );
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.info.find( "bogus TCP header length (12" ) != std::string::npos );
            REQUIRE( pkt.info.find( "GET" ) == std::string::npos );
        }
    }
}

SCENARIO( "Stacked VLAN tags are stripped", "[pcap_parser]" )
{
    const auto ip = ipv4( IpProtoUdp, udp( 7, 8 ) );

    auto parseOne = []( const Bytes& frame, uint32_t linkType = DltEthernet ) {
        auto result = parse( pcapOf( { frame }, linkType ) );
        REQUIRE( result.packets.size() == 1 );
        return result.packets[ 0 ];
    };

    GIVEN( "a QinQ frame: an 802.1ad service tag around an 802.1Q customer tag" )
    {
        auto pkt = parseOne(
            eth( EthertypeQinQ, vlanTag( 10, EthertypeVlan, vlanTag( 20, EthertypeIpv4, ip ) ) ) );

        THEN( "the IPv4 packet inside is parsed" )
        {
            REQUIRE( pkt.etherType == EthertypeIpv4 );
            REQUIRE( pkt.srcPort == 7 );
        }
    }

    GIVEN( "three stacked 802.1Q tags, and a legacy 0x9100 tag" )
    {
        auto pkt = parseOne( eth(
            0x9100,
            vlanTag( 1, EthertypeVlan,
                     vlanTag( 2, EthertypeVlan,
                              vlanTag( 3, EthertypeVlan, vlanTag( 4, EthertypeIpv4, ip ) ) ) ) ) );

        THEN( "the IPv4 packet inside is parsed" )
        {
            REQUIRE( pkt.srcPort == 7 );
        }
    }

    GIVEN( "a tag cut off by the end of the frame" )
    {
        auto pkt = parseOne( eth( EthertypeVlan, Bytes{ 0x00 } ) );

        THEN( "it is shown by its EtherType, without reading past the frame" )
        {
            REQUIRE( pkt.protocol == "ETH(0x8100)" );
        }
    }

    GIVEN( "a VLAN-tagged packet in a Linux cooked capture" )
    {
        Bytes sll( 16, 0 );
        sll[ 14 ] = 0x81;
        sll[ 15 ] = 0x00;
        auto pkt = parseOne( sll + vlanTag( 5, EthertypeIpv4, ip ), DltLinuxSll );

        THEN( "the tag is stripped too" )
        {
            REQUIRE( pkt.srcPort == 7 );
        }
    }
}

SCENARIO( "The pcap header is found only where it can really start", "[pcap_parser]" )
{
    const auto capture = pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 7, 8 ) ) ) } );

    GIVEN( "binary data with a stray pcap magic in it" )
    {
        auto file = Bytes{ 0x00, 0x01, 0xFE, 0x42 } + capture;

        THEN( "it is not taken for a capture" )
        {
            auto result = parse( file );
            REQUIRE_FALSE( result.ok );
            REQUIRE( result.error.find( "no pcap magic" ) != std::string::npos );
        }
    }

    GIVEN( "a text preamble followed by a magic whose header is not a pcap header" )
    {
        auto bogus = capture;
        bogus[ 4 ] = 0x09; // version 9.4
        auto file = text( "tcpdump: listening on eth0\n" ) + bogus;

        THEN( "it is rejected" )
        {
            auto result = parse( file );
            REQUIRE_FALSE( result.ok );
            REQUIRE( result.error.find( "no pcap magic" ) != std::string::npos );
        }
    }

    GIVEN( "a text preamble with CRLF line ends and a tab, then a capture" )
    {
        auto file = text( "tcpdump: verbose output suppressed\r\n\tlistening\r\n" ) + capture;

        THEN( "the capture is read" )
        {
            auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.packets.size() == 1 );
        }
    }

    GIVEN( "a capture with an unsupported version at the start of the file" )
    {
        FileOptions o;
        o.versionMajor = 1;
        o.versionMinor = 0;
        auto file = pcapFile( {}, o );

        THEN( "it is rejected, naming the version" )
        {
            auto result = parse( file );
            REQUIRE_FALSE( result.ok );
            REQUIRE( result.error.find( "version 1.0" ) != std::string::npos );
        }
    }
}

SCENARIO( "A TCP segment without flags shows [none]", "[pcap_parser]" )
{
    GIVEN( "a TCP segment with no flag set" )
    {
        auto file
            = pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, {}, 5, 0 ) ) ) } );

        THEN( "its flags read [none], as formatTcpFlags() renders them" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].info.find( "40000 \xe2\x86\x92 40001 [none] Seq=" )
                     != std::string::npos );
        }
    }
}

SCENARIO( "Len is taken from the IP header when the capture was cut at the snaplen",
          "[pcap_parser]" )
{
    const auto payload = text( std::string( 1460, 'a' ) );

    GIVEN( "an IPv4 TCP segment of 1460 bytes captured with -s 96" )
    {
        auto frame = eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, payload ) ) );
        frame.resize( 96 );
        auto result = parse( pcapOf( { frame } ) );

        THEN( "Len is the segment's length, and only the captured bytes are previewed" )
        {
            REQUIRE( result.packets.size() == 1 );
            const auto& pkt = result.packets[ 0 ];
            REQUIRE( pkt.payloadLen == 1460 );
            REQUIRE( pkt.info.find( "Len=1460" ) != std::string::npos );
            REQUIRE( pkt.info.find( " | " + std::string( 96 - 54, 'a' ) ) != std::string::npos );
            REQUIRE( pkt.info.find( std::string( 96 - 54 + 1, 'a' ) ) == std::string::npos );
        }
    }

    GIVEN( "an IPv6 TCP segment of 1000 bytes behind a hop-by-hop header, cut at 120 bytes" )
    {
        auto frame
            = eth( EthertypeIpv6,
                   ipv6( 0, ipv6Options( IpProtoTcp, tcp( 40000, 40001,
                                                          text( std::string( 1000, 'b' ) ) ) ) ) );
        frame.resize( 120 );
        auto result = parse( pcapOf( { frame } ) );

        THEN( "Len is the segment's length" )
        {
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].payloadLen == 1000 );
            REQUIRE( result.packets[ 0 ].info.find( "Len=1000" ) != std::string::npos );
        }
    }

    GIVEN( "an IPv4 packet cut off inside its TCP header" )
    {
        auto frame = eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 40001, payload ) ) );
        frame.resize( 14 + 20 + 10 );
        auto result = parse( pcapOf( { frame } ) );

        THEN( "no TCP fields are made up" )
        {
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].srcPort == 0 );
        }
    }
}
