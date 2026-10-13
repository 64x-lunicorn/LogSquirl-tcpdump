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
 * @file packet_line_test.cpp
 * @brief BDD tests for reading a packet line back: the round trip from the
 *        Packet Formatter to readPacketLine().
 */

#include <catch2/catch.hpp>

#include "corpus_layouts.h"
#include "packet_formatter.h"
#include "packet_line.h"
#include "pcapbuilder.h"

#include <algorithm>
#include <array>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kAck = 0x10;

/// From @p src to @p dst.
Ipv4Options between( std::array<uint8_t, 4> src, std::array<uint8_t, 4> dst )
{
    Ipv4Options o;
    std::copy( src.begin(), src.end(), o.src );
    std::copy( dst.begin(), dst.end(), o.dst );
    return o;
}

/// The way back of the builder's default packet, from 192.168.1.2 to 192.168.1.1.
const auto kBack = between( { 192, 168, 1, 2 }, { 192, 168, 1, 1 } );

/// What a packet line must read back as.
struct Expected {
    uint32_t number;
    int stream;
    const char* source;
    const char* destination;
    const char* irtt;
};

} // namespace

SCENARIO( "A packet line reads back as the Packet Formatter wrote it", "[packet_formatter]" )
{
    GIVEN( "a TCP handshake, each segment a second after the one before, a UDP datagram and "
           "an ICMP echo" )
    {
        const Bytes echoRequest{ 8, 0, 0, 0, 0, 1, 0, 1 };
        const auto capture = pcapOf( {
            eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 443, {}, 5, kSyn, 100 ) ) ),
            eth( EthertypeIpv4,
                 ipv4( IpProtoTcp, tcp( 443, 40000, {}, 5, kSyn | kAck, 500, 101 ), kBack ) ),
            eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 443, {}, 5, kAck, 101, 501 ) ) ),
            eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 50000, 9999 ) ) ),
            eth( EthertypeIpv4, ipv4( IpProtoIcmp, echoRequest ) ),
        } );
        const std::array<Expected, 5> expected{ {
            { 1, 0, "192.168.1.1", "192.168.1.2", "" },
            { 2, 0, "192.168.1.2", "192.168.1.1", "" },
            { 3, 0, "192.168.1.1", "192.168.1.2", "2.000000" },
            { 4, 0, "192.168.1.1", "192.168.1.2", "" },
            { 5, kNoStream, "192.168.1.1", "192.168.1.2", "" },
        } };

        WHEN( "its lines are formatted in every Line Layout and read back" )
        {
            THEN( "each reads back its packet number, stream, addresses and iRTT, and the "
                  "header is no packet line" )
            {
                for ( const auto& layout : allLineLayouts() ) {
                    INFO( describeLayout( layout ) );
                    const auto lines = formatAllPackets( capture, {}, layout );
                    REQUIRE( lines.size() == expected.size() + 1 );
                    REQUIRE_FALSE( readPacketLine( QString::fromStdString( lines[ 0 ] ) ) );
                    for ( size_t i = 0; i < expected.size(); ++i ) {
                        const auto& line = lines[ i + 1 ];
                        INFO( line );
                        const auto read = readPacketLine( QString::fromStdString( line ) );
                        REQUIRE( read );
                        CHECK( read->number == expected[ i ].number );
                        CHECK( read->stream == expected[ i ].stream );
                        CHECK( read->source == expected[ i ].source );
                        CHECK( read->destination == expected[ i ].destination );
                        CHECK( read->irtt == expected[ i ].irtt );
                    }
                }
            }
        }
    }

    GIVEN( "a TCP packet past the stream cap whose Info shows an iRTT to the nanosecond" )
    {
        PacketRecord pkt;
        pkt.number = 1234567;
        pkt.transport = Transport::Tcp;
        pkt.srcIp = "fe80::1";
        pkt.dstIp = "fe80::2";
        pkt.protocol = "TCP";
        pkt.info = "40000 \xe2\x86\x92 80 [ACK] Seq=1 Ack=1 Win=512 [iRTT=0.000123456]";

        WHEN( "its line is formatted unnumbered in every Line Layout and read back" )
        {
            THEN( "it reads back unnumbered, with its packet number and iRTT" )
            {
                for ( const auto& layout : allLineLayouts() ) {
                    INFO( describeLayout( layout ) );
                    PacketFormatter formatter( TimePrecision::Nanoseconds, layout );
                    const auto line = formatter.format( pkt, kUnnumbered );
                    INFO( line );
                    const auto read = readPacketLine( QString::fromStdString( line ) );
                    REQUIRE( read );
                    CHECK( read->number == 1234567 );
                    CHECK( read->stream == kUnnumbered );
                    CHECK( read->source == "fe80::1" );
                    CHECK( read->destination == "fe80::2" );
                    CHECK( read->irtt == "0.000123456" );
                    CHECK( read->body.endsWith( "[iRTT=0.000123456]" ) );
                }
            }
        }
    }

    GIVEN( "a numbered UDP packet" )
    {
        PacketRecord pkt;
        pkt.number = 9;
        pkt.transport = Transport::Udp;
        pkt.srcIp = "10.0.0.1";
        pkt.dstIp = "10.0.0.2";
        pkt.protocol = "UDP";
        pkt.info = "53 \xe2\x86\x92 53 Len=0";

        WHEN( "its line is formatted and read back" )
        {
            PacketFormatter formatter;
            const auto read
                = readPacketLine( QString::fromStdString( formatter.format( pkt, 42 ) ) );

            THEN( "it reads back its stream and no iRTT" )
            {
                REQUIRE( read );
                CHECK( read->number == 9 );
                CHECK( read->stream == 42 );
                CHECK( read->protocol == "UDP" );
                CHECK( read->body == QString::fromUtf8( "53 \xe2\x86\x92 53 Len=0" ) );
                CHECK( read->irtt.isEmpty() );
            }
        }
    }
}

SCENARIO( "A line that is no packet line reads back as none", "[packet_formatter]" )
{
    THEN( "a line of another log is none" )
    {
        REQUIRE_FALSE( readPacketLine( "2026-10-09 12:00:00 INFO 10.0.0.1 TCP" ) );
        REQUIRE_FALSE( readPacketLine( "" ) );
    }

    THEN( "a packet number no packet can have reads back as 0" )
    {
        for ( const auto* line : { "0 1 0.000000 10.0.0.1 10.0.0.2 UDP 60 x",
                                   "99999999999 1 0.000000 10.0.0.1 10.0.0.2 UDP 60 x" } ) {
            INFO( line );
            const auto read = readPacketLine( line );
            REQUIRE( read );
            REQUIRE( read->number == 0 );
            REQUIRE( read->stream == 1 );
        }
    }

    THEN( "a stream number no stream can have reads back as past the numbered ones" )
    {
        const auto read = readPacketLine( "1 99999999999 0.000000 10.0.0.1 10.0.0.2 UDP 60 x" );
        REQUIRE( read );
        REQUIRE( read->number == 1 );
        REQUIRE( read->stream == kUnnumbered );
    }
}
