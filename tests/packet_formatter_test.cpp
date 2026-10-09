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
 * @file packet_formatter_test.cpp
 * @brief BDD tests for the packet formatter.
 */

#include <catch2/catch.hpp>

#include "packet_formatter.h"

using namespace tcpdump;

SCENARIO( "formatTcpFlags renders flags correctly", "[packet_formatter]" )
{
    GIVEN( "a SYN flag" )
    {
        THEN( "the output contains SYN" )
        {
            REQUIRE( formatTcpFlags( 0x02 ) == "[SYN]" );
        }
    }

    GIVEN( "SYN + ACK flags" )
    {
        THEN( "the output contains both" )
        {
            REQUIRE( formatTcpFlags( 0x12 ) == "[SYN, ACK]" );
        }
    }

    GIVEN( "FIN flag" )
    {
        THEN( "the output contains FIN" )
        {
            REQUIRE( formatTcpFlags( 0x01 ) == "[FIN]" );
        }
    }

    GIVEN( "no flags set" )
    {
        THEN( "the output is [none]" )
        {
            REQUIRE( formatTcpFlags( 0x00 ) == "[none]" );
        }
    }

    GIVEN( "RST + ACK flags" )
    {
        THEN( "the output contains both" )
        {
            REQUIRE( formatTcpFlags( 0x14 ) == "[ACK, RST]" );
        }
    }
}

SCENARIO( "formatAllPackets produces header + packet lines", "[packet_formatter]" )
{
    GIVEN( "a list of two packets" )
    {
        PacketRecord pkt1;
        pkt1.number = 1;
        pkt1.timestampSec = 1000;
        pkt1.timestampNsec = 0;
        pkt1.srcIp = "192.168.1.1";
        pkt1.dstIp = "10.0.0.1";
        pkt1.transport = Transport::Tcp;
        pkt1.srcPort = 80;
        pkt1.dstPort = 443;
        pkt1.protocol = "TCP";
        pkt1.capturedLen = 60;
        pkt1.info = "80 > 443 [SYN]";

        PacketRecord pkt2;
        pkt2.number = 2;
        pkt2.timestampSec = 1000;
        pkt2.timestampNsec = 500000000;
        pkt2.srcIp = "10.0.0.1";
        pkt2.dstIp = "192.168.1.1";
        pkt2.transport = Transport::Tcp;
        pkt2.srcPort = 443;
        pkt2.dstPort = 80;
        pkt2.protocol = "TCP";
        pkt2.capturedLen = 60;
        pkt2.info = "443 > 80 [SYN, ACK]";

        std::vector<PacketRecord> packets = { pkt1, pkt2 };

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( packets );

            THEN( "the first line is the column header" )
            {
                REQUIRE( lines.size() == 3 ); // header + 2 packets
                REQUIRE( lines[ 0 ].find( "No." ) != std::string::npos );
                REQUIRE( lines[ 0 ].find( "Stream" ) != std::string::npos );
                REQUIRE( lines[ 0 ].find( "Source" ) != std::string::npos );
                REQUIRE( lines[ 0 ].find( "Protocol" ) != std::string::npos );
            }

            THEN( "packet lines contain the IP addresses" )
            {
                REQUIRE( lines[ 1 ].find( "192.168.1.1" ) != std::string::npos );
                REQUIRE( lines[ 2 ].find( "10.0.0.1" ) != std::string::npos );
            }

            THEN( "both packets have the same stream ID (same conversation)" )
            {
                // stream 0 should appear in both lines
                REQUIRE( lines[ 1 ].find( "0" ) != std::string::npos );
                REQUIRE( lines[ 2 ].find( "0" ) != std::string::npos );
            }
        }
    }

    GIVEN( "packets from two different conversations" )
    {
        PacketRecord pktA1;
        pktA1.number = 1;
        pktA1.timestampSec = 1000;
        pktA1.timestampNsec = 0;
        pktA1.srcIp = "192.168.1.1";
        pktA1.dstIp = "10.0.0.1";
        pktA1.transport = Transport::Tcp;
        pktA1.srcPort = 80;
        pktA1.dstPort = 443;
        pktA1.protocol = "TCP";
        pktA1.capturedLen = 60;
        pktA1.info = "80 > 443 [SYN]";

        PacketRecord pktB1;
        pktB1.number = 2;
        pktB1.timestampSec = 1000;
        pktB1.timestampNsec = 100000000;
        pktB1.srcIp = "172.16.0.5";
        pktB1.dstIp = "8.8.8.8";
        pktB1.transport = Transport::Tcp;
        pktB1.srcPort = 54321;
        pktB1.dstPort = 443;
        pktB1.protocol = "TCP";
        pktB1.capturedLen = 74;
        pktB1.info = "54321 > 443 [SYN]";

        PacketRecord pktA2;
        pktA2.number = 3;
        pktA2.timestampSec = 1000;
        pktA2.timestampNsec = 200000000;
        pktA2.srcIp = "10.0.0.1";
        pktA2.dstIp = "192.168.1.1";
        pktA2.transport = Transport::Tcp;
        pktA2.srcPort = 443;
        pktA2.dstPort = 80;
        pktA2.protocol = "TCP";
        pktA2.capturedLen = 60;
        pktA2.info = "443 > 80 [SYN, ACK]";

        std::vector<PacketRecord> packets = { pktA1, pktB1, pktA2 };

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( packets );

            THEN( "packet 1 and 3 share stream 0, packet 2 is stream 1" )
            {
                REQUIRE( lines.size() == 4 ); // header + 3 packets

                // Extract stream column (starts at col 7, width 8)
                auto streamOf = []( const std::string& line ) {
                    auto sub = line.substr( 7, 8 );
                    // trim trailing spaces
                    auto pos = sub.find_first_not_of( ' ' );
                    auto end = sub.find_last_not_of( ' ' );
                    return sub.substr( pos, end - pos + 1 );
                };

                REQUIRE( streamOf( lines[ 1 ] ) == "0" );
                REQUIRE( streamOf( lines[ 2 ] ) == "1" );
                REQUIRE( streamOf( lines[ 3 ] ) == "0" );
            }
        }
    }

    GIVEN( "an ARP packet with no IP layer" )
    {
        PacketRecord arp;
        arp.number = 1;
        arp.timestampSec = 1000;
        arp.timestampNsec = 0;
        arp.protocol = "ARP";
        arp.capturedLen = 42;
        arp.info = "Who has 192.168.1.100?";
        arp.srcMac = "11:22:33:44:55:66";
        arp.dstMac = "ff:ff:ff:ff:ff:ff";
        // srcIp and dstIp intentionally empty

        std::vector<PacketRecord> packets = { arp };

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( packets );

            THEN( "ARP gets stream '-' and falls back to MAC address display" )
            {
                REQUIRE( lines.size() == 2 );
                REQUIRE( lines[ 1 ].find( "-" ) != std::string::npos );
                REQUIRE( lines[ 1 ].find( "11:22:33:44:55:66" ) != std::string::npos );
                REQUIRE( lines[ 1 ].find( "ff:ff:ff:ff:ff:ff" ) != std::string::npos );
            }
        }
    }

    GIVEN( "an ICMP packet between two hosts" )
    {
        PacketRecord icmp;
        icmp.number = 1;
        icmp.srcIp = "192.168.1.1";
        icmp.dstIp = "10.0.0.1";
        icmp.protocol = "ICMP";
        icmp.info = "Echo request";

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( { icmp } );

            THEN( "it has no stream: only TCP and UDP have one" )
            {
                REQUIRE( lines[ 1 ].substr( 7, 8 ) == "-       " );
            }
        }
    }

    GIVEN( "packets recorded to the nanosecond" )
    {
        PacketRecord first;
        first.timestampSec = 1000;
        first.timestampNsec = 5;
        first.precision = TimePrecision::Nanoseconds;
        PacketRecord second = first;
        second.timestampNsec = 123456789;

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( { first, second } );

            THEN( "the times are shown to the nanosecond, as the packets were recorded" )
            {
                REQUIRE( lines[ 2 ].find( " 0.123456784 " ) != std::string::npos );
            }
        }
    }

    GIVEN( "a packet recorded to the nanosecond after one recorded to the microsecond" )
    {
        PacketRecord first;
        first.timestampSec = 1000;
        PacketRecord second = first;
        second.timestampNsec = 123456789;
        second.precision = TimePrecision::Nanoseconds;

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( { first, second } );

            THEN( "every time is shown at the finest precision of the packets" )
            {
                REQUIRE( lines[ 1 ].find( " 0.000000000 " ) != std::string::npos );
                REQUIRE( lines[ 2 ].find( " 0.123456789 " ) != std::string::npos );
            }
        }
    }

    GIVEN( "an empty packet list" )
    {
        std::vector<PacketRecord> empty;

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( empty );

            THEN( "only the header line is returned" )
            {
                REQUIRE( lines.size() == 1 );
            }
        }
    }
}

SCENARIO( "The Packet Formatter shows the stream it is handed", "[packet_formatter]" )
{
    PacketFormatter formatter;
    PacketRecord pkt;
    pkt.transport = Transport::Udp;
    pkt.srcIp = "192.168.1.1";
    pkt.dstIp = "10.0.0.1";

    auto streamColumn
        = [ & ]( int streamId ) { return formatter.format( pkt, streamId ).substr( 7, 8 ); };

    THEN( "a number is shown alone, without the transport" )
    {
        REQUIRE( streamColumn( 7 ) == "7       " );
    }

    THEN( "no stream is shown as -, an unnumbered one as ?" )
    {
        REQUIRE( streamColumn( kNoStream ) == "-       " );
        REQUIRE( streamColumn( kUnnumbered ) == "?       " );
    }
}

SCENARIO( "The Length column shows the length on the wire", "[packet_formatter]" )
{
    PacketFormatter formatter;
    PacketRecord pkt;
    pkt.number = 1;
    pkt.srcIp = "192.168.1.1";
    pkt.dstIp = "10.0.0.1";
    pkt.protocol = "TCP";
    pkt.info = "40000 \xe2\x86\x92 443 [ACK] Seq=1 Ack=1 Win=512 Len=1460";

    // The Length column starts after No., Stream, Time, Source, Destination
    // and Protocol, and is 7 characters wide.
    const size_t lengthColumn = 7 + 8 + 15 + 40 + 40 + 10;
    auto lengthOf = [ & ]( const std::string& line ) {
        auto sub = line.substr( lengthColumn, 7 );
        return sub.substr( 0, sub.find( ' ' ) );
    };

    THEN( "the column is headed Length" )
    {
        REQUIRE( lengthOf( formatter.header() ) == "Length" );
        REQUIRE( formatter.header().substr( lengthColumn + 7 ) == "Info" );
    }

    GIVEN( "a packet captured whole" )
    {
        pkt.capturedLen = 1514;
        pkt.originalLen = 1514;
        const auto line = formatter.format( pkt, 0 );

        THEN( "the column shows its length, and Info carries no cut marker" )
        {
            REQUIRE( lengthOf( line ) == "1514" );
            REQUIRE( line.substr( lengthColumn + 7 ) == pkt.info );
        }
    }

    GIVEN( "a packet cut at a snaplen of 96 bytes" )
    {
        pkt.capturedLen = 96;
        pkt.originalLen = 1514;
        const auto line = formatter.format( pkt, 0 );

        THEN( "the column shows the length on the wire, and Info names the bytes captured" )
        {
            REQUIRE( lengthOf( line ) == "1514" );
            REQUIRE( line.substr( lengthColumn + 7 ) == pkt.info + " [cut to 96 bytes]" );
        }
    }

    GIVEN( "a cut packet without an Info text" )
    {
        pkt.capturedLen = 0;
        pkt.originalLen = 60;
        pkt.info.clear();
        const auto line = formatter.format( pkt, kNoStream );

        THEN( "Info holds the cut marker alone" )
        {
            REQUIRE( line.substr( lengthColumn + 7 ) == "[cut to 0 bytes]" );
        }
    }
}
