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

} // namespace

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
    // The Stream column of a packet line: it starts at column 7, 8 wide.
    auto streamOf = []( const std::string& line ) {
        auto sub = line.substr( 7, 8 );
        return sub.substr( 0, sub.find( ' ' ) );
    };

    GIVEN( "a capture of two packets" )
    {
        const auto capture = pcapOf( {
            eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 443, {}, 5, kSyn, 100 ) ) ),
            eth( EthertypeIpv4,
                 ipv4( IpProtoTcp, tcp( 443, 40000, {}, 5, kSyn | kAck, 500, 101 ), kBack ) ),
        } );

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( capture );

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
                REQUIRE( lines[ 2 ].find( "192.168.1.2" ) != std::string::npos );
            }

            THEN( "both packets have the same stream ID (same conversation)" )
            {
                REQUIRE( streamOf( lines[ 1 ] ) == "0" );
                REQUIRE( streamOf( lines[ 2 ] ) == "0" );
            }
        }
    }

    GIVEN( "packets from two different conversations" )
    {
        const auto capture = pcapOf( {
            eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 443, {}, 5, kSyn, 100 ) ) ),
            eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 54321, 443, {}, 5, kSyn, 700 ),
                                      between( { 172, 16, 0, 5 }, { 8, 8, 8, 8 } ) ) ),
            eth( EthertypeIpv4,
                 ipv4( IpProtoTcp, tcp( 443, 40000, {}, 5, kSyn | kAck, 500, 101 ), kBack ) ),
        } );

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( capture );

            THEN( "packet 1 and 3 share stream 0, packet 2 is stream 1" )
            {
                REQUIRE( lines.size() == 4 ); // header + 3 packets
                REQUIRE( streamOf( lines[ 1 ] ) == "0" );
                REQUIRE( streamOf( lines[ 2 ] ) == "1" );
                REQUIRE( streamOf( lines[ 3 ] ) == "0" );
            }
        }
    }

    GIVEN( "an LLDP frame, with no IP layer" )
    {
        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( pcapOf( { eth( 0x88CC, Bytes( 20, 0 ) ) } ) );

            THEN( "it gets stream '-' and falls back to MAC address display" )
            {
                REQUIRE( lines.size() == 2 );
                REQUIRE( streamOf( lines[ 1 ] ) == "-" );
                REQUIRE( lines[ 1 ].find( "66:77:88:99:aa:bb" ) != std::string::npos );
                REQUIRE( lines[ 1 ].find( "00:11:22:33:44:55" ) != std::string::npos );
            }
        }
    }

    GIVEN( "an ICMP packet between two hosts" )
    {
        const Bytes echoRequest{ 8, 0, 0, 0, 0, 1, 0, 1 };

        WHEN( "formatting" )
        {
            auto lines = formatAllPackets(
                pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoIcmp, echoRequest ) ) } ) );

            THEN( "it has no stream: only TCP and UDP have one" )
            {
                REQUIRE( lines[ 1 ].substr( 7, 8 ) == "-       " );
            }
        }
    }

    GIVEN( "packets recorded to the nanosecond" )
    {
        const auto frame = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999 ) ) );
        FileOptions nanoseconds;
        nanoseconds.nanoseconds = true;
        const auto capture
            = pcapFile( { { frame, 1000, 5 }, { frame, 1000, 123456789 } }, nanoseconds );

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( capture );

            THEN( "the times are shown to the nanosecond, as the packets were recorded" )
            {
                REQUIRE( lines[ 2 ].find( " 0.123456784 " ) != std::string::npos );
            }
        }
    }

    GIVEN( "a packet recorded to the nanosecond after one recorded to the microsecond" )
    {
        const auto frame = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999 ) ) );
        const Pcapng le;
        const auto capture = le.shb() + le.idb( DltEthernet ) + le.idb( DltEthernet, 9 )
                             + le.epb( 0, 1000 * 1000000ull, frame )
                             + le.epb( 1, 1000 * 1000000000ull + 123456789, frame );

        WHEN( "formatting all packets" )
        {
            auto lines = formatAllPackets( capture );

            THEN( "every time is shown at the finest precision the capture announces" )
            {
                REQUIRE( lines[ 1 ].find( " 0.000000000 " ) != std::string::npos );
                REQUIRE( lines[ 2 ].find( " 0.123456789 " ) != std::string::npos );
            }
        }
    }

    GIVEN( "a capture without packets" )
    {
        WHEN( "formatting" )
        {
            auto lines = formatAllPackets( pcapOf( {} ) );

            THEN( "only the header line is returned" )
            {
                REQUIRE( lines.size() == 1 );
            }
        }
    }

    GIVEN( "bytes that are no capture" )
    {
        THEN( "they give no lines" )
        {
            REQUIRE( formatAllPackets( text( "not a capture" ) ).empty() );
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

    // The Length column starts after No., Stream, UTC Time, Time, Source,
    // Destination and Protocol, and is 7 characters wide.
    const size_t lengthColumn = 7 + 8 + 29 + 15 + 40 + 40 + 10;
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

SCENARIO( "formatUtcTime writes a time as an ISO 8601 date and time in UTC", "[packet_formatter]" )
{
    THEN( "the epoch is midnight of 1970-01-01, marked Z" )
    {
        REQUIRE( formatUtcTime( 0, 0, TimePrecision::Microseconds )
                 == "1970-01-01 00:00:00.000000Z" );
    }

    THEN( "a microsecond time has six decimals, the nanoseconds below them cut off" )
    {
        REQUIRE( formatUtcTime( 1791535272, 123456789, TimePrecision::Microseconds )
                 == "2026-10-09 08:41:12.123456Z" );
    }

    THEN( "a nanosecond time has nine decimals" )
    {
        REQUIRE( formatUtcTime( 1791535272, 5, TimePrecision::Nanoseconds )
                 == "2026-10-09 08:41:12.000000005Z" );
    }

    THEN( "leap days and the last second a pcap can hold are dated right" )
    {
        REQUIRE( formatUtcTime( 1709251199, 0, TimePrecision::Microseconds )
                 == "2024-02-29 23:59:59.000000Z" );
        REQUIRE( formatUtcTime( 4294967295, 999999999, TimePrecision::Nanoseconds )
                 == "2106-02-07 06:28:15.999999999Z" );
    }

    THEN( "a time before 1970 counts back from the epoch" )
    {
        REQUIRE( formatUtcTime( -1, 500000000, TimePrecision::Microseconds )
                 == "1969-12-31 23:59:59.500000Z" );
    }

    THEN( "a year outside 0000 to 9999 is written with its sign, as ISO 8601 expands it" )
    {
        REQUIRE( formatUtcTime( 253402300800, 0, TimePrecision::Microseconds )
                 == "+10000-01-01 00:00:00.000000Z" );
        REQUIRE( formatUtcTime( -62167219200, 0, TimePrecision::Microseconds )
                 == "0000-01-01 00:00:00.000000Z" );
        REQUIRE( formatUtcTime( -62167219201, 0, TimePrecision::Microseconds )
                 == "-0001-12-31 23:59:59.000000Z" );
    }

    THEN( "a fraction of a second or more, which no reader passes, is written whole" )
    {
        REQUIRE( formatUtcTime( 0, 1234567890, TimePrecision::Nanoseconds )
                 == "1970-01-01 00:00:00.1234567890Z" );
    }
}

SCENARIO( "The UTC Time column shows each packet's wall-clock time", "[packet_formatter]" )
{
    // The column follows No. and Stream: 27 characters and two spaces, or 30
    // and two for nanoseconds.
    const size_t utcColumn = 7 + 8;

    PacketRecord first;
    first.number = 1;
    first.timestampSec = 1791535272;
    first.timestampNsec = 123456789;
    first.srcIp = "192.168.1.1";
    first.dstIp = "10.0.0.1";
    first.protocol = "ICMP";

    GIVEN( "a capture recorded to the microsecond" )
    {
        PacketFormatter formatter;

        THEN( "the header names the column, and the relative Time follows it" )
        {
            REQUIRE( formatter.header().substr( utcColumn, 29 )
                     == "UTC Time                     " );
            REQUIRE( formatter.header().substr( utcColumn + 29, 4 ) == "Time" );
        }

        THEN( "a packet line carries its date and time with six decimals" )
        {
            REQUIRE( formatter.format( first, kNoStream ).substr( utcColumn, 29 )
                     == "2026-10-09 08:41:12.123456Z  " );
        }

        AND_GIVEN( "a later packet recorded before the first one" )
        {
            PacketRecord earlier = first;
            earlier.number = 2;
            earlier.timestampSec -= 2;
            formatter.format( first, kNoStream );
            const auto line = formatter.format( earlier, kNoStream );

            THEN( "it shows its own absolute time, its relative time negative" )
            {
                REQUIRE( line.substr( utcColumn, 29 ) == "2026-10-09 08:41:10.123456Z  " );
                REQUIRE( line.substr( utcColumn + 29, 15 ) == "-2.000000      " );
            }
        }
    }

    GIVEN( "a capture recorded to the nanosecond" )
    {
        PacketFormatter formatter( TimePrecision::Nanoseconds );

        THEN( "the column is three characters wider and has nine decimals" )
        {
            REQUIRE( formatter.header().substr( utcColumn, 32 )
                     == "UTC Time                        " );
            REQUIRE( formatter.format( first, kNoStream ).substr( utcColumn, 32 )
                     == "2026-10-09 08:41:12.123456789Z  " );
        }
    }
}

SCENARIO( "Every column of a packet line is separated from the next", "[packet_formatter]" )
{
    PacketFormatter formatter;
    PacketRecord pkt;
    pkt.number = 1;
    pkt.srcIp = "192.168.1.1";
    pkt.dstIp = "10.0.0.1";
    pkt.protocol = "UDP";
    pkt.capturedLen = 60;
    pkt.originalLen = 60;
    pkt.info = "443 \xe2\x86\x92 80 Len=18";

    // The columns of a line, as a reader splits them: at runs of spaces,
    // Info being the rest.  UTC Time has a space between date and time, so
    // there are ten.
    auto columnsOf = [ & ]( const std::string& line ) {
        std::vector<std::string> columns;
        size_t pos = 0;
        for ( int i = 0; i < 10 && pos < line.size(); ++i ) {
            const auto end = line.find( ' ', pos );
            columns.push_back( line.substr( pos, end - pos ) );
            pos = line.find_first_not_of( ' ', end );
        }
        return columns;
    };

    GIVEN( "values as wide as their columns, or wider" )
    {
        pkt.number = 1000000;
        pkt.protocol = "ETH(0x88CC)";
        pkt.capturedLen = 1234567;
        pkt.originalLen = 1234567;
        pkt.srcIp = "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff:1";
        const auto line = formatter.format( pkt, 1234567 );

        THEN( "a space still follows each of them" )
        {
            const auto columns = columnsOf( line );
            REQUIRE( columns.size() == 10 );
            REQUIRE( columns[ 0 ] == "1000000" );
            REQUIRE( columns[ 1 ] == "1234567" );
            REQUIRE( columns[ 5 ] == pkt.srcIp );
            REQUIRE( columns[ 7 ] == "ETH(0x88CC)" );
            REQUIRE( columns[ 8 ] == "1234567" );
            REQUIRE( line.substr( line.find( "1234567 443" ) + 8 ) == pkt.info );
        }
    }

    GIVEN( "a packet without addresses or protocol" )
    {
        pkt.srcIp.clear();
        pkt.dstIp.clear();
        pkt.protocol.clear();
        const auto line = formatter.format( pkt, kNoStream );

        THEN( "Source, Destination and Protocol show -" )
        {
            const auto columns = columnsOf( line );
            REQUIRE( columns.size() == 10 );
            REQUIRE( columns[ 5 ] == "-" );
            REQUIRE( columns[ 6 ] == "-" );
            REQUIRE( columns[ 7 ] == "-" );
            REQUIRE( columns[ 8 ] == "60" );
        }
    }

    GIVEN( "values that fit" )
    {
        const auto line = formatter.format( pkt, 0 );

        THEN( "the columns keep their fixed widths" )
        {
            REQUIRE( line.find( "192.168.1.1" ) == 7 + 8 + 29 + 15 );
            REQUIRE( line.find( pkt.info ) == 7 + 8 + 29 + 15 + 40 + 40 + 10 + 7 );
        }
    }
}

SCENARIO( "The line layout chooses the time columns and adds the MAC columns",
          "[packet_formatter]" )
{
    PacketRecord pkt;
    pkt.number = 2;
    pkt.timestampSec = 1760000000; // 2025-10-09 08:53:20 UTC
    pkt.timestampNsec = 500000000;
    pkt.srcIp = "192.168.1.1";
    pkt.dstIp = "10.0.0.1";
    pkt.srcMac = "00:11:22:33:44:55";
    pkt.dstMac = "66:77:88:99:aa:bb";
    pkt.protocol = "UDP";
    pkt.capturedLen = pkt.originalLen = 60;
    pkt.info = "443 \xe2\x86\x92 80 Len=18";
    const std::string utc = "2025-10-09 08:53:20.500000Z  ";
    const std::string time = "0.500000       ";
    const std::string addresses
        = "192.168.1.1" + std::string( 29, ' ' ) + "10.0.0.1" + std::string( 32, ' ' );
    const std::string rest = "UDP       60     " + pkt.info;

    auto lineWith = [ & ]( LineLayout layout ) {
        PacketFormatter formatter( TimePrecision::Microseconds, layout );
        PacketRecord first = pkt;
        first.timestampNsec = 0;
        formatter.format( first, 0 );
        return formatter.format( pkt, 0 );
    };
    auto headerWith = [ & ]( LineLayout layout ) {
        return PacketFormatter( TimePrecision::Microseconds, layout ).header();
    };

    GIVEN( "the default layout" )
    {
        THEN( "both time columns are shown, and no MAC columns" )
        {
            REQUIRE( lineWith( {} ) == "2      0       " + utc + time + addresses + rest );
            REQUIRE( headerWith( {} ).find( "UTC Time" ) != std::string::npos );
            REQUIRE( headerWith( {} ).find( "MAC" ) == std::string::npos );
        }
    }

    GIVEN( "the absolute time only" )
    {
        const LineLayout layout{ TimeColumns::AbsoluteOnly, false };

        THEN( "the Time column is left out" )
        {
            REQUIRE( lineWith( layout ) == "2      0       " + utc + addresses + rest );
            REQUIRE( headerWith( layout ).rfind( "No.    Stream  UTC Time", 0 ) == 0 );
            REQUIRE( headerWith( layout ).find( "Time", 15 + 8 ) == std::string::npos );
        }
    }

    GIVEN( "the relative time only" )
    {
        const LineLayout layout{ TimeColumns::RelativeOnly, false };

        THEN( "the UTC Time column is left out" )
        {
            REQUIRE( lineWith( layout ) == "2      0       " + time + addresses + rest );
            REQUIRE( headerWith( layout ).rfind( "No.    Stream  Time ", 0 ) == 0 );
            REQUIRE( headerWith( layout ).find( "UTC" ) == std::string::npos );
        }
    }

    GIVEN( "the MAC columns" )
    {
        const LineLayout layout{ TimeColumns::Both, true };

        THEN( "Source MAC and Destination MAC come before Info" )
        {
            REQUIRE( lineWith( layout )
                     == "2      0       " + utc + time + addresses + "UDP       60     "
                            + "00:11:22:33:44:55  66:77:88:99:aa:bb  " + pkt.info );
            const auto header = headerWith( layout );
            REQUIRE( header.find( "Length" ) < header.find( "Source MAC" ) );
            REQUIRE( header.find( "Source MAC" ) < header.find( "Destination MAC" ) );
            REQUIRE( header.find( "Destination MAC" ) < header.find( "Info" ) );
        }

        AND_WHEN( "the packet has no MAC addresses" )
        {
            pkt.srcMac.clear();
            pkt.dstMac.clear();

            THEN( "they show -" )
            {
                REQUIRE( lineWith( layout ).find( "60     -" + std::string( 18, ' ' ) + "-"
                                                  + std::string( 18, ' ' ) + "443" )
                         != std::string::npos );
            }
        }
    }
}
