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
 * @file streaming_test.cpp
 * @brief BDD tests for reading, summarising and converting a capture packet by packet.
 */

#include <catch2/catch.hpp>

#include "capture_stats.h"
#include "packet_formatter.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"

#include <QFile>
#include <QTemporaryDir>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

Bytes udpPacket( uint16_t port )
{
    return eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, port, text( "hello" ) ) ) );
}

QString writeFile( const QTemporaryDir& dir, const QString& name, const Bytes& content )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    REQUIRE( file.write( reinterpret_cast<const char*>( content.data() ),
                         static_cast<qint64>( content.size() ) )
             == static_cast<qint64>( content.size() ) );
    return path;
}

QStringList readLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    if ( !lines.isEmpty() && lines.last().isEmpty() ) {
        lines.removeLast();
    }
    return lines;
}

} // namespace

SCENARIO( "A record longer than what is dissected is skipped, not loaded", "[pcap_parser]" )
{
    GIVEN( "a packet of 300000 bytes followed by a small one" )
    {
        auto big = udpPacket( 1111 ) + Bytes( 300000 - udpPacket( 1111 ).size(), 'x' );
        auto file = pcapOf( { big, udpPacket( 2222 ) } );

        THEN( "both are parsed, and the big one reports its full length" )
        {
            auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE_FALSE( result.truncated );
            REQUIRE( result.packets.size() == 2 );
            REQUIRE( result.packets[ 0 ].capturedLen == 300000 );
            REQUIRE( result.packets[ 0 ].dstPort == 1111 );
            REQUIRE( result.packets[ 1 ].dstPort == 2222 );
        }
    }

    GIVEN( "a record claiming almost 4 GiB after a complete packet" )
    {
        std::vector<Record> records{ { udpPacket( 1111 ) }, { udpPacket( 2222 ) } };
        records[ 1 ].inclLen = 0xFFFFFFF0;
        auto file = pcapFile( records );

        THEN( "the packets before it are kept and the capture is reported cut off" )
        {
            auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.truncated );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].dstPort == 1111 );
        }
    }

    GIVEN( "a capture that ends inside a record header" )
    {
        auto file = pcapOf( { udpPacket( 1111 ) } ) + Bytes( 7, 0 );

        THEN( "it is reported cut off" )
        {
            auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.truncated );
        }
    }
}

SCENARIO( "A record of zero bytes is read without copying anything", "[pcap_parser]" )
{
    GIVEN( "a capture whose first record is empty" )
    {
        // The packet buffer is still unallocated then: its data() may be null,
        // and must not be handed to memcpy, not even for 0 bytes.
        auto file = pcapFile( { { Bytes{} }, { udpPacket( 2222 ) } } );

        THEN( "the empty record and the next one are parsed" )
        {
            auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE_FALSE( result.truncated );
            REQUIRE( result.packets.size() == 2 );
            REQUIRE( result.packets[ 0 ].capturedLen == 0 );
            REQUIRE( result.packets[ 1 ].dstPort == 2222 );
        }
    }
}

SCENARIO( "Capture statistics are collected packet by packet", "[capture_stats]" )
{
    GIVEN( "packets whose times are not in order, as in a merged capture" )
    {
        CaptureStats stats;
        PacketRecord pkt;
        pkt.protocol = "UDP";
        pkt.capturedLen = 10;
        pkt.srcIp = "10.0.0.1";
        pkt.dstIp = "10.0.0.2";
        for ( auto [ sec, usec ] : { std::pair<uint32_t, uint32_t>{ 1000, 500000 },
                                     { 999, 0 },
                                     { 1002, 250000 },
                                     { 1001, 0 } } ) {
            pkt.timestampSec = sec;
            pkt.timestampNsec = usec * 1000;
            stats.add( pkt );
        }

        THEN( "the duration spans the earliest to the latest packet" )
        {
            REQUIRE( stats.durationSeconds() == Approx( 3.25 ) );
        }

        THEN( "packets, bytes, protocols and endpoints are counted" )
        {
            REQUIRE( stats.packets == 4 );
            REQUIRE( stats.bytes == 40 );
            REQUIRE( stats.protocolPackets.at( "UDP" ) == 4 );
            REQUIRE( stats.protocolBytes.at( "UDP" ) == 40 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.1" ) == 4 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.2" ) == 4 );
        }
    }
}

SCENARIO( "A capture is converted to a text file packet by packet", "[converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a capture with three packets" )
    {
        auto bytes = pcapOf( { udpPacket( 1111 ), udpPacket( 2222 ), udpPacket( 1111 ) } );
        const auto input = writeFile( dir, "three.pcap", bytes );
        const auto output = dir.filePath( "three.log" );

        WHEN( "it is converted" )
        {
            std::vector<int> progress;
            const auto result = convertPcap( input, output, nullptr,
                                             [ &progress ]( int p ) { progress.push_back( p ); } );

            THEN( "the text file holds the same lines as formatting the parsed capture" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                QStringList expected;
                for ( const auto& line : formatAllPackets( parse( bytes ).packets ) ) {
                    expected << QString::fromStdString( line );
                }
                REQUIRE( readLines( output ) == expected );
            }

            THEN( "the statistics cover every packet" )
            {
                REQUIRE( result.stats.packets == 3 );
                REQUIRE( result.header.network == DltEthernet );
            }

            THEN( "progress rises to 1000 per mille" )
            {
                REQUIRE_FALSE( progress.empty() );
                REQUIRE( std::is_sorted( progress.begin(), progress.end() ) );
                REQUIRE( progress.back() == 1000 );
            }
        }

        WHEN( "the conversion is cancelled" )
        {
            std::atomic_bool cancel{ true };
            const auto result = convertPcap( input, output, &cancel );

            THEN( "it says so and leaves no output file behind" )
            {
                REQUIRE( result.status == ConversionResult::Status::Cancelled );
                REQUIRE_FALSE( QFile::exists( output ) );
            }
        }
    }

    GIVEN( "a file that is not a capture" )
    {
        const auto input = writeFile( dir, "junk.pcap", Bytes( 100, 0xEE ) );
        const auto output = dir.filePath( "junk.log" );

        THEN( "the conversion fails with the parser's error and writes nothing" )
        {
            const auto result = convertPcap( input, output );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "magic" ) );
            REQUIRE_FALSE( QFile::exists( output ) );
        }
    }

    GIVEN( "a file that does not exist" )
    {
        THEN( "the conversion fails" )
        {
            const auto result
                = convertPcap( dir.filePath( "missing.pcap" ), dir.filePath( "x.log" ) );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE_FALSE( result.error.isEmpty() );
        }
    }
}

#ifdef Q_OS_UNIX
#include <sys/stat.h>

SCENARIO( "Only regular files are converted", "[converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a FIFO, which would block the reader until something writes to it" )
    {
        const auto fifo = dir.filePath( "capture.pcap" );
        REQUIRE( ::mkfifo( QFile::encodeName( fifo ).constData(), 0600 ) == 0 );

        THEN( "it is refused at once, with a message saying why" )
        {
            const auto result = convertPcap( fifo, dir.filePath( "out.log" ) );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "not a regular file" ) );
            REQUIRE_FALSE( QFile::exists( dir.filePath( "out.log" ) ) );
        }

        AND_GIVEN( "a symbolic link to it" )
        {
            const auto link = dir.filePath( "link.pcap" );
            REQUIRE( QFile::link( fifo, link ) );

            THEN( "the link is refused too" )
            {
                const auto result = convertPcap( link, dir.filePath( "out.log" ) );
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error.contains( "not a regular file" ) );
            }
        }
    }

    GIVEN( "a character device" )
    {
        THEN( "it is refused" )
        {
            const auto result = convertPcap( "/dev/zero", dir.filePath( "out.log" ) );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "not a regular file" ) );
        }
    }

    GIVEN( "a symbolic link to a capture" )
    {
        const auto capture = writeFile( dir, "real.pcap", pcapOf( { udpPacket( 1 ) } ) );
        const auto link = dir.filePath( "alias.pcap" );
        REQUIRE( QFile::link( capture, link ) );

        THEN( "it is converted" )
        {
            REQUIRE( convertPcap( link, dir.filePath( "alias.log" ) ).status
                     == ConversionResult::Status::Converted );
        }
    }
}
#endif
