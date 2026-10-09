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

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

#include <stdexcept>

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

/// Whether @p root holds no output directory (and no file) at all.
bool nothingBelow( const QTemporaryDir& root )
{
    return QDir( root.path() ).isEmpty();
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
    GIVEN( "packets of two link-layer types, as one capture of several interfaces holds" )
    {
        CaptureStats stats;
        PacketRecord pkt;
        for ( const uint32_t linkType : { DltLinuxSll2, DltEthernet, DltLinuxSll2, DltRaw } ) {
            pkt.linkType = linkType;
            stats.add( pkt );
        }

        THEN( "each link-layer type is listed once, in the order it was first seen" )
        {
            REQUIRE( stats.linkTypes
                     == std::vector<uint32_t>{ DltLinuxSll2, DltEthernet, DltRaw } );
        }

        THEN( "a link-layer type announced again is not listed twice" )
        {
            stats.addLinkType( DltEthernet );
            stats.addLinkType( DltNull );
            REQUIRE( stats.linkTypes
                     == std::vector<uint32_t>{ DltLinuxSll2, DltEthernet, DltRaw, DltNull } );
        }
    }

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

SCENARIO( "The median initial round-trip time is kept in bounded memory", "[capture_stats]" )
{
    GIVEN( "fewer handshakes than are kept exactly" )
    {
        RunningMedian median;
        for ( const uint64_t ns : { 30u, 10u, 20u, 40u } ) {
            median.add( ns );
        }

        THEN( "the median is exact, the upper middle one of an even count" )
        {
            REQUIRE( median.exact() );
            REQUIRE( median.count() == 4 );
            REQUIRE( median.median() == 30u );
        }
    }

    GIVEN( "no value" )
    {
        THEN( "there is no median" )
        {
            REQUIRE_FALSE( RunningMedian{}.median() );
        }
    }

    GIVEN( "far more handshakes than are kept exactly, as a long or live capture has" )
    {
        RunningMedian median;
        // 1 to 200000 microseconds, every value once, in a scrambled order.
        constexpr uint64_t kCount = 200000;
        for ( uint64_t i = 0; i < kCount; ++i ) {
            median.add( ( ( i * 7919 ) % kCount + 1 ) * 1000 );
        }

        THEN( "the values are counted in a histogram of fixed size" )
        {
            REQUIRE_FALSE( median.exact() );
            REQUIRE( median.count() == kCount );
            REQUIRE( median.memoryBytes() <= RunningMedian::kMaxMemoryBytes );
        }

        THEN( "the median lies within the histogram's precision of the exact one" )
        {
            const double exact = 100001.0 * 1000;
            REQUIRE( static_cast<double>( *median.median() )
                     == Approx( exact ).epsilon( RunningMedian::kRelativePrecision ) );
        }
    }

    GIVEN( "values beyond the exact buffer of zero and of the largest round-trip times" )
    {
        RunningMedian median;
        for ( size_t i = 0; i <= RunningMedian::kExactValues; ++i ) {
            median.add( i % 2 == 0 ? 0 : UINT64_MAX );
        }

        THEN( "both ends of the range are counted" )
        {
            REQUIRE( median.median() == 0u );
            median.add( UINT64_MAX );
            median.add( UINT64_MAX );
            REQUIRE( static_cast<double>( *median.median() )
                     == Approx( static_cast<double>( UINT64_MAX ) )
                            .epsilon( RunningMedian::kRelativePrecision ) );
        }
    }
}

SCENARIO( "Packets captured shorter than on the wire are counted as cut", "[capture_stats]" )
{
    CaptureStats stats;
    PacketRecord pkt;
    pkt.capturedLen = 96;
    pkt.originalLen = 1514;
    stats.add( pkt );
    pkt.capturedLen = 60;
    pkt.originalLen = 60;
    stats.add( pkt );
    pkt.capturedLen = 54;
    pkt.originalLen = 66;
    stats.add( pkt );

    REQUIRE( stats.packets == 3 );
    REQUIRE( stats.cutPackets == 2 );
}

SCENARIO( "The summary counts the packets cut at the snaplen", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a capture whose second packet was cut to 50 of its bytes" )
    {
        auto cut = eth( EthertypeIpv4,
                        ipv4( IpProtoUdp, udp( 40000, 2222, text( std::string( 200, 'a' ) ) ) ) );
        const auto wireLen = static_cast<int64_t>( cut.size() );
        cut.resize( 50 );
        std::vector<Record> records{ { udpPacket( 1111 ) }, { cut }, { udpPacket( 1111 ) } };
        records[ 1 ].origLen = wireLen;
        const auto input = writeFile( dir, "cut.pcap", pcapFile( records ) );

        WHEN( "it is converted" )
        {
            const auto result = convertPcap( input, out.path() );

            THEN( "one packet is counted as cut, and its line says how many bytes were "
                  "captured" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.packets == 3 );
                REQUIRE( result.summary.cutPackets == 1 );
                const auto lines = readLines( result.outputPath );
                REQUIRE( lines.size() == 4 );
                REQUIRE( lines[ 2 ].endsWith( " [cut to 50 bytes]" ) );
                REQUIRE_FALSE( lines[ 1 ].contains( "[cut to" ) );
            }
        }
    }
}

SCENARIO( "The summary counts the TCP analysis markers per kind", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a segment sent three times and acknowledged twice alike" )
    {
        const auto data
            = eth( EthertypeIpv4,
                   ipv4( IpProtoTcp, tcp( 40000, 80, text( "ab" ), 5, 0x18, 1000, 5000 ) ) );
        Ipv4Options back;
        std::swap( back.src, back.dst );
        const auto ack = eth( EthertypeIpv4,
                              ipv4( IpProtoTcp, tcp( 80, 40000, {}, 5, 0x10, 5000, 1000 ), back ) );
        const auto input = writeFile( dir, "lossy.pcap", pcapOf( { data, data, data, ack, ack } ) );

        WHEN( "it is converted" )
        {
            const auto result = convertPcap( input, out.path() );

            THEN( "the summary has each kind that occurs, with its count, in Wireshark's words" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                using Count = std::pair<std::string, uint64_t>;
                REQUIRE(
                    result.summary.tcpMarkers
                    == std::vector<Count>{ { "TCP Retransmission", 2 }, { "TCP Dup ACK", 1 } } );
            }
        }
    }
}

SCENARIO( "The summary gives the median initial round-trip time of the handshakes", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    // A handshake from client port @p port whose ACK comes @p usec after its SYN.
    auto handshake = []( uint16_t port, uint32_t second, uint32_t usec ) {
        Ipv4Options back;
        std::swap( back.src, back.dst );
        return std::vector<Record>{
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( port, 80, {}, 5, 0x02, 100, 0 ) ) ),
              second, 0 },
            { eth( EthertypeIpv4,
                   ipv4( IpProtoTcp, tcp( 80, port, {}, 5, 0x12, 900, 101 ), back ) ),
              second, usec / 2 },
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( port, 80, {}, 5, 0x10, 101, 901 ) ) ),
              second, usec },
        };
    };

    GIVEN( "three handshakes of 10, 30 and 20 ms, and a stream captured mid-way" )
    {
        std::vector<Record> records;
        for ( const auto& part : { handshake( 40000, 1000, 10000 ), handshake( 40001, 1001, 30000 ),
                                   handshake( 40002, 1002, 20000 ) } ) {
            records.insert( records.end(), part.begin(), part.end() );
        }
        records.push_back(
            { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40003, 80, {}, 5, 0x10, 1, 1 ) ) ), 1003,
              0 } );
        const auto input = writeFile( dir, "handshakes.pcap", pcapFile( records ) );

        WHEN( "it is converted" )
        {
            const auto result = convertPcap( input, out.path() );

            THEN( "the summary counts the three, with their median" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.handshakes == 3 );
                REQUIRE( result.summary.medianInitialRttNs == 20000000u );
            }
        }
    }

    GIVEN( "no handshake" )
    {
        const auto input = writeFile(
            dir, "midway.pcap",
            pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40003, 80, {}, 5, 0x10 ) ) ) } ) );

        THEN( "the summary has no median" )
        {
            const auto result = convertPcap( input, out.path() );
            REQUIRE( result.summary.handshakes == 0 );
            REQUIRE_FALSE( result.summary.medianInitialRttNs );
        }
    }
}

SCENARIO( "The summary names the earliest and latest packet time in UTC", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a nanosecond capture whose packets are not in time order" )
    {
        FileOptions nano;
        nano.nanoseconds = true;
        std::vector<Record> records{ { udpPacket( 1111 ), 1791535272, 5 },
                                     { udpPacket( 1111 ), 1791535270, 123456789 },
                                     { udpPacket( 1111 ), 1791535300, 0 },
                                     { udpPacket( 1111 ), 1791535290, 0 } };
        const auto input = writeFile( dir, "merged.pcap", pcapFile( records, nano ) );

        WHEN( "it is converted" )
        {
            const auto result = convertPcap( input, out.path() );

            THEN( "they are written as the UTC Time column writes them, to the nanosecond" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.firstTimeUtc == "2026-10-09 08:41:10.123456789Z" );
                REQUIRE( result.summary.lastTimeUtc == "2026-10-09 08:41:40.000000000Z" );
            }
        }
    }

    GIVEN( "a capture without packets" )
    {
        const auto input = writeFile( dir, "empty.pcap", pcapOf( {} ) );

        THEN( "there is no time to name" )
        {
            const auto result = convertPcap( input, out.path() );
            REQUIRE( result.summary.firstTimeUtc.empty() );
            REQUIRE( result.summary.lastTimeUtc.empty() );
        }
    }
}

SCENARIO( "A capture is converted to a text file packet by packet", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a capture with three packets" )
    {
        auto bytes = pcapOf( { udpPacket( 1111 ), udpPacket( 2222 ), udpPacket( 1111 ) } );
        const auto input = writeFile( dir, "three.pcap", bytes );

        WHEN( "it is converted" )
        {
            std::vector<int> progress;
            const auto result = convertPcap( input, out.path(), nullptr,
                                             [ &progress ]( int p ) { progress.push_back( p ); } );

            THEN( "the text file, named after the capture in a directory of its own below the "
                  "root, holds the same lines as formatting the parsed capture" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( QFileInfo( result.outputPath ).fileName() == "three.log" );
                REQUIRE( QFileInfo( QFileInfo( result.outputPath ).absolutePath() ).absolutePath()
                         == QFileInfo( out.path() ).absoluteFilePath() );
                QStringList expected;
                for ( const auto& line : formatAllPackets( parse( bytes ).packets ) ) {
                    expected << QString::fromStdString( line );
                }
                REQUIRE( readLines( result.outputPath ) == expected );
            }

            THEN( "the summary covers every packet, and nothing was cut" )
            {
                REQUIRE( result.summary.packets == 3 );
                REQUIRE( result.summary.linkTypeNames == std::vector<std::string>{ "Ethernet" } );
                REQUIRE( result.summary.protocolPackets.at( "UDP" ) == 3 );
                REQUIRE( result.summary.endpointPackets.at( "192.168.1.1" ) == 3 );
                REQUIRE_FALSE( result.summary.endsInsideRecord );
                REQUIRE( result.summary.cutPackets == 0 );
                REQUIRE_FALSE( result.summary.streamCap );
                REQUIRE_FALSE( result.summary.otherEndpointPackets );
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
            const auto result = convertPcap( input, out.path(), &cancel );

            THEN( "it says so and leaves nothing behind" )
            {
                REQUIRE( result.status == ConversionResult::Status::Cancelled );
                REQUIRE( result.outputPath.isEmpty() );
                REQUIRE( nothingBelow( out ) );
            }
        }

        WHEN( "the progress callback throws in the middle of the capture" )
        {
            const auto result = convertPcap( input, out.path(), nullptr, []( int ) {
                throw std::runtime_error( "the disk is on fire" );
            } );

            THEN( "the conversion fails with that message and leaves nothing behind" )
            {
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error == "the disk is on fire" );
                REQUIRE( nothingBelow( out ) );
            }
        }

        WHEN( "memory runs out in the middle of the capture" )
        {
            const auto result
                = convertPcap( input, out.path(), nullptr, []( int ) { throw std::bad_alloc(); } );

            THEN( "the conversion fails saying so" )
            {
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error.contains( "Not enough memory" ) );
                REQUIRE( nothingBelow( out ) );
            }
        }

        WHEN( "the output root does not exist" )
        {
            const auto result = convertPcap( input, dir.filePath( "no-such-dir" ) );

            THEN( "the conversion fails, naming the directory as the problem" )
            {
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error.contains( "Cannot create a temporary directory" ) );
            }
        }
    }

    GIVEN( "a capture of three conversations between four addresses" )
    {
        auto segmentFrom = []( uint8_t lastOctet, uint16_t srcPort ) {
            Ipv4Options addresses; // 10.0.0.<lastOctet> → 10.0.0.1
            for ( auto* address : { addresses.src, addresses.dst } ) {
                address[ 0 ] = 10;
                address[ 1 ] = 0;
                address[ 2 ] = 0;
            }
            addresses.src[ 3 ] = lastOctet;
            addresses.dst[ 3 ] = 1;
            return eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( srcPort, 80 ), addresses ) );
        };
        const auto input = writeFile(
            dir, "many.pcap",
            pcapOf( { segmentFrom( 2, 1001 ), segmentFrom( 3, 1002 ), segmentFrom( 4, 1003 ) } ) );

        WHEN( "it is converted with both caps lowered to one" )
        {
            ConversionOptions options;
            options.maxStreams = 1;
            options.maxEndpoints = 1;
            const auto result = convertPcap( input, out.path(), nullptr, {}, options );

            THEN( "the summary says that both caps were reached, and by how much" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.streamCap == 1 );
                // One address was counted; the other five address occurrences were not.
                REQUIRE( result.summary.endpointPackets.size() == 1 );
                REQUIRE( result.summary.otherEndpointPackets == 5 );
            }
        }

        WHEN( "it is converted with the default caps" )
        {
            const auto result = convertPcap( input, out.path() );

            THEN( "neither cap is reached" )
            {
                REQUIRE_FALSE( result.summary.streamCap );
                REQUIRE_FALSE( result.summary.otherEndpointPackets );
            }
        }
    }

    GIVEN( "a file that is not a capture" )
    {
        const auto input = writeFile( dir, "junk.pcap", Bytes( 100, 0xEE ) );

        THEN( "the conversion fails with the parser's error and writes nothing" )
        {
            const auto result = convertPcap( input, out.path() );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "magic" ) );
            REQUIRE( nothingBelow( out ) );
        }
    }

    GIVEN( "a file that does not exist" )
    {
        THEN( "the conversion fails" )
        {
            const auto result = convertPcap( dir.filePath( "missing.pcap" ), out.path() );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE_FALSE( result.error.isEmpty() );
        }
    }
}

SCENARIO( "A cancel request wins, even over a conversion that has just finished", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );
    const auto input = writeFile( dir, "done.pcap", pcapOf( { udpPacket( 1 ) } ) );

    GIVEN( "a conversion that completed" )
    {
        auto result = convertPcap( input, out.path() );
        REQUIRE( result.status == ConversionResult::Status::Converted );
        REQUIRE( QFile::exists( result.outputPath ) );

        WHEN( "a cancel request came after it" )
        {
            std::atomic_bool cancel{ true };
            const auto settled = applyCancelRequest( result, &cancel );

            THEN( "it is cancelled and its output is gone" )
            {
                REQUIRE( settled.status == ConversionResult::Status::Cancelled );
                REQUIRE( settled.outputPath.isEmpty() );
                REQUIRE( nothingBelow( out ) );
            }
        }

        WHEN( "no cancel was requested" )
        {
            std::atomic_bool cancel{ false };

            THEN( "the result and its output stay as they are" )
            {
                REQUIRE( applyCancelRequest( result, &cancel ).status
                         == ConversionResult::Status::Converted );
                REQUIRE( applyCancelRequest( result, nullptr ).outputPath == result.outputPath );
                REQUIRE( QFile::exists( result.outputPath ) );
            }
        }
    }

    GIVEN( "a conversion that failed" )
    {
        const auto result = convertPcap( dir.filePath( "missing.pcap" ), out.path() );
        REQUIRE( result.status == ConversionResult::Status::Failed );

        THEN( "a cancel request still wins" )
        {
            std::atomic_bool cancel{ true };
            REQUIRE( applyCancelRequest( result, &cancel ).status
                     == ConversionResult::Status::Cancelled );
        }
    }
}

SCENARIO( "The summary names the capture's link-layer type", "[converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    const std::vector<std::pair<uint32_t, std::string>> names{
        { DltNull, "BSD Loopback" },
        { DltEthernet, "Ethernet" },
        { DltRaw, "Raw IP" },
        { DltLoop, "OpenBSD Loopback" },
        { DltLinuxSll, "Linux SLL" },
        { DltLinuxSll2, "Linux SLL2" },
        { 147, "147" }, // DLT_USER0: unknown here, shown as its number
    };

    for ( const auto& [ linkType, name ] : names ) {
        GIVEN( "a capture of link-layer type " + std::to_string( linkType ) )
        {
            const auto input = writeFile( dir, QString( "link-%1.pcap" ).arg( linkType ),
                                          pcapOf( { udpPacket( 1 ) }, linkType ) );

            THEN( "the summary calls it " + name )
            {
                const auto result = convertPcap( input, dir.path() );
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.linkTypeNames == std::vector<std::string>{ name } );
            }
        }
    }
}

#ifdef Q_OS_UNIX
#include <csignal>
#include <sys/resource.h>
#include <sys/stat.h>

namespace {

/// Caps the size of any file this process writes while it lives, so that a
/// write past the cap fails with EFBIG instead of filling the disk.
class FileSizeLimit {
public:
    explicit FileSizeLimit( rlim_t bytes )
    {
        ::getrlimit( RLIMIT_FSIZE, &saved_ );
        previousHandler_ = std::signal( SIGXFSZ, SIG_IGN ); // get EFBIG, not killed
        rlimit limit = saved_;
        limit.rlim_cur = bytes;
        ::setrlimit( RLIMIT_FSIZE, &limit );
    }

    ~FileSizeLimit()
    {
        ::setrlimit( RLIMIT_FSIZE, &saved_ );
        std::signal( SIGXFSZ, previousHandler_ );
    }

private:
    rlimit saved_{};
    void ( *previousHandler_ )( int ) = nullptr;
};

} // namespace

SCENARIO( "A capture without packets still names its link-layer type", "[converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a Linux SLL2 pcap with a header and no packets" )
    {
        const auto input = writeFile( dir, "empty.pcap", pcapOf( {}, DltLinuxSll2 ) );

        THEN( "the summary lists the link-layer type the capture announces" )
        {
            const auto result = convertPcap( input, dir.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == 0 );
            REQUIRE( result.summary.linkTypeNames == std::vector<std::string>{ "Linux SLL2" } );
        }
    }
}

SCENARIO( "A write that fails in the middle of the capture fails the conversion", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a capture whose text is longer than any file this process may write" )
    {
        std::vector<Bytes> packets( 200, udpPacket( 1 ) );
        const auto input = writeFile( dir, "long.pcap", pcapOf( packets ) );

        WHEN( "it is converted" )
        {
            ConversionResult result;
            {
                const FileSizeLimit limit( 4096 );
                result = convertPcap( input, out.path() );
            }

            THEN( "the conversion fails with the write error and leaves nothing behind" )
            {
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error.startsWith( "Cannot write the output file: " ) );
                REQUIRE( nothingBelow( out ) );
            }
        }
    }
}

SCENARIO( "Only regular files are converted", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "a FIFO, which would block the reader until something writes to it" )
    {
        const auto fifo = dir.filePath( "capture.pcap" );
        REQUIRE( ::mkfifo( QFile::encodeName( fifo ).constData(), 0600 ) == 0 );

        THEN( "it is refused at once, with a message saying why" )
        {
            const auto result = convertPcap( fifo, out.path() );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "not a regular file" ) );
            REQUIRE( nothingBelow( out ) );
        }

        AND_GIVEN( "a symbolic link to it" )
        {
            const auto link = dir.filePath( "link.pcap" );
            REQUIRE( QFile::link( fifo, link ) );

            THEN( "the link is refused too" )
            {
                const auto result = convertPcap( link, out.path() );
                REQUIRE( result.status == ConversionResult::Status::Failed );
                REQUIRE( result.error.contains( "not a regular file" ) );
            }
        }
    }

    GIVEN( "a character device" )
    {
        THEN( "it is refused" )
        {
            const auto result = convertPcap( "/dev/zero", out.path() );
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
            REQUIRE( convertPcap( link, out.path() ).status
                     == ConversionResult::Status::Converted );
        }
    }
}
#endif

SCENARIO( "Endpoint counts stop growing at their cap", "[capture_stats]" )
{
    auto packetBetween = []( const std::string& src, uint16_t srcPort ) {
        PacketRecord pkt;
        pkt.protocol = "TCP";
        pkt.srcIp = src;
        pkt.dstIp = "10.0.0.1";
        pkt.srcPort = srcPort;
        pkt.dstPort = 80;
        return pkt;
    };

    GIVEN( "statistics that keep at most three endpoints" )
    {
        CaptureStats stats;
        stats.maxEndpoints = 3;
        for ( const auto* src : { "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5", "10.0.0.2" } ) {
            stats.add( packetBetween( src, 1 ) );
        }

        THEN( "the rest is counted as other endpoints" )
        {
            REQUIRE( stats.endpointPackets.size() == 3 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.1" ) == 5 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.2" ) == 2 );
            REQUIRE( stats.otherEndpointPackets == 2 );
            REQUIRE( stats.endpointLimitReached() );
        }
    }
}

SCENARIO( "The TCP reassembly holds the memory the options allow", "[converter]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;
    REQUIRE( dir.isValid() );
    REQUIRE( out.isValid() );

    GIVEN( "80 connections that each begin a TLS record of 18,000 bytes before any ends it" )
    {
        constexpr int kConnections = 80;
        Bytes record{ 0x17, 0x03, 0x03 };
        putBE16( record, 18000 );
        record.resize( 5 + 18000, 0xA5 );
        auto segment = [ & ]( int connection, size_t from, size_t to ) {
            const Bytes part( record.begin() + static_cast<std::ptrdiff_t>( from ),
                              record.begin() + static_cast<std::ptrdiff_t>( to ) );
            const auto port = static_cast<uint16_t>( 40000 + connection );
            return eth( EthertypeIpv4,
                        ipv4( IpProtoTcp, tcp( port, 443, part, 5, 0x18,
                                               1 + static_cast<uint32_t>( from ) ) ) );
        };
        std::vector<Bytes> frames;
        for ( int i = 0; i < kConnections; ++i ) {
            frames.push_back( segment( i, 0, 1000 ) );
        }
        for ( int i = 0; i < kConnections; ++i ) {
            frames.push_back( segment( i, 1000, record.size() ) );
        }
        const auto input = writeFile( dir, "records.pcap", pcapOf( frames ) );

        auto marked = []( const QStringList& lines ) {
            return lines.filter( QStringLiteral( "[reassembly limit]" ) ).size();
        };
        auto reassembled = []( const QStringList& lines ) {
            return lines.filter( QStringLiteral( "[reassembled from 2 segments]" ) ).size();
        };

        WHEN( "it is converted with the default memory" )
        {
            const auto result = convertPcap( input, out.path() );
            THEN( "every record is described where it ends" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                const auto lines = readLines( result.outputPath );
                REQUIRE( reassembled( lines ) == kConnections );
                REQUIRE( marked( lines ) == 0 );
            }
        }

        WHEN( "it is converted with 1 MB, room for some 55 of them" )
        {
            ConversionOptions options;
            options.reassemblyMegabytes = 1;
            const auto result = convertPcap( input, out.path(), nullptr, {}, options );
            THEN( "the records that waited longest are given up, their ends marked" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                const auto lines = readLines( result.outputPath );
                REQUIRE( marked( lines ) > 0 );
                REQUIRE( marked( lines ) + reassembled( lines ) == kConnections );
            }
        }
    }
}
