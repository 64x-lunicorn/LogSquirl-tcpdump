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
 * @file conversations_test.cpp
 * @brief BDD tests for the Conversations table's counts, as the Converter
 *        collects them, and the pattern of a conversation's lines.
 */

#include <catch2/catch.hpp>

#include "conversations.h"
#include "corpus_layouts.h"
#include "follow_stream.h"
#include "packet_pipeline.h"
#include "pcap_converter.h"
#include "stream_tracker.h"

#include <QFile>
#include <QRegularExpression>
#include <QTemporaryDir>

#include <map>
#include <set>
#include <utility>

using namespace tcpdump;

namespace {

/// A TCP packet from @p src:@p srcPort to @p dst:@p dstPort at @p sec.@p nsec.
PacketRecord tcpPacket( const std::string& src, uint16_t srcPort, const std::string& dst,
                        uint16_t dstPort, int64_t sec, uint32_t nsec, uint32_t length )
{
    PacketRecord pkt;
    pkt.transport = Transport::Tcp;
    pkt.srcIp = src;
    pkt.dstIp = dst;
    pkt.srcPort = srcPort;
    pkt.dstPort = dstPort;
    pkt.timestampSec = sec;
    pkt.timestampNsec = nsec;
    pkt.originalLen = length;
    pkt.capturedLen = length;
    pkt.protocol = "TCP";
    return pkt;
}

/// The Packet Pipeline, which a conversion runs before the counts, and the counts.
struct Pipeline {
    explicit Pipeline( size_t maxStreams = StreamTracker::kMaxStreams )
        : steps( optionsFor( maxStreams ) )
    {
    }

    void add( PacketRecord pkt )
    {
        const auto outcome = steps.run( pkt, {} );
        stats.add( pkt, outcome.stream );
    }

    std::vector<Conversation> table( int64_t sec = 100, uint32_t nsec = 0 ) const
    {
        return stats.conversations( steps.tracker(), steps.labels(), sec, nsec );
    }

    std::shared_ptr<const ConversationRows> rows( int64_t sec, uint32_t nsec ) const
    {
        return stats.rows( steps.tracker(), steps.labels(), sec, nsec );
    }

    static PipelineOptions optionsFor( size_t maxStreams )
    {
        PipelineOptions options;
        options.maxStreams = maxStreams;
        return options;
    }

    PacketPipeline steps;
    ConversationStats stats;
};

/// The packet lines of @p result's text, header excluded.
QStringList packetLines( const ConversionResult& result )
{
    QFile file( result.outputPath );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
    lines.removeFirst();
    return lines;
}

/// The No. of the lines @p pattern matches, as the Regex Lab does with Match case.
std::set<int> matched( const QString& pattern, const QStringList& lines )
{
    const QRegularExpression regex( pattern );
    INFO( pattern.toStdString() );
    REQUIRE( regex.isValid() );
    std::set<int> numbers;
    for ( const auto& line : lines ) {
        if ( regex.match( line ).hasMatch() ) {
            numbers.insert( line.section( ' ', 0, 0 ).toInt() );
        }
    }
    return numbers;
}

/// The pattern of @p row's lines.
QString patternOf( const Conversation& row )
{
    return conversationPattern( row.stream, QString::fromStdString( row.addressA ), row.portA,
                                QString::fromStdString( row.addressB ), row.portB );
}

/// The row of stream @p stream of @p transport.
const Conversation& rowOf( const std::vector<Conversation>& table, Transport transport, int stream )
{
    for ( const auto& row : table ) {
        if ( row.transport == transport && row.stream == stream ) {
            return row;
        }
    }
    FAIL( "no row of stream " << stream );
    return table.front();
}

} // namespace

SCENARIO( "The Conversations table counts each stream each way", "[conversations]" )
{
    GIVEN( "a TCP conversation whose first packet comes from its client" )
    {
        Pipeline pipeline;
        pipeline.add( tcpPacket( "10.0.0.2", 50000, "10.0.0.1", 80, 101, 0, 60 ) );
        pipeline.add( tcpPacket( "10.0.0.1", 80, "10.0.0.2", 50000, 101, 500000000, 1500 ) );
        pipeline.add( tcpPacket( "10.0.0.1", 80, "10.0.0.2", 50000, 102, 0, 1400 ) );
        // Captured out of order: before the first.
        pipeline.add( tcpPacket( "10.0.0.2", 50000, "10.0.0.1", 80, 100, 750000000, 54 ) );

        THEN( "end A is the first packet's source, and each way is counted on its own" )
        {
            const auto table = pipeline.table();
            REQUIRE( table.size() == 1 );
            const auto& row = table.front();
            REQUIRE( row.transport == Transport::Tcp );
            REQUIRE( row.stream == 0 );
            REQUIRE( row.protocol == "TCP" );
            REQUIRE( row.addressA == "10.0.0.2" );
            REQUIRE( row.portA == 50000 );
            REQUIRE( row.addressB == "10.0.0.1" );
            REQUIRE( row.portB == 80 );
            REQUIRE( row.packetsAToB == 2 );
            REQUIRE( row.bytesAToB == 114 );
            REQUIRE( row.packetsBToA == 2 );
            REQUIRE( row.bytesBToA == 2900 );
        }

        THEN( "it starts at its earliest packet, counted from the capture's, and lasts to its "
              "latest" )
        {
            const auto table = pipeline.table( 100, 500000000 );
            const auto& row = table.front();
            REQUIRE( row.startSeconds == Approx( 0.25 ) );
            REQUIRE( row.durationSeconds == Approx( 1.25 ) );
        }
    }

    GIVEN( "IPv6 conversations of both transports with the same number" )
    {
        Pipeline pipeline;
        auto udp = tcpPacket( "2001:db8::1", 5353, "2001:db8::2", 53, 100, 0, 80 );
        udp.transport = Transport::Udp;
        pipeline.add( udp );
        pipeline.add( tcpPacket( "2001:db8::2", 443, "2001:db8::1", 40000, 100, 0, 70 ) );

        THEN( "each transport has its row, TCP's first, with the IPv6 ends whole" )
        {
            const auto table = pipeline.table();
            REQUIRE( table.size() == 2 );
            REQUIRE( table[ 0 ].transport == Transport::Tcp );
            REQUIRE( table[ 0 ].addressA == "2001:db8::2" );
            REQUIRE( table[ 0 ].portA == 443 );
            REQUIRE( table[ 0 ].addressB == "2001:db8::1" );
            REQUIRE( table[ 0 ].portB == 40000 );
            REQUIRE( table[ 1 ].transport == Transport::Udp );
            REQUIRE( table[ 1 ].stream == 0 );
            REQUIRE( table[ 1 ].protocol == "UDP" );
            REQUIRE( table[ 1 ].addressA == "2001:db8::1" );
            REQUIRE( table[ 1 ].portB == 53 );
        }
    }

    GIVEN( "a stream a detector recognised" )
    {
        Pipeline pipeline;
        auto hello = tcpPacket( "10.0.0.2", 50000, "10.0.0.1", 443, 100, 0, 300 );
        hello.protocol = "TLS";
        hello.protocolRecognised = true;
        pipeline.add( tcpPacket( "10.0.0.2", 50000, "10.0.0.1", 443, 100, 0, 60 ) );
        pipeline.add( hello );

        THEN( "its protocol is its Stream Label" )
        {
            REQUIRE( pipeline.table().front().protocol == "TLS" );
        }
    }

    GIVEN( "more conversations than the stream cap" )
    {
        Pipeline pipeline( 1 );
        pipeline.add( tcpPacket( "10.0.0.2", 50000, "10.0.0.1", 80, 100, 0, 60 ) );
        pipeline.add( tcpPacket( "10.0.0.2", 50001, "10.0.0.1", 80, 100, 0, 70 ) );
        pipeline.add( tcpPacket( "10.0.0.1", 80, "10.0.0.2", 50001, 100, 0, 80 ) );
        PacketRecord icmp;
        icmp.originalLen = 98;
        pipeline.add( icmp );

        THEN( "only the numbered one has a row; the others' packets are counted together" )
        {
            REQUIRE( pipeline.table().size() == 1 );
            REQUIRE( pipeline.stats.otherPackets() == 2 );
            REQUIRE( pipeline.stats.otherBytes() == 150 );
        }
    }
}

SCENARIO( "The Conversations table taken again shares the rows that did not change",
          "[conversations]" )
{
    GIVEN( "more streams than a chunk of rows holds, the table taken" )
    {
        Pipeline pipeline;
        const auto streams = static_cast<uint16_t>( ConversationRows::kChunkRows + 100 );
        for ( uint16_t i = 0; i < streams; ++i ) {
            pipeline.add( tcpPacket( "10.0.0.2", static_cast<uint16_t>( 1024 + i ), "10.0.0.1", 80,
                                     100, 0, 60 ) );
        }
        const auto first = pipeline.rows( 100, 0 );
        REQUIRE( first->size() == streams );
        REQUIRE( first->chunks().size() == 2 );

        WHEN( "a packet of a stream of the second chunk comes, and it is taken again" )
        {
            pipeline.add( tcpPacket( "10.0.0.1", 80, "10.0.0.2",
                                     static_cast<uint16_t>( 1024 + streams - 1 ), 101, 0, 1500 ) );
            const auto second = pipeline.rows( 100, 0 );

            THEN( "the first chunk is the same, the second one made anew" )
            {
                REQUIRE( second->chunks()[ 0 ] == first->chunks()[ 0 ] );
                REQUIRE( second->chunks()[ 1 ] != first->chunks()[ 1 ] );
                REQUIRE( ( *second )[ streams - 1 ].packetsBToA == 1 );
                REQUIRE( ( *first )[ streams - 1 ].packetsBToA == 0 );
                REQUIRE( second->list() == pipeline.table() );
            }
        }

        WHEN( "a packet earlier than the capture's first comes" )
        {
            const auto second = pipeline.rows( 99, 0 );

            THEN( "every row's start is told anew" )
            {
                REQUIRE( second->chunks()[ 0 ] != first->chunks()[ 0 ] );
                REQUIRE( ( *second )[ 0 ].startSeconds == Approx( 1.0 ) );
            }
        }
    }
}

SCENARIO( "The Converter collects the Conversations table", "[conversations]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    GIVEN( "the mixed synthetic capture" )
    {
        const auto result = convertPcap( TCPDUMP_CORPUS_DIR "/mixed.pcap", out.path() );
        REQUIRE( result.status == ConversionResult::Status::Converted );
        REQUIRE( result.summary.conversations );
        const auto table = result.summary.conversations->list();

        THEN( "each numbered stream has a row, as its lines show it" )
        {
            REQUIRE( table.size() == 11 ); // TCP 0–7, UDP 0–2
        }

        THEN( "a stream's row counts its packets, their Length and its time" )
        {
            const auto& http = rowOf( table, Transport::Tcp, 0 );
            REQUIRE( http.protocol == "HTTP" );
            REQUIRE( http.addressA == "192.168.1.1" );
            REQUIRE( http.portA == 50000 );
            REQUIRE( http.addressB == "192.168.1.2" );
            REQUIRE( http.portB == 80 );
            REQUIRE( http.packetsAToB == 2 );
            REQUIRE( http.bytesAToB == 54 + 101 );
            REQUIRE( http.packetsBToA == 0 );
            // Packet 6 is the capture's earliest, a second before packet 1.
            REQUIRE( http.startSeconds == Approx( 0.938275 ) );
            REQUIRE( http.durationSeconds == Approx( 0.012345 ) );

            const auto& nmea = rowOf( table, Transport::Udp, 1 );
            REQUIRE( nmea.protocol == "NMEA" );
            REQUIRE( nmea.startSeconds == 0.0 );
            REQUIRE( nmea.portB == 10110 );

            const auto& socks = rowOf( table, Transport::Tcp, 4 );
            REQUIRE( socks.packetsAToB == 3 );
            REQUIRE( socks.bytesAToB == 58 + 66 + 65 );
        }

        THEN( "nothing is past the stream cap" )
        {
            REQUIRE( result.summary.otherStreamPackets == 0 );
            REQUIRE( result.summary.otherStreamBytes == 0 );
        }
    }

    GIVEN( "the mixed capture converted with a stream cap of 2" )
    {
        ConversionOptions options;
        options.maxStreams = 2;
        const auto result
            = convertPcap( TCPDUMP_CORPUS_DIR "/mixed.pcap", out.path(), nullptr, {}, options );
        REQUIRE( result.status == ConversionResult::Status::Converted );

        THEN( "the table holds the two numbered streams, the rest counted as other streams" )
        {
            REQUIRE( result.summary.conversations->size() == 2 );
            // 16 packets have a stream, 3 of them of the numbered two.
            REQUIRE( result.summary.otherStreamPackets == 13 );
            uint64_t bytes = 0;
            for ( const auto& line : packetLines( result ) ) {
                const auto columns = line.split( ' ', Qt::SkipEmptyParts );
                if ( columns[ 1 ] == "?" ) {
                    bytes += columns[ 8 ].toULongLong(); // Length, after the two of UTC Time
                }
            }
            REQUIRE( result.summary.otherStreamBytes == bytes );
        }
    }

    GIVEN( "every committed corpus capture" )
    {
        for ( const auto& capture : tcpdump_test::committedCaptures() ) {
            INFO( capture.toStdString() );
            const auto result = convertPcap( capture, out.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            const auto lines = packetLines( result );
            const auto table = result.summary.conversations->list();

            THEN( "a row's pattern finds exactly its packets, of its stream number" )
            {
                // Lines and Length per Stream column, both transports together.
                std::map<QString, std::pair<uint64_t, uint64_t>> byStream;
                for ( const auto& line : lines ) {
                    const auto columns = line.split( ' ', Qt::SkipEmptyParts );
                    const auto stream = columns[ 1 ];
                    if ( stream != "-" && stream != "?" ) {
                        // No., Stream, date, time, Time, Source, Destination, Protocol, Length
                        byStream[ stream ].first += 1;
                        byStream[ stream ].second += columns[ 8 ].toULongLong();
                    }
                }
                std::map<QString, std::pair<uint64_t, uint64_t>> counted;
                std::map<QString, std::set<int>> found;
                for ( const auto& row : table ) {
                    const auto stream = QString::number( row.stream );
                    const auto packets = row.packetsAToB + row.packetsBToA;
                    counted[ stream ].first += packets;
                    counted[ stream ].second += row.bytesAToB + row.bytesBToA;
                    const auto numbers = matched( patternOf( row ), lines );
                    REQUIRE( numbers.size() == packets );
                    for ( const auto number : numbers ) {
                        REQUIRE( found[ stream ].insert( number ).second );
                    }
                }
                REQUIRE( counted == byStream );
            }
        }
    }
}
