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
 * @file capture_index_test.cpp
 * @brief BDD tests for the line → record index of a converted capture and
 *        reading its packets back.
 */

#include <catch2/catch.hpp>

#include "capture_index.h"
#include "capture_reader.h"
#include "corpus_layouts.h"
#include "packet_formatter.h"
#include "packet_layers.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "regex_lab.h"

#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QThread>

#include <algorithm>
#include <map>
#include <random>

using namespace tcpdump;

namespace {

/// @p capture converted into @p outputRoot with a checkpoint every @p interval packets.
ConversionResult convertWithInterval( const QString& capture, const QString& outputRoot,
                                      uint32_t interval )
{
    ConversionOptions options;
    options.checkpointInterval = interval;
    auto result = convertPcap( capture, outputRoot, nullptr, {}, options );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    REQUIRE( result.index );
    return result;
}

/// The packet lines of the text at @p path, header excluded.
QStringList packetLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
    lines.removeFirst();
    return lines;
}

ParseResult parseFile( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto bytes = file.readAll();
    return parsePcap( reinterpret_cast<const uint8_t*>( bytes.constData() ),
                      static_cast<size_t>( bytes.size() ) );
}

QString column( const std::string& value )
{
    return value.empty() ? QStringLiteral( "-" ) : QString::fromStdString( value );
}

} // namespace

SCENARIO( "The Converter keeps checkpoints of a capture's records", "[capture_index]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const auto capture = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );

    GIVEN( "a capture converted with a checkpoint every 3 packets" )
    {
        const auto result = convertWithInterval( capture, out.path(), 3 );
        const auto& index = *result.index;

        THEN( "it counts the packets and keeps a checkpoint after every third" )
        {
            REQUIRE( index.packets() == result.summary.packets );
            REQUIRE( index.interval() == 3 );
            REQUIRE( index.checkpoints().size() == result.summary.packets / 3 );
            for ( size_t i = 0; i < index.checkpoints().size(); ++i ) {
                REQUIRE( index.checkpoints()[ i ].packetsBefore == 3 * ( i + 1 ) );
            }
            REQUIRE( index.capturePath() == QFileInfo( capture ).canonicalFilePath() );
        }

        THEN( "a packet is read from the last checkpoint before it" )
        {
            REQUIRE( index.nearest( 1 ) == nullptr );
            REQUIRE( index.nearest( 3 ) == nullptr );
            REQUIRE( index.nearest( 4 )->packetsBefore == 3 );
            REQUIRE( index.nearest( 7 )->packetsBefore == 6 );
        }
    }

    GIVEN( "a capture converted with the default interval" )
    {
        const auto result = convertPcap( capture, out.path() );

        THEN( "a small capture needs no checkpoint" )
        {
            REQUIRE( result.index->interval() == CaptureIndex::kCheckpointInterval );
            REQUIRE( result.index->checkpoints().empty() );
            REQUIRE( result.index->packets() == result.summary.packets );
        }
    }
}

SCENARIO( "The Converter keeps where each stream begins and ends", "[capture_index]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    GIVEN( "a converted capture of TCP and UDP streams" )
    {
        const auto capture = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );
        const auto result = convertPcap( capture, out.path() );
        REQUIRE( result.status == ConversionResult::Status::Converted );
        const auto lines = packetLines( result.outputPath );
        const auto parsed = parseFile( capture );
        REQUIRE( parsed.packets.size() == static_cast<size_t>( lines.size() ) );

        THEN( "each stream's extent runs from its first to its last packet line" )
        {
            // Per transport and stream: the first and last line numbering it.
            std::map<std::pair<int, int>, std::pair<uint32_t, uint32_t>> expected;
            for ( int i = 0; i < lines.size(); ++i ) {
                const auto match = packetLineRegex().match( lines[ i ] );
                REQUIRE( match.hasMatch() );
                bool numbered = false;
                const int stream = match.captured( "stream" ).toInt( &numbered );
                const auto& transport = parsed.packets[ static_cast<size_t>( i ) ].transport;
                if ( !numbered || !transport ) {
                    continue;
                }
                const auto number = static_cast<uint32_t>( i + 1 );
                auto [ it, added ] = expected.try_emplace(
                    { static_cast<int>( *transport ), stream }, number, number );
                it->second.second = number;
            }
            REQUIRE( expected.size() >= 3 );
            for ( const auto& [ key, extent ] : expected ) {
                const auto noted
                    = result.index->streamExtent( static_cast<Transport>( key.first ), key.second );
                REQUIRE( noted );
                REQUIRE( noted->first == extent.first );
                REQUIRE( noted->last == extent.second );
            }
        }

        THEN( "a stream not numbered has no extent" )
        {
            REQUIRE_FALSE( result.index->streamExtent( Transport::Tcp, 100000 ) );
            REQUIRE_FALSE( result.index->streamExtent( Transport::Udp, -2 ) );
        }
    }
}

SCENARIO( "A packet line's number leads to its packet in the capture", "[capture_index]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    for ( const auto& capture : tcpdump_test::committedCaptures() ) {
        GIVEN( "the corpus capture " + QFileInfo( capture ).fileName().toStdString() )
        {
            const auto result = convertWithInterval( capture, out.path(), 4 );
            const auto lines = packetLines( result.outputPath );
            const auto parsed = parseFile( capture );
            REQUIRE( parsed.ok );
            REQUIRE( static_cast<size_t>( lines.size() ) == parsed.packets.size() );

            THEN( "the packet of every line, read in any order, is the one the line shows" )
            {
                std::vector<int> order( static_cast<size_t>( lines.size() ) );
                for ( size_t i = 0; i < order.size(); ++i ) {
                    order[ i ] = static_cast<int>( i );
                }
                std::shuffle( order.begin(), order.end(), std::mt19937( 52 ) );

                CaptureCursor cursor( result.index );
                for ( const auto i : order ) {
                    const auto match = packetLineRegex().match( lines[ i ] );
                    REQUIRE( match.hasMatch() );
                    const auto number = match.captured( "number" ).toUInt();
                    INFO( "line " << lines[ i ].toStdString() );

                    CapturedPacket packet;
                    REQUIRE( cursor.read( number, packet ) );
                    const auto& record = packet.record;
                    const auto& expected = parsed.packets[ number - 1 ];
                    REQUIRE( record.number == number );
                    REQUIRE( record.info == expected.info );
                    REQUIRE( record.capturedLen == expected.capturedLen );
                    REQUIRE( packet.bytes.size()
                             == std::min( record.capturedLen, kMaxDissectedBytes ) );
                    REQUIRE( match.captured( "timestamp" ).toStdString()
                             == formatUtcTime( record.timestampSec, record.timestampNsec,
                                               parsed.precision ) );
                    REQUIRE( match.captured( "source" )
                             == column( record.srcIp.empty() ? record.srcMac : record.srcIp ) );
                    REQUIRE( match.captured( "destination" )
                             == column( record.dstIp.empty() ? record.dstMac : record.dstIp ) );
                    REQUIRE( match.captured( "length" ).toUInt() == record.originalLen );

                    // Its layers lie within its bytes.
                    const auto layers = dissectLayers( record, packet.bytes.data(),
                                                       packet.bytes.size(), packet.byteSwapped );
                    REQUIRE( layers.size() >= 2 );
                    for ( const auto& layer : layers ) {
                        REQUIRE( layer.offset + layer.length <= packet.bytes.size() );
                        for ( const auto& field : layer.fields ) {
                            REQUIRE( field.offset + field.length <= packet.bytes.size() );
                        }
                    }
                }
            }

            THEN( "the record's place in the file holds the record" )
            {
                QFile file( capture );
                REQUIRE( file.open( QIODevice::ReadOnly ) );
                const auto bytes = file.readAll();
                CaptureCursor cursor( result.index );
                for ( uint32_t number = 1; number <= result.index->packets(); ++number ) {
                    CapturedPacket packet;
                    REQUIRE( cursor.read( number, packet ) );
                    REQUIRE( packet.recordOffset + packet.recordLength
                             <= static_cast<uint64_t>( bytes.size() ) );
                    // The packet's bytes are the record's last ones but its trailer.
                    const auto record = bytes.mid( static_cast<qsizetype>( packet.recordOffset ),
                                                   static_cast<qsizetype>( packet.recordLength ) );
                    const QByteArray data( reinterpret_cast<const char*>( packet.bytes.data() ),
                                           static_cast<qsizetype>( packet.bytes.size() ) );
                    REQUIRE( record.contains( data ) );
                }
            }
        }
    }
}

SCENARIO( "A packet past the capture or of a changed file is reported", "[capture_index]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    const auto capture = dir.filePath( "copy.pcap" );
    REQUIRE( QFile::copy( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ), capture ) );
    const auto result = convertWithInterval( capture, dir.path(), 3 );
    CaptureCursor cursor( result.index );
    CapturedPacket packet;

    GIVEN( "a number the capture has no packet of" )
    {
        THEN( "the cursor says so" )
        {
            REQUIRE_FALSE( cursor.read( 0, packet ) );
            REQUIRE_FALSE( cursor.read( result.index->packets() + 1, packet ) );
            REQUIRE( cursor.error().contains( "has no packet" ) );
        }
    }

    GIVEN( "the capture file changed after the conversion" )
    {
        REQUIRE( cursor.read( 2, packet ) );
        QFile file( capture );
        REQUIRE( file.open( QIODevice::Append ) );
        file.write( QByteArray( 16, '\0' ) );
        file.close();

        THEN( "no packet is read from it" )
        {
            REQUIRE_FALSE( cursor.read( 5, packet ) );
            REQUIRE( cursor.error().contains( "has changed since it was converted" ) );
        }
    }

    GIVEN( "a live capture's file, still growing, set Growing" )
    {
        auto growing = std::make_shared<CaptureIndex>( *result.index );
        growing->setCaptureFile( capture, CaptureIndex::Growth::Growing );
        CaptureCursor live( growing );

        WHEN( "more is written behind its packets" )
        {
            QFile file( capture );
            REQUIRE( file.open( QIODevice::Append ) );
            file.write( QByteArray( 16, '\0' ) );
            file.close();

            THEN( "its packets are still read" )
            {
                REQUIRE( live.read( 5, packet ) );
                REQUIRE( packet.record.number == 5 );
            }
        }

        WHEN( "it became shorter" )
        {
            QFile file( capture );
            REQUIRE( file.resize( file.size() - 1 ) );

            THEN( "no packet is read from it" )
            {
                REQUIRE_FALSE( live.read( 5, packet ) );
                REQUIRE( live.error().contains( "has changed since it was converted" ) );
            }
        }
    }

    GIVEN( "the capture file was removed" )
    {
        REQUIRE( QFile::remove( capture ) );

        THEN( "the cursor says it is gone" )
        {
            REQUIRE_FALSE( cursor.read( 1, packet ) );
            REQUIRE( cursor.error().contains( "is gone" ) );
        }
    }
}

SCENARIO( "A ring buffer file without the headers a checkpoint names is not misread",
          "[capture_index]" )
{
    using namespace tcpdump_test;
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    // A section header, a custom block, an interface and six packets.
    Pcapng le;
    const auto shb = le.shb();
    const auto custom = le.block( 0x00000BAD, Bytes( 8, 0x11 ) );
    const auto idb = le.idb( DltEthernet );
    std::vector<Bytes> epbs;
    for ( uint32_t i = 0; i < 6; ++i ) {
        epbs.push_back( le.epb(
            0, 1000 + i,
            eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 5000, 6000 + i, Bytes( 20, 'a' ) ) ) ) ) );
    }
    Bytes whole = shb + custom + idb;
    for ( const auto& epb : epbs ) {
        whole = whole + epb;
    }
    const auto write = [ & ]( const QString& name, const Bytes& bytes ) {
        const auto path = dir.filePath( name );
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( reinterpret_cast<const char*>( bytes.data() ),
                    static_cast<qint64>( bytes.size() ) );
        file.close();
        return QFileInfo( path ).canonicalFilePath();
    };
    const auto first = write( "ring-1.pcapng", whole );
    const auto converted = convertWithInterval( first, dir.path(), 2 );

    // A second file from packet 4 on, the section header and interface
    // copied ahead of its records, as a ring buffer writes it.
    const uint64_t cut = shb.size() + custom.size() + idb.size() + 3 * epbs[ 0 ].size();
    Bytes second
        = shb + idb + Bytes( whole.begin() + static_cast<std::ptrdiff_t>( cut ), whole.end() );
    CapturePart part1;
    part1.path = first;
    CapturePart part2;
    part2.path = write( "ring-2.pcapng", second );
    part2.packetsBefore = 3;
    part2.streamOffset = cut;
    part2.headerLength = shb.size() + idb.size();
    auto index = std::make_shared<CaptureIndex>( *converted.index );
    CapturedPacket packet;

    GIVEN( "the file's headers where it says" )
    {
        part2.headerOffsets = { { 0, 0 }, { shb.size() + custom.size(), shb.size() } };
        index->setCaptureParts( { part1, part2 } );
        CaptureCursor cursor( index );

        THEN( "a packet after a checkpoint in it has its headers where they are" )
        {
            REQUIRE( cursor.read( 5, packet ) );
            REQUIRE( packet.file == part2.path );
            REQUIRE( packet.headers.records.size() == 2 );
            REQUIRE( packet.headers.records[ 1 ].offset == shb.size() );
        }
    }

    GIVEN( "the file without where its headers are" )
    {
        index->setCaptureParts( { part1, part2 } );
        CaptureCursor cursor( index );

        THEN( "the packet is not read, and the cursor says why" )
        {
            REQUIRE_FALSE( cursor.read( 5, packet ) );
            REQUIRE( cursor.error().contains( "headers" ) );
        }
    }
}
