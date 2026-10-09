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
 * @file stream_content_test.cpp
 * @brief BDD tests for Follow stream content: a stream's payload read back
 *        from its capture in order, rendered as text or hex, exported.
 */

#include <catch2/catch.hpp>

#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "stream_content.h"

#include <QFile>
#include <QTemporaryDir>

#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;
using Status = StreamContentReader::Status;

namespace {

constexpr uint8_t kSyn = 0x02, kAck = 0x10, kPshAck = 0x18, kSynAck = 0x12, kFinAck = 0x11;
constexpr uint32_t kClientIsn = 1000, kServerIsn = 5000;

/// A segment from the client (port 40000) to the server (port 80), or back.
Bytes segment( bool fromServer, uint8_t flags, uint32_t seq, uint32_t ack,
               const std::string& payload = {} )
{
    Ipv4Options addresses;
    if ( fromServer ) {
        std::swap( addresses.src, addresses.dst );
    }
    return eth( EthertypeIpv4,
                ipv4( IpProtoTcp,
                      fromServer ? tcp( 80, 40000, text( payload ), 5, flags, seq, ack )
                                 : tcp( 40000, 80, text( payload ), 5, flags, seq, ack ),
                      addresses ) );
}

/// Client data at relative sequence number @p rel (1 = the first byte).
Bytes client( uint32_t rel, const std::string& payload, uint32_t serverRel = 1 )
{
    return segment( false, kPshAck, kClientIsn + rel, kServerIsn + serverRel, payload );
}

Bytes server( uint32_t rel, const std::string& payload, uint32_t clientRel )
{
    return segment( true, kPshAck, kServerIsn + rel, kClientIsn + clientRel, payload );
}

/// The three packets of a handshake.
std::vector<Bytes> handshake()
{
    return { segment( false, kSyn, kClientIsn, 0 ),
             segment( true, kSynAck, kServerIsn, kClientIsn + 1 ),
             segment( false, kAck, kClientIsn + 1, kServerIsn + 1 ) };
}

/// A capture of @p packets, converted; its index.
struct Converted {
    explicit Converted( const std::vector<Bytes>& packets, const FileOptions& options = {} )
    {
        REQUIRE( dir.isValid() );
        std::vector<Record> records;
        uint32_t usec = 0;
        for ( const auto& packet : packets ) {
            records.push_back( { packet, 1000, usec += 1000 } );
        }
        const auto bytes = pcapFile( records, options );
        const auto path = dir.filePath( "stream.pcap" );
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( reinterpret_cast<const char*>( bytes.data() ),
                    static_cast<qint64>( bytes.size() ) );
        file.close();
        result = convertPcap( path, dir.path() );
        REQUIRE( result.status == ConversionResult::Status::Converted );
    }

    QTemporaryDir dir;
    ConversionResult result;
};

/// All chunks of the stream of packet @p number.
std::vector<StreamChunk> chunksOf( const Converted& capture, uint32_t number, int stream = 0 )
{
    StreamContentReader reader( capture.result.index, number, stream );
    std::vector<StreamChunk> chunks;
    REQUIRE(
        reader.read( [ & ]( StreamChunk&& c ) { chunks.push_back( std::move( c ) ); }, UINT64_MAX )
        == Status::Done );
    return chunks;
}

/// The chunks as "c:bytes", "s:bytes" and "c:[n missing]".
std::vector<std::string> describe( const std::vector<StreamChunk>& chunks )
{
    std::vector<std::string> out;
    for ( const auto& chunk : chunks ) {
        const std::string side = chunk.direction == 0 ? "c:" : "s:";
        out.push_back( chunk.missing
                           ? side + "[" + std::to_string( chunk.missing ) + " missing]"
                           : side + std::string( chunk.bytes.begin(), chunk.bytes.end() ) );
    }
    return out;
}

QString render( const std::vector<StreamChunk>& chunks, StreamFormat format,
                unsigned directions = kBothDirections, Transport transport = Transport::Tcp )
{
    StreamRenderer renderer( format, directions, transport );
    QString out;
    for ( const auto& chunk : chunks ) {
        out += renderer.render( chunk );
    }
    return out;
}

QByteArray readAll( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return file.readAll();
}

} // namespace

SCENARIO( "A TCP stream's content is read back in sequence order", "[stream_content]" )
{
    GIVEN( "a request in two segments, the second captured first, then the first again, "
           "and a response" )
    {
        auto packets = handshake();
        packets.push_back( client( 9, "HTTP/1.1\r\n\r\n" ) );        // 4: early
        packets.push_back( client( 1, "GET / ex" ) );                // 5: next, then 4
        packets.push_back( client( 1, "GET / ex" ) );                // 6: retransmission
        packets.push_back( client( 5, " / exHTTP" ) );               // 7: overlapping, taken
        packets.push_back( server( 1, "HTTP/1.1 200 OK\r\n", 21 ) ); // 8
        packets.push_back( server( 18, "\r\nhello", 21 ) );          // 9
        const Converted capture( packets );

        WHEN( "the stream of a packet in it is followed" )
        {
            const auto chunks = chunksOf( capture, 8 );

            THEN( "each direction's bytes come once, in order" )
            {
                REQUIRE( describe( chunks )
                         == std::vector<std::string>{ "c:GET / ex", "c:HTTP/1.1\r\n\r\n",
                                                      "s:HTTP/1.1 200 OK\r\n", "s:\r\nhello" } );
                REQUIRE( chunks[ 1 ].packet == 5 );
            }

            THEN( "as text, each direction's run begins a line" )
            {
                REQUIRE( render( chunks, StreamFormat::Text )
                         == "GET / exHTTP/1.1\n\nHTTP/1.1 200 OK\n\nhello" );
                REQUIRE( render( chunks, StreamFormat::Text, kServerToClient )
                         == "HTTP/1.1 200 OK\n\nhello" );
            }

            THEN( "as hex, the offsets count per direction and the server's lines are indented" )
            {
                const auto lines = render( chunks, StreamFormat::Hex, kBothDirections )
                                       .split( '\n', Qt::SkipEmptyParts );
                REQUIRE( lines.size() == 5 );
                REQUIRE( lines[ 0 ]
                         == "00000000  47 45 54 20 2f 20 65 78" + QString( 28, ' ' ) + "GET / ex" );
                REQUIRE(
                    lines[ 1 ].startsWith( "00000008  48 54 54 50 2f 31 2e 31  0d 0a 0d 0a" ) );
                REQUIRE( lines[ 1 ].endsWith( "  HTTP/1.1...." ) );
                REQUIRE( lines[ 2 ].startsWith( "    00000000  48 54 54 50" ) );
                REQUIRE( lines[ 3 ].startsWith( "    00000010  0a " ) );
                REQUIRE( lines[ 4 ].startsWith( "    00000011  0d 0a 68 65 6c 6c 6f" ) );
            }
        }
    }

    GIVEN( "a segment the capture lost, which the server acknowledges" )
    {
        auto packets = handshake();
        packets.push_back( client( 1, "aaaa" ) );
        packets.push_back( client( 9, "cccc" ) );
        packets.push_back( segment( true, kAck, kServerIsn + 1, kClientIsn + 13 ) );
        packets.push_back( server( 1, "ok", 13 ) );
        const Converted capture( packets );

        THEN( "the gap is shown where the bytes are missing" )
        {
            const auto chunks = chunksOf( capture, 4 );
            REQUIRE( describe( chunks )
                     == std::vector<std::string>{ "c:aaaa", "c:[4 missing]", "c:cccc", "s:ok" } );
            REQUIRE( render( chunks, StreamFormat::Text ) == "aaaa\n[4 bytes missing]\ncccc\nok" );
        }
    }

    GIVEN( "an acknowledgement far past what the client sent and its window allows" )
    {
        auto packets = handshake();
        packets.push_back( client( 1, "aaaa" ) );
        packets.push_back( segment( true, kAck, kServerIsn + 1, kClientIsn + 1000000000 ) );
        packets.push_back( client( 5, "bb" ) );
        packets.push_back( server( 1, "ok", 7 ) );
        const Converted capture( packets );

        THEN( "it is taken for bogus: no gap, the bytes after it in order" )
        {
            REQUIRE( describe( chunksOf( capture, 4 ) )
                     == std::vector<std::string>{ "c:aaaa", "c:bb", "s:ok" } );
        }
    }

    GIVEN( "a lost segment nothing acknowledges, at the end of the capture" )
    {
        auto packets = handshake();
        packets.push_back( client( 1, "aaaa" ) );
        packets.push_back( client( 7, "cc" ) );
        const Converted capture( packets );

        THEN( "the bytes held are shown after their gap at the end" )
        {
            REQUIRE( describe( chunksOf( capture, 1 ) )
                     == std::vector<std::string>{ "c:aaaa", "c:[2 missing]", "c:cc" } );
        }
    }

    GIVEN( "a connection closed with FINs, each acknowledged" )
    {
        auto packets = handshake();
        packets.push_back( client( 1, "hi" ) );
        packets.push_back( segment( false, kFinAck, kClientIsn + 3, kServerIsn + 1 ) );
        packets.push_back( segment( true, kFinAck, kServerIsn + 1, kClientIsn + 4 ) );
        packets.push_back( segment( false, kAck, kClientIsn + 4, kServerIsn + 2 ) );
        const Converted capture( packets );

        THEN( "the FIN's sequence number is no byte missing" )
        {
            REQUIRE( describe( chunksOf( capture, 5 ) ) == std::vector<std::string>{ "c:hi" } );
        }
    }

    GIVEN( "a stream captured after its handshake, the server's packet first" )
    {
        const Converted capture( { server( 1, "banner\n", 1 ), client( 1, "hello\n" ) } );

        THEN( "the side that sent the first packet is the client" )
        {
            StreamContentReader reader( capture.result.index, 2, 0 );
            std::vector<StreamChunk> chunks;
            REQUIRE( reader.read( [ & ]( StreamChunk&& c ) { chunks.push_back( std::move( c ) ); },
                                  UINT64_MAX )
                     == Status::Done );
            REQUIRE( reader.ends().name( 0 ) == "192.168.1.2:80" );
            REQUIRE( reader.ends().name( 1 ) == "192.168.1.1:40000" );
            REQUIRE( describe( chunks ) == std::vector<std::string>{ "c:banner\n", "s:hello\n" } );
            REQUIRE( reader.bytesSent( 0 ) == 7 );
            REQUIRE( reader.bytesSent( 1 ) == 6 );
        }
    }
}

SCENARIO( "Other streams' packets are not followed", "[stream_content]" )
{
    GIVEN( "two TCP streams between the same hosts, interleaved, and a UDP one" )
    {
        std::vector<Bytes> packets{
            client( 1, "one" ),
            eth( EthertypeIpv4,
                 ipv4( IpProtoTcp, tcp( 40001, 80, text( "two" ), 5, kPshAck, 1, 1 ) ) ),
            eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 80, text( "udp" ) ) ) ),
            client( 4, "ONE" ),
        };
        const Converted capture( packets );

        THEN( "only the stream of the packet is read, by its extent" )
        {
            REQUIRE( describe( chunksOf( capture, 4 ) )
                     == std::vector<std::string>{ "c:one", "c:ONE" } );
            REQUIRE( describe( chunksOf( capture, 2, 1 ) ) == std::vector<std::string>{ "c:two" } );
        }

        THEN( "an unnumbered stream is looked for in the whole capture" )
        {
            REQUIRE( describe( chunksOf( capture, 1, kUnnumbered ) )
                     == std::vector<std::string>{ "c:one", "c:ONE" } );
        }
    }
}

SCENARIO( "A UDP stream's content is its datagrams", "[stream_content]" )
{
    GIVEN( "datagrams both ways, one cut at the snaplen" )
    {
        Ipv4Options back;
        std::swap( back.src, back.dst );
        const auto query
            = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 5000, 6000, text( "ping" ) ) ) );
        const auto answer
            = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 6000, 5000, text( "pong" ) ), back ) );
        const auto longer
            = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 5000, 6000, text( "abcdefgh" ) ) ) );
        QTemporaryDir dir;
        std::vector<Record> records{ { query }, { answer }, { query } };
        Record cut{ longer };
        cut.inclLen = static_cast<int64_t>( longer.size() - 3 );
        cut.data.resize( longer.size() - 3 );
        cut.origLen = static_cast<int64_t>( longer.size() );
        records.push_back( cut );
        const auto bytes = pcapFile( records );
        const auto path = dir.filePath( "udp.pcap" );
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( reinterpret_cast<const char*>( bytes.data() ),
                    static_cast<qint64>( bytes.size() ) );
        file.close();
        const auto result = convertPcap( path, dir.path() );
        REQUIRE( result.status == ConversionResult::Status::Converted );

        THEN( "each datagram is a chunk, the part cut missing, and each shows on its own line" )
        {
            StreamContentReader reader( result.index, 2, 0 );
            std::vector<StreamChunk> chunks;
            REQUIRE( reader.read( [ & ]( StreamChunk&& c ) { chunks.push_back( std::move( c ) ); },
                                  UINT64_MAX )
                     == Status::Done );
            REQUIRE( describe( chunks )
                     == std::vector<std::string>{ "c:ping", "s:pong", "c:ping", "c:abcde",
                                                  "c:[3 missing]" } );
            REQUIRE( render( chunks, StreamFormat::Text, kBothDirections, Transport::Udp )
                     == "ping\npong\nping\nabcde\n[3 bytes missing]\n" );
        }
    }
}

SCENARIO( "A stream is read a budget at a time, and can be cancelled", "[stream_content]" )
{
    std::vector<Bytes> packets;
    for ( uint32_t i = 0; i < 10; ++i ) {
        packets.push_back( client( 1 + i * 10, std::string( 10, static_cast<char>( 'a' + i ) ) ) );
    }
    const Converted capture( packets );

    GIVEN( "a budget of 25 bytes" )
    {
        StreamContentReader reader( capture.result.index, 1, 0 );
        std::vector<StreamChunk> chunks;
        const auto sink = [ & ]( StreamChunk&& c ) { chunks.push_back( std::move( c ) ); };

        THEN( "each read stops after the packet that reaches it, and goes on from there" )
        {
            REQUIRE( reader.read( sink, 25 ) == Status::More );
            REQUIRE( chunks.size() == 3 );
            REQUIRE( reader.read( sink, 25 ) == Status::More );
            REQUIRE( chunks.size() == 6 );
            REQUIRE( reader.read( sink, 1000 ) == Status::Done );
            REQUIRE( chunks.size() == 10 );
            REQUIRE( reader.bytesSent( 0 ) == 100 );
        }

        THEN( "progress counts the packets read of the stream's" )
        {
            uint32_t done = 0, total = 0;
            reader.read( sink, UINT64_MAX, nullptr, [ & ]( uint32_t d, uint32_t t ) {
                done = d;
                total = t;
            } );
            REQUIRE( done == 10 );
            REQUIRE( total == 10 );
        }
    }

    GIVEN( "a cancel request" )
    {
        StreamContentReader reader( capture.result.index, 1, 0 );
        std::atomic_bool cancel{ true };

        THEN( "the read stops" )
        {
            REQUIRE( reader.read( []( StreamChunk&& ) {}, UINT64_MAX, &cancel )
                     == Status::Cancelled );
        }
    }

    GIVEN( "a packet of no stream" )
    {
        const Converted arp( { eth( 0x0806, Bytes( 28, 0 ) ) } );
        StreamContentReader reader( arp.result.index, 1, kNoStream );

        THEN( "it cannot be followed" )
        {
            REQUIRE_FALSE( reader.open() );
            REQUIRE( reader.error().contains( "no TCP or UDP stream" ) );
        }
    }
}

SCENARIO( "Stream text keeps UTF-8 and escapes control bytes", "[stream_content]" )
{
    const std::string bytes = "a\r\nb\x01\xff \xc3\xa9\xe2\x82\xac\xc2\x85\tz\r";
    const auto text = streamText( reinterpret_cast<const uint8_t*>( bytes.data() ), bytes.size() );
    REQUIRE( text == QString::fromUtf8( "a\nb\\x01\\xff \xc3\xa9\xe2\x82\xac\\xc2\\x85\tz\\x0d" ) );
}

SCENARIO( "A stream's content is exported whole", "[stream_content]" )
{
    auto packets = handshake();
    packets.push_back( client( 1, "GET /\r\n" ) );
    packets.push_back( server( 1, "body\n", 8 ) );
    packets.push_back( client( 8, "bye\n", 6 ) );
    const Converted capture( packets );
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const auto path = out.filePath( "stream.bin" );

    GIVEN( "a reader of the stream" )
    {
        StreamContentReader reader( capture.result.index, 4, 0 );

        THEN( "the raw bytes of one direction are written as they were sent" )
        {
            const auto result
                = exportStreamContent( reader, path, true, StreamFormat::Text, kClientToServer );
            REQUIRE( result.status == Status::Done );
            REQUIRE( readAll( path ) == "GET /\r\nbye\n" );
            REQUIRE( result.bytes == 11 );
        }

        THEN( "the raw bytes of both are written in the order they were sent" )
        {
            exportStreamContent( reader, path, true, StreamFormat::Text, kBothDirections );
            REQUIRE( readAll( path ) == "GET /\r\nbody\nbye\n" );
        }

        THEN( "as shown, the text is written as rendered" )
        {
            exportStreamContent( reader, path, false, StreamFormat::Hex, kServerToClient );
            REQUIRE( readAll( path ).startsWith( "    00000000  62 6f 64 79 0a" ) );
        }

        THEN( "a cancelled export leaves no file" )
        {
            std::atomic_bool cancel{ true };
            const auto result = exportStreamContent( reader, path, true, StreamFormat::Text,
                                                     kBothDirections, &cancel );
            REQUIRE( result.status == Status::Cancelled );
            REQUIRE_FALSE( QFile::exists( path ) );
        }

        THEN( "a file that cannot be written fails the export" )
        {
            const auto result = exportStreamContent( reader, out.filePath( "no/such/dir" ), true,
                                                     StreamFormat::Text, kBothDirections );
            REQUIRE( result.status == Status::Failed );
            REQUIRE( result.error.startsWith( "Cannot write" ) );
        }
    }
}
