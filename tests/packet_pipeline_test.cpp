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
 * @file packet_pipeline_test.cpp
 * @brief BDD tests for the Packet Pipeline, through its interface: a
 *        message reassembled, a TLS record decrypted with a key log, and a
 *        packet labelled "Continuation" by its stream.
 */

#include <catch2/catch.hpp>

#include "capture_reader.h"
#include "packet_pipeline.h"
#include "pcapbuilder.h"
#include "tls_key_log.h"

#include <QFile>

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kAck = 0x10;
constexpr uint8_t kPshAck = 0x18;

constexpr uint16_t kClient = 50000;

/// A TCP segment between the client and @p server, back when @p fromServer.
Bytes segment( uint16_t server, bool fromServer, uint32_t seq, uint32_t ack,
               const Bytes& payload = {}, uint8_t flags = kPshAck )
{
    auto addresses = Ipv4Options{};
    if ( fromServer ) {
        std::swap( addresses.src, addresses.dst );
    }
    return eth( EthertypeIpv4,
                ipv4( IpProtoTcp,
                      fromServer ? tcp( server, kClient, payload, 5, flags, seq, ack )
                                 : tcp( kClient, server, payload, 5, flags, seq, ack ),
                      addresses ) );
}

/// A packet as the Packet Pipeline left it, and what it found out.
struct Piped {
    PacketRecord pkt;
    Stream stream;
    Bytes completed; ///< The messages it completed (PacketOutcome::messages)
    uint32_t segments = 0;
};

/// The packets of @p capture, each taken through @p pipeline with its
/// payload as the reader gives it.
std::vector<Piped> piped( const Bytes& capture, PacketPipeline& pipeline )
{
    MemorySource memory( capture.data(), capture.size() );
    HeadSource head( memory );
    const auto reader = makeCaptureReader( head );
    REQUIRE( reader->open() );
    std::vector<Piped> out;
    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto outcome = pipeline.run( pkt, reader->payloadOf( pkt ) );
        Piped one{ pkt, outcome.stream, {}, outcome.messages.segments };
        if ( outcome.messages.bytes.data ) {
            one.completed.assign( outcome.messages.bytes.data,
                                  outcome.messages.bytes.data + outcome.messages.bytes.size );
        }
        out.push_back( std::move( one ) );
    }
    return out;
}

std::vector<Piped> piped( const Bytes& capture, const PipelineOptions& options = {} )
{
    PacketPipeline pipeline( options );
    return piped( capture, pipeline );
}

bool contains( const std::string& text, const std::string& part )
{
    return text.find( part ) != std::string::npos;
}

Bytes corpusFile( const QString& name )
{
    QFile file( QStringLiteral( TCPDUMP_CORPUS_DIR ) + "/" + name );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto bytes = file.readAll();
    return Bytes( bytes.begin(), bytes.end() );
}

/// A TLS application data record of @p size bytes.
Bytes tlsRecord( size_t size )
{
    Bytes b{ 0x17, 0x03, 0x03 };
    putBE16( b, static_cast<uint16_t>( size ) );
    b.resize( b.size() + size, 0xAB );
    return b;
}

} // namespace

SCENARIO( "The Packet Pipeline reassembles a message over segments", "[packet_pipeline]" )
{
    GIVEN( "a TLS record sent in two segments" )
    {
        const auto record = tlsRecord( 300 );
        const Bytes first( record.begin(), record.begin() + 100 );
        const Bytes rest( record.begin() + 100, record.end() );
        const auto packets = piped( pcapOf( {
            segment( 443, false, 1, 1, first ),
            segment( 443, false, 101, 1, rest ),
        } ) );

        THEN( "both are of the one stream" )
        {
            REQUIRE( packets[ 0 ].stream.id == 0 );
            REQUIRE( packets[ 1 ].stream.id == 0 );
        }
        THEN( "the first segment is a part of the message, and completes none" )
        {
            REQUIRE( contains( packets[ 0 ].pkt.info, kSegmentOfMessage ) );
            REQUIRE( packets[ 0 ].completed.empty() );
        }
        THEN( "the second completes the record, put together from both" )
        {
            REQUIRE( packets[ 1 ].completed == record );
            REQUIRE( packets[ 1 ].segments == 2 );
            REQUIRE( contains( packets[ 1 ].pkt.info, "[reassembled from 2 segments]" ) );
        }
    }
}

SCENARIO( "The Packet Pipeline decrypts TLS with a key log", "[packet_pipeline]" )
{
    const auto capture = corpusFile( "tls-decrypt.pcap" );

    GIVEN( "the synthetic sessions and the secrets of their key log" )
    {
        const auto text = corpusFile( "tls-decrypt.keys" );
        tls::KeyLog keys;
        keys.addLines( reinterpret_cast<const char*>( text.data() ), text.size() );
        PipelineOptions options;
        options.tlsKeys
            = [ &keys ]( const uint8_t* clientRandom ) { return keys.find( clientRandom ); };
        PacketPipeline pipeline( options );
        const auto packets = piped( capture, pipeline );

        THEN( "records are decrypted, and what they carry described" )
        {
            const auto decrypted
                = std::count_if( packets.begin(), packets.end(), []( const Piped& p ) {
                      return contains( p.pkt.info, kDecryptedMarker );
                  } );
            REQUIRE( decrypted > 0 );
            REQUIRE( std::any_of( packets.begin(), packets.end(), []( const Piped& p ) {
                return contains( p.pkt.info, std::string( kDecryptedMarker ) + " | GET " );
            } ) );
        }
        THEN( "the pipeline counts the sessions it decrypted" )
        {
            REQUIRE( pipeline.tlsSessionsDecrypted().value_or( 0 ) > 0 );
        }
    }
    GIVEN( "the sessions without a key log" )
    {
        PacketPipeline pipeline;
        const auto packets = piped( capture, pipeline );

        THEN( "nothing is decrypted, and no sessions are counted" )
        {
            REQUIRE( std::none_of( packets.begin(), packets.end(), []( const Piped& p ) {
                return contains( p.pkt.info, kDecryptedMarker );
            } ) );
            REQUIRE_FALSE( pipeline.tlsSessionsDecrypted() );
        }
    }
}

SCENARIO( "The Packet Pipeline labels a packet by its stream", "[packet_pipeline]" )
{
    const auto get = text( "GET / HTTP/1.1\r\nHost: x\r\n\r\n" );
    const auto body = text( "{\"hello\": \"world\"}" );
    const auto capture = pcapOf( {
        segment( 3000, false, 1, 1, get ),
        segment( 3000, true, 1, 1 + get.size(), {}, kAck ),
        segment( 3000, true, 1, 1 + get.size(), body ),
    } );

    GIVEN( "an HTTP exchange on a port without a hint" )
    {
        const auto packets = piped( capture );

        THEN( "the body is HTTP by its stream, a continuation with its preview" )
        {
            REQUIRE( packets[ 0 ].pkt.protocol == "HTTP" );
            REQUIRE( packets[ 2 ].pkt.protocol == "HTTP" );
            REQUIRE( contains( packets[ 2 ].pkt.info, " | Continuation: {\"hello\"" ) );
        }
    }
    GIVEN( "the same exchange with previews left out" )
    {
        PipelineOptions options;
        options.previewChars = 0;
        const auto packets = piped( capture, options );

        THEN( "the preview was cut before the label: a bare continuation" )
        {
            REQUIRE( packets[ 2 ].pkt.protocol == "HTTP" );
            REQUIRE( packets[ 2 ].pkt.info.size() >= std::string( " | Continuation" ).size() );
            REQUIRE( packets[ 2 ].pkt.info.substr( packets[ 2 ].pkt.info.size()
                                                   - std::string( " | Continuation" ).size() )
                     == " | Continuation" );
        }
    }
}
