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
 * @file websocket_test.cpp
 * @brief BDD tests for WebSocket: the HTTP upgrade that makes a stream
 *        WebSocket, its frames of every opcode with their flags, lengths,
 *        text and close code, framing for the TCP Reassembly, and frames
 *        mangled and cut anywhere.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"

#include <array>
#include <optional>
#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kServerPort = 8080;
constexpr uint16_t kClientPort = 50080;

const std::string kEllipsis = "\xe2\x80\xa6";

using Mask = std::array<uint8_t, 4>;
constexpr Mask kMask = { 0x37, 0xFA, 0x21, 0x3D };

/// A WebSocket frame: opcode @p opcode, @p payload, masked with @p mask if
/// there is one, its length in the shortest of the 7-, 16- and 64-bit forms
/// (or the 64-bit one with @p longForm).
Bytes frame( uint8_t opcode, const Bytes& payload, std::optional<Mask> mask = std::nullopt,
             bool fin = true, uint8_t rsv = 0, bool longForm = false )
{
    Bytes b{ static_cast<uint8_t>( ( fin ? 0x80 : 0 ) | rsv | opcode ) };
    const uint8_t maskBit = mask ? 0x80 : 0;
    const auto n = payload.size();
    if ( n < 126 && !longForm ) {
        b.push_back( static_cast<uint8_t>( maskBit | n ) );
    }
    else if ( n <= 0xFFFF && !longForm ) {
        b.push_back( maskBit | 126 );
        putBE16( b, static_cast<uint16_t>( n ) );
    }
    else {
        b.push_back( maskBit | 127 );
        putBE32( b, 0 );
        putBE32( b, static_cast<uint32_t>( n ) );
    }
    if ( !mask ) {
        return b + payload;
    }
    b.insert( b.end(), mask->begin(), mask->end() );
    for ( size_t i = 0; i < n; ++i ) {
        b.push_back( payload[ i ] ^ ( *mask )[ i % 4 ] );
    }
    return b;
}

Bytes closePayload( uint16_t code, const std::string& reason = {} )
{
    Bytes b;
    putBE16( b, code );
    return b + text( reason );
}

const Bytes kUpgradeRequest = text( "GET /chat HTTP/1.1\r\n"
                                    "Host: example.com\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                                    "Sec-WebSocket-Version: 13\r\n\r\n" );

Bytes upgradeResponse( const std::string& upgrade = "websocket",
                       const std::string& status = "101 Switching Protocols" )
{
    return text( "HTTP/1.1 " + status
                 + "\r\n"
                   "Upgrade: "
                 + upgrade
                 + "\r\n"
                   "Connection: Upgrade\r\n"
                   "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                   "Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n" );
}

/// The label of @p extent, empty without one.
std::string labelOf( const MessageExtent& extent )
{
    return extent.label ? extent.label : "";
}

/// The WebSocket framer's number, as tcpMessageExtent() gives it on an
/// upgraded stream.
uint8_t webSocketFramer()
{
    StreamState state;
    state.protocols = StreamState::kWebSocket;
    const Stream stream{ 0, &state, 0 };
    const auto ping = frame( 0x9, {} );
    const auto extent
        = tcpMessageExtent( ping.data(), ping.size(), kClientPort, kServerPort, 0, &stream );
    REQUIRE( labelOf( extent ) == "WebSocket" );
    return extent.framer;
}

/// The description of @p bytes, whole frames of an upgraded stream, as the
/// TCP Reassembly describes them.
std::string frames( const Bytes& bytes )
{
    const auto described = describeTcpMessages( bytes.data(), bytes.size(), kClientPort,
                                                kServerPort, webSocketFramer() );
    REQUIRE( described.label == "WebSocket" );
    return described.description;
}

Bytes prefix( const Bytes& b, size_t n )
{
    return Bytes( b.begin(), b.begin() + static_cast<std::ptrdiff_t>( std::min( n, b.size() ) ) );
}

/// A packet's description, after the transport summary.
std::string descriptionOf( const PacketRecord& pkt )
{
    const auto at = pkt.info.find( kDescriptionSeparator );
    return at == std::string::npos
               ? std::string()
               : pkt.info.substr( at + std::string( kDescriptionSeparator ).size() );
}

/// @p payloads sent between the client and the server, true from the
/// client, run through the Converter's steps but the TCP Reassembly.
std::vector<PacketRecord> inStream( const std::vector<std::pair<bool, Bytes>>& payloads )
{
    std::vector<Bytes> packets;
    for ( const auto& [ client, payload ] : payloads ) {
        Ipv4Options o;
        if ( !client ) {
            std::swap( o.src, o.dst );
        }
        packets.push_back(
            eth( EthertypeIpv4, ipv4( IpProtoTcp,
                                      client ? tcp( kClientPort, kServerPort, payload )
                                             : tcp( kServerPort, kClientPort, payload ),
                                      o ) ) );
    }
    auto records = parse( pcapOf( packets ) ).packets;
    StreamTracker tracker;
    for ( auto& pkt : records ) {
        const auto stream = tracker.track( pkt );
        describeInStream( pkt, stream );
        rememberInStream( pkt, stream );
    }
    return records;
}

} // namespace

SCENARIO( "An HTTP upgrade makes its stream WebSocket", "[websocket]" )
{
    GIVEN( "the upgrade request and the 101 response" )
    {
        const auto request = describePayload( Transport::Tcp, kUpgradeRequest.data(),
                                              kUpgradeRequest.size(), kClientPort, kServerPort );
        const auto response = upgradeResponse();
        const auto described = describePayload( Transport::Tcp, response.data(), response.size(),
                                                kServerPort, kClientPort );

        THEN( "both stay HTTP; the response names the upgrade and tells the stream" )
        {
            REQUIRE( request.label == "HTTP" );
            REQUIRE( request.description == "GET example.com/chat HTTP/1.1" );
            REQUIRE( request.streamCue == StreamCue::None );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description
                     == "HTTP/1.1 101 Switching Protocols, Upgrade: websocket, "
                        "Sec-WebSocket-Extensions: permessage-deflate" );
            REQUIRE( described.streamCue == StreamCue::WebSocketUpgrade );
        }
    }

    GIVEN( "a 101 to another protocol, and a 200 with an Upgrade header" )
    {
        const auto h2c = upgradeResponse( "h2c" );
        const auto ok = upgradeResponse( "websocket", "200 OK" );

        THEN( "neither upgrades the stream to WebSocket" )
        {
            REQUIRE(
                describePayload( Transport::Tcp, h2c.data(), h2c.size(), kServerPort, kClientPort )
                    .streamCue
                == StreamCue::None );
            const auto described
                = describePayload( Transport::Tcp, ok.data(), ok.size(), kServerPort, kClientPort );
            REQUIRE( described.streamCue == StreamCue::None );
            REQUIRE( described.description == "HTTP/1.1 200 OK" );
        }
    }

    GIVEN( "a stream with the upgrade, then frames both ways" )
    {
        const auto packets = inStream( {
            { true, kUpgradeRequest },
            { false, upgradeResponse() },
            { true, frame( 0x1, text( "Hello" ), kMask ) },
            { false, frame( 0x1, text( "Hi there" ) ) },
            { false, frame( 0x9, {} ) + frame( 0xA, text( "pong" ) ) },
        } );

        THEN( "the frames after the response are WebSocket, the client's unmasked" )
        {
            REQUIRE( packets[ 0 ].protocol == "HTTP" );
            REQUIRE( packets[ 1 ].protocol == "HTTP" );
            for ( size_t i = 2; i < packets.size(); ++i ) {
                REQUIRE( packets[ i ].protocol == "WebSocket" );
                REQUIRE( packets[ i ].protocolRecognised );
            }
            REQUIRE( descriptionOf( packets[ 2 ] )
                     == "WebSocket Text [FIN] [MASKED] len=5 \"Hello\"" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "WebSocket Text [FIN] len=8 \"Hi there\"" );
            REQUIRE( descriptionOf( packets[ 4 ] )
                     == "WebSocket Ping [FIN] len=0, WebSocket Pong [FIN] len=4" );
        }
    }

    GIVEN( "the same frames on a stream without the upgrade" )
    {
        const auto packets = inStream( {
            { true, kUpgradeRequest },
            { true, frame( 0x1, text( "Hello" ), kMask ) },
        } );

        THEN( "they are not WebSocket, nor framed as it" )
        {
            REQUIRE( packets[ 1 ].protocol != "WebSocket" );
            const auto hello = frame( 0x1, text( "Hello" ) );
            REQUIRE(
                labelOf( tcpMessageExtent( hello.data(), hello.size(), kClientPort, kServerPort ) )
                != "WebSocket" );
        }
    }
}

SCENARIO( "WebSocket frames are described as Wireshark shows them", "[websocket]" )
{
    GIVEN( "a frame of each opcode" )
    {
        THEN( "each is named with its FIN and MASKED flags and its length" )
        {
            REQUIRE( frames( frame( 0x1, text( "Hello" ) ) )
                     == "WebSocket Text [FIN] len=5 \"Hello\"" );
            REQUIRE( frames( frame( 0x2, Bytes( 20, 0xAB ), kMask ) )
                     == "WebSocket Binary [FIN] [MASKED] len=20" );
            REQUIRE( frames( frame( 0x1, text( "Hel" ), std::nullopt, false ) )
                     == "WebSocket Text len=3 \"Hel\"" );
            REQUIRE( frames( frame( 0x0, text( "lo" ), kMask ) )
                     == "WebSocket Continuation [FIN] [MASKED] len=2" );
            REQUIRE( frames( frame( 0x9, text( "?" ), kMask ) )
                     == "WebSocket Ping [FIN] [MASKED] len=1" );
            REQUIRE( frames( frame( 0xA, {} ) ) == "WebSocket Pong [FIN] len=0" );
        }
    }

    GIVEN( "close frames with a status code and reason" )
    {
        THEN( "the code is named and the reason shown" )
        {
            REQUIRE( frames( frame( 0x8, closePayload( 1000, "bye" ), kMask ) )
                     == "WebSocket Connection Close [FIN] [MASKED] len=5 Normal Closure (1000) "
                        "\"bye\"" );
            REQUIRE( frames( frame( 0x8, closePayload( 1001 ) ) )
                     == "WebSocket Connection Close [FIN] len=2 Going Away (1001)" );
            REQUIRE( frames( frame( 0x8, closePayload( 4321, "app" ) ) )
                     == "WebSocket Connection Close [FIN] len=5 Status 4321 \"app\"" );
            REQUIRE( frames( frame( 0x8, {} ) ) == "WebSocket Connection Close [FIN] len=0" );
        }
    }

    GIVEN( "lengths in the 16- and the 64-bit forms" )
    {
        THEN( "they are read" )
        {
            REQUIRE( frames( frame( 0x2, Bytes( 300, 0 ) ) ) == "WebSocket Binary [FIN] len=300" );
            REQUIRE( frames( frame( 0x2, Bytes( 70000, 0 ), kMask ) )
                     == "WebSocket Binary [FIN] [MASKED] len=70000" );
            REQUIRE( frames( frame( 0x1, text( "x" ), std::nullopt, true, 0, true ) )
                     == "WebSocket Text [FIN] len=1 \"x\"" );
        }
    }

    GIVEN( "long text, and text that is no ASCII" )
    {
        THEN( "the preview is cut, the bytes escaped" )
        {
            REQUIRE( frames( frame( 0x1, text( std::string( 100, 'a' ) ), kMask ) )
                     == "WebSocket Text [FIN] [MASKED] len=100 \"" + std::string( 40, 'a' ) + "\""
                            + kEllipsis );
            REQUIRE( frames( frame( 0x1, text( "caf\xc3\xa9\n" ) ) )
                     == "WebSocket Text [FIN] len=6 \"caf\\xC3\\xA9\\x0A\"" );
        }
    }

    GIVEN( "a compressed message (permessage-deflate)" )
    {
        THEN( "it is shown as compressed, its bytes not as text" )
        {
            REQUIRE( frames( frame( 0x1, Bytes{ 0xF2, 0x48, 0xCD, 0xC9, 0xC9, 0x07, 0x00 }, kMask,
                                    true, 0x40 ) )
                     == "WebSocket Text [FIN] [MASKED] [COMPRESSED] len=7" );
        }
    }

    GIVEN( "several frames in one segment" )
    {
        Bytes segment;
        for ( int i = 0; i < 10; ++i ) {
            segment = segment + frame( 0x1, text( std::to_string( i ) ), kMask );
        }
        THEN( "all are named, up to eight, then an ellipsis" )
        {
            REQUIRE( frames( frame( 0x1, text( "a" ) ) + frame( 0x8, closePayload( 1000 ) ) )
                     == "WebSocket Text [FIN] len=1 \"a\", WebSocket Connection Close [FIN] len=2 "
                        "Normal Closure (1000)" );
            std::string expected;
            for ( int i = 0; i < 8; ++i ) {
                expected += "WebSocket Text [FIN] [MASKED] len=1 \"" + std::to_string( i ) + "\", ";
            }
            REQUIRE( frames( segment ) == expected + kEllipsis );
        }
    }
}

SCENARIO( "A truncated or malformed WebSocket frame is described as such", "[websocket]" )
{
    GIVEN( "frames cut in their header and in their payload" )
    {
        const auto hello = frame( 0x1, text( "Hello world" ), kMask );
        THEN( "they are described as far as they go, then an ellipsis" )
        {
            REQUIRE( frames( prefix( hello, 1 ) ) == "WebSocket Text " + kEllipsis );
            REQUIRE( frames( prefix( hello, 4 ) ) == "WebSocket Text " + kEllipsis );
            REQUIRE( frames( prefix( hello, 9 ) )
                     == "WebSocket Text [FIN] [MASKED] len=11 \"Hel\"" + kEllipsis );
            const auto close = frame( 0x8, closePayload( 1000, "bye" ) );
            REQUIRE( frames( prefix( close, 3 ) )
                     == "WebSocket Connection Close [FIN] len=5 " + kEllipsis );
        }
    }

    GIVEN( "frames that break the rules of their opcode" )
    {
        Bytes huge{ 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1 };
        THEN( "they are malformed, and the bytes after them not read as frames" )
        {
            REQUIRE( frames( frame( 0x9, text( "x" ), std::nullopt, false ) + frame( 0xA, {} ) )
                     == "WebSocket Ping len=1 [Malformed Packet]" );
            REQUIRE( frames( frame( 0x9, Bytes( 126, 0 ) ) )
                     == "WebSocket Ping [FIN] len=126 [Malformed Packet]" );
            REQUIRE( frames( frame( 0x8, Bytes{ 3 } ) )
                     == "WebSocket Connection Close [FIN] len=1 [Malformed Packet]" );
            REQUIRE( frames( frame( 0x3, {} ) )
                     == "WebSocket Unknown 0x03 [FIN] len=0 "
                        "[Malformed Packet]" );
            REQUIRE( frames( frame( 0xA, {}, std::nullopt, true, 0x40 ) )
                     == "WebSocket Pong [FIN] [COMPRESSED] len=0 [Malformed Packet]" );
            REQUIRE( frames( frame( 0x1, text( "a" ) ) + huge )
                     == "WebSocket Text [FIN] len=1 \"a\", WebSocket Binary [Malformed Packet]" );
        }
    }
}

SCENARIO( "WebSocket is framed for the TCP Reassembly on upgraded streams only", "[websocket]" )
{
    StreamState state;
    const Stream stream{ 0, &state, 0 };
    const auto message = frame( 0x2, Bytes( 300, 0x11 ), kMask );

    GIVEN( "a stream the upgrade has not reached" )
    {
        THEN( "no frame is framed" )
        {
            REQUIRE( labelOf( tcpMessageExtent( message.data(), 100, kClientPort, kServerPort, 0,
                                                &stream ) )
                     != "WebSocket" );
        }
    }

    GIVEN( "an upgraded stream" )
    {
        state.protocols = StreamState::kWebSocket;
        THEN( "a frame is framed by its header, whole messages described in the stream" )
        {
            const auto cut
                = tcpMessageExtent( message.data(), 100, kClientPort, kServerPort, 0, &stream );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == message.size() );
            REQUIRE( cut.describedInStream );
            const auto header
                = tcpMessageExtent( message.data(), 3, kClientPort, kServerPort, 0, &stream );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 8 );
            const auto one
                = tcpMessageExtent( message.data(), 1, kClientPort, kServerPort, 0, &stream );
            REQUIRE( one.needsMore );
            REQUIRE( one.length == 2 );
            const auto whole = tcpMessageExtent( message.data(), message.size(), kClientPort,
                                                 kServerPort, 0, &stream );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == message.size() );
            // A 64-bit length with its top bit set begins no frame.
            const Bytes huge{ 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 1 };
            REQUIRE(
                tcpMessageExtent( huge.data(), huge.size(), kClientPort, kServerPort, 0, &stream )
                    .framer
                == 0 );
        }
    }
}

SCENARIO( "Mangled WebSocket frames never break the describer", "[websocket][fuzz]" )
{
    const std::vector<Bytes> messages = {
        frame( 0x1, text( "Hello" ), kMask ),
        frame( 0x1, text( "Hello" ) ),
        frame( 0x2, Bytes( 200, 0x5A ), kMask ),
        frame( 0x2, Bytes( 20, 0x5A ), std::nullopt, true, 0, true ),
        frame( 0x0, text( "more" ), std::nullopt, false ),
        frame( 0x8, closePayload( 1000, "bye" ), kMask ),
        frame( 0x8, closePayload( 1011 ) ),
        frame( 0x9, text( "ping" ), kMask ),
        frame( 0xA, {} ),
        frame( 0x1, Bytes{ 0xF2, 0x48, 0xCD }, kMask, true, 0x40 ),
    };
    StreamState state;
    state.protocols = StreamState::kWebSocket;
    const Stream stream{ 0, &state, 0 };
    const auto framer = webSocketFramer();
    auto check = [ & ]( const Bytes& bytes ) {
        const auto described
            = describeTcpMessages( bytes.data(), bytes.size(), kClientPort, kServerPort, framer );
        REQUIRE( described.description.find( '\n' ) == std::string::npos );
        REQUIRE( described.description.size() < 4096 );
        const auto extent
            = tcpMessageExtent( bytes.data(), bytes.size(), kClientPort, kServerPort, 0, &stream );
        REQUIRE( ( extent.framer == 0 || extent.length > 0 ) );
        const auto packets = inStream( { { false, upgradeResponse() }, { true, bytes } } );
        REQUIRE( packets[ 1 ].info.find( '\n' ) == std::string::npos );
    };

    GIVEN( "every prefix of each frame" )
    {
        THEN( "each is described in one line, the whole one without fault" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    check( prefix( message, n ) );
                }
                const auto whole = frames( message );
                REQUIRE( whole.find( "Malformed" ) == std::string::npos );
                REQUIRE( whole.find( " " + kEllipsis ) == std::string::npos );
            }
        }
    }

    GIVEN( "every single byte of each frame set to telling values" )
    {
        THEN( "the description is one line" )
        {
            for ( const auto& message : messages ) {
                for ( size_t i = 0; i < std::min<size_t>( message.size(), 24 ); ++i ) {
                    for ( int value : { 0x00, 0x01, 0x08, 0x0F, 0x7D, 0x7E, 0x7F, 0x80, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        check( mutated );
                    }
                }
            }
        }
    }

    GIVEN( "segments of several frames with random bytes changed, cut anywhere" )
    {
        Bytes segment;
        for ( const auto& message : messages ) {
            segment = segment + message;
        }
        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 6455 );
            for ( int round = 0; round < 3000; ++round ) {
                auto mutated = segment;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto start = random() % mutated.size();
                const Bytes from( mutated.begin() + static_cast<std::ptrdiff_t>( start ),
                                  mutated.end() );
                check( prefix( from, random() % ( from.size() + 1 ) ) );
            }
        }
    }
}
