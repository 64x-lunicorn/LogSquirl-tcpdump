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
 * @file tcp_reassembly_test.cpp
 * @brief BDD tests for the TCP Reassembly: messages across segments
 *        described once, in sequence order, within bounded memory.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pipeline_harness.h"

#include <algorithm>
#include <cstring>
#include <random>
#include <string>
#include <utility>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kAck = 0x10;
constexpr uint8_t kPshAck = 0x18;
constexpr uint8_t kFinAck = 0x11;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kSyn = 0x02;

constexpr uint32_t kClientIsn = 1000;
constexpr uint32_t kServerIsn = 5000;

/// A TCP segment between the client's @p clientPort and the server's
/// @p serverPort, with absolute sequence and acknowledgement numbers.
struct Segment {
    bool fromClient = true;
    uint32_t seq = 0;
    uint32_t ack = 0;
    Bytes payload;
    uint8_t flags = kPshAck;
    uint16_t serverPort = 443;
    uint16_t clientPort = 50000;
    int64_t capturedPayload = -1; ///< -1: all of it; otherwise cut at the snaplen
};

Bytes frameOf( const Segment& s )
{
    Ipv4Options o;
    if ( !s.fromClient ) {
        std::swap( o.src, o.dst );
    }
    const auto header
        = s.fromClient ? tcp( s.clientPort, s.serverPort, s.payload, 5, s.flags, s.seq, s.ack )
                       : tcp( s.serverPort, s.clientPort, s.payload, 5, s.flags, s.seq, s.ack );
    return eth( EthertypeIpv4, ipv4( IpProtoTcp, header, o ) );
}

/// What a packet ended as.
struct Line {
    std::string protocol;
    std::string info;
    std::string description; ///< Info after " | ", empty without one
    Bytes completed;         ///< The messages the segment completed
    uint32_t segments = 0;
    size_t sipCalls = 0; ///< The calls whose media its SDP bodies announce
};

/// Run @p segments through @p pipeline as a conversion runs them, the
/// payload taken from the reader as a conversion takes it.
std::vector<Line> converted( const std::vector<Segment>& segments, PacketPipeline& pipeline )
{
    std::vector<Record> records;
    uint32_t sec = 1000;
    for ( const auto& s : segments ) {
        Record r{ frameOf( s ), sec++, 0, -1, -1 };
        if ( s.capturedPayload >= 0 ) {
            r.inclLen
                = static_cast<int64_t>( r.data.size() - s.payload.size() ) + s.capturedPayload;
            r.origLen = static_cast<int64_t>( r.data.size() );
            r.data.resize( static_cast<size_t>( r.inclLen ) );
        }
        records.push_back( r );
    }
    std::vector<Line> lines;
    for ( const auto& p : piped( pcapFile( records ), pipeline ) ) {
        Line line{ p.pkt.protocol, p.pkt.info, {}, p.completed, p.segments, p.pkt.sipCalls.size() };
        const auto at = p.pkt.info.find( kDescriptionSeparator );
        if ( at != std::string::npos ) {
            line.description = p.pkt.info.substr( at + std::strlen( kDescriptionSeparator ) );
        }
        lines.push_back( line );
    }
    REQUIRE( lines.size() == segments.size() );
    return lines;
}

std::vector<Line> converted( const std::vector<Segment>& segments )
{
    PacketPipeline pipeline;
    return converted( segments, pipeline );
}

/// The options of a Packet Pipeline whose reassembly holds @p memory bytes
/// at most, and @p streamLimit of one direction.
PipelineOptions reassemblyLimits( size_t memory, size_t streamLimit = TcpReassembly::kStreamLimit )
{
    PipelineOptions options;
    options.reassemblyMemory = memory;
    options.reassemblyStreamLimit = streamLimit;
    return options;
}

/// What the describer says of @p payload, sent from the client to @p port.
std::string describedWhole( const Bytes& payload, uint16_t port = 443 )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), 50000, port )
        .description;
}

Bytes slice( const Bytes& b, size_t from, size_t to )
{
    to = std::min( to, b.size() );
    return Bytes( b.begin() + static_cast<std::ptrdiff_t>( from ),
                  b.begin() + static_cast<std::ptrdiff_t>( to ) );
}

/// A TLS record of @p type around @p fragment.
Bytes tlsRecord( uint8_t type, const Bytes& fragment )
{
    Bytes b{ type, 0x03, 0x03 };
    putBE16( b, static_cast<uint16_t>( fragment.size() ) );
    return b + fragment;
}

/// A TLS ClientHello record naming @p serverName, padded to some 600 bytes,
/// as a browser's is.
Bytes clientHello( const std::string& serverName )
{
    Bytes extensions;
    Bytes sni;
    putBE16( sni, static_cast<uint16_t>( serverName.size() + 3 ) );
    sni.push_back( 0 ); // host_name
    putBE16( sni, static_cast<uint16_t>( serverName.size() ) );
    sni = sni + text( serverName );
    putBE16( extensions, 0x0000 );
    putBE16( extensions, static_cast<uint16_t>( sni.size() ) );
    extensions = extensions + sni;
    putBE16( extensions, 0x0015 ); // padding
    putBE16( extensions, 500 );
    extensions.resize( extensions.size() + 500, 0 );

    Bytes body{ 0x03, 0x03 };
    body.resize( body.size() + 32, 0x42 ); // random
    body.push_back( 0 );                   // no session ID
    putBE16( body, 2 );
    putBE16( body, 0x1301 );
    body.push_back( 1 );
    body.push_back( 0 ); // no compression
    putBE16( body, static_cast<uint16_t>( extensions.size() ) );
    body = body + extensions;

    Bytes handshake{ 0x01, 0, static_cast<uint8_t>( body.size() >> 8 ),
                     static_cast<uint8_t>( body.size() ) };
    return tlsRecord( 0x16, handshake + body );
}

/// A DNS answer for example.com, A 192.0.2.1, behind its 2-byte length.
Bytes dnsAnswer()
{
    Bytes m;
    putBE16( m, 0x1234 );
    putBE16( m, 0x8180 );
    putBE16( m, 1 ); // questions
    putBE16( m, 1 ); // answers
    putBE16( m, 0 );
    putBE16( m, 0 );
    const Bytes name{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    m = m + name;
    putBE16( m, 1 );
    putBE16( m, 1 );
    m = m + Bytes{ 0xC0, 0x0C };
    putBE16( m, 1 );
    putBE16( m, 1 );
    putBE32( m, 300 );
    putBE16( m, 4 );
    m = m + Bytes{ 192, 0, 2, 1 };
    Bytes framed;
    putBE16( framed, static_cast<uint16_t>( m.size() ) );
    return framed + m;
}

/// An MQTT PUBLISH to alerts/door with @p payloadBytes bytes of payload.
Bytes mqttPublish( size_t payloadBytes )
{
    const std::string topic = "alerts/door";
    const auto remaining = 2 + topic.size() + payloadBytes;
    Bytes b{ 0x30 };
    for ( auto rest = remaining;; ) {
        const auto digit = static_cast<uint8_t>( rest & 0x7F );
        rest >>= 7;
        b.push_back( rest ? static_cast<uint8_t>( digit | 0x80 ) : digit );
        if ( !rest ) {
            break;
        }
    }
    putBE16( b, static_cast<uint16_t>( topic.size() ) );
    return b + text( topic ) + Bytes( payloadBytes, 'x' );
}

/// A SIP INVITE with an SDP body that announces audio on port 49170.
Bytes sipInvite()
{
    const std::string sdp = "v=0\r\no=alice 1 1 IN IP4 192.0.2.10\r\ns=-\r\n"
                            "c=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 49170 RTP/AVP 0\r\n";
    return text( "INVITE sip:bob@example.com SIP/2.0\r\n"
                 "Via: SIP/2.0/TCP 192.0.2.10:50000;branch=z9hG4bK776asdhds\r\n"
                 "Call-ID: a84b4c76e66710@pc33.example.com\r\n"
                 "CSeq: 314159 INVITE\r\n"
                 "Content-Type: application/sdp\r\n"
                 "Content-Length: "
                 + std::to_string( sdp.size() ) + "\r\n\r\n" + sdp );
}

/// @p message cut into segments from the client at @p cuts, numbered on
/// from @p seq.
std::vector<Segment> cut( const Bytes& message, const std::vector<size_t>& cuts,
                          uint32_t seq = kClientIsn + 1, uint16_t port = 443 )
{
    std::vector<Segment> segments;
    size_t from = 0;
    auto bounds = cuts;
    bounds.push_back( message.size() );
    for ( const auto to : bounds ) {
        Segment s;
        s.seq = seq + static_cast<uint32_t>( from );
        s.ack = kServerIsn + 1;
        s.payload = slice( message, from, to );
        s.serverPort = port;
        segments.push_back( s );
        from = to;
    }
    return segments;
}

/// The handshake that opens a connection to @p port.
std::vector<Segment> handshake( uint16_t port = 443 )
{
    Segment syn;
    syn.seq = kClientIsn;
    syn.flags = kSyn;
    syn.serverPort = port;
    Segment synAck;
    synAck.fromClient = false;
    synAck.seq = kServerIsn;
    synAck.ack = kClientIsn + 1;
    synAck.flags = kSyn | kAck;
    synAck.serverPort = port;
    Segment ack;
    ack.seq = kClientIsn + 1;
    ack.ack = kServerIsn + 1;
    ack.flags = kAck;
    ack.serverPort = port;
    return { syn, synAck, ack };
}

/// An SSH binary packet of the unencrypted phase: message @p code and
/// @p body, padded to a multiple of 8.
Bytes sshPacket( uint8_t code, const Bytes& body )
{
    const size_t padding = 8 - ( 6 + body.size() ) % 8 + ( ( 6 + body.size() ) % 8 > 4 ? 8 : 0 );
    Bytes b;
    putBE32( b, static_cast<uint32_t>( 2 + body.size() + padding ) );
    b.push_back( static_cast<uint8_t>( padding ) );
    b.push_back( code );
    b = b + body;
    b.resize( b.size() + padding, 0 );
    return b;
}

/// An SSH string of @p n bytes of @p fill.
Bytes sshString( size_t n, uint8_t fill )
{
    Bytes b;
    putBE32( b, static_cast<uint32_t>( n ) );
    b.resize( b.size() + n, fill );
    return b;
}

/// SSH_MSG_KEXINIT, its ten name-lists long ones, some 800 bytes.
Bytes sshKexInit()
{
    Bytes body( 16, 0x5A );
    for ( int i = 0; i < 10; ++i ) {
        const std::string names = i < 8 ? "aes" + std::string( 70, 'x' ) + ",none" : "";
        Bytes list;
        putBE32( list, static_cast<uint32_t>( names.size() ) );
        body = body + list + text( names );
    }
    body.push_back( 0 );
    putBE32( body, 0 );
    return sshPacket( 20, body );
}

/// A WebSocket binary frame of @p size bytes, its length in 8 bytes,
/// masked as a client's is.
Bytes webSocketBinary( size_t size )
{
    Bytes b{ 0x82, 0x80 | 127 };
    putBE32( b, static_cast<uint32_t>( static_cast<uint64_t>( size ) >> 32 ) );
    putBE32( b, static_cast<uint32_t>( size ) );
    b = b + Bytes{ 0x01, 0x02, 0x03, 0x04 };
    b.resize( b.size() + size, 0x5A );
    return b;
}

/// An SMB2 Read response carrying @p size bytes, behind its NetBIOS header.
Bytes smbReadResponse( size_t size )
{
    Bytes smb{ 0xFE, 'S', 'M', 'B', 64, 0 };
    smb.resize( 12, 0 );
    smb = smb + Bytes{ 0x08, 0x00 }; // Read
    smb.resize( 16, 0 );
    smb.push_back( 0x01 ); // a response
    smb.resize( 64, 0 );
    smb = smb + Bytes{ 17, 0, 0x50, 0 };
    putLE32( smb, static_cast<uint32_t>( size ) );
    smb.resize( 64 + 16, 0 );
    smb.resize( smb.size() + size, 0xA5 );
    Bytes message{ 0x00, static_cast<uint8_t>( smb.size() >> 16 ) };
    putBE16( message, static_cast<uint16_t>( smb.size() ) );
    return message + smb;
}

/// An SMB2 Write request of @p size bytes, behind its NetBIOS header.
Bytes smbWriteRequest( size_t size )
{
    Bytes smb{ 0xFE, 'S', 'M', 'B', 64, 0 };
    smb.resize( 12, 0 );
    smb = smb + Bytes{ 0x09, 0x00 }; // Write
    smb.resize( 64, 0 );
    smb = smb + Bytes{ 49, 0, 112, 0 };
    putLE32( smb, static_cast<uint32_t>( size ) );
    smb.resize( 64 + 48, 0 );
    smb.resize( smb.size() + size, 0x5A );
    Bytes message{ 0x00, 0x00 };
    putBE16( message, static_cast<uint16_t>( smb.size() ) );
    return message + smb;
}

/// The offsets that cut @p size bytes into segments of @p every bytes.
std::vector<size_t> cutsEvery( size_t size, size_t every )
{
    std::vector<size_t> cuts;
    for ( size_t at = every; at < size; at += every ) {
        cuts.push_back( at );
    }
    return cuts;
}

/// @p segments sent by the server instead, numbered on from @p seq.
std::vector<Segment> fromServer( std::vector<Segment> segments, uint32_t seq )
{
    const auto first = segments.empty() ? 0 : segments.front().seq;
    for ( auto& s : segments ) {
        s.fromClient = false;
        s.seq = s.seq - first + seq;
        s.ack = kClientIsn + 1;
    }
    return segments;
}

std::vector<Segment> operator+( std::vector<Segment> a, const std::vector<Segment>& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

/// A WebSocket text frame carrying @p message, masked as a client's is.
Bytes webSocketText( const std::string& message )
{
    static const uint8_t kMask[ 4 ] = { 0x01, 0x02, 0x03, 0x04 };
    Bytes b{ 0x81 };
    if ( message.size() < 126 ) {
        b.push_back( static_cast<uint8_t>( 0x80 | message.size() ) );
    }
    else {
        b.push_back( 0x80 | 126 );
        putBE16( b, static_cast<uint16_t>( message.size() ) );
    }
    b.insert( b.end(), kMask, kMask + 4 );
    for ( size_t i = 0; i < message.size(); ++i ) {
        b.push_back( static_cast<uint8_t>( message[ i ] ) ^ kMask[ i % 4 ] );
    }
    return b;
}

/// The client's request to upgrade its connection to WebSocket.
const Bytes kWebSocketRequest = text( "GET /chat HTTP/1.1\r\nHost: example.com\r\n"
                                      "Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n" );

/// The client's sequence number after webSocketUpgrade().
const uint32_t kWebSocketClientSeq
    = kClientIsn + 1 + static_cast<uint32_t>( kWebSocketRequest.size() );

/// The upgrade of a connection to port 8080 to WebSocket: the client's
/// request and the server's 101 response, after the handshake.
std::vector<Segment> webSocketUpgrade()
{
    const auto& request = kWebSocketRequest;
    const auto response = text( "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                "Connection: Upgrade\r\n\r\n" );
    auto segments = handshake( 8080 ) + cut( request, {}, kClientIsn + 1, 8080 );
    Segment reply;
    reply.fromClient = false;
    reply.seq = kServerIsn + 1;
    reply.ack = kClientIsn + 1 + static_cast<uint32_t>( request.size() );
    reply.payload = response;
    reply.serverPort = 8080;
    segments.push_back( reply );
    return segments;
}

std::string reassembledFrom( uint32_t k )
{
    return " [reassembled from " + std::to_string( k ) + " segments]";
}

} // namespace

SCENARIO( "The describer frames the messages the reassembly puts together", "[tcp_reassembly]" )
{
    const auto hello = clientHello( "example.com" );

    GIVEN( "a TLS record" )
    {
        THEN( "its header says how long it is, whole or cut" )
        {
            const auto whole = tcpMessageExtent( hello.data(), hello.size(), 50000, 443 );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == hello.size() );
            REQUIRE( std::string( whole.label ) == "TLS" );

            const auto part = tcpMessageExtent( hello.data(), 100, 50000, 443 );
            REQUIRE( part.needsMore );
            REQUIRE( part.length == hello.size() );
            const auto header = tcpMessageExtent( hello.data(), 3, 50000, 443 );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 5 );
        }
        THEN( "a length past the largest record is no record" )
        {
            const Bytes huge{ 0x17, 0x03, 0x03, 0xFF, 0xFF };
            REQUIRE( tcpMessageExtent( huge.data(), huge.size(), 50000, 443 ).framer == 0 );
        }
    }

    GIVEN( "DNS over TCP" )
    {
        const auto answer = dnsAnswer();
        THEN( "the 2-byte length frames it on port 53 only" )
        {
            const auto extent = tcpMessageExtent( answer.data(), 20, 53, 50000 );
            REQUIRE( extent.needsMore );
            REQUIRE( extent.length == answer.size() );
            REQUIRE( std::string( extent.label ) == "DNS" );
            REQUIRE( tcpMessageExtent( answer.data(), 20, 5353, 50000 ).framer == 0 );
        }
    }

    GIVEN( "an HTTP request" )
    {
        const auto request = text( "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nbody" );
        THEN( "its header section ends at the empty line" )
        {
            const auto whole = tcpMessageExtent( request.data(), request.size(), 50000, 80 );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == request.size() - 4 );
            const auto part = tcpMessageExtent( request.data(), 30, 50000, 80 );
            REQUIRE( part.needsMore );
            REQUIRE( part.length == 31 );
        }
    }

    GIVEN( "an MQTT PUBLISH on port 1883" )
    {
        const auto publish = mqttPublish( 300 );
        THEN( "its Remaining Length frames it, whole or cut" )
        {
            const auto whole = tcpMessageExtent( publish.data(), publish.size(), 50000, 1883 );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == publish.size() );
            REQUIRE( std::string( whole.label ) == "MQTT" );
            const auto part = tcpMessageExtent( publish.data(), 100, 50000, 1883 );
            REQUIRE( part.needsMore );
            REQUIRE( part.length == publish.size() );
            const auto header = tcpMessageExtent( publish.data(), 2, 50000, 1883 );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 3 );
        }
        THEN( "on another port, or with a reserved type or a fifth length byte, it is none" )
        {
            REQUIRE( tcpMessageExtent( publish.data(), publish.size(), 50000, 1884 ).framer == 0 );
            const Bytes reserved{ 0x00, 0x00 };
            REQUIRE( tcpMessageExtent( reserved.data(), reserved.size(), 50000, 1883 ).framer
                     == 0 );
            const Bytes tooLong{ 0x30, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };
            REQUIRE( tcpMessageExtent( tooLong.data(), tooLong.size(), 50000, 1883 ).framer == 0 );
        }
    }

    GIVEN( "a SIP request with a body" )
    {
        const auto invite = sipInvite();
        THEN( "its Content-Length frames it on any port" )
        {
            const auto whole = tcpMessageExtent( invite.data(), invite.size(), 50000, 5080 );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == invite.size() );
            REQUIRE( std::string( whole.label ) == "SIP" );
            const auto body = tcpMessageExtent( invite.data(), invite.size() - 10, 50000, 5080 );
            REQUIRE( body.needsMore );
            REQUIRE( body.length == invite.size() );
            const auto headers = tcpMessageExtent( invite.data(), 60, 50000, 5080 );
            REQUIRE( headers.needsMore );
            REQUIRE( headers.length == 61 );
        }
        THEN( "without Content-Length its headers are all of it" )
        {
            const auto options = text( "OPTIONS sip:bob@example.com SIP/2.0\r\nCSeq: 1 "
                                       "OPTIONS\r\nCall-ID: x\r\n\r\nrest" );
            const auto extent = tcpMessageExtent( options.data(), options.size(), 50000, 5060 );
            REQUIRE( extent.complete() );
            REQUIRE( std::string( extent.label ) == "SIP" );
            REQUIRE( extent.length == options.size() - 4 );
        }
    }

    GIVEN( "bytes no framer knows" )
    {
        const auto other = text( "hello world" );
        THEN( "there is no message" )
        {
            REQUIRE( tcpMessageExtent( other.data(), other.size(), 50000, 443 ).framer == 0 );
        }
    }
}

SCENARIO( "A message split over segments is described once, where it completes",
          "[tcp_reassembly]" )
{
    GIVEN( "a TLS ClientHello split over 3 segments" )
    {
        const auto hello = clientHello( "example.com" );
        const auto lines = converted( handshake() + cut( hello, { 200, 400 } ) );

        THEN( "the first two are segments of it, labelled TLS" )
        {
            for ( size_t i : { 3, 4 } ) {
                REQUIRE( lines[ i ].protocol == "TLS" );
                REQUIRE( lines[ i ].description == kSegmentOfMessage );
            }
        }
        THEN( "the third describes the whole hello" )
        {
            REQUIRE( lines[ 5 ].protocol == "TLS" );
            REQUIRE( lines[ 5 ].description == describedWhole( hello ) + reassembledFrom( 3 ) );
            REQUIRE( lines[ 5 ].description.find( "SNI=example.com" ) != std::string::npos );
            REQUIRE( lines[ 5 ].completed == hello );
            REQUIRE( lines[ 5 ].segments == 3 );
        }
    }

    GIVEN( "an HTTP request split in its headers" )
    {
        const auto request
            = text( "GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n" );
        const auto lines
            = converted( handshake( 80 ) + cut( request, { 30 }, kClientIsn + 1, 80 ) );

        THEN( "the request is described with its Host on the second" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].protocol == "HTTP" );
            REQUIRE( lines[ 4 ].description
                     == "GET example.com/index.html HTTP/1.1" + reassembledFrom( 2 ) );
        }
    }

    GIVEN( "a DNS-over-TCP answer split across 2 segments" )
    {
        const auto answer = dnsAnswer();
        std::vector<Segment> segments;
        for ( auto s : cut( answer, { 20 }, kServerIsn + 1, 53 ) ) {
            s.fromClient = false;
            s.ack = kClientIsn + 1;
            segments.push_back( s );
        }
        const auto lines = converted( handshake( 53 ) + segments );

        THEN( "the answer is described on the second" )
        {
            REQUIRE( lines[ 3 ].protocol == "DNS" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].description
                     == describedWhole( answer, 53 ) + reassembledFrom( 2 ) );
            REQUIRE( lines[ 4 ].description.find( "192.0.2.1" ) != std::string::npos );
        }
    }

    GIVEN( "an MQTT PUBLISH split across 2 segments" )
    {
        const auto publish = mqttPublish( 300 );
        const auto lines
            = converted( handshake( 1883 ) + cut( publish, { 100 }, kClientIsn + 1, 1883 ) );

        THEN( "it is described whole on the second" )
        {
            REQUIRE( lines[ 3 ].protocol == "MQTT" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].protocol == "MQTT" );
            REQUIRE( lines[ 4 ].description
                     == describedWhole( publish, 1883 ) + reassembledFrom( 2 ) );
            REQUIRE( lines[ 4 ].description.find( " \xe2\x80\xa6" ) == std::string::npos );
        }
    }

    GIVEN( "a SIP INVITE split in its SDP body" )
    {
        const auto invite = sipInvite();
        const auto lines = converted(
            handshake( 5060 ) + cut( invite, { invite.size() - 20 }, kClientIsn + 1, 5060 ) );

        THEN( "the media it announces are known where it completes, not before" )
        {
            REQUIRE( lines[ 3 ].protocol == "SIP" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 3 ].sipCalls == 0 );
            REQUIRE( lines[ 4 ].description
                     == describedWhole( invite, 5060 ) + reassembledFrom( 2 ) );
            REQUIRE( lines[ 4 ].description.find( "SDP (audio 49170 RTP/AVP 0)" )
                     != std::string::npos );
            REQUIRE( lines[ 4 ].sipCalls == 1 );
        }
    }

    GIVEN( "a SOME/IP notification split across 2 segments, on a port told by its header" )
    {
        Bytes message{ 0x12, 0x34, 0x80, 0x01 };
        putBE32( message, 8 + 600 );
        message = message + Bytes{ 0x00, 0x10, 0x00, 0x01, 0x01, 0x01, 0x02, 0x00 }
                  + Bytes( 600, 0x5A );
        const auto lines
            = converted( handshake( 30501 ) + cut( message, { 100 }, kClientIsn + 1, 30501 ) );

        THEN( "it is described whole on the second" )
        {
            REQUIRE( lines[ 3 ].protocol == "SOME/IP" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].protocol == "SOME/IP" );
            REQUIRE( lines[ 4 ].description
                     == "Service 0x1234 Event 0x8001 Client 0x0010 Session 0x0001 NOTIFICATION, "
                        "600 bytes"
                            + reassembledFrom( 2 ) );
        }
    }

    GIVEN( "an SSH KEXINIT split across 2 segments after the client's banner, on port 22 "
           "and on another" )
    {
        const auto banner = text( "SSH-2.0-OpenSSH_9.6\r\n" );
        for ( const uint16_t port : { uint16_t{ 22 }, uint16_t{ 2222 } } ) {
            const auto lines = converted(
                handshake( port )
                + cut( banner + sshKexInit(), { banner.size(), 300 }, kClientIsn + 1, port ) );

            THEN( "it is described whole on the second" )
            {
                REQUIRE( lines[ 3 ].description == "Client: Protocol (SSH-2.0-OpenSSH_9.6)" );
                REQUIRE( lines[ 4 ].protocol == "SSHv2" );
                REQUIRE( lines[ 4 ].description == kSegmentOfMessage );
                REQUIRE( lines[ 5 ].protocol == "SSHv2" );
                REQUIRE( lines[ 5 ].description
                         == "Client: Key Exchange Init kex=aes" + std::string( 70, 'x' )
                                + ",\xe2\x80\xa6 hostkey=aes" + std::string( 70, 'x' )
                                + ",\xe2\x80\xa6 cipher=aes" + std::string( 70, 'x' )
                                + ",\xe2\x80\xa6" + reassembledFrom( 2 ) );
            }
        }
    }

    GIVEN( "an SSH key exchange init and NEWKEYS split across 2 segments, then encrypted "
           "packets" )
    {
        const auto banner = text( "SSH-2.0-OpenSSH_10.0\r\n" );
        const auto init = sshPacket( 30, sshString( 1216, 0x11 ) ) + sshPacket( 21, {} );
        const auto lines
            = converted( handshake( 22 )
                         + cut( banner + init + Bytes( 64, 0xE1 ) + Bytes( 96, 0xE2 ),
                                { banner.size(), banner.size() + 700, banner.size() + init.size(),
                                  banner.size() + init.size() + 64 },
                                kClientIsn + 1, 22 ) );

        THEN( "they are described whole on the second, the rest as encrypted" )
        {
            REQUIRE( lines[ 4 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 5 ].description
                     == "Client: Elliptic Curve Diffie-Hellman Key Exchange Init, New Keys"
                            + reassembledFrom( 2 ) );
            REQUIRE( lines[ 6 ].protocol == "SSHv2" );
            REQUIRE( lines[ 6 ].description == "Client: Encrypted packet (len=64)" );
            REQUIRE( lines[ 7 ].description == "Client: Encrypted packet (len=96)" );
        }
    }

    GIVEN( "an SSH connection on port 22 whose key exchange the capture did not see" )
    {
        Bytes encrypted;
        putBE32( encrypted, 1020 ); // as a packet_length of the unencrypted phase would be
        encrypted = encrypted + Bytes{ 6, 94 } + Bytes( 600, 0xC3 );
        const auto lines
            = converted( handshake( 22 ) + cut( encrypted, { 300 }, kClientIsn + 1, 22 ) );

        THEN( "no segment is held, each is taken for an encrypted packet" )
        {
            REQUIRE( lines[ 3 ].description == "Client: Encrypted packet (len=300)" );
            REQUIRE( lines[ 4 ].description == "Client: Encrypted packet (len=306)" );
        }
    }

    GIVEN( "WebSocket frames after the upgrade: one split across 2 segments, then several "
           "in one segment, longer than the bytes the parser keeps" )
    {
        const auto split = webSocketText( std::string( 100, 'a' ) );
        const auto several = webSocketText( std::string( 30, 'b' ) )
                             + webSocketText( std::string( 30, 'c' ) ) + webSocketText( "d" );
        const auto lines = converted(
            webSocketUpgrade()
            + cut( split + several, { 30, split.size() }, kWebSocketClientSeq, 8080 ) );

        THEN( "the split one is described whole on the second, the others all named" )
        {
            REQUIRE( lines[ 3 ].protocol == "HTTP" );
            REQUIRE( lines[ 4 ].description
                     == "HTTP/1.1 101 Switching Protocols, Upgrade: websocket" );
            REQUIRE( lines[ 5 ].protocol == "WebSocket" );
            REQUIRE( lines[ 5 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 6 ].protocol == "WebSocket" );
            REQUIRE( lines[ 6 ].description
                     == "WebSocket Text [FIN] [MASKED] len=100 \"" + std::string( 40, 'a' )
                            + "\"\xe2\x80\xa6" + reassembledFrom( 2 ) );
            REQUIRE( lines[ 7 ].protocol == "WebSocket" );
            REQUIRE( lines[ 7 ].description
                     == "WebSocket Text [FIN] [MASKED] len=30 \"" + std::string( 30, 'b' )
                            + "\", WebSocket Text [FIN] [MASKED] len=30 \"" + std::string( 30, 'c' )
                            + "\", WebSocket Text [FIN] [MASKED] len=1 \"d\"" );
            REQUIRE( lines[ 7 ].completed == several ); // whole in their segment
        }
    }

    GIVEN( "the server's 101 response with its first frames in the same segment, the last "
           "cut and completed by the next" )
    {
        auto serverText = []( const std::string& message ) {
            Bytes b{ 0x81, static_cast<uint8_t>( message.size() ) };
            return b + text( message );
        };
        const auto response = text( "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n\r\n" );
        const auto hello = serverText( "hello" );
        const auto split = serverText( std::string( 100, 'a' ) );
        const auto after = serverText( "bye" );
        const auto bytes = response + hello + split + after;
        const auto lines = converted(
            handshake( 8080 ) + cut( kWebSocketRequest, {}, kClientIsn + 1, 8080 )
            + fromServer( cut( bytes, { response.size() + hello.size() + 10 }, 0, 8080 ),
                          kServerIsn + 1 ) );

        THEN( "the frames after the response are framed and described, the cut one whole on "
              "the next segment" )
        {
            REQUIRE( lines[ 4 ].protocol == "HTTP" );
            REQUIRE( lines[ 4 ].description
                     == "HTTP/1.1 101 Switching Protocols, Upgrade: websocket; "
                        "WebSocket Text [FIN] len=5 \"hello\"" );
            REQUIRE( lines[ 5 ].protocol == "WebSocket" );
            REQUIRE( lines[ 5 ].description
                     == "WebSocket Text [FIN] len=100 \"" + std::string( 40, 'a' )
                            + "\"\xe2\x80\xa6, WebSocket Text [FIN] len=3 \"bye\""
                            + reassembledFrom( 2 ) );
        }
    }

    GIVEN( "WebSocket frames on a stream without the upgrade" )
    {
        const auto frames = webSocketText( std::string( 100, 'a' ) );
        const auto lines
            = converted( handshake( 8080 ) + cut( frames, { 30 }, kClientIsn + 1, 8080 ) );

        THEN( "no segment is held" )
        {
            REQUIRE( lines[ 3 ].protocol != "WebSocket" );
            REQUIRE( lines[ 3 ].description != kSegmentOfMessage );
            REQUIRE( lines[ 4 ].protocol != "WebSocket" );
        }
    }

    GIVEN( "a DoIP diagnostic message split across 2 segments" )
    {
        Bytes message{ 0x02, 0xFD, 0x80, 0x01 };
        putBE32( message, 4 + 2 + 600 );
        message = message + Bytes{ 0x0E, 0x00, 0x10, 0x00, 0x36, 0x01 } + Bytes( 600, 0x5A );
        const auto lines
            = converted( handshake( 13400 ) + cut( message, { 100 }, kClientIsn + 1, 13400 ) );

        THEN( "it is described whole on the second" )
        {
            REQUIRE( lines[ 3 ].protocol == "DoIP" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].protocol == "DoIP" );
            REQUIRE( lines[ 4 ].description
                     == "Diagnostic message 0x0E00 \xe2\x86\x92 0x1000, UDS TransferData Block 1"
                            + reassembledFrom( 2 ) );
        }
    }

    GIVEN( "an SMB2 Write request split across 3 segments" )
    {
        Bytes smb{ 0xFE, 'S', 'M', 'B', 64, 0 };
        smb.resize( 12, 0 );
        smb = smb + Bytes{ 0x09, 0x00 }; // Write
        smb.resize( 64, 0 );
        smb = smb + Bytes{ 49, 0, 112, 0 };
        putLE32( smb, 1000 ); // length
        smb.resize( 64 + 48, 0 );
        smb = smb + Bytes( 1000, 0x5A );
        Bytes message{ 0x00, 0x00 };
        putBE16( message, static_cast<uint16_t>( smb.size() ) );
        message = message + smb;
        const auto lines
            = converted( handshake( 445 ) + cut( message, { 100, 700 }, kClientIsn + 1, 445 ) );

        THEN( "it is described whole on the third" )
        {
            REQUIRE( lines[ 3 ].protocol == "SMB2" );
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 5 ].protocol == "SMB2" );
            REQUIRE( lines[ 5 ].description
                     == "Write Request Len:1000 Off:0" + reassembledFrom( 3 ) );
        }
    }

    GIVEN( "whole records and the start of another in one segment" )
    {
        const auto first = tlsRecord( 0x17, Bytes( 100, 0xAA ) );
        const auto second = tlsRecord( 0x17, Bytes( 300, 0xBB ) );
        const auto stream = first + first + second;
        PacketPipeline pipeline;
        const auto lines
            = converted( handshake() + cut( stream, { first.size() * 2 + 50 } ), pipeline );

        THEN( "the first names the whole records only" )
        {
            REQUIRE( lines[ 3 ].description == "Application Data, Application Data" );
            REQUIRE( lines[ 3 ].completed == first + first );
        }
        THEN( "the second names the record it completes" )
        {
            REQUIRE( lines[ 4 ].description == "Application Data" + reassembledFrom( 2 ) );
            REQUIRE( lines[ 4 ].completed == second );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
            REQUIRE( pipeline.reassembly().memoryUsed() == 0 );
        }
    }

    GIVEN( "segments of whole messages" )
    {
        const auto record = tlsRecord( 0x17, Bytes( 100, 0xAA ) );
        PacketPipeline pipeline;
        const auto lines
            = converted( handshake() + cut( record + record, { record.size() } ), pipeline );

        THEN( "each keeps its own description, and nothing is held" )
        {
            REQUIRE( lines[ 3 ].description == "Application Data" );
            REQUIRE( lines[ 4 ].description == "Application Data" );
            REQUIRE( pipeline.reassembly().memoryUsed() == 0 );
        }

        THEN( "each hands out its own message, as the TLS Decryption reads them" )
        {
            REQUIRE( lines[ 3 ].completed == record );
            REQUIRE( lines[ 4 ].completed == record );
            REQUIRE( lines[ 4 ].segments == 1 );
        }
    }
}

SCENARIO( "Segments are taken in sequence order", "[tcp_reassembly]" )
{
    const auto hello = clientHello( "example.com" );
    const auto parts = cut( hello, { 200, 400 } );

    GIVEN( "the second segment captured after the third" )
    {
        const auto lines
            = converted( handshake() + std::vector<Segment>{ parts[ 0 ], parts[ 2 ], parts[ 1 ] } );

        THEN( "the hello is described on the late one, which completes it" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 5 ].description == describedWhole( hello ) + reassembledFrom( 3 ) );
            REQUIRE( lines[ 5 ].completed == hello );
        }
    }

    GIVEN( "a segment retransmitted" )
    {
        const auto lines = converted(
            handshake() + std::vector<Segment>{ parts[ 0 ], parts[ 0 ], parts[ 1 ], parts[ 2 ] } );

        THEN( "its bytes are taken once" )
        {
            REQUIRE( lines[ 6 ].description == describedWhole( hello ) + reassembledFrom( 3 ) );
            REQUIRE( lines[ 6 ].completed == hello );
        }
    }

    GIVEN( "segments that overlap" )
    {
        auto overlapping = parts[ 1 ];
        overlapping.seq -= 50;
        overlapping.payload = slice( hello, 150, 400 );
        auto late = parts[ 2 ];
        late.seq -= 10;
        late.payload = slice( hello, 390, hello.size() );
        const auto lines
            = converted( handshake() + std::vector<Segment>{ parts[ 0 ], overlapping, late } );

        THEN( "the overlap is dropped" )
        {
            REQUIRE( lines[ 5 ].description == describedWhole( hello ) + reassembledFrom( 3 ) );
            REQUIRE( lines[ 5 ].completed == hello );
        }
    }

    GIVEN( "a segment the capture lost, acknowledged by the other side" )
    {
        const auto record = tlsRecord( 0x17, Bytes( 100, 0xCC ) );
        auto next = cut( record, {},
                         parts[ 2 ].seq + static_cast<uint32_t>( parts[ 2 ].payload.size() ) );
        Segment ack;
        ack.fromClient = false;
        ack.seq = kServerIsn + 1;
        ack.ack = next[ 0 ].seq;
        ack.flags = kAck;
        PacketPipeline pipeline;
        const auto lines = converted(
            handshake() + std::vector<Segment>{ parts[ 0 ], parts[ 2 ], ack } + next, pipeline );

        THEN( "the hello is given up and the next record is described as it is" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines.at( 6 ).description == "Application Data" );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
        }
    }

    GIVEN( "a segment cut at the snaplen" )
    {
        auto cutShort = parts[ 1 ];
        cutShort.capturedPayload = 20;
        auto again = cut( hello, { 300 },
                          parts[ 2 ].seq + static_cast<uint32_t>( parts[ 2 ].payload.size() ) );
        PacketPipeline pipeline;
        const auto lines = converted(
            handshake() + std::vector<Segment>{ parts[ 0 ], cutShort, parts[ 2 ] } + again,
            pipeline );

        THEN( "it is a gap, and the stream resynchronises on the next hello" )
        {
            REQUIRE( lines[ 5 ].description != kSegmentOfMessage );
            REQUIRE( lines[ 5 ].segments == 0 );
            REQUIRE( lines[ 6 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 7 ].description == describedWhole( hello ) + reassembledFrom( 2 ) );
        }
    }
}

SCENARIO( "A message past the reassembly limit is skipped to its end", "[tcp_reassembly]" )
{
    GIVEN( "a WebSocket frame of 200 KiB in segments of 1448 bytes, then a short text frame" )
    {
        const auto big = webSocketBinary( 200 * 1024 );
        const auto hello = webSocketText( "Hello" );
        auto segments = cut( big, cutsEvery( big.size(), 1448 ), kWebSocketClientSeq, 8080 );
        const auto bigSegments = segments.size();
        segments
            = segments
              + cut( hello, {}, kWebSocketClientSeq + static_cast<uint32_t>( big.size() ), 8080 );
        const auto first = webSocketUpgrade().size();

        WHEN( "all of them are captured" )
        {
            PacketPipeline pipeline;
            const auto lines = converted( webSocketUpgrade() + segments, pipeline );

            THEN( "the frame's first segment is marked, the others are its continuation, and "
                  "the text frame is described" )
            {
                REQUIRE( lines[ first ].protocol == "WebSocket" );
                REQUIRE( lines[ first ].description.find( "WebSocket Binary" ) == 0 );
                REQUIRE( lines[ first ].info.find( kReassemblyLimit ) != std::string::npos );
                for ( size_t i = first + 1; i < first + bigSegments; ++i ) {
                    INFO( "segment " << i - first );
                    REQUIRE( lines[ i ].protocol == "WebSocket" );
                    REQUIRE( lines[ i ].description == kContinuationOfMessage );
                }
                REQUIRE( lines.back().description
                         == "WebSocket Text [FIN] [MASKED] len=5 \"Hello\"" );
                REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
                REQUIRE( pipeline.reassembly().memoryUsed() == 0 );
            }
        }

        WHEN( "segments inside the frame are lost, reordered and cut at the snaplen" )
        {
            auto mangled = segments;
            mangled[ 21 ].capturedPayload = 100;
            std::swap( mangled[ 30 ], mangled[ 31 ] );
            mangled.erase( mangled.begin() + 10, mangled.begin() + 12 );
            const auto lines = converted( webSocketUpgrade() + mangled );

            THEN( "the frame's segments are still its continuation, and the text frame is "
                  "described" )
            {
                for ( size_t i = first + 1; i + 1 < lines.size(); ++i ) {
                    INFO( "line " << i );
                    REQUIRE( lines[ i ].description == kContinuationOfMessage );
                }
                REQUIRE( lines.back().description
                         == "WebSocket Text [FIN] [MASKED] len=5 \"Hello\"" );
            }
        }
    }

    GIVEN( "a WebSocket frame of 100 KiB whose last segment begins a text frame too" )
    {
        const auto big = webSocketBinary( 100 * 1024 );
        const auto hello = webSocketText( "Hello" );
        const auto stream = big + hello + webSocketText( "World" );
        auto cuts = cutsEvery( big.size(), 1448 );
        cuts.push_back( big.size() + hello.size() );
        const auto segments = cut( stream, cuts, kWebSocketClientSeq, 8080 );

        WHEN( "it is captured" )
        {
            const auto lines = converted( webSocketUpgrade() + segments );

            THEN( "that segment is described from where the text frame begins" )
            {
                REQUIRE( lines[ lines.size() - 3 ].description == kContinuationOfMessage );
                REQUIRE( lines[ lines.size() - 2 ].description
                         == "WebSocket Text [FIN] [MASKED] len=5 \"Hello\"" );
                REQUIRE( lines.back().description
                         == "WebSocket Text [FIN] [MASKED] len=5 \"World\"" );
            }
        }

        WHEN( "the segment where the frame ends is lost" )
        {
            auto lost = segments;
            lost.erase( lost.end() - 2 );
            const auto lines = converted( webSocketUpgrade() + lost );

            THEN( "the stream resynchronises on the next segment that begins a frame" )
            {
                REQUIRE( lines[ lines.size() - 2 ].description == kContinuationOfMessage );
                REQUIRE( lines.back().description
                         == "WebSocket Text [FIN] [MASKED] len=5 \"World\"" );
            }
        }
    }

    GIVEN( "an MQTT PUBLISH of 100 KiB, then a short one" )
    {
        const auto big = mqttPublish( 100 * 1024 );
        const auto small = mqttPublish( 5 );
        auto segments = cut( big, cutsEvery( big.size(), 1448 ), kClientIsn + 1, 1883 );
        const auto bigSegments = segments.size();
        segments = segments
                   + cut( small, {}, kClientIsn + 1 + static_cast<uint32_t>( big.size() ), 1883 );
        const auto lines = converted( handshake( 1883 ) + segments );

        THEN( "its segments after the first are its continuation, and the short one is "
              "described" )
        {
            REQUIRE( lines[ 3 ].protocol == "MQTT" );
            REQUIRE( lines[ 3 ].info.find( kReassemblyLimit ) != std::string::npos );
            for ( size_t i = 4; i < 3 + bigSegments; ++i ) {
                INFO( "segment " << i - 3 );
                REQUIRE( lines[ i ].protocol == "MQTT" );
                REQUIRE( lines[ i ].description == kContinuationOfMessage );
            }
            REQUIRE( lines.back().protocol == "MQTT" );
            REQUIRE( lines.back().description == describedWhole( small, 1883 ) );
        }
    }

    GIVEN( "an SMB2 Read response of 200 KiB, then a Write request" )
    {
        const auto big = smbReadResponse( 200 * 1024 );
        auto segments
            = fromServer( cut( big, cutsEvery( big.size(), 1448 ), 0, 445 ), kServerIsn + 1 );
        const auto bigSegments = segments.size();
        segments = segments + cut( smbWriteRequest( 100 ), {}, kClientIsn + 1, 445 )
                   + fromServer( cut( smbWriteRequest( 10 ), {}, 0, 445 ),
                                 kServerIsn + 1 + static_cast<uint32_t>( big.size() ) );
        const auto lines = converted( handshake( 445 ) + segments );

        THEN( "its segments after the first are its continuation, and the next message is "
              "described" )
        {
            REQUIRE( lines[ 3 ].protocol == "SMB2" );
            REQUIRE( lines[ 3 ].description.find( "Read Response" ) == 0 );
            REQUIRE( lines[ 3 ].info.find( kReassemblyLimit ) != std::string::npos );
            for ( size_t i = 4; i < 3 + bigSegments; ++i ) {
                INFO( "segment " << i - 3 );
                REQUIRE( lines[ i ].description == kContinuationOfMessage );
            }
            REQUIRE( lines[ lines.size() - 2 ].description == "Write Request Len:100 Off:0" );
            REQUIRE( lines.back().description == "Write Request Len:10 Off:0" );
        }
    }

    GIVEN( "a TLS record longer than a per-stream limit of 300 bytes, then a short one" )
    {
        const auto big = tlsRecord( 0x17, Bytes( 1000, 0xAA ) );
        const auto small = tlsRecord( 0x17, Bytes( 10, 0xBB ) );
        PacketPipeline pipeline( reassemblyLimits( TcpReassembly::kDefaultMemoryLimit, 300 ) );
        const auto lines
            = converted( handshake() + cut( big + small, { 200, 600, big.size() } ), pipeline );

        THEN( "the record's other segments are its continuation, and the short one is "
              "described" )
        {
            REQUIRE( lines[ 3 ].info.find( kReassemblyLimit ) != std::string::npos );
            REQUIRE( lines[ 4 ].protocol == "TLS" );
            REQUIRE( lines[ 4 ].description == kContinuationOfMessage );
            REQUIRE( lines[ 5 ].description == kContinuationOfMessage );
            REQUIRE( lines[ 6 ].description == "Application Data" );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
        }
    }

    GIVEN( "an MQTT PUBLISH whose length comes in its second segment, past a limit of 256" )
    {
        const auto big = mqttPublish( 1000 );
        const auto small = mqttPublish( 5 );
        PacketPipeline pipeline( reassemblyLimits( TcpReassembly::kDefaultMemoryLimit, 256 ) );
        const auto lines = converted(
            handshake( 1883 )
                + cut( big + small, { 1, 100, 400, 800, big.size() }, kClientIsn + 1, 1883 ),
            pipeline );

        THEN( "the segment that tells the length is marked, the later ones are the "
              "continuation, and the short one is described" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 4 ].info.find( kReassemblyLimit ) != std::string::npos );
            REQUIRE( lines[ 5 ].description == kContinuationOfMessage );
            REQUIRE( lines[ 6 ].description == kContinuationOfMessage );
            REQUIRE( lines[ 7 ].description == kContinuationOfMessage );
            REQUIRE( lines[ 8 ].description == describedWhole( small, 1883 ) );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
        }
    }

    GIVEN( "a WebSocket frame that announces more than the bytes skipped at most" )
    {
        auto huge = webSocketBinary( 2000 );
        huge[ 2 ] = 0x7F; // 2^63 and more
        const auto lines
            = converted( webSocketUpgrade() + cut( huge, { 1000 }, kWebSocketClientSeq, 8080 ) );

        THEN( "it is marked, and nothing is skipped" )
        {
            REQUIRE( lines[ lines.size() - 2 ].info.find( kReassemblyLimit ) != std::string::npos );
            REQUIRE( lines.back().description != kContinuationOfMessage );
        }
    }
}

SCENARIO( "Reassembly holds bounded memory", "[tcp_reassembly]" )
{
    const auto hello = clientHello( "example.com" );

    GIVEN( "a per-stream limit below the message" )
    {
        PacketPipeline pipeline( reassemblyLimits( TcpReassembly::kDefaultMemoryLimit, 300 ) );
        const auto lines = converted( handshake() + cut( hello, { 200, 400 } ), pipeline );

        THEN( "its segments keep their own descriptions, with the limit marker on the first" )
        {
            REQUIRE( lines[ 3 ].description
                     == describedWhole( slice( hello, 0, 200 ) ) + " " + kReassemblyLimit );
            REQUIRE( lines[ 5 ].description.find( "reassembled" ) == std::string::npos );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
        }
    }

    GIVEN( "a message that outgrows the per-stream limit while held" )
    {
        const auto request
            = text( "GET / HTTP/1.1\r\nX-Long: " + std::string( 400, 'a' ) + "\r\n\r\n" );
        PacketPipeline pipeline( reassemblyLimits( TcpReassembly::kDefaultMemoryLimit, 256 ) );
        const auto lines = converted(
            handshake( 80 ) + cut( request, { 100, 200, 300 }, kClientIsn + 1, 80 ), pipeline );

        THEN( "the segment that passes it is marked and nothing stays held" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            bool marked = false;
            for ( size_t i = 4; i < lines.size(); ++i ) {
                marked = marked || lines[ i ].info.find( kReassemblyLimit ) != std::string::npos;
            }
            REQUIRE( marked );
            REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
            REQUIRE( pipeline.reassembly().memoryUsed() == 0 );
        }
    }

    GIVEN( "a global limit that holds one message only" )
    {
        auto other = handshake( 8443 ) + cut( hello, { 200 }, kClientIsn + 1, 8443 );
        for ( auto& s : other ) {
            s.clientPort = 50001;
        }
        const auto first = cut( hello, { 200 } );
        PacketPipeline pipeline(
            reassemblyLimits( hello.size() + TcpReassembly::kEntryOverhead + 100 ) );
        const auto lines = converted( handshake() + std::vector<Segment>{ first[ 0 ] }
                                          + std::vector<Segment>( other.begin(), other.end() - 1 )
                                          + std::vector<Segment>{ first[ 1 ], other.back() },
                                      pipeline );

        THEN( "the stream that waited longest is let go, its next segment marked" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 7 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 8 ].info.find( kReassemblyLimit ) != std::string::npos );
            REQUIRE( lines[ 8 ].segments == 0 );
            REQUIRE( lines[ 9 ].description == describedWhole( hello ) + reassembledFrom( 2 ) );
            REQUIRE( pipeline.reassembly().memoryUsed()
                     <= hello.size() + TcpReassembly::kEntryOverhead + 100 );
        }
    }

    GIVEN( "a global limit, and a message whose last segment begins a long one" )
    {
        const auto first = tlsRecord( 0x17, Bytes( 2000, 0xAA ) );
        const auto next = tlsRecord( 0x17, Bytes( 16000, 0xBB ) );
        const size_t limit = TcpReassembly::kEntryOverhead + 4000;
        PacketPipeline pipeline( reassemblyLimits( limit ) );
        auto parts = cut( first + next, { 1000, first.size() + 10 } );
        parts.pop_back();
        const auto lines = converted( handshake() + parts, pipeline );

        THEN( "the next message is held only as far as the limit lets it" )
        {
            REQUIRE( lines[ 4 ].description.find( reassembledFrom( 2 ) ) != std::string::npos );
            REQUIRE( pipeline.reassembly().memoryUsed() <= limit );
        }
    }

    GIVEN( "a stream that ends inside a message" )
    {
        auto parts = cut( hello, { 200 } );
        PacketPipeline pipeline;
        WHEN( "its sender closes it" )
        {
            parts[ 0 ].flags = kFinAck;
            converted( handshake() + std::vector<Segment>{ parts[ 0 ] }, pipeline );
            THEN( "its bytes are let go" )
            {
                REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
                REQUIRE( pipeline.reassembly().memoryUsed() == 0 );
            }
        }
        WHEN( "it is reset" )
        {
            Segment reset;
            reset.fromClient = false;
            reset.seq = kServerIsn + 1;
            reset.flags = kRst;
            converted( handshake() + std::vector<Segment>{ parts[ 0 ], reset }, pipeline );
            THEN( "its bytes are let go" )
            {
                REQUIRE( pipeline.reassembly().directionsHeld() == 0 );
            }
        }
    }
}

SCENARIO( "Mangled streams never break the reassembly", "[tcp_reassembly][fuzz]" )
{
    const auto hello = clientHello( "fuzz.example" );
    const auto record = tlsRecord( 0x17, Bytes( 700, 0x5A ) );
    // TLS, and the framers of SIP and MQTT on their ports.
    const std::pair<Bytes, uint16_t> streams[] = {
        { hello + record + record + hello, 443 },
        { sipInvite() + sipInvite() + sipInvite(), 5060 },
        { mqttPublish( 900 ) + mqttPublish( 10 ) + mqttPublish( 300 ), 1883 },
        // Messages past the limit, skipped to their ends.
        { mqttPublish( 5000 ) + mqttPublish( 10 ) + mqttPublish( 3000 ) + mqttPublish( 10 ), 1883 },
        { record + tlsRecord( 0x17, Bytes( 6000, 0x5A ) ) + record, 443 },
    };
    std::mt19937 random( 78 );
    constexpr size_t kLimit = 4096;

    for ( int round = 0; round < 750; ++round ) {
        const auto& [ stream, port ] = streams[ round % std::size( streams ) ];
        // Random cuts, then shuffles, drops, duplicates, overlaps and flipped bytes.
        std::vector<size_t> cuts;
        for ( size_t at = 0;; ) {
            at += 1 + random() % 400;
            if ( at >= stream.size() ) {
                break;
            }
            cuts.push_back( at );
        }
        auto data = stream;
        for ( int flips = random() % 4; flips > 0; --flips ) {
            data[ random() % data.size() ] = static_cast<uint8_t>( random() );
        }
        auto segments = cut( data, cuts, kClientIsn + 1, port );
        std::vector<Segment> mangled;
        for ( auto& s : segments ) {
            switch ( random() % 8 ) {
            case 0:
                continue; // lost
            case 1:
                mangled.push_back( s ); // retransmitted
                break;
            case 2:
                s.seq += static_cast<uint32_t>( random() % 64 ); // overlapping or off
                break;
            case 3:
                s.capturedPayload = static_cast<int64_t>( random() % ( s.payload.size() + 1 ) );
                break;
            default:
                break;
            }
            mangled.push_back( s );
        }
        for ( size_t i = 0; i + 1 < mangled.size(); ++i ) {
            if ( random() % 6 == 0 ) {
                std::swap( mangled[ i ], mangled[ i + 1 ] );
            }
        }
        Segment reset;
        reset.fromClient = false;
        reset.seq = kServerIsn + 1;
        reset.flags = kRst;
        reset.serverPort = port;

        PacketPipeline pipeline( reassemblyLimits( kLimit, 2048 ) );
        const auto lines = converted( handshake( port ) + mangled, pipeline );
        INFO( "round " << round );
        for ( const auto& line : lines ) {
            REQUIRE( line.info.find( '\n' ) == std::string::npos );
        }
        REQUIRE( pipeline.reassembly().memoryUsed() <= kLimit );

        PacketPipeline resetOne( reassemblyLimits( kLimit, 2048 ) );
        converted( handshake( port ) + mangled + std::vector<Segment>{ reset }, resetOne );
        REQUIRE( resetOne.reassembly().directionsHeld() == 0 );
        REQUIRE( resetOne.reassembly().memoryUsed() == 0 );
    }
}
