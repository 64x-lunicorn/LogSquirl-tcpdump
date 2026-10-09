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

#include "capture_reader.h"
#include "payload_describer.h"
#include "pcapbuilder.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tcp_reassembly.h"

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

/// Run @p segments through the Converter's steps, the payload taken from the
/// reader as the Converter takes it.
std::vector<Line> converted( const std::vector<Segment>& segments, TcpReassembly& reassembly )
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
    const auto file = pcapFile( records );
    MemorySource memory( file.data(), file.size() );
    HeadSource head( memory );
    const auto reader = makeCaptureReader( head );
    REQUIRE( reader->open() );

    StreamTracker tracker;
    StreamLabels labels;
    std::vector<Line> lines;
    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto stream = tracker.track( pkt );
        analyseTcp( pkt, stream );
        describeInStream( pkt, stream );
        const auto done = reassembly.apply( pkt, stream, reader->payloadOf( pkt ) );
        rememberInStream( pkt, stream );
        labels.apply( pkt, stream );
        Line line{ pkt.protocol, pkt.info, {}, {}, done.segments, pkt.sipCalls.size() };
        const auto at = pkt.info.find( kDescriptionSeparator );
        if ( at != std::string::npos ) {
            line.description = pkt.info.substr( at + std::strlen( kDescriptionSeparator ) );
        }
        if ( done.bytes.data ) {
            line.completed.assign( done.bytes.data, done.bytes.data + done.bytes.size );
        }
        lines.push_back( line );
    }
    REQUIRE( lines.size() == segments.size() );
    return lines;
}

std::vector<Line> converted( const std::vector<Segment>& segments )
{
    TcpReassembly reassembly;
    return converted( segments, reassembly );
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

std::vector<Segment> operator+( std::vector<Segment> a, const std::vector<Segment>& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
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

    GIVEN( "whole records and the start of another in one segment" )
    {
        const auto first = tlsRecord( 0x17, Bytes( 100, 0xAA ) );
        const auto second = tlsRecord( 0x17, Bytes( 300, 0xBB ) );
        const auto stream = first + first + second;
        TcpReassembly reassembly;
        const auto lines
            = converted( handshake() + cut( stream, { first.size() * 2 + 50 } ), reassembly );

        THEN( "the first names the whole records only" )
        {
            REQUIRE( lines[ 3 ].description == "Application Data, Application Data" );
            REQUIRE( lines[ 3 ].completed == first + first );
        }
        THEN( "the second names the record it completes" )
        {
            REQUIRE( lines[ 4 ].description == "Application Data" + reassembledFrom( 2 ) );
            REQUIRE( lines[ 4 ].completed == second );
            REQUIRE( reassembly.directionsHeld() == 0 );
            REQUIRE( reassembly.memoryUsed() == 0 );
        }
    }

    GIVEN( "segments of whole messages" )
    {
        const auto record = tlsRecord( 0x17, Bytes( 100, 0xAA ) );
        TcpReassembly reassembly;
        const auto lines
            = converted( handshake() + cut( record + record, { record.size() } ), reassembly );

        THEN( "each keeps its own description, and nothing is held" )
        {
            REQUIRE( lines[ 3 ].description == "Application Data" );
            REQUIRE( lines[ 4 ].description == "Application Data" );
            REQUIRE( lines[ 4 ].segments == 0 );
            REQUIRE( reassembly.memoryUsed() == 0 );
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
        TcpReassembly reassembly;
        const auto lines = converted(
            handshake() + std::vector<Segment>{ parts[ 0 ], parts[ 2 ], ack } + next, reassembly );

        THEN( "the hello is given up and the next record is described as it is" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines.at( 6 ).description == "Application Data" );
            REQUIRE( reassembly.directionsHeld() == 0 );
        }
    }

    GIVEN( "a segment cut at the snaplen" )
    {
        auto cutShort = parts[ 1 ];
        cutShort.capturedPayload = 20;
        auto again = cut( hello, { 300 },
                          parts[ 2 ].seq + static_cast<uint32_t>( parts[ 2 ].payload.size() ) );
        TcpReassembly reassembly;
        const auto lines = converted(
            handshake() + std::vector<Segment>{ parts[ 0 ], cutShort, parts[ 2 ] } + again,
            reassembly );

        THEN( "it is a gap, and the stream resynchronises on the next hello" )
        {
            REQUIRE( lines[ 5 ].description != kSegmentOfMessage );
            REQUIRE( lines[ 5 ].segments == 0 );
            REQUIRE( lines[ 6 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 7 ].description == describedWhole( hello ) + reassembledFrom( 2 ) );
        }
    }
}

SCENARIO( "Reassembly holds bounded memory", "[tcp_reassembly]" )
{
    const auto hello = clientHello( "example.com" );

    GIVEN( "a per-stream limit below the message" )
    {
        TcpReassembly reassembly( TcpReassembly::kDefaultMemoryLimit, 300 );
        const auto lines = converted( handshake() + cut( hello, { 200, 400 } ), reassembly );

        THEN( "its segments keep their own descriptions, with the limit marker on the first" )
        {
            REQUIRE( lines[ 3 ].description
                     == describedWhole( slice( hello, 0, 200 ) ) + " " + kReassemblyLimit );
            REQUIRE( lines[ 5 ].description.find( "reassembled" ) == std::string::npos );
            REQUIRE( reassembly.directionsHeld() == 0 );
        }
    }

    GIVEN( "a message that outgrows the per-stream limit while held" )
    {
        const auto request
            = text( "GET / HTTP/1.1\r\nX-Long: " + std::string( 400, 'a' ) + "\r\n\r\n" );
        TcpReassembly reassembly( TcpReassembly::kDefaultMemoryLimit, 256 );
        const auto lines = converted(
            handshake( 80 ) + cut( request, { 100, 200, 300 }, kClientIsn + 1, 80 ), reassembly );

        THEN( "the segment that passes it is marked and nothing stays held" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            bool marked = false;
            for ( size_t i = 4; i < lines.size(); ++i ) {
                marked = marked || lines[ i ].info.find( kReassemblyLimit ) != std::string::npos;
            }
            REQUIRE( marked );
            REQUIRE( reassembly.directionsHeld() == 0 );
            REQUIRE( reassembly.memoryUsed() == 0 );
        }
    }

    GIVEN( "a global limit that holds one message only" )
    {
        auto other = handshake( 8443 ) + cut( hello, { 200 }, kClientIsn + 1, 8443 );
        for ( auto& s : other ) {
            s.clientPort = 50001;
        }
        const auto first = cut( hello, { 200 } );
        TcpReassembly reassembly( hello.size() + TcpReassembly::kEntryOverhead + 100 );
        const auto lines = converted( handshake() + std::vector<Segment>{ first[ 0 ] }
                                          + std::vector<Segment>( other.begin(), other.end() - 1 )
                                          + std::vector<Segment>{ first[ 1 ], other.back() },
                                      reassembly );

        THEN( "the stream that waited longest is let go, its next segment marked" )
        {
            REQUIRE( lines[ 3 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 7 ].description == kSegmentOfMessage );
            REQUIRE( lines[ 8 ].info.find( kReassemblyLimit ) != std::string::npos );
            REQUIRE( lines[ 8 ].segments == 0 );
            REQUIRE( lines[ 9 ].description == describedWhole( hello ) + reassembledFrom( 2 ) );
            REQUIRE( reassembly.memoryUsed()
                     <= hello.size() + TcpReassembly::kEntryOverhead + 100 );
        }
    }

    GIVEN( "a stream that ends inside a message" )
    {
        auto parts = cut( hello, { 200 } );
        TcpReassembly reassembly;
        WHEN( "its sender closes it" )
        {
            parts[ 0 ].flags = kFinAck;
            converted( handshake() + std::vector<Segment>{ parts[ 0 ] }, reassembly );
            THEN( "its bytes are let go" )
            {
                REQUIRE( reassembly.directionsHeld() == 0 );
                REQUIRE( reassembly.memoryUsed() == 0 );
            }
        }
        WHEN( "it is reset" )
        {
            Segment reset;
            reset.fromClient = false;
            reset.seq = kServerIsn + 1;
            reset.flags = kRst;
            converted( handshake() + std::vector<Segment>{ parts[ 0 ], reset }, reassembly );
            THEN( "its bytes are let go" )
            {
                REQUIRE( reassembly.directionsHeld() == 0 );
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
    };
    std::mt19937 random( 78 );
    constexpr size_t kLimit = 4096;

    for ( int round = 0; round < 450; ++round ) {
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

        TcpReassembly reassembly( kLimit, 2048 );
        const auto lines = converted( handshake( port ) + mangled, reassembly );
        INFO( "round " << round );
        for ( const auto& line : lines ) {
            REQUIRE( line.info.find( '\n' ) == std::string::npos );
        }
        REQUIRE( reassembly.memoryUsed() <= kLimit );

        TcpReassembly resetOne( kLimit, 2048 );
        converted( handshake( port ) + mangled + std::vector<Segment>{ reset }, resetOne );
        REQUIRE( resetOne.directionsHeld() == 0 );
        REQUIRE( resetOne.memoryUsed() == 0 );
    }
}
