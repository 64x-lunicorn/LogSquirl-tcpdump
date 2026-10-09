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
        labels.apply( pkt, stream );
        Line line{ pkt.protocol, pkt.info, {}, {}, done.segments };
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
    const auto stream = hello + record + record + hello;
    std::mt19937 random( 78 );
    constexpr size_t kLimit = 4096;

    for ( int round = 0; round < 300; ++round ) {
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
        auto segments = cut( data, cuts );
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

        TcpReassembly reassembly( kLimit, 2048 );
        const auto lines = converted( handshake() + mangled, reassembly );
        INFO( "round " << round );
        for ( const auto& line : lines ) {
            REQUIRE( line.info.find( '\n' ) == std::string::npos );
        }
        REQUIRE( reassembly.memoryUsed() <= kLimit );

        TcpReassembly resetOne( kLimit, 2048 );
        converted( handshake() + mangled + std::vector<Segment>{ reset }, resetOne );
        REQUIRE( resetOne.directionsHeld() == 0 );
        REQUIRE( resetOne.memoryUsed() == 0 );
    }
}
