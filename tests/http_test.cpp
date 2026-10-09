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
 * @file http_test.cpp
 * @brief BDD tests for the HTTP descriptions: request lines with the Host
 *        header, status lines with Content-Type and Content-Length, the
 *        HTTP/2 connection preface and the frames of its stream, and
 *        messages cut or mangled anywhere.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kClientPort = 50080;
constexpr uint16_t kServerPort = 80;

const std::string kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

constexpr uint8_t kData = 0x0;
constexpr uint8_t kHeaders = 0x1;
constexpr uint8_t kRstStream = 0x3;
constexpr uint8_t kSettings = 0x4;
constexpr uint8_t kPing = 0x6;
constexpr uint8_t kWindowUpdate = 0x8;

PayloadDescription toServer( const Bytes& payload )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort,
                            kServerPort );
}

PayloadDescription fromServer( const Bytes& payload )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kServerPort,
                            kClientPort );
}

/// An HTTP/2 frame (RFC 9113, 4.1) of @p type on @p stream, with @p payload.
Bytes frame( uint8_t type, uint32_t stream, const Bytes& payload, uint8_t flags = 0 )
{
    const auto length = payload.size();
    Bytes b{ static_cast<uint8_t>( length >> 16 ), static_cast<uint8_t>( length >> 8 ),
             static_cast<uint8_t>( length ), type, flags };
    putBE32( b, stream );
    return b + payload;
}

Bytes settings()
{
    return frame( kSettings, 0, Bytes{ 0x00, 0x03, 0x00, 0x00, 0x00, 0x64 } ); // max streams 100
}

Bytes windowUpdate( uint32_t stream )
{
    Bytes increment;
    putBE32( increment, 0x00FF0001 );
    return frame( kWindowUpdate, stream, increment );
}

/// The first @p n bytes of @p bytes, in a buffer of exactly that size.
Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

/// A segment between client and server.
struct Segment {
    bool fromClient;
    Bytes payload;
};

/// Parse @p segments as a capture and describe each packet in its stream,
/// as the Converter does.
std::vector<PacketRecord> describedInStreams( const std::vector<Segment>& segments )
{
    std::vector<Bytes> frames;
    for ( const auto& s : segments ) {
        Ipv4Options o;
        if ( !s.fromClient ) {
            std::swap( o.src, o.dst );
        }
        frames.push_back(
            eth( EthertypeIpv4, ipv4( IpProtoTcp,
                                      s.fromClient ? tcp( kClientPort, kServerPort, s.payload )
                                                   : tcp( kServerPort, kClientPort, s.payload ),
                                      o ) ) );
    }
    auto packets = parse( pcapOf( frames ) ).packets;
    StreamTracker tracker;
    for ( auto& pkt : packets ) {
        describeInStream( pkt, tracker.track( pkt ) );
    }
    return packets;
}

/// The description in a packet's Info.
std::string descriptionOf( const PacketRecord& pkt )
{
    const auto at = pkt.info.find( kDescriptionSeparator );
    return at == std::string::npos
               ? std::string()
               : pkt.info.substr( at + std::string( kDescriptionSeparator ).size() );
}

} // namespace

SCENARIO( "A request line names the host from the Host header", "[http]" )
{
    GIVEN( "a request with a Host header" )
    {
        THEN( "the host comes between the method and the path" )
        {
            const auto described = toServer(
                text( "GET /index.html HTTP/1.1\r\nUser-Agent: t\r\nHost: example.com\r\n\r\n" ) );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description == "GET example.com/index.html HTTP/1.1" );
        }
    }

    GIVEN( "a request without one" )
    {
        THEN( "the line is the request line" )
        {
            REQUIRE(
                toServer( text( "GET /index.html HTTP/1.0\r\nAccept: */*\r\n\r\n" ) ).description
                == "GET /index.html HTTP/1.0" );
            REQUIRE( toServer( text( "GET / HTTP/1.0\r\n\r\n" ) ).description == "GET / HTTP/1.0" );
        }
    }

    GIVEN( "a Host header in any case, with a port and blanks around its value" )
    {
        THEN( "its value is shown as it is, without the blanks" )
        {
            REQUIRE(
                toServer( text( "POST /api HTTP/1.1\r\nhOsT: \t example.com:8080 \t\r\n\r\n" ) )
                    .description
                == "POST example.com:8080/api HTTP/1.1" );
        }
    }

    GIVEN( "lines that end in a bare line feed" )
    {
        THEN( "the header is found all the same" )
        {
            REQUIRE( toServer( text( "GET /a HTTP/1.1\nHost: example.com\n\n" ) ).description
                     == "GET example.com/a HTTP/1.1" );
        }
    }

    GIVEN( "a request whose target already names the host, or is no path" )
    {
        THEN( "the line is the request line" )
        {
            REQUIRE(
                toServer( text( "GET http://example.org/ HTTP/1.1\r\nHost: example.org\r\n\r\n" ) )
                    .description
                == "GET http://example.org/ HTTP/1.1" );
            REQUIRE( toServer( text( "CONNECT example.org:443 HTTP/1.1\r\nHost: "
                                     "example.org:443\r\n\r\n" ) )
                         .description
                     == "CONNECT example.org:443 HTTP/1.1" );
            REQUIRE(
                toServer( text( "OPTIONS * HTTP/1.1\r\nHost: example.org\r\n\r\n" ) ).description
                == "OPTIONS * HTTP/1.1" );
        }
    }

    GIVEN( "a Host header that is not one" )
    {
        THEN( "only a whole header line of the header section counts" )
        {
            // Cut by the segment before its line ends: the value may be cut too.
            REQUIRE( toServer( text( "GET /a HTTP/1.1\r\nHost: exam" ) ).description
                     == "GET /a HTTP/1.1" );
            // In the body, after the empty line.
            REQUIRE( toServer( text( "POST /a HTTP/1.1\r\n\r\nHost: example.com\r\n" ) ).description
                     == "POST /a HTTP/1.1" );
            // Another header that begins with the same letters.
            REQUIRE(
                toServer( text( "GET /a HTTP/1.1\r\nHostname: example.com\r\n\r\n" ) ).description
                == "GET /a HTTP/1.1" );
            // An empty value.
            REQUIRE( toServer( text( "GET /a HTTP/1.1\r\nHost: \r\n\r\n" ) ).description
                     == "GET /a HTTP/1.1" );
        }
    }

    GIVEN( "a Host header with control characters and one beyond the field cap" )
    {
        THEN( "the value is escaped and cut like every field" )
        {
            REQUIRE( toServer( text( "GET /a HTTP/1.1\r\nHost: a\x1b"
                                     "b\x7f\r\n\r\n" ) )
                         .description
                     == "GET a\\x1Bb\\x7F/a HTTP/1.1" );
            const std::string longHost( 200, 'h' );
            REQUIRE(
                toServer( text( "GET /a HTTP/1.1\r\nHost: " + longHost + "\r\n\r\n" ) ).description
                == "GET " + longHost.substr( 0, 120 ) + "\xe2\x80\xa6/a HTTP/1.1" );
        }
    }
}

SCENARIO( "A status line adds the Content-Type and Content-Length", "[http]" )
{
    GIVEN( "a response with both headers" )
    {
        const auto described
            = fromServer( text( "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                                "Server: t\r\ncontent-length: 1234\r\n\r\n<html>" ) );

        THEN( "both follow the status line, the type first" )
        {
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description
                     == "HTTP/1.1 200 OK, Content-Type: text/html; charset=utf-8, "
                        "Content-Length: 1234" );
        }
    }

    GIVEN( "a response with one of them" )
    {
        THEN( "only that one is added" )
        {
            REQUIRE( fromServer( text( "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" ) )
                         .description
                     == "HTTP/1.1 404 Not Found, Content-Length: 0" );
            REQUIRE( fromServer( text( "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" ) )
                         .description
                     == "HTTP/1.1 200 OK, Content-Type: image/png" );
        }
    }

    GIVEN( "a response with neither" )
    {
        THEN( "the line is the status line" )
        {
            REQUIRE(
                fromServer( text( "HTTP/1.1 304 Not Modified\r\nETag: \"x\"\r\n\r\n" ) ).description
                == "HTTP/1.1 304 Not Modified" );
            REQUIRE( fromServer( text( "HTTP/1.1 204 No Content" ) ).description
                     == "HTTP/1.1 204 No Content" );
        }
    }

    GIVEN( "a request with a body" )
    {
        THEN( "its Content-Type and Content-Length are not added: only a response's are" )
        {
            REQUIRE( toServer( text( "POST /a HTTP/1.1\r\nContent-Type: text/plain\r\n"
                                     "Content-Length: 2\r\n\r\nhi" ) )
                         .description
                     == "POST /a HTTP/1.1" );
        }
    }
}

SCENARIO( "The HTTP/2 connection preface is HTTP2", "[http][http2]" )
{
    GIVEN( "the preface alone" )
    {
        const auto described = toServer( text( kPreface ) );

        THEN( "it is HTTP2, the Magic" )
        {
            REQUIRE( described.label == "HTTP2" );
            REQUIRE( described.description == "Magic" );
        }
        THEN( "it cues its stream that an HTTP/2 connection began, by type, not by label" )
        {
            REQUIRE( described.streamCue == StreamCue::Http2Preface );
        }
    }

    GIVEN( "the preface with the client's first frames behind it" )
    {
        THEN( "each frame is named with its stream, in order" )
        {
            REQUIRE( toServer( text( kPreface ) + settings() + windowUpdate( 0 ) ).description
                     == "Magic, SETTINGS[0], WINDOW_UPDATE[0]" );
        }
    }

    GIVEN( "the preface with bytes that are no frame behind it" )
    {
        THEN( "only the Magic is named" )
        {
            REQUIRE( toServer( text( kPreface + "GET / HTTP/1.1\r\n\r\n" ) ).description
                     == "Magic" );
        }
    }

    GIVEN( "the preface cut short" )
    {
        THEN( "it is not HTTP2" )
        {
            REQUIRE( toServer( text( kPreface.substr( 0, 20 ) ) ).label != "HTTP2" );
        }
    }
}

SCENARIO( "Frames in a stream that began with the preface are HTTP2", "[http][http2]" )
{
    Bytes headerBlock( 30, 0x82 ); // HPACK, not decoded
    Bytes body = text( "<html>hello</html>" );

    GIVEN( "a connection: preface, SETTINGS both ways, a request and its response" )
    {
        const auto packets = describedInStreams( {
            { true, text( kPreface ) + settings() },
            { false, settings() + frame( kSettings, 0, {}, 0x1 ) },
            { true, frame( kHeaders, 1, headerBlock, 0x5 ) },
            { false, frame( kHeaders, 1, Bytes( 5, 0x88 ), 0x4 ) + frame( kData, 1, body, 0x1 ) },
            { true, frame( kData, 3, body ) },
        } );
        REQUIRE( packets.size() == 5 );

        THEN( "the preface is described as before" )
        {
            REQUIRE( packets[ 0 ].protocol == "HTTP2" );
            REQUIRE( descriptionOf( packets[ 0 ] ) == "Magic, SETTINGS[0]" );
        }

        THEN( "the frames of both sides are named with their streams" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTP2" );
            REQUIRE( descriptionOf( packets[ 1 ] ) == "SETTINGS[0], SETTINGS[0]" );
            REQUIRE( packets[ 2 ].protocol == "HTTP2" );
            REQUIRE( packets[ 2 ].info
                     == "50080 \xe2\x86\x92 80 [ACK, PSH] Seq=1 Ack=0 Win=65535 Len=39 | "
                        "HEADERS[1]" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "HEADERS[1], DATA[1]" );
            REQUIRE( packets[ 4 ].protocol == "HTTP2" );
            REQUIRE( descriptionOf( packets[ 4 ] ) == "DATA[3]" );
        }
    }

    GIVEN( "frames beyond the first bytes the parser keeps of a segment" )
    {
        Bytes many;
        for ( uint32_t i = 0; i < 6; ++i ) {
            many = many + frame( kRstStream, 2 * i + 1, Bytes( 4, 0 ) );
        }
        const auto packets = describedInStreams( { { true, text( kPreface ) }, { true, many } } );

        THEN( "the frames whose header is kept are named, then an ellipsis" )
        {
            REQUIRE(
                descriptionOf( packets[ 1 ] )
                == "RST_STREAM[1], RST_STREAM[3], RST_STREAM[5], RST_STREAM[7], \xe2\x80\xa6" );
        }
    }

    GIVEN( "frames on a stream without the preface" )
    {
        const auto packets = describedInStreams( {
            { true, settings() },
            { true, frame( kHeaders, 1, headerBlock ) },
        } );

        THEN( "they cannot be told from other bytes: the port's hint names them" )
        {
            REQUIRE( packets[ 0 ].protocol == "HTTP" );
            REQUIRE( packets[ 1 ].protocol == "HTTP" );
        }
    }

    GIVEN( "an HTTP2 stream, then segments that cannot begin with a frame" )
    {
        const auto packets = describedInStreams( {
            { true, text( kPreface ) },
            { false, text( "y" ) + body },                         // the rest of a DATA frame
            { true, frame( 0x7F, 0, Bytes( 4, 0 ) ) },             // an unknown type
            { true, frame( kPing, 1, Bytes( 8, 0 ) ) },            // PING on a request stream
            { true, frame( kData, 0, body ) },                     // DATA on stream 0
            { true, frame( kPing, 0, Bytes( 4, 0 ) ) },            // PING of the wrong length
            { true, frame( kData, 0x80000001, body ) },            // the reserved bit set
            { true, frame( kData, 1, Bytes( 20000, 0 ) ) },        // beyond the default maximum
            { true, frame( kData, 1, body ) + Bytes( 12, 0xFF ) }, // a second header that is none
            { true, {} },
        } );

        THEN( "they are not HTTP2" )
        {
            for ( size_t i = 1; i < packets.size(); ++i ) {
                INFO( "packet " << i );
                REQUIRE( packets[ i ].protocol == "HTTP" );
            }
        }
    }

    GIVEN( "a frame whose payload goes on in the next segment" )
    {
        const auto whole = frame( kData, 1, Bytes( 3000, 0x41 ) );
        const auto packets = describedInStreams(
            { { true, text( kPreface ) }, { false, prefix( whole, 1400 ) } } );

        THEN( "it is named by its header" )
        {
            REQUIRE( descriptionOf( packets[ 1 ] ) == "DATA[1]" );
        }
    }
}

SCENARIO( "A mangled or cut HTTP message is never read beyond the payload", "[http]" )
{
    const auto request = text( "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" );
    const auto response = text( "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                                "Content-Length: 5\r\n\r\nhello" );
    const auto preface = text( kPreface ) + settings() + windowUpdate( 0 )
                         + frame( kHeaders, 1, Bytes( 20, 0x82 ) );

    GIVEN( "each message cut at every length" )
    {
        THEN( "every prefix is described on one line" )
        {
            for ( const auto& message : { request, response, preface } ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto described = toServer( prefix( message, n ) );
                    REQUIRE( described.description.find( '\n' ) == std::string::npos );
                }
            }
        }
    }

    GIVEN( "messages with random bytes changed, cut anywhere, alone and in their stream" )
    {
        THEN( "the describer reads them without fault and within the length policy" )
        {
            std::mt19937 random( 80 );
            for ( int round = 0; round < 3000; ++round ) {
                const auto& original = round % 3 == 0   ? request
                                       : round % 3 == 1 ? response
                                                        : preface;
                auto mutated = original;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto cut = prefix( mutated, random() % ( mutated.size() + 1 ) );
                for ( const auto& described : { toServer( cut ), fromServer( cut ) } ) {
                    REQUIRE( described.description.find( '\n' ) == std::string::npos );
                    REQUIRE( described.description.size() < 1024 );
                }
                if ( round % 10 == 0 ) {
                    const auto packets
                        = describedInStreams( { { true, text( kPreface ) }, { false, cut } } );
                    REQUIRE( packets[ 1 ].info.find( '\n' ) == std::string::npos );
                }
            }
        }
    }
}
