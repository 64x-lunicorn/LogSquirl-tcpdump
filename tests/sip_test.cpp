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
 * @file sip_test.cpp
 * @brief BDD tests for the SIP, SDP, RTP and RTCP descriptions: SIP
 *        requests and responses over UDP and TCP, SDP bodies and the media
 *        they announce, RTP and RTCP where an SDP body announced them
 *        (MediaExpectations) and nowhere else, the expectations' cap and
 *        expiry, and messages mangled and cut anywhere.
 */

#include <catch2/catch.hpp>

#include "media_expectations.h"
#include "payload_describer.h"
#include "pcapbuilder.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

const std::string kEllipsis = "\xe2\x80\xa6";

constexpr uint16_t kSipPort = 5060;

/// An SDP body offering audio at @p ip, @p port, with @p extra lines.
std::string sdp( const std::string& ip, uint16_t port, const std::string& extra = "" )
{
    return "v=0\r\n"
           "o=alice 2890844526 2890844526 IN IP4 "
           + ip
           + "\r\n"
             "s=-\r\n"
             "c=IN IP4 "
           + ip
           + "\r\n"
             "t=0 0\r\n"
             "m=audio "
           + std::to_string( port )
           + " RTP/AVP 0 8\r\n"
             "a=rtpmap:0 PCMU/8000\r\n"
           + extra;
}

/// A SIP message: the start line, Call-ID and CSeq, the extra headers, the
/// body behind its Content-Length (and an SDP Content-Type).
std::string sip( const std::string& startLine, const std::string& cseq,
                 const std::string& body = "", const std::string& headers = "",
                 const std::string& callId = "a84b4c76e66710@pc33.example.com" )
{
    std::string m = startLine + "\r\n"
                    + "Via: SIP/2.0/UDP pc33.example.com;branch=z9hG4bK776asdhds\r\n"
                      "From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
                      "To: Bob <sip:bob@example.com>\r\n"
                      "Call-ID: "
                    + callId + "\r\nCSeq: " + cseq + "\r\n" + headers;
    if ( !body.empty() ) {
        m += "Content-Type: application/sdp\r\n";
    }
    m += "Content-Length: " + std::to_string( body.size() ) + "\r\n\r\n" + body;
    return m;
}

std::string invite( const std::string& body = "" )
{
    return sip( "INVITE sip:bob@example.com SIP/2.0", "1 INVITE", body );
}

PayloadDescription overUdp( const std::string& message, uint16_t port = kSipPort )
{
    const auto bytes = text( message );
    return describePayload( Transport::Udp, bytes.data(), bytes.size(), 5062, port );
}

PayloadDescription overTcp( const std::string& message, uint16_t port = kSipPort )
{
    const auto bytes = text( message );
    return describePayload( Transport::Tcp, bytes.data(), bytes.size(), 50600, port );
}

std::string described( const std::string& message )
{
    const auto result = overUdp( message );
    REQUIRE( result.label == "SIP" );
    REQUIRE_FALSE( result.guessed );
    return result.description;
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

// ── RTP and RTCP in a capture ────────────────────────────────────────────

/// An RTP packet's header and payload.
Bytes rtp( uint8_t type, uint16_t seq, uint32_t time, uint32_t ssrc, bool marker = false,
           size_t payloadBytes = 160 )
{
    Bytes b{ 0x80, static_cast<uint8_t>( ( marker ? 0x80 : 0 ) | type ) };
    putBE16( b, seq );
    putBE32( b, time );
    putBE32( b, ssrc );
    return b + Bytes( payloadBytes, 0xFF );
}

/// An RTCP packet of @p type with @p words 32-bit words behind its header.
Bytes rtcp( uint8_t type, uint16_t words, uint8_t count = 0 )
{
    Bytes b{ static_cast<uint8_t>( 0x80 | count ), type };
    putBE16( b, words );
    return b + Bytes( 4 * words, 0 );
}

/// A UDP packet between two IPv4 addresses (their last byte, of
/// 192.0.2.0/24), at second @p sec.
struct Udp {
    uint8_t src;
    uint16_t srcPort;
    uint8_t dst;
    uint16_t dstPort;
    Bytes payload;
    uint32_t sec = 1000;
};

/// Parse @p packets as a capture and run each through @p media, as the
/// Converter does.
std::vector<PacketRecord> throughExpectations( const std::vector<Udp>& packets,
                                               MediaExpectations& media )
{
    std::vector<Record> records;
    for ( const auto& p : packets ) {
        Ipv4Options o;
        const uint8_t src[ 4 ] = { 192, 0, 2, p.src };
        const uint8_t dst[ 4 ] = { 192, 0, 2, p.dst };
        std::copy( src, src + 4, o.src );
        std::copy( dst, dst + 4, o.dst );
        records.push_back(
            { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( p.srcPort, p.dstPort, p.payload ), o ) ),
              p.sec } );
    }
    auto parsed = parse( pcapFile( records ) ).packets;
    for ( auto& pkt : parsed ) {
        media.apply( pkt );
    }
    return parsed;
}

std::vector<PacketRecord> throughExpectations( const std::vector<Udp>& packets )
{
    MediaExpectations media;
    return throughExpectations( packets, media );
}

std::string descriptionOf( const PacketRecord& pkt )
{
    const auto at = pkt.info.find( kDescriptionSeparator );
    return at == std::string::npos
               ? std::string()
               : pkt.info.substr( at + std::string( kDescriptionSeparator ).size() );
}

/// Alice (192.0.2.10) and Bob (192.0.2.20) and their offer and answer.
constexpr uint8_t kAlice = 10;
constexpr uint8_t kBob = 20;

Bytes offer( uint16_t port = 49170, const std::string& extra = "",
             const std::string& callId = "a84b4c76e66710@pc33.example.com" )
{
    return text( sip( "INVITE sip:bob@example.com SIP/2.0", "1 INVITE",
                      sdp( "192.0.2.10", port, extra ), "", callId ) );
}

Bytes answer( uint16_t port = 3456 )
{
    return text( sip( "SIP/2.0 200 OK", "1 INVITE", sdp( "192.0.2.20", port ) ) );
}

Bytes bye( const std::string& callId = "a84b4c76e66710@pc33.example.com" )
{
    return text( sip( "BYE sip:bob@example.com SIP/2.0", "2 BYE", "", "", callId ) );
}

} // namespace

SCENARIO( "SIP requests and responses are described as Wireshark names them", "[sip]" )
{
    GIVEN( "an INVITE with an SDP offer" )
    {
        const auto result = overUdp( invite( sdp( "192.0.2.10", 49170 ) ) );

        THEN( "the request, its CSeq, the Call-ID cut short and the SDP media are shown" )
        {
            REQUIRE( result.label == "SIP" );
            REQUIRE( result.description
                     == "Request: INVITE sip:bob@example.com, CSeq 1, Call-ID a84b4c76e667"
                            + kEllipsis + ", SDP (audio 49170 RTP/AVP 0 8)" );
        }
        THEN( "the media it offers goes with the description, RTCP on the next port" )
        {
            REQUIRE( result.sipCalls.size() == 1 );
            const auto& call = result.sipCalls[ 0 ];
            REQUIRE( call.callId == "a84b4c76e66710@pc33.example.com" );
            REQUIRE_FALSE( call.ends );
            REQUIRE( call.media.size() == 1 );
            REQUIRE( call.media[ 0 ].ip == "192.0.2.10" );
            REQUIRE( call.media[ 0 ].rtpPort == 49170 );
            REQUIRE( call.media[ 0 ].rtcpPort == 49171 );
        }
    }

    GIVEN( "responses" )
    {
        THEN( "the status names the method of its CSeq" )
        {
            REQUIRE( described( sip( "SIP/2.0 180 Ringing", "1 INVITE", "", "", "x" ) )
                     == "Status: 180 Ringing (INVITE), CSeq 1, Call-ID x" );
            REQUIRE( described( sip( "SIP/2.0 200 OK", "2 BYE", "", "", "x" ) )
                     == "Status: 200 OK (BYE), CSeq 2, Call-ID x" );
            REQUIRE( described( sip( "SIP/2.0 486", "1 INVITE", "", "", "x" ) )
                     == "Status: 486 (INVITE), CSeq 1, Call-ID x" );
        }
    }

    GIVEN( "requests of every kind, on another port" )
    {
        THEN( "each is SIP by its start line, OPTIONS too, which HTTP shares" )
        {
            for ( const char* method :
                  { "ACK", "BYE", "CANCEL", "OPTIONS", "REGISTER", "SUBSCRIBE", "NOTIFY" } ) {
                const auto message = sip( std::string( method ) + " sip:example.com SIP/2.0",
                                          std::string( "7 " ) + method, "", "", "x" );
                for ( const auto& result : { overUdp( message, 15060 ), overTcp( message, 80 ) } ) {
                    REQUIRE( result.label == "SIP" );
                    REQUIRE( result.description
                             == std::string( "Request: " ) + method
                                    + " sip:example.com, CSeq 7, Call-ID x" );
                }
            }
        }
    }

    GIVEN( "compact header names" )
    {
        const std::string message = "INVITE sip:bob@example.com SIP/2.0\r\n"
                                    "i: short-id\r\n"
                                    "CSeq: 5 INVITE\r\n"
                                    "c: application/sdp\r\n"
                                    "l: "
                                    + std::to_string( sdp( "192.0.2.10", 4000 ).size() )
                                    + "\r\n\r\n" + sdp( "192.0.2.10", 4000 );

        THEN( "they are read as their long forms" )
        {
            REQUIRE( described( message )
                     == "Request: INVITE sip:bob@example.com, CSeq 5, Call-ID short-id, SDP (audio "
                        "4000 RTP/AVP 0 8)" );
        }
    }

    GIVEN( "a BYE" )
    {
        const auto result = overUdp( sip( "BYE sip:bob@example.com SIP/2.0", "2 BYE" ) );

        THEN( "it ends its call" )
        {
            REQUIRE( result.sipCalls.size() == 1 );
            REQUIRE( result.sipCalls[ 0 ].ends );
            REQUIRE( result.sipCalls[ 0 ].callId == "a84b4c76e66710@pc33.example.com" );
        }
    }

    GIVEN( "payloads that are not SIP" )
    {
        THEN( "no SIP is found in them" )
        {
            for ( const char* payload :
                  { "GET / HTTP/1.1\r\nHost: x\r\n\r\n", "INVITE bob SIP/2.0\r\n\r\n",
                    "INVITE sip:bob@example.com SIP/3.0\r\n\r\n", "SIP/2.0 99 Low\r\n\r\n",
                    "SIP/2.0 2000 OK\r\n\r\n", "SIP/2.0 200 OK" } ) {
                REQUIRE( overUdp( payload, 15060 ).label != "SIP" );
            }
        }
    }
}

SCENARIO( "SIP over TCP is read message by message by its Content-Length", "[sip]" )
{
    GIVEN( "two messages in one segment" )
    {
        const auto result
            = overTcp( sip( "SIP/2.0 100 Trying", "1 INVITE", "", "", "c1" )
                       + sip( "SIP/2.0 200 OK", "1 INVITE", sdp( "192.0.2.20", 3456 ), "", "c1" ) );

        THEN( "both are described, the second with its SDP" )
        {
            REQUIRE( result.description
                     == "Status: 100 Trying (INVITE), CSeq 1, Call-ID c1; Status: 200 OK (INVITE), "
                        "CSeq 1, Call-ID c1, SDP (audio 3456 RTP/AVP 0 8)" );
            REQUIRE( result.sipCalls.size() == 1 );
        }
    }

    GIVEN( "more messages than are named, with keep-alives between them" )
    {
        std::string segment;
        for ( int i = 1; i <= 6; ++i ) {
            segment += sip( "OPTIONS sip:x SIP/2.0", std::to_string( i ) + " OPTIONS", "", "", "o" )
                       + "\r\n\r\n";
        }

        THEN( "the first four are named, then an ellipsis" )
        {
            const auto text = overTcp( segment ).description;
            REQUIRE( text.find( "CSeq 4" ) != std::string::npos );
            REQUIRE( text.find( "CSeq 5" ) == std::string::npos );
            REQUIRE( text.size() > kEllipsis.size() );
            REQUIRE( text.substr( text.size() - kEllipsis.size() ) == kEllipsis );
        }
    }

    GIVEN( "a message whose SDP body goes on in the next segment" )
    {
        const auto whole = invite( sdp( "192.0.2.10", 49170 ) );
        const auto cut = whole.substr( 0, whole.size() - 12 );

        THEN( "it is described as far as it goes" )
        {
            REQUIRE( overTcp( cut ).description
                     == "Request: INVITE sip:bob@example.com, CSeq 1, Call-ID a84b4c76e667"
                            + kEllipsis + ", SDP (audio 49170 RTP/AVP 0 8) " + kEllipsis );
        }
    }

    GIVEN( "a message whose header section goes on in the next segment" )
    {
        const auto whole = invite();
        THEN( "its start line is shown, then an ellipsis" )
        {
            const auto text = overTcp( whole.substr( 0, 60 ) ).description;
            REQUIRE( text.rfind( "Request: INVITE sip:bob@example.com", 0 ) == 0 );
            REQUIRE( text.substr( text.size() - kEllipsis.size() ) == kEllipsis );
        }
    }

    GIVEN( "a segment that begins inside a message, on SIP's port" )
    {
        THEN( "it is SIP by its port alone" )
        {
            const auto result = overTcp( "a=rtpmap:0 PCMU/8000\r\n" );
            REQUIRE( result.label == "SIP" );
            REQUIRE( result.guessed );
        }
    }
}

SCENARIO( "A malformed SIP message is described as such", "[sip]" )
{
    THEN( "a message without Call-ID or with a bad CSeq is malformed" )
    {
        REQUIRE( described( "OPTIONS sip:x SIP/2.0\r\nCSeq: 1 OPTIONS\r\n\r\n" )
                 == "Request: OPTIONS sip:x, CSeq 1 [Malformed Packet]" );
        REQUIRE( described( "OPTIONS sip:x SIP/2.0\r\nCall-ID: y\r\nCSeq: one\r\n\r\n" )
                 == "Request: OPTIONS sip:x, Call-ID y [Malformed Packet]" );
    }
    THEN( "a bad Content-Length or a header line without colon is malformed" )
    {
        REQUIRE( described( "OPTIONS sip:x SIP/2.0\r\nCall-ID: y\r\nContent-Length: -1\r\n\r\n" )
                 == "Request: OPTIONS sip:x, Call-ID y [Malformed Packet]" );
        REQUIRE( described( "OPTIONS sip:x SIP/2.0\r\nCall-ID: y\r\nCSeq: 1 OPTIONS\r\n"
                            "Content-Length: 99999999999\r\n\r\n" )
                 == "Request: OPTIONS sip:x, CSeq 1, Call-ID y [Malformed Packet]" );
        REQUIRE( described( "OPTIONS sip:x SIP/2.0\r\nCall-ID y\r\n\r\n" )
                 == "Request: OPTIONS sip:x [Malformed Packet]" );
    }
    THEN( "an SDP body that does not begin with v= is malformed" )
    {
        REQUIRE( described( invite( "o=x\r\n" ) )
                 == "Request: INVITE sip:bob@example.com, CSeq 1, Call-ID a84b4c76e667" + kEllipsis
                        + ", SDP [Malformed Packet]" );
    }
    THEN( "a Content-Length beyond the datagram is a cut body" )
    {
        auto message = invite( sdp( "192.0.2.10", 49170 ) );
        message = message.substr( 0, message.size() - 30 );
        REQUIRE( described( message ).substr( described( message ).size() - kEllipsis.size() )
                 == kEllipsis );
    }
}

SCENARIO( "SDP bodies announce the media streams RTP and RTCP are expected on", "[sip]" )
{
    auto mediaOf = []( const std::string& body ) {
        const auto result = overUdp( invite( body ) );
        REQUIRE( result.sipCalls.size() <= 1 );
        return result.sipCalls.empty() ? std::vector<MediaEndpoint>{} : result.sipCalls[ 0 ].media;
    };

    GIVEN( "an a=rtcp attribute and rtcp-mux" )
    {
        THEN( "RTCP is expected where they say" )
        {
            REQUIRE( mediaOf( sdp( "192.0.2.10", 5000, "a=rtcp:5011\r\n" ) )[ 0 ].rtcpPort
                     == 5011 );
            REQUIRE( mediaOf( sdp( "192.0.2.10", 5000, "a=rtcp-mux\r\n" ) )[ 0 ].rtcpPort == 5000 );
        }
    }

    GIVEN( "several media, one rejected, one not RTP, one with its own address" )
    {
        const std::string body = "v=0\r\nc=IN IP4 192.0.2.10\r\n"
                                 "m=audio 4000 RTP/AVP 0\r\n"
                                 "m=video 0 RTP/AVP 31\r\n"
                                 "m=application 5000 TCP/BFCP *\r\n"
                                 "m=video 6000 RTP/SAVPF 96\r\nc=IN IP6 2001:DB8:0:0::0001\r\n";

        THEN( "the RTP ones with a port are expected, each at its address" )
        {
            const auto media = mediaOf( body );
            REQUIRE( media.size() == 2 );
            REQUIRE( media[ 0 ].ip == "192.0.2.10" );
            REQUIRE( media[ 0 ].rtpPort == 4000 );
            REQUIRE( media[ 1 ].ip == "2001:db8::1" );
            REQUIRE( media[ 1 ].rtpPort == 6000 );
            REQUIRE(
                overUdp( invite( body ) )
                    .description.find(
                        "SDP (audio 4000 RTP/AVP 0, video 0 RTP/AVP 31, application 5000 TCP/BFCP "
                        "*, video 6000 RTP/SAVPF 96)" )
                != std::string::npos );
        }
    }

    GIVEN( "addresses that are no IP addresses, and a multicast TTL" )
    {
        THEN( "only addresses are expected, without the TTL" )
        {
            REQUIRE( mediaOf( "v=0\r\nc=IN IP4 host.example.com\r\nm=audio 4000 RTP/AVP 0\r\n" )
                         .empty() );
            REQUIRE(
                mediaOf( "v=0\r\nc=IN IP4 192.0.2.300\r\nm=audio 4000 RTP/AVP 0\r\n" ).empty() );
            REQUIRE( mediaOf( "v=0\r\nc=IN IP6 1::2::3\r\nm=audio 4000 RTP/AVP 0\r\n" ).empty() );
            REQUIRE(
                mediaOf( "v=0\r\nc=IN IP4 233.252.0.1/127\r\nm=audio 4000 RTP/AVP 0\r\n" )[ 0 ].ip
                == "233.252.0.1" );
            REQUIRE(
                mediaOf( "v=0\r\nc=IN IP6 ::ffff:192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n" )[ 0 ].ip
                == "::ffff:c000:201" );
        }
    }

    GIVEN( "more media than are kept" )
    {
        std::string body = "v=0\r\nc=IN IP4 192.0.2.10\r\n";
        for ( int i = 0; i < 20; ++i ) {
            body += "m=audio " + std::to_string( 4000 + 2 * i ) + " RTP/AVP 0\r\n";
        }

        THEN( "kMaxSdpMedia are expected" )
        {
            REQUIRE( mediaOf( body ).size() == kMaxSdpMedia );
        }
    }
}

SCENARIO( "RTP and RTCP are described on the endpoints SDP announced", "[sip][rtp]" )
{
    GIVEN( "a call's offer and answer, then its media both ways" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer() },
            { kBob, 5060, kAlice, 5060, answer() },
            { kAlice, 49170, kBob, 3456, rtp( 0, 1, 160, 0x1234ABCD, true ) },
            { kBob, 3456, kAlice, 49170, rtp( 8, 7, 320, 0xCAFE ) },
            { kAlice, 49170, kBob, 3456, rtp( 101, 2, 320, 0x1234ABCD ) },
            { kAlice, 49171, kBob, 3457, rtcp( 200, 6, 0 ) + rtcp( 202, 2, 1 ) },
            { kBob, 3457, kAlice, 49171, rtcp( 201, 1 ) },
            { kAlice, 49172, kBob, 3460, rtp( 0, 1, 160, 1 ) },
        } );

        THEN( "RTP shows its payload type, SSRC, sequence and time" )
        {
            REQUIRE( packets[ 2 ].protocol == "RTP" );
            REQUIRE( packets[ 2 ].protocolRecognised );
            REQUIRE( descriptionOf( packets[ 2 ] )
                     == "PT=PCMU, SSRC=0x1234ABCD, Seq=1, Time=160, Mark" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "PT=PCMA, SSRC=0x0000CAFE, Seq=7, Time=320" );
            REQUIRE( descriptionOf( packets[ 4 ] )
                     == "PT=DynamicRTP-Type-101, SSRC=0x1234ABCD, Seq=2, Time=320" );
        }
        THEN( "RTCP shows the packets of its compound packet" )
        {
            REQUIRE( packets[ 5 ].protocol == "RTCP" );
            REQUIRE( descriptionOf( packets[ 5 ] ) == "Sender Report, Source description" );
            REQUIRE( descriptionOf( packets[ 6 ] ) == "Receiver Report" );
        }
        THEN( "UDP between other ports is not RTP" )
        {
            REQUIRE( packets[ 7 ].protocol == "UDP" );
        }
    }

    GIVEN( "rtcp-mux: RTCP on the RTP port" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer( 49170, "a=rtcp-mux\r\n" ) },
            { kBob, 4000, kAlice, 49170, rtcp( 201, 1 ) },
            { kBob, 4000, kAlice, 49170, rtp( 0, 9, 0, 2 ) },
        } );

        THEN( "both are told apart by their packet type" )
        {
            REQUIRE( packets[ 1 ].protocol == "RTCP" );
            REQUIRE( packets[ 2 ].protocol == "RTP" );
        }
    }

    GIVEN( "a payload on an expected endpoint that is no RTP" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer() },
            { kBob, 4000, kAlice, 49170, text( "hello" ) },
            { kBob, 4000, kAlice, 49171, Bytes{ 0x80, 0x00 } },
        } );

        THEN( "it is left as it was" )
        {
            REQUIRE( packets[ 1 ].protocol == "UDP" );
            REQUIRE( packets[ 2 ].protocol == "UDP" );
        }
    }

    GIVEN( "an RTP header whose CSRC list runs past the packet, and RTCP whose length does" )
    {
        auto bad = rtp( 0, 1, 0, 1, false, 0 );
        bad[ 0 ] = 0x8F;
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer() },
            { kBob, 4000, kAlice, 49170, bad },
            { kBob, 4000, kAlice, 49171, Bytes{ 0x80, 200, 0, 50, 0, 0, 0, 0 } },
        } );

        THEN( "they are described as malformed" )
        {
            REQUIRE( descriptionOf( packets[ 1 ] )
                     == "PT=PCMU, SSRC=0x00000001, Seq=1, Time=0 [Malformed Packet]" );
            REQUIRE( descriptionOf( packets[ 2 ] ) == "Sender Report [Malformed Packet]" );
        }
    }
}

SCENARIO( "Media expectations are capped and expire", "[sip][rtp]" )
{
    GIVEN( "a BYE" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer() },
            { kBob, 4000, kAlice, 49170, rtp( 0, 1, 0, 1 ) },
            { kAlice, 5060, kBob, 5060, bye() },
            { kBob, 4000, kAlice, 49170, rtp( 0, 2, 160, 1 ) },
        } );

        THEN( "the call's media is no longer expected" )
        {
            REQUIRE( packets[ 1 ].protocol == "RTP" );
            REQUIRE( packets[ 3 ].protocol == "UDP" );
        }
    }

    GIVEN( "a BYE of another call" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer() },
            { kAlice, 5060, kBob, 5060, bye( "other" ) },
            { kBob, 4000, kAlice, 49170, rtp( 0, 2, 160, 1 ) },
        } );

        THEN( "the media stays expected" )
        {
            REQUIRE( packets[ 2 ].protocol == "RTP" );
        }
    }

    GIVEN( "a re-INVITE that moves the media to another port" )
    {
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer( 49170 ) },
            { kAlice, 5060, kBob, 5060, offer( 50000 ) },
            { kBob, 4000, kAlice, 49170, rtp( 0, 1, 0, 1 ) },
            { kBob, 4000, kAlice, 50000, rtp( 0, 2, 0, 1 ) },
        } );

        THEN( "only the new port is expected" )
        {
            REQUIRE( packets[ 2 ].protocol == "UDP" );
            REQUIRE( packets[ 3 ].protocol == "RTP" );
        }
    }

    GIVEN( "media idle for longer than kIdleSeconds" )
    {
        const auto idle = static_cast<uint32_t>( MediaExpectations::kIdleSeconds );
        const auto packets = throughExpectations( {
            { kAlice, 5060, kBob, 5060, offer(), 1000 },
            { kBob, 4000, kAlice, 49170, rtp( 0, 1, 0, 1 ), 1000 + idle },
            { kBob, 4000, kAlice, 49170, rtp( 0, 2, 0, 1 ), 1000 + 2 * idle },
            { kBob, 4000, kAlice, 49170, rtp( 0, 3, 0, 1 ), 1001 + 3 * idle },
        } );

        THEN( "it expires, but every packet keeps it fresh" )
        {
            REQUIRE( packets[ 1 ].protocol == "RTP" );
            REQUIRE( packets[ 2 ].protocol == "RTP" );
            REQUIRE( packets[ 3 ].protocol == "UDP" );
        }
    }

    GIVEN( "more calls than expectations are kept" )
    {
        MediaExpectations media( 4 ); // two calls' RTP and RTCP
        std::vector<Udp> packets;
        for ( uint16_t call = 0; call < 3; ++call ) {
            packets.push_back( { kAlice, 5060, kBob, 5060,
                                 offer( static_cast<uint16_t>( 40000 + 10 * call ), "",
                                        "call-" + std::to_string( call ) ),
                                 static_cast<uint32_t>( 1000 + call ) } );
        }
        packets.push_back( { kBob, 4000, kAlice, 40000, rtp( 0, 1, 0, 1 ), 1010 } );
        packets.push_back( { kBob, 4000, kAlice, 40020, rtp( 0, 1, 0, 1 ), 1010 } );
        const auto parsed = throughExpectations( packets, media );

        THEN( "the oldest are forgotten, and no more are kept" )
        {
            REQUIRE( media.size() == 4 );
            REQUIRE( parsed[ 3 ].protocol == "UDP" );
            REQUIRE( parsed[ 4 ].protocol == "RTP" );
        }
    }
}

SCENARIO( "A malformed SIP message or RTP packet is never read beyond the payload", "[sip]" )
{
    const std::vector<std::string> messages{
        invite( sdp( "192.0.2.10", 49170, "a=rtcp:49180 IN IP4 192.0.2.10\r\n" ) ),
        sip( "SIP/2.0 200 OK", "1 INVITE",
             "v=0\r\nc=IN IP6 2001:db8::1\r\nm=audio 4000/2 RTP/AVP 0\r\na=rtcp-mux\r\n" ),
        sip( "BYE sip:bob@example.com SIP/2.0", "2 BYE" ),
        "OPTIONS sip:x SIP/2.0\r\ni: y\r\nCSeq: 1 OPTIONS\r\n l: 5\r\n\r\n",
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each describes one line, SIP once its start line is whole" )
        {
            for ( const auto& message : messages ) {
                const auto bytes = text( message );
                for ( size_t n = 0; n <= bytes.size(); ++n ) {
                    const auto cut = prefix( bytes, n );
                    const std::string s( cut.begin(), cut.end() );
                    for ( const auto& result : { overUdp( s, 15060 ), overTcp( s, 15060 ) } ) {
                        REQUIRE( result.description.find( '\n' ) == std::string::npos );
                        if ( n == bytes.size() ) {
                            REQUIRE( result.label == "SIP" );
                            REQUIRE( result.description.find( "Malformed" ) == std::string::npos );
                        }
                    }
                }
            }
        }
    }

    GIVEN( "segments of several messages with random bytes changed, cut anywhere" )
    {
        std::string all;
        for ( const auto& message : messages ) {
            all += message;
        }
        const auto segment = text( all );

        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 5060 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = segment;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>(
                        random() % 2 ? random() : "\r\n:0 /=;"[ random() % 8 ] );
                }
                const auto cut = prefix( mutated, random() % ( mutated.size() + 1 ) );
                for ( auto transport : { Transport::Udp, Transport::Tcp } ) {
                    const auto result
                        = describePayload( transport, cut.data(), cut.size(), 5060, 5060 );
                    REQUIRE( result.description.find( '\n' ) == std::string::npos );
                    REQUIRE( result.description.size() < 4096 );
                    REQUIRE( result.sipCalls.size() <= kMaxSipMessages );
                    for ( const auto& call : result.sipCalls ) {
                        REQUIRE( call.media.size() <= kMaxSdpMedia );
                        REQUIRE( call.callId.size() <= kMaxSipCallIdBytes );
                    }
                }
            }
        }
    }

    GIVEN( "random RTP and RTCP payloads on an expected endpoint, of every length" )
    {
        THEN( "they are described as one line, or left as they were" )
        {
            std::mt19937 random( 3550 );
            std::vector<Udp> packets{ { kAlice, 5060, kBob, 5060, offer() } };
            for ( int round = 0; round < 2000; ++round ) {
                Bytes payload( random() % 80 );
                for ( auto& b : payload ) {
                    b = static_cast<uint8_t>( random() );
                }
                if ( !payload.empty() && random() % 2 ) {
                    payload[ 0 ] = static_cast<uint8_t>( 0x80 | ( payload[ 0 ] & 0x3F ) );
                }
                if ( payload.size() > 1 && random() % 2 ) {
                    payload[ 1 ] = static_cast<uint8_t>( 200 + random() % 8 );
                }
                packets.push_back( { kBob, 4000, kAlice,
                                     static_cast<uint16_t>( 49170 + random() % 2 ), payload } );
            }
            for ( const auto& pkt : throughExpectations( packets ) ) {
                REQUIRE( pkt.info.find( '\n' ) == std::string::npos );
            }
        }
    }
}
