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
 * @file stream_labels_test.cpp
 * @brief BDD tests for the Stream Labels: a protocol a detector recognised
 *        sticks to the rest of its stream.
 */

#include <catch2/catch.hpp>

#include <cstring>

#include "payload_describer.h"
#include "pcapbuilder.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kPshAck = 0x18;

constexpr uint16_t kClient = 40000;

/// A TCP segment between the client and @p server, back when @p fromServer.
Bytes segment( uint16_t server, bool fromServer, uint8_t flags, uint32_t seq, uint32_t ack,
               const Bytes& payload = {} )
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

/// A UDP datagram from the client to @p server.
Bytes datagram( uint16_t server, const Bytes& payload )
{
    return eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( kClient, server, payload ) ) );
}

/// The packets after the Converter's steps, in order: Stream Tracker, TCP
/// Analysis, the Payload Describer in the stream, Stream Labels.
std::vector<PacketRecord> labelled( const std::vector<Bytes>& frames,
                                    StreamTracker tracker = StreamTracker() )
{
    auto packets = parse( pcapOf( frames ) ).packets;
    REQUIRE( packets.size() == frames.size() );
    StreamLabels labels;
    for ( auto& pkt : packets ) {
        const auto stream = tracker.track( pkt );
        analyseTcp( pkt, stream );
        describeInStream( pkt, stream );
        labels.apply( pkt, stream );
    }
    return packets;
}

/// The description of @p pkt: Info after " | ", empty without one.
std::string descriptionOf( const PacketRecord& pkt )
{
    const auto at = pkt.info.find( kDescriptionSeparator );
    return at == std::string::npos ? std::string()
                                   : pkt.info.substr( at + std::strlen( kDescriptionSeparator ) );
}

const Bytes kGet = text( "GET / HTTP/1.1\r\nHost: x\r\n\r\n" );
const Bytes kBody = text( "{\"hello\": \"world\"}" );

} // namespace

SCENARIO( "A protocol a detector recognised sticks to the stream", "[stream_labels]" )
{
    GIVEN( "an HTTP exchange on a port without a hint" )
    {
        const auto packets = labelled( {
            segment( 3000, false, kPshAck, 1, 1, kGet ),
            segment( 3000, true, kAck, 1, 1 + kGet.size() ),
            segment( 3000, true, kPshAck, 1, 1 + kGet.size(), kBody ),
            segment( 3000, false, kPshAck, 1 + kGet.size(), 1 + kBody.size(),
                     Bytes{ 0x00, 0x01, 0x02, 0x03 } ),
        } );

        THEN( "the request is HTTP by its content" )
        {
            REQUIRE( packets[ 0 ].protocol == "HTTP" );
            REQUIRE( descriptionOf( packets[ 0 ] ) == "GET x/ HTTP/1.1" );
        }
        THEN( "a bare ACK carries the label, without a description" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTP" );
            REQUIRE( packets[ 1 ].info.find( kDescriptionSeparator ) == std::string::npos );
        }
        THEN( "the body is HTTP too, a continuation with its preview" )
        {
            REQUIRE( packets[ 2 ].protocol == "HTTP" );
            REQUIRE( descriptionOf( packets[ 2 ] ) == "Continuation: {\"hello\": \"world\"}" );
        }
        THEN( "a binary segment is a continuation without a preview" )
        {
            REQUIRE( packets[ 3 ].protocol == "HTTP" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "Continuation" );
        }
    }

    GIVEN( "HTTP on port 8080, whose port hint is HTTP-Alt" )
    {
        const auto packets = labelled( {
            segment( 8080, false, kPshAck, 1, 1, kGet ),
            segment( 8080, true, kPshAck, 1, 1 + kGet.size(), kBody ),
            segment( 8080, false, kAck, 1 + kGet.size(), 1 + kBody.size() ),
        } );

        THEN( "the body and the ACK are HTTP, not HTTP-Alt" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTP" );
            REQUIRE( packets[ 2 ].protocol == "HTTP" );
        }
    }

    GIVEN( "a stream on port 443 that starts with a segment no detector recognises" )
    {
        const Bytes clientHello{ 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
        const Bytes encrypted{ 0x8a, 0x13, 0xf0, 0x42, 0x99, 0x00, 0x7e, 0xc1 };
        const auto packets = labelled( {
            segment( 443, false, kPshAck, 1, 1, encrypted ),
            segment( 443, true, kAck, 1, 1 + encrypted.size() ),
            segment( 443, false, kPshAck, 1 + encrypted.size(), 1, clientHello ),
            segment( 443, true, kPshAck, 1, 1 + encrypted.size() + clientHello.size(), encrypted ),
        } );

        THEN( "the port's guess names it, and does not stick" )
        {
            REQUIRE( packets[ 0 ].protocol == "HTTPS" );
            REQUIRE( packets[ 0 ].info.find( "Continuation" ) == std::string::npos );
            REQUIRE( packets[ 1 ].protocol == "HTTPS" );
        }
        THEN( "a later content match overrides it, and sticks" )
        {
            REQUIRE( packets[ 2 ].protocol == "TLS" );
            REQUIRE( packets[ 3 ].protocol == "TLS" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "Continuation" );
        }
    }

    GIVEN( "a stream that recognised a protocol, then another detector's match" )
    {
        const Bytes clientHello{ 0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00 };
        const Bytes encrypted{ 0x8a, 0x13, 0xf0, 0x42, 0x99, 0x00, 0x7e, 0xc1 };
        const auto packets = labelled( {
            segment( 3000, false, kPshAck, 1, 1, kGet ),
            segment( 3000, false, kPshAck, 1 + kGet.size(), 1, clientHello ),
            segment( 3000, false, kPshAck, 1 + kGet.size() + clientHello.size(), 1, encrypted ),
        } );

        THEN( "the matching segment is named by its own content" )
        {
            REQUIRE( packets[ 1 ].protocol == "TLS" );
        }
        THEN( "the stream keeps the label it recognised first" )
        {
            REQUIRE( packets[ 2 ].protocol == "HTTP" );
        }
    }

    GIVEN( "a new connection on the same addresses and ports" )
    {
        const auto packets = labelled( {
            segment( 3000, false, kSyn, 1000, 0 ),
            segment( 3000, false, kPshAck, 1001, 1, kGet ),
            segment( 3000, false, kPshAck, 1001 + kGet.size(), 1, kBody ),
            segment( 3000, false, kSyn, 90000, 0 ),
            segment( 3000, false, kPshAck, 90001, 1, kBody ),
        } );

        THEN( "the first connection's segments are HTTP" )
        {
            REQUIRE( packets[ 2 ].protocol == "HTTP" );
        }
        THEN( "the new SYN and what follows it forget the label" )
        {
            REQUIRE( packets[ 3 ].protocol == "TCP" );
            REQUIRE( packets[ 4 ].protocol == "TCP" );
            REQUIRE( descriptionOf( packets[ 4 ] ) == "{\"hello\": \"world\"}" );
        }
    }

    GIVEN( "a retransmitted SYN" )
    {
        const auto packets = labelled( {
            segment( 3000, false, kSyn, 1000, 0 ),
            segment( 3000, false, kPshAck, 1001, 1, kGet ),
            segment( 3000, false, kSyn, 1000, 0 ),
            segment( 3000, false, kPshAck, 1001 + kGet.size(), 1, kBody ),
        } );

        THEN( "the stream keeps its label" )
        {
            REQUIRE( packets[ 2 ].protocol == "HTTP" );
            REQUIRE( packets[ 3 ].protocol == "HTTP" );
        }
    }

    GIVEN( "a UDP stream that carried an NMEA sentence" )
    {
        const auto packets = labelled( {
            datagram( 10110, text( "$GPGGA,1,2,3*47\r\n" ) ),
            datagram( 10110, text( "garbled" ) ),
        } );

        THEN( "its later datagrams are NMEA continuations" )
        {
            REQUIRE( packets[ 1 ].protocol == "NMEA" );
            REQUIRE( descriptionOf( packets[ 1 ] ) == "Continuation: garbled" );
        }
    }

    GIVEN( "a stream past the stream cap" )
    {
        const auto packets = labelled(
            {
                datagram( 9, text( "first" ) ),
                segment( 3000, false, kPshAck, 1, 1, kGet ),
                segment( 3000, false, kPshAck, 1 + kGet.size(), 1, kBody ),
            },
            StreamTracker( 1 ) );

        THEN( "it has no state, and each segment is named on its own" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTP" );
            REQUIRE( packets[ 2 ].protocol == "TCP" );
        }
    }
}

SCENARIO( "What the Payload Describer recognises in a stream sticks too", "[stream_labels]" )
{
    GIVEN( "an HTTP/2 connection on a port without a hint: the preface, a frame, then a "
           "segment in the middle of a frame" )
    {
        const auto preface = text( "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" );
        // A SETTINGS frame without settings: length 0, type 4, stream 0.
        const Bytes settings{ 0, 0, 0, 4, 0, 0, 0, 0, 0 };
        const auto packets = labelled( {
            segment( 3000, false, kPshAck, 1, 1, preface ),
            segment( 3000, true, kPshAck, 1, 1 + preface.size(), settings ),
            segment( 3000, true, kPshAck, 1 + settings.size(), 1 + preface.size(), kBody ),
        } );

        THEN( "the frame, which only its stream makes HTTP2, is described as such" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTP2" );
            REQUIRE( packets[ 1 ].protocolRecognised );
            REQUIRE( descriptionOf( packets[ 1 ] ) == "SETTINGS[0]" );
        }
        THEN( "the segment in the middle of a frame is an HTTP2 continuation" )
        {
            REQUIRE( packets[ 2 ].protocol == "HTTP2" );
            REQUIRE( descriptionOf( packets[ 2 ] ).rfind( "Continuation", 0 ) == 0 );
        }
    }
}
