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
 * @file mqtt_test.cpp
 * @brief BDD tests for the MQTT descriptions, through the Payload Describer:
 *        every control packet type of MQTT 3.1.1 and 5.0, several packets
 *        in a segment, packets cut by the segment or malformed, a
 *        connection on another port found by its CONNECT, and packets
 *        mangled and cut anywhere.
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

constexpr uint16_t kClientPort = 50883;
constexpr uint16_t kMqttPort = 1883;

const std::string kEllipsis = "\xe2\x80\xa6";

enum : uint8_t {
    kConnect = 1,
    kConnAck,
    kPublish,
    kPubAck,
    kPubRec,
    kPubRel,
    kPubComp,
    kSubscribe,
    kSubAck,
    kUnsubscribe,
    kUnsubAck,
    kPingReq,
    kPingResp,
    kDisconnect,
    kAuth,
};

/// A variable byte integer (MQTT 5.0, 1.5.5).
Bytes varint( size_t value )
{
    Bytes out;
    do {
        auto byte = static_cast<uint8_t>( value & 0x7F );
        value >>= 7;
        out.push_back( value > 0 ? byte | 0x80 : byte );
    } while ( value > 0 );
    return out;
}

Bytes u16( size_t v )
{
    return { static_cast<uint8_t>( v >> 8 ), static_cast<uint8_t>( v ) };
}

/// A UTF-8 string behind its length.
Bytes str( const std::string& s )
{
    return u16( s.size() ) + Bytes( s.begin(), s.end() );
}

/// MQTT 5.0 properties behind their length.
Bytes props( const Bytes& properties = {} )
{
    return varint( properties.size() ) + properties;
}

/// A control packet: its type and flags, the Remaining Length, the body.
Bytes packet( uint8_t type, const Bytes& body, uint8_t flags = 0 )
{
    return Bytes{ static_cast<uint8_t>( type << 4 | flags ) } + varint( body.size() ) + body;
}

Bytes connect311( const std::string& clientId, uint8_t flags = 0x02, uint16_t keepAlive = 60 )
{
    return packet( kConnect,
                   str( "MQTT" ) + Bytes{ 4, flags } + u16( keepAlive ) + str( clientId ) );
}

Bytes publish( const std::string& topic, const std::string& payload, uint8_t qos = 0,
               uint16_t id = 0, const Bytes& properties = {}, bool v5 = false )
{
    Bytes body = str( topic );
    if ( qos > 0 ) {
        body = body + u16( id );
    }
    if ( v5 ) {
        body = body + props( properties );
    }
    return packet( kPublish, body + Bytes( payload.begin(), payload.end() ),
                   static_cast<uint8_t>( qos << 1 ) );
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

PayloadDescription toBroker( const Bytes& payload, uint16_t port = kMqttPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort, port );
}

PayloadDescription fromBroker( const Bytes& payload, uint16_t port = kMqttPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), port, kClientPort );
}

std::string described( const Bytes& payload )
{
    const auto result = toBroker( payload );
    REQUIRE( result.label == "MQTT" );
    return result.description;
}

/// A segment between client and broker.
struct Segment {
    bool fromClient;
    Bytes payload;
};

/// Parse @p segments, between the client and @p port, as a capture and
/// describe each packet in its stream, as the Converter does.
std::vector<PacketRecord> describedInStreams( const std::vector<Segment>& segments, uint16_t port )
{
    std::vector<Bytes> frames;
    for ( const auto& s : segments ) {
        Ipv4Options o;
        if ( !s.fromClient ) {
            std::swap( o.src, o.dst );
        }
        frames.push_back(
            eth( EthertypeIpv4, ipv4( IpProtoTcp,
                                      s.fromClient ? tcp( kClientPort, port, s.payload )
                                                   : tcp( port, kClientPort, s.payload ),
                                      o ) ) );
    }
    auto packets = parse( pcapOf( frames ) ).packets;
    StreamTracker tracker;
    for ( auto& pkt : packets ) {
        describeInStream( pkt, tracker.track( pkt ) );
    }
    return packets;
}

std::string descriptionOf( const PacketRecord& pkt )
{
    const auto at = pkt.info.find( kDescriptionSeparator );
    return at == std::string::npos
               ? std::string()
               : pkt.info.substr( at + std::string( kDescriptionSeparator ).size() );
}

} // namespace

SCENARIO( "MQTT 3.1.1 control packets are described as Wireshark names them", "[mqtt]" )
{
    GIVEN( "a CONNECT with a clean session and a user name" )
    {
        const auto connect
            = packet( kConnect, str( "MQTT" ) + Bytes{ 4, 0xC2 } + u16( 30 ) + str( "sensor-1" )
                                    + str( "bob" ) + str( "secret" ) );

        THEN( "version, keep alive, session, client and user are shown, not the password" )
        {
            const auto text = described( connect );
            REQUIRE( text
                     == "Connect Command (MQTT 3.1.1, Keep Alive 30, Clean Session, Client ID "
                        "\"sensor-1\", User \"bob\")" );
        }
    }

    GIVEN( "an MQTT 3.1 CONNECT with a will" )
    {
        const auto connect
            = packet( kConnect, str( "MQIsdp" ) + Bytes{ 3, 0x0C } + u16( 10 ) + str( "old" )
                                    + str( "will/topic" ) + str( "gone" ) );

        THEN( "its version is 3.1, the will skipped" )
        {
            REQUIRE( described( connect )
                     == "Connect Command (MQTT 3.1, Keep Alive 10, Client ID \"old\")" );
        }
    }

    GIVEN( "CONNACKs" )
    {
        THEN( "the return code is named" )
        {
            REQUIRE( described( packet( kConnAck, { 0, 0 } ) )
                     == "Connect Ack (Connection Accepted)" );
            REQUIRE( described( packet( kConnAck, { 1, 5 } ) )
                     == "Connect Ack (Not Authorized, Session Present)" );
            REQUIRE( described( packet( kConnAck, { 0, 9 } ) ) == "Connect Ack (Unknown (0x09))" );
        }
    }

    GIVEN( "PUBLISH packets of each QoS" )
    {
        THEN( "topic, QoS, id and a payload preview are shown" )
        {
            REQUIRE( described( publish( "sensors/temp", "21.5" ) )
                     == "Publish Message [sensors/temp] \"21.5\"" );
            REQUIRE( described( publish( "a/b", "x", 1, 7 ) )
                     == "Publish Message (QoS 1, id=7) [a/b] \"x\"" );
            REQUIRE( described( publish( "a/b", "", 2, 8 ) )
                     == "Publish Message (QoS 2, id=8) [a/b]" );
        }
    }

    GIVEN( "a retained duplicate PUBLISH with a long binary payload" )
    {
        auto pub = publish( "t", std::string( 40, '\x01' ), 1, 1 );
        pub[ 0 ] |= 0x09;

        THEN( "DUP and Retain are shown, the payload escaped and cut" )
        {
            const auto text = described( pub );
            REQUIRE( text.rfind( "Publish Message (QoS 1, id=1, DUP, Retain) [t] \"\\x01", 0 )
                     == 0 );
            REQUIRE( text.size() > kEllipsis.size() );
            REQUIRE( text.substr( text.size() - kEllipsis.size() - 1 ) == "\"" + kEllipsis );
        }
    }

    GIVEN( "the acknowledgements of a PUBLISH" )
    {
        THEN( "each is named with its id" )
        {
            REQUIRE( described( packet( kPubAck, u16( 7 ) ) ) == "Publish Ack (id=7)" );
            REQUIRE( described( packet( kPubRec, u16( 8 ) ) ) == "Publish Received (id=8)" );
            REQUIRE( described( packet( kPubRel, u16( 8 ), 0x2 ) ) == "Publish Release (id=8)" );
            REQUIRE( described( packet( kPubComp, u16( 8 ) ) ) == "Publish Complete (id=8)" );
        }
    }

    GIVEN( "a SUBSCRIBE, an UNSUBSCRIBE and their acknowledgements" )
    {
        THEN( "the topic filters are listed" )
        {
            REQUIRE( described( packet( kSubscribe,
                                        u16( 1 ) + str( "sensors/+/temp" ) + Bytes{ 1 }
                                            + str( "alerts/#" ) + Bytes{ 0 },
                                        0x2 ) )
                     == "Subscribe Request (id=1) [sensors/+/temp, alerts/#]" );
            REQUIRE( described( packet( kSubAck, u16( 1 ) + Bytes{ 1, 0 } ) )
                     == "Subscribe Ack (id=1)" );
            REQUIRE( described( packet( kUnsubscribe, u16( 2 ) + str( "alerts/#" ), 0x2 ) )
                     == "Unsubscribe Request (id=2) [alerts/#]" );
            REQUIRE( described( packet( kUnsubAck, u16( 2 ) ) ) == "Unsubscribe Ack (id=2)" );
        }
    }

    GIVEN( "a SUBSCRIBE with more filters than are listed" )
    {
        Bytes body = u16( 3 );
        for ( int i = 0; i < 6; ++i ) {
            body = body + str( "t/" + std::to_string( i ) ) + Bytes{ 0 };
        }

        THEN( "the first four are, then an ellipsis" )
        {
            REQUIRE( described( packet( kSubscribe, body, 0x2 ) )
                     == "Subscribe Request (id=3) [t/0, t/1, t/2, t/3, " + kEllipsis + "]" );
        }
    }

    GIVEN( "pings and a disconnect" )
    {
        THEN( "they are named" )
        {
            REQUIRE( described( packet( kPingReq, {} ) ) == "Ping Request" );
            REQUIRE( described( packet( kPingResp, {} ) ) == "Ping Response" );
            REQUIRE( described( packet( kDisconnect, {} ) ) == "Disconnect Req" );
        }
    }
}

SCENARIO( "MQTT 5.0 packets are described with their reason codes, properties skipped", "[mqtt]" )
{
    GIVEN( "a CONNECT with properties, a will with properties and a user name" )
    {
        const Bytes sessionExpiry{ 0x11, 0, 0, 0x0E, 0x10 };
        const Bytes userProperty = Bytes{ 0x26 } + str( "k" ) + str( "v" );
        const auto connect = packet( kConnect, str( "MQTT" ) + Bytes{ 5, 0x86 } + u16( 60 )
                                                   + props( sessionExpiry + userProperty )
                                                   + str( "dev" ) + props( { 0x18, 0, 0, 0, 5 } )
                                                   + str( "w" ) + str( "x" ) + str( "alice" ) );

        THEN( "it is MQTT 5.0 with a clean start" )
        {
            REQUIRE( described( connect )
                     == "Connect Command (MQTT 5.0, Keep Alive 60, Clean Start, Client ID "
                        "\"dev\", User \"alice\")" );
        }
    }

    GIVEN( "CONNACKs with properties" )
    {
        THEN( "the reason code is named, and a reason string shown" )
        {
            REQUIRE( described( packet( kConnAck, Bytes{ 0, 0 } + props( { 0x21, 0, 10 } ) ) )
                     == "Connect Ack (Success)" );
            REQUIRE( described( packet( kConnAck,
                                        Bytes{ 0, 0x87 } + props( Bytes{ 0x1F } + str( "no" ) ) ) )
                     == "Connect Ack (Not authorized, \"no\")" );
        }
    }

    GIVEN( "a PUBLISH with properties after a CONNECT in the same segment" )
    {
        const auto segment
            = packet( kConnect, str( "MQTT" ) + Bytes{ 5, 0 } + u16( 0 ) + props() + str( "c" ) )
              + publish( "a", std::string( "\0z", 2 ), 1, 4, { 0x01, 0x00 }, true );

        THEN( "the properties are skipped and the payload shown" )
        {
            REQUIRE(
                described( segment )
                == "Connect Command (MQTT 5.0, Keep Alive 0, Client ID \"c\"), Publish Message "
                   "(QoS 1, id=4) [a] \"\\x00z\"" );
        }
    }

    GIVEN( "a PUBLISH whose bytes behind the topic parse as properties, alone" )
    {
        const auto pub = publish( "a", "hello", 0, 0, Bytes{ 0x23, 0, 1 }, true );

        THEN( "they are taken for properties" )
        {
            REQUIRE( described( pub ) == "Publish Message [a] \"hello\"" );
        }
    }

    GIVEN( "acknowledgements with reason codes" )
    {
        THEN( "a code other than success is named, with its reason string" )
        {
            REQUIRE( described( packet( kPubAck, u16( 5 ) + Bytes{ 0x10 } ) )
                     == "Publish Ack (id=5, No matching subscribers)" );
            REQUIRE( described( packet( kPubRec, u16( 5 ) + Bytes{ 0x97 }
                                                     + props( Bytes{ 0x1F } + str( "slow" ) ) ) )
                     == "Publish Received (id=5, Quota exceeded, \"slow\")" );
            REQUIRE( described( packet( kPubComp, u16( 5 ) + Bytes{ 0 } + props() ) )
                     == "Publish Complete (id=5)" );
            REQUIRE( described( packet( kUnsubAck, u16( 6 ) + props() + Bytes{ 0x11 } ) )
                     == "Unsubscribe Ack (id=6)" );
        }
    }

    GIVEN( "a SUBSCRIBE and UNSUBSCRIBE with properties" )
    {
        THEN( "the filters behind them are listed" )
        {
            REQUIRE( described( packet(
                         kSubscribe,
                         u16( 9 ) + props( { 0x0B, 0x05 } ) + str( "x/#" ) + Bytes{ 0x2E }, 0x2 ) )
                     == "Subscribe Request (id=9) [x/#]" );
            REQUIRE( described( packet( kUnsubscribe, u16( 9 ) + props() + str( "x/#" ), 0x2 ) )
                     == "Unsubscribe Request (id=9) [x/#]" );
        }
    }

    GIVEN( "DISCONNECT and AUTH with reason codes" )
    {
        THEN( "the reason is named" )
        {
            REQUIRE( described( packet( kDisconnect,
                                        Bytes{ 0x8B } + props( Bytes{ 0x1F } + str( "bye" ) ) ) )
                     == "Disconnect Req (Server shutting down, \"bye\")" );
            REQUIRE( described( packet( kDisconnect, Bytes{ 0x00 } ) ) == "Disconnect Req" );
            REQUIRE( described(
                         packet( kAuth, Bytes{ 0x18 } + props( Bytes{ 0x15 } + str( "SCRAM" ) ) ) )
                     == "Authentication Exchange (Continue authentication)" );
            REQUIRE( described( packet( kAuth, {} ) ) == "Authentication Exchange" );
        }
    }
}

SCENARIO( "Several MQTT packets in a segment are all named", "[mqtt]" )
{
    GIVEN( "two PUBLISH packets in one segment" )
    {
        THEN( "both are named, in order" )
        {
            REQUIRE( described( publish( "a", "1" ) + publish( "b", "2" ) )
                     == "Publish Message [a] \"1\", Publish Message [b] \"2\"" );
        }
    }

    GIVEN( "six pings in one segment" )
    {
        Bytes six;
        for ( int i = 0; i < 6; ++i ) {
            six = six + packet( kPingReq, {} );
        }

        THEN( "four are named, then an ellipsis" )
        {
            REQUIRE( described( six )
                     == "Ping Request, Ping Request, Ping Request, Ping Request, " + kEllipsis );
        }
    }

    GIVEN( "a PUBACK followed by bytes that are no packet" )
    {
        THEN( "the rest is malformed" )
        {
            REQUIRE( described( packet( kPubAck, u16( 1 ) ) + Bytes{ 0x00, 0x01 } )
                     == "Publish Ack (id=1), [Malformed Packet]" );
        }
    }

    GIVEN( "a PING and a PUBACK too long for MQTT 3.1.1, after an MQTT 3.1.1 CONNECT" )
    {
        THEN( "the PUBACK is malformed, the packet after it named" )
        {
            REQUIRE( described( connect311( "c" ) + packet( kPubAck, u16( 1 ) + Bytes{ 0x10 } )
                                + packet( kPingReq, {} ) )
                     == "Connect Command (MQTT 3.1.1, Keep Alive 60, Clean Session, Client ID "
                        "\"c\"), Publish Ack [Malformed Packet], Ping Request" );
        }
    }
}

SCENARIO( "An MQTT packet cut by its segment is described as far as it goes", "[mqtt]" )
{
    GIVEN( "a PUBLISH whose payload goes on in the next segment" )
    {
        const auto pub = publish( "sensors/temp", std::string( 100, 'x' ), 1, 3 );

        THEN( "the first segment describes it, cut" )
        {
            REQUIRE( described( prefix( pub, 30 ) )
                     == "Publish Message (QoS 1, id=3) [sensors/temp] \"xxxxxxxxxxxx\""
                            + kEllipsis );
        }

        THEN( "the second is no MQTT packet: MQTT by its port alone" )
        {
            const Bytes rest( pub.begin() + 30, pub.end() );
            const auto result = toBroker( rest );
            REQUIRE( result.label == "MQTT" );
            REQUIRE( result.guessed );
        }
    }

    GIVEN( "a PUBLISH cut within its topic, after a ping" )
    {
        const auto segment = packet( kPingReq, {} ) + prefix( publish( "sensors/temp", "1" ), 6 );

        THEN( "it is named and marked as going on" )
        {
            REQUIRE( described( segment ) == "Ping Request, Publish Message " + kEllipsis );
        }
    }

    GIVEN( "a PUBLISH cut in its two-byte Remaining Length" )
    {
        const auto pub = publish( "t", std::string( 200, 'x' ) );

        THEN( "a lone first byte is no packet, but behind another it is named" )
        {
            REQUIRE( toBroker( prefix( pub, 2 ) ).guessed );
            REQUIRE( described( packet( kPingResp, {} ) + prefix( pub, 2 ) )
                     == "Ping Response, Publish Message " + kEllipsis );
        }
    }

    GIVEN( "a SUBSCRIBE cut within its second filter" )
    {
        const auto sub = packet(
            kSubscribe, u16( 1 ) + str( "a/b" ) + Bytes{ 0 } + str( "c/d" ) + Bytes{ 0 }, 0x2 );

        THEN( "the first filter is listed" )
        {
            REQUIRE( described( prefix( sub, sub.size() - 3 ) )
                     == "Subscribe Request (id=1) [a/b] " + kEllipsis );
        }
    }
}

SCENARIO( "Only what has the shape of MQTT is taken for it", "[mqtt]" )
{
    GIVEN( "a CONNECT to a port other than MQTT's" )
    {
        const auto result = toBroker( connect311( "probe" ), 18830 );

        THEN( "it is recognised by its content" )
        {
            REQUIRE( result.label == "MQTT" );
            REQUIRE_FALSE( result.guessed );
            REQUIRE( result.streamCue == StreamCue::MqttConnect );
        }
    }

    GIVEN( "other MQTT packets on a port other than MQTT's" )
    {
        THEN( "they are not taken for MQTT" )
        {
            REQUIRE( toBroker( publish( "a", "b" ), 18830 ).label != "MQTT" );
            REQUIRE( toBroker( packet( kPingReq, {} ), 18830 ).label != "MQTT" );
        }
    }

    GIVEN( "text on port 1883" )
    {
        const std::string line = "0123 hello world";
        const auto result = toBroker( Bytes( line.begin(), line.end() ) );

        THEN( "it is MQTT by the port alone, with a preview" )
        {
            REQUIRE( result.label == "MQTT" );
            REQUIRE( result.guessed );
            REQUIRE( result.preview );
        }
    }

    GIVEN( "a packet of the reserved type 0, or with wrong flags" )
    {
        THEN( "it is no MQTT packet" )
        {
            REQUIRE( toBroker( Bytes{ 0x00, 0x00 } ).guessed );
            REQUIRE( toBroker( Bytes{ 0x62 + 1, 0x02, 0, 1 } ).guessed );  // PUBREL flags 3
            REQUIRE( toBroker( Bytes{ 0x36, 0x03, 0, 1, 'a' } ).guessed ); // QoS 3
            REQUIRE( toBroker( Bytes{ 0xC1, 0x00 } ).guessed );            // PINGREQ flags 1
        }
    }

    GIVEN( "a Remaining Length in five bytes, or in more bytes than it needs" )
    {
        THEN( "it is no MQTT packet" )
        {
            REQUIRE( toBroker( Bytes{ 0x30, 0x80, 0x80, 0x80, 0x80, 0x01 } ).guessed );
            REQUIRE( toBroker( Bytes{ 0xC0, 0x80, 0x00 } ).guessed );
        }
        THEN( "nor is it framed as one for the TCP Reassembly" )
        {
            for ( const auto& bytes : { Bytes{ 0xC0, 0x80, 0x00 }, Bytes{ 0x30, 0x81, 0x00, 0x00 },
                                        Bytes{ 0x30, 0x80, 0x80, 0x80, 0x80, 0x01 } } ) {
                const auto extent
                    = tcpMessageExtent( bytes.data(), bytes.size(), 50000, kMqttPort );
                REQUIRE( ( extent.label == nullptr || std::string( extent.label ) != "MQTT" ) );
            }
            const auto minimal = Bytes{ 0xC0, 0x00 };
            const auto extent
                = tcpMessageExtent( minimal.data(), minimal.size(), 50000, kMqttPort );
            REQUIRE( extent.complete() );
            REQUIRE( std::string( extent.label ) == "MQTT" );
        }
    }

    GIVEN( "a lone malformed packet that fills the segment" )
    {
        THEN( "it is named as malformed" )
        {
            REQUIRE( described( packet( kConnect, str( "HTTP" ) + Bytes{ 4, 0, 0, 0 } ) )
                     == "Connect Command [Malformed Packet]" );
            REQUIRE( described( packet( kPingReq, Bytes{ 0 } ) )
                     == "Ping Request [Malformed Packet]" );
            REQUIRE( described( packet( kPublish, str( "a/#" ) ) )
                     == "Publish Message [Malformed Packet]" );
        }
    }

    GIVEN( "a malformed packet followed by more bytes" )
    {
        THEN( "the segment is taken for the middle of a packet" )
        {
            REQUIRE( toBroker( packet( kPingReq, Bytes{ 0 } ) + Bytes{ 1, 2 } ).guessed );
        }
    }

    GIVEN( "MQTT over TLS on port 8883" )
    {
        const Bytes clientHello{ 0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00 };

        THEN( "it stays TLS" )
        {
            REQUIRE( toBroker( clientHello, 8883 ).label == "TLS" );
        }
    }
}

SCENARIO( "A connection that began with a CONNECT on another port is read as MQTT", "[mqtt]" )
{
    GIVEN( "a CONNECT to port 18830, then its CONNACK, a PUBLISH and a ping" )
    {
        const auto packets = describedInStreams(
            {
                { true, connect311( "probe" ) },
                { false, packet( kConnAck, { 0, 0 } ) },
                { true, publish( "a/b", "on", 1, 1 ) },
                { true, packet( kPingReq, {} ) },
            },
            18830 );

        THEN( "every packet is labelled MQTT and described" )
        {
            REQUIRE( packets.size() == 4 );
            for ( const auto& pkt : packets ) {
                REQUIRE( pkt.protocol == "MQTT" );
                REQUIRE( pkt.protocolRecognised );
            }
            REQUIRE( descriptionOf( packets[ 1 ] ) == "Connect Ack (Connection Accepted)" );
            REQUIRE( descriptionOf( packets[ 2 ] )
                     == "Publish Message (QoS 1, id=1) [a/b] \"on\"" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "Ping Request" );
        }
    }

    GIVEN( "a PUBLISH longer than the bytes kept of a packet" )
    {
        const auto packets = describedInStreams(
            { { true, connect311( "probe" ) }, { true, publish( "t", std::string( 100, 'y' ) ) } },
            18830 );

        THEN( "it is described as far as those go" )
        {
            REQUIRE( descriptionOf( packets[ 1 ] )
                     == "Publish Message [t] \"" + std::string( 32, 'y' ) + "\"" + kEllipsis );
        }
    }

    GIVEN( "the same packets without the CONNECT" )
    {
        const auto packets = describedInStreams(
            { { false, packet( kConnAck, { 0, 0 } ) }, { true, packet( kPingReq, {} ) } }, 18830 );

        THEN( "none is taken for MQTT" )
        {
            for ( const auto& pkt : packets ) {
                REQUIRE( pkt.protocol != "MQTT" );
            }
        }
    }
}

SCENARIO( "A malformed MQTT packet is never read beyond the payload", "[mqtt]" )
{
    const Bytes v5Connect = packet(
        kConnect, str( "MQTT" ) + Bytes{ 5, 0xEE } + u16( 60 )
                      + props( Bytes{ 0x11, 0, 0, 0, 1 } + Bytes{ 0x26 } + str( "k" ) + str( "v" ) )
                      + str( "id" ) + props( { 0x01, 1 } ) + str( "w" ) + str( "x" ) + str( "u" )
                      + str( "p" ) );
    const std::vector<Bytes> messages{
        connect311( "client" ),
        v5Connect,
        packet( kConnAck, Bytes{ 0, 0x87 } + props( Bytes{ 0x1F } + str( "no" ) ) ),
        publish( "sensors/temp", "21.5", 1, 3 ),
        publish( "a", "payload", 2, 9, Bytes{ 0x23, 0, 1, 0x26 } + str( "k" ) + str( "v" ), true ),
        packet( kPubAck, u16( 5 ) + Bytes{ 0x97 } + props( Bytes{ 0x1F } + str( "slow" ) ) ),
        packet( kPubRel, u16( 5 ), 0x2 ),
        packet( kSubscribe, u16( 1 ) + str( "a/+" ) + Bytes{ 1 } + str( "b/#" ) + Bytes{ 2 }, 0x2 ),
        packet( kSubscribe, u16( 1 ) + props( { 0x0B, 0x81, 0x01 } ) + str( "a" ) + Bytes{ 0x2D },
                0x2 ),
        packet( kSubAck, u16( 1 ) + Bytes{ 1, 2 } ),
        packet( kUnsubscribe, u16( 2 ) + str( "a/+" ), 0x2 ),
        packet( kUnsubAck, u16( 2 ) + props() + Bytes{ 0 } ),
        packet( kPingReq, {} ),
        packet( kDisconnect, Bytes{ 0x8B } + props( Bytes{ 0x1F } + str( "bye" ) ) ),
        packet( kAuth, Bytes{ 0x18 } + props( Bytes{ 0x15 } + str( "SCRAM" ) ) ),
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each describes one line, MQTT once the first byte is there" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto cut = prefix( message, n );
                    for ( const auto& result : { toBroker( cut ), fromBroker( cut ) } ) {
                        REQUIRE( result.description.find( '\n' ) == std::string::npos );
                        if ( n == message.size() ) {
                            REQUIRE_FALSE( result.guessed );
                            REQUIRE( result.description.find( "Malformed" ) == std::string::npos );
                        }
                    }
                }
            }
        }
    }

    GIVEN( "every single byte of each message set to every value" )
    {
        THEN( "the description is one line" )
        {
            for ( const auto& message : messages ) {
                for ( size_t i = 0; i < message.size(); ++i ) {
                    for ( int value : { 0x00, 0x01, 0x02, 0x1F, 0x26, 0x7F, 0x80, 0xC0, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        const auto result = toBroker( mutated );
                        REQUIRE( result.label == "MQTT" );
                        REQUIRE( result.description.find( '\n' ) == std::string::npos );
                    }
                }
            }
        }
    }

    GIVEN( "segments of several messages with random bytes changed, cut anywhere" )
    {
        Bytes segment;
        for ( const auto& message : messages ) {
            segment = segment + message;
        }

        THEN( "the describer reads them without fault and within the length policy" )
        {
            std::mt19937 random( 1883 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = segment;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto start = random() % mutated.size();
                const Bytes from( mutated.begin() + static_cast<std::ptrdiff_t>( start ),
                                  mutated.end() );
                const auto cut = prefix( from, random() % ( from.size() + 1 ) );
                for ( const auto& result : { toBroker( cut ), toBroker( cut, 18830 ) } ) {
                    REQUIRE( result.description.find( '\n' ) == std::string::npos );
                    REQUIRE( result.description.size() < 4096 );
                }
            }
        }
    }
}
