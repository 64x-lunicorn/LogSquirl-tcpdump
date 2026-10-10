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
 * @file quic_test.cpp
 * @brief BDD tests for the QUIC descriptions: long headers through the
 *        Payload Describer alone, short headers through their stream, and
 *        headers cut or lying about their lengths.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pipeline_harness.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kClientPort = 50443;
constexpr uint16_t kServerPort = 443;

constexpr uint32_t kV1 = 0x00000001;
constexpr uint32_t kV2 = 0x6B3343CF;
constexpr uint32_t kDraft29 = 0xFF00001D;

const Bytes kClientDcid = { 0x83, 0x94, 0xC8, 0xF0, 0x3E, 0x51, 0x57, 0x08 };
const Bytes kClientScid = { 0x0A, 0x0B, 0x0C, 0x0D };
const Bytes kServerScid = Bytes( 8, 0x5E );

Bytes be32( uint32_t v )
{
    Bytes b;
    putBE32( b, v );
    return b;
}

/// @p body behind its 8-bit length.
Bytes vector8( const Bytes& body )
{
    return Bytes{ static_cast<uint8_t>( body.size() ) } + body;
}

/// A 2-byte QUIC variable-length integer.
Bytes varint2( size_t v )
{
    return { static_cast<uint8_t>( 0x40 | ( v >> 8 ) ), static_cast<uint8_t>( v ) };
}

/// A long header packet: @p type is the 2-bit packet type of @p version,
/// @p payload what follows the length (packet number and frames).
Bytes longPacket( uint8_t type, uint32_t version, const Bytes& dcid, const Bytes& scid,
                  size_t payload, bool withToken )
{
    const auto firstByte = static_cast<uint8_t>( 0xC0 | ( type << 4 ) | 0x03 );
    return Bytes{ firstByte } + be32( version ) + vector8( dcid ) + vector8( scid )
           + ( withToken ? Bytes{ 0x00 } : Bytes{} ) + varint2( payload ) + Bytes( payload, 0xA5 );
}

/// A v1 or draft Initial; a v2 Initial has type 1.
Bytes initial( uint32_t version, const Bytes& dcid, const Bytes& scid, size_t payload = 1162 )
{
    return longPacket( version == kV2 ? 1 : 0, version, dcid, scid, payload, true );
}

Bytes handshakePacket( const Bytes& dcid, const Bytes& scid )
{
    return longPacket( 2, kV1, dcid, scid, 40, false );
}

/// A short header packet to @p dcid with @p payload bytes behind it.
Bytes shortPacket( const Bytes& dcid, size_t payload = 40 )
{
    return Bytes{ 0x43 } + dcid + Bytes( payload, 0x5A );
}

Bytes versionNegotiation( const std::vector<uint32_t>& versions )
{
    Bytes b = Bytes{ 0x80 | 0x2A } + be32( 0 ) + vector8( kClientScid ) + vector8( kClientDcid );
    for ( const auto version : versions ) {
        b = b + be32( version );
    }
    return b;
}

PayloadDescription toServer( const Bytes& payload )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), kClientPort,
                            kServerPort );
}

PayloadDescription fromServer( const Bytes& payload )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), kServerPort,
                            kClientPort );
}

/// The first @p n bytes of @p bytes, in a buffer of exactly that size.
Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

/// A datagram between client and server, as one Ethernet frame.
struct Datagram {
    bool fromClient;
    Bytes payload;
    /// The client's port, kClientPort unless another client sends it.
    uint16_t clientPort = kClientPort;
};

/// @p datagrams as a capture, run through the Packet Pipeline as a
/// conversion runs them.
std::vector<PacketRecord> describedInStreams( const std::vector<Datagram>& datagrams )
{
    std::vector<Bytes> frames;
    for ( const auto& d : datagrams ) {
        Ipv4Options o;
        if ( !d.fromClient ) {
            std::swap( o.src, o.dst );
        }
        frames.push_back(
            eth( EthertypeIpv4, ipv4( IpProtoUdp,
                                      d.fromClient ? udp( d.clientPort, kServerPort, d.payload )
                                                   : udp( kServerPort, d.clientPort, d.payload ),
                                      o ) ) );
    }
    std::vector<PacketRecord> packets;
    for ( const auto& p : piped( pcapOf( frames ) ) ) {
        packets.push_back( p.pkt );
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

SCENARIO( "A QUIC long header names its packet type, version and connection IDs", "[quic]" )
{
    GIVEN( "a QUIC v1 Initial from the client" )
    {
        const auto described = toServer( initial( kV1, kClientDcid, kClientScid ) );

        THEN( "it is QUIC, with the type, the version and both connection IDs" )
        {
            REQUIRE( described.label == "QUIC" );
            REQUIRE( described.description
                     == "Initial, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
        }
        THEN( "it cues its stream that a QUIC connection began, by type, not by label" )
        {
            REQUIRE( described.streamCue == StreamCue::QuicLongHeader );
        }
    }

    GIVEN( "a QUIC v2 Initial, whose packet types are numbered differently" )
    {
        const auto described = toServer( initial( kV2, kClientDcid, kClientScid ) );

        THEN( "it is still an Initial" )
        {
            REQUIRE( described.label == "QUIC" );
            REQUIRE( described.description
                     == "Initial, Version 2, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
        }
    }

    GIVEN( "a QUIC v2 packet of type 0" )
    {
        const auto retry = Bytes{ 0xC0 } + be32( kV2 ) + vector8( kClientScid )
                           + vector8( kServerScid )
                           + Bytes( 16 + 20, 0x77 ); // token, integrity tag

        THEN( "it is a Retry" )
        {
            REQUIRE( fromServer( retry ).description
                     == "Retry, Version 2, DCID=0a0b0c0d, SCID=5e5e5e5e5e5e5e5e" );
        }
    }

    GIVEN( "an Initial of draft-29" )
    {
        const auto described = toServer( initial( kDraft29, kClientDcid, {} ) );

        THEN( "the draft is named, and the empty source connection ID left out" )
        {
            REQUIRE( described.label == "QUIC" );
            REQUIRE( described.description == "Initial, Version draft-29, DCID=8394c8f03e515708" );
        }
    }

    GIVEN( "a 0-RTT packet" )
    {
        THEN( "its type is named" )
        {
            REQUIRE(
                toServer( longPacket( 1, kV1, kClientDcid, kClientScid, 30, false ) ).description
                == "0-RTT, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
        }
    }

    GIVEN( "a server's datagram of coalesced packets" )
    {
        const auto datagram = initial( kV1, kClientScid, kServerScid, 100 )
                              + handshakePacket( kClientScid, kServerScid )
                              + shortPacket( kClientScid );

        THEN( "each packet is named in order, the header fields of the first once" )
        {
            REQUIRE( fromServer( datagram ).description
                     == "Initial, Handshake, Protected Payload, Version 1, DCID=0a0b0c0d, "
                        "SCID=5e5e5e5e5e5e5e5e" );
        }
    }

    GIVEN( "an Initial padded with zeros after its packet" )
    {
        const auto datagram = initial( kV1, kClientDcid, kClientScid, 100 ) + Bytes( 50, 0 );

        THEN( "the padding is no packet" )
        {
            REQUIRE( toServer( datagram ).description
                     == "Initial, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
        }
    }

    GIVEN( "more coalesced packets than are named" )
    {
        Bytes datagram;
        for ( int i = 0; i < 6; ++i ) {
            datagram = datagram + handshakePacket( kClientScid, kServerScid );
        }

        THEN( "the first four are named, then an ellipsis" )
        {
            REQUIRE( fromServer( datagram ).description
                     == "Handshake, Handshake, Handshake, Handshake, \xe2\x80\xa6, Version 1, "
                        "DCID=0a0b0c0d, SCID=5e5e5e5e5e5e5e5e" );
        }
    }

    GIVEN( "QUIC on a port other than 443" )
    {
        const auto datagram = initial( kV1, kClientDcid, kClientScid );

        THEN( "it is QUIC by its bytes" )
        {
            REQUIRE(
                describePayload( Transport::Udp, datagram.data(), datagram.size(), 50000, 8443 )
                    .label
                == "QUIC" );
        }
    }
}

SCENARIO( "A Version Negotiation packet lists the versions the server supports", "[quic]" )
{
    GIVEN( "a Version Negotiation packet with a GREASE version, v1 and draft-29" )
    {
        const auto described = fromServer( versionNegotiation( { 0x0A1A2A3A, kV1, kDraft29 } ) );

        THEN( "it is described as such" )
        {
            REQUIRE( described.label == "QUIC" );
            REQUIRE( described.description
                     == "Version Negotiation, DCID=0a0b0c0d, SCID=8394c8f03e515708, "
                        "Versions=0x0A1A2A3A,1,draft-29" );
        }
    }

    GIVEN( "a Version Negotiation packet with many versions" )
    {
        THEN( "the first eight are named, then an ellipsis" )
        {
            const auto described = fromServer(
                versionNegotiation( { kV1, kV1, kV1, kV1, kV1, kV1, kV1, kV1, kV1, kV1 } ) );
            REQUIRE( described.description
                     == "Version Negotiation, DCID=0a0b0c0d, SCID=8394c8f03e515708, "
                        "Versions=1,1,1,1,1,1,1,1,\xe2\x80\xa6" );
        }
    }

    GIVEN( "a version 0 header that lists no QUIC version, or no whole list" )
    {
        THEN( "it is not QUIC" )
        {
            REQUIRE( fromServer( versionNegotiation( { 0x12345678 } ) ).label != "QUIC" );
            REQUIRE( fromServer( versionNegotiation( {} ) ).label != "QUIC" );
            const auto ragged = versionNegotiation( { kV1 } ) + Bytes{ 0x00 };
            REQUIRE( fromServer( ragged ).label != "QUIC" );
        }
    }
}

SCENARIO( "Only a header of a known QUIC version is QUIC, whatever the port", "[quic]" )
{
    GIVEN( "a UDP payload to port 443 that is not QUIC" )
    {
        THEN( "it gets the port's hint, not QUIC" )
        {
            REQUIRE( toServer( text( "hello, port 443" ) ).label == "HTTPS" );
            REQUIRE( toServer( Bytes( 1200, 0xC3 ) ).label == "HTTPS" );
        }
    }

    GIVEN( "long headers that break a rule" )
    {
        auto unknownVersion = initial( kV1, kClientDcid, kClientScid );
        unknownVersion[ 4 ] = 0x07;
        auto noFixedBit = initial( kV1, kClientDcid, kClientScid );
        noFixedBit[ 0 ] &= ~0x40;
        const auto draft21 = initial( 0xFF000015, kClientDcid, kClientScid );
        const auto longCid = initial( kV1, Bytes( 21, 0x11 ), kClientScid );

        THEN( "none is QUIC" )
        {
            REQUIRE( toServer( unknownVersion ).label == "HTTPS" );
            REQUIRE( toServer( noFixedBit ).label == "HTTPS" );
            REQUIRE( toServer( draft21 ).label == "HTTPS" );
            REQUIRE( toServer( longCid ).label == "HTTPS" );
        }
    }

    GIVEN( "a short header packet seen on its own" )
    {
        THEN( "it cannot be told from other bytes: the port's hint names it" )
        {
            REQUIRE( toServer( shortPacket( kServerScid ) ).label == "HTTPS" );
        }
    }
}

SCENARIO( "Short header packets are QUIC in a stream that began as QUIC", "[quic]" )
{
    GIVEN( "a connection: client Initial, server Initial and Handshake, then short headers" )
    {
        const auto packets = describedInStreams( {
            { true, initial( kV1, kClientDcid, kClientScid ) },
            { false, initial( kV1, kClientScid, kServerScid, 100 )
                         + handshakePacket( kClientScid, kServerScid ) },
            { true, shortPacket( kServerScid ) },
            { false, shortPacket( kClientScid ) },
        } );
        REQUIRE( packets.size() == 4 );

        THEN( "the long headers are described as they were" )
        {
            REQUIRE( packets[ 0 ].protocol == "QUIC" );
            REQUIRE( descriptionOf( packets[ 1 ] )
                     == "Initial, Handshake, Version 1, DCID=0a0b0c0d, SCID=5e5e5e5e5e5e5e5e" );
        }

        THEN( "each short header is QUIC, its connection ID as long as the other side chose" )
        {
            REQUIRE( packets[ 2 ].protocol == "QUIC" );
            REQUIRE( packets[ 2 ].protocolRecognised );
            REQUIRE(
                packets[ 2 ].info
                == "50443 \xe2\x86\x92 443 Len=49 | Protected Payload, DCID=5e5e5e5e5e5e5e5e" );
            REQUIRE( packets[ 3 ].protocol == "QUIC" );
            REQUIRE( descriptionOf( packets[ 3 ] ) == "Protected Payload, DCID=0a0b0c0d" );
        }
    }

    GIVEN( "a stream captured after the client's Initial: only the server's long header seen" )
    {
        const auto packets = describedInStreams( {
            { false, initial( kV1, kClientScid, kServerScid, 100 ) },
            { true, shortPacket( kServerScid ) },
            { false, shortPacket( kClientScid ) },
        } );

        THEN( "both directions are QUIC, the connection ID shown where its length is known" )
        {
            REQUIRE( descriptionOf( packets[ 1 ] ) == "Protected Payload, DCID=5e5e5e5e5e5e5e5e" );
            REQUIRE( packets[ 2 ].protocol == "QUIC" );
            REQUIRE( descriptionOf( packets[ 2 ] ) == "Protected Payload" );
        }
    }

    GIVEN( "short headers on a stream without a QUIC long header" )
    {
        const auto packets = describedInStreams( {
            { true, text( "hello" ) },
            { true, shortPacket( kServerScid ) },
        } );

        THEN( "they fall through to the port's hint" )
        {
            REQUIRE( packets[ 1 ].protocol == "HTTPS" );
        }
    }

    GIVEN( "a QUIC stream, then datagrams that cannot be short headers" )
    {
        const auto packets = describedInStreams( {
            { true, initial( kV1, kClientDcid, kClientScid ) },
            { false, initial( kV1, kClientScid, kServerScid, 100 ) },
            { true, shortPacket( kServerScid, 4 ) },                   // too short to be protected
            { true, Bytes{ 0x83 } + kServerScid + Bytes( 40, 0x5A ) }, // no fixed bit
            { true, {} },
        } );

        THEN( "no QUIC header is read in them: they are continuations of the QUIC stream" )
        {
            for ( size_t i = 2; i < 4; ++i ) {
                INFO( "packet " << i );
                REQUIRE( packets[ i ].protocol == "QUIC" );
                REQUIRE( descriptionOf( packets[ i ] ).rfind( "Continuation", 0 ) == 0 );
            }
            REQUIRE( packets[ 4 ].protocol == "QUIC" );
            REQUIRE( descriptionOf( packets[ 4 ] ).empty() );
        }
    }

    GIVEN( "a QUIC stream between other hosts" )
    {
        const auto packets = describedInStreams( {
            { true, initial( kV1, kClientDcid, kClientScid ) },
            { true, shortPacket( kServerScid ), 40000 },
        } );

        THEN( "its state is not another stream's" )
        {
            REQUIRE( packets[ 0 ].protocol == "QUIC" );
            REQUIRE( packets[ 1 ].protocol == "HTTPS" );
        }
    }
}

SCENARIO( "A cut or malformed QUIC header is never read beyond the payload", "[quic]" )
{
    const auto clientInitial = initial( kV1, kClientDcid, kClientScid, 100 );

    GIVEN( "an Initial cut at every possible length" )
    {
        THEN( "a prefix holding both connection IDs is an Initial, a shorter one no QUIC" )
        {
            const size_t headerEnd = 1 + 4 + 1 + kClientDcid.size() + 1 + kClientScid.size();
            for ( size_t n = 0; n <= clientInitial.size(); ++n ) {
                const auto described = toServer( prefix( clientInitial, n ) );
                if ( n >= headerEnd ) {
                    REQUIRE( described.description
                             == "Initial, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
                }
                else {
                    REQUIRE( described.label != "QUIC" );
                }
            }
        }
    }

    GIVEN( "a length field that claims more than there is" )
    {
        auto lying = clientInitial + handshakePacket( kClientDcid, kClientScid );
        const size_t lengthAt = 1 + 4 + 1 + kClientDcid.size() + 1 + kClientScid.size() + 1;
        lying[ lengthAt ] = 0x7F;
        lying[ lengthAt + 1 ] = 0xFF;

        THEN( "the first packet is named, and nothing behind it" )
        {
            REQUIRE( toServer( lying ).description
                     == "Initial, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d" );
        }
    }

    GIVEN( "every single byte of a coalesced datagram set to every value" )
    {
        const auto datagram = clientInitial + handshakePacket( kClientDcid, kClientScid );

        THEN( "the description is QUIC with a description, or no QUIC at all" )
        {
            for ( size_t i = 0; i < datagram.size(); ++i ) {
                for ( int value : { 0x00, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xBF, 0xC0, 0xFF } ) {
                    auto mutated = datagram;
                    mutated[ i ] = static_cast<uint8_t>( value );
                    const auto described = toServer( mutated );
                    if ( described.label == "QUIC" ) {
                        REQUIRE( !described.description.empty() );
                    }
                }
            }
        }
    }

    GIVEN( "connections with random bytes changed, cut anywhere" )
    {
        const auto serverFlight = initial( kV1, kClientScid, kServerScid, 100 )
                                  + handshakePacket( kClientScid, kServerScid )
                                  + shortPacket( kClientScid );
        const auto negotiation = versionNegotiation( { 0x0A1A2A3A, kV1, kDraft29 } );

        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 44 );
            for ( int round = 0; round < 3000; ++round ) {
                std::vector<Datagram> datagrams;
                for ( const auto* original : { &clientInitial, &serverFlight, &negotiation } ) {
                    auto mutated = *original;
                    const auto changes = random() % 8;
                    for ( unsigned c = 0; c < changes; ++c ) {
                        mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                    }
                    datagrams.push_back(
                        { random() % 2 == 0, prefix( mutated, random() % mutated.size() ) } );
                }
                datagrams.push_back( { true, shortPacket( kServerScid, random() % 64 ) } );
                const auto packets = describedInStreams( datagrams );
                for ( size_t i = 0; i < packets.size(); ++i ) {
                    REQUIRE( packets[ i ].info.find( '\n' ) == std::string::npos );
                    // An empty datagram carries its stream's label alone.
                    if ( packets[ i ].protocol == "QUIC" && !datagrams[ i ].payload.empty() ) {
                        REQUIRE( !descriptionOf( packets[ i ] ).empty() );
                    }
                }
            }
        }
    }
}
