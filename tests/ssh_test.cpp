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
 * @file ssh_test.cpp
 * @brief BDD tests for the SSH detector: banners, the binary packets of
 *        the key exchange, KEXINIT's name-lists, the encrypted packets
 *        after NEWKEYS in a stream, framing for the TCP Reassembly, and
 *        packets mangled and cut anywhere.
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

constexpr uint16_t kSshPort = 22;
constexpr uint16_t kClientPort = 50022;

const std::string kEllipsis = "\xe2\x80\xa6";

Bytes u32( uint32_t v )
{
    Bytes b;
    putBE32( b, v );
    return b;
}

/// An SSH string: its 32-bit length and its bytes.
Bytes str( const Bytes& bytes )
{
    return u32( static_cast<uint32_t>( bytes.size() ) ) + bytes;
}

Bytes str( const std::string& s )
{
    return str( text( s ) );
}

/// A binary packet of the unencrypted phase carrying message @p code and
/// @p body, padded to a multiple of 8 with at least 4 bytes.
Bytes packet( uint8_t code, const Bytes& body = {} )
{
    const size_t payload = 1 + body.size();
    size_t padding = 8 - ( 5 + payload ) % 8;
    if ( padding < 4 ) {
        padding += 8;
    }
    Bytes b = u32( static_cast<uint32_t>( 1 + payload + padding ) );
    b.push_back( static_cast<uint8_t>( padding ) );
    b.push_back( code );
    b = b + body;
    b.resize( b.size() + padding, 0 );
    return b;
}

Bytes banner( const std::string& line = "SSH-2.0-OpenSSH_9.6" )
{
    return text( line + "\r\n" );
}

/// SSH_MSG_KEXINIT with the name-lists OpenSSH's client sends, @p kex first.
Bytes kexInit( const std::string& kex = "curve25519-sha256,curve25519-sha256@libssh.org,ext-info-c",
               uint8_t follows = 0 )
{
    Bytes body( 16, 0x5A ); // cookie
    for ( const auto* list :
          { kex.c_str(), "ssh-ed25519,rsa-sha2-512", "chacha20-poly1305@openssh.com,aes128-ctr",
            "chacha20-poly1305@openssh.com,aes128-ctr", "umac-64-etm@openssh.com,hmac-sha2-256",
            "umac-64-etm@openssh.com,hmac-sha2-256", "none,zlib@openssh.com",
            "none,zlib@openssh.com", "", "" } ) {
        body = body + str( std::string( list ) );
    }
    body.push_back( follows );
    return packet( 20, body + u32( 0 ) );
}

const Bytes kNewKeys = packet( 21 );

Bytes ecdhInit()
{
    return packet( 30, str( Bytes( 32, 0x11 ) ) );
}

Bytes ecdhReply()
{
    return packet( 31, str( str( "ssh-ed25519" ) + str( Bytes( 32, 0x22 ) ) )
                           + str( Bytes( 32, 0x33 ) )
                           + str( str( "ssh-ed25519" ) + str( Bytes( 64, 0x44 ) ) ) );
}

PayloadDescription fromClient( const Bytes& payload, uint16_t port = kSshPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort, port );
}

PayloadDescription fromServer( const Bytes& payload, uint16_t port = kSshPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), port, kClientPort );
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

/// @p payloads sent between the client and @p port, true from the client,
/// run through the Converter's steps but the TCP Reassembly.
std::vector<PacketRecord> inStream( const std::vector<std::pair<bool, Bytes>>& payloads,
                                    uint16_t port )
{
    std::vector<Bytes> frames;
    for ( const auto& [ client, payload ] : payloads ) {
        Ipv4Options o;
        if ( !client ) {
            std::swap( o.src, o.dst );
        }
        frames.push_back( eth( EthertypeIpv4, ipv4( IpProtoTcp,
                                                    client ? tcp( kClientPort, port, payload )
                                                           : tcp( port, kClientPort, payload ),
                                                    o ) ) );
    }
    auto packets = parse( pcapOf( frames ) ).packets;
    StreamTracker tracker;
    for ( auto& pkt : packets ) {
        const auto stream = tracker.track( pkt );
        describeInStream( pkt, stream );
        rememberInStream( pkt, stream );
    }
    return packets;
}

const std::string kKexInitText = "Key Exchange Init kex=curve25519-sha256," + kEllipsis
                                 + " hostkey=ssh-ed25519," + kEllipsis
                                 + " cipher=chacha20-poly1305@openssh.com," + kEllipsis;

} // namespace

SCENARIO( "SSH banners are described as Wireshark shows them", "[ssh]" )
{
    GIVEN( "the client's and the server's identification strings" )
    {
        const auto client = fromClient( banner() );
        const auto server = fromServer( banner( "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10" ) );

        THEN( "each is the side's protocol, SSHv2, and begins an SSH connection" )
        {
            REQUIRE( client.label == "SSHv2" );
            REQUIRE_FALSE( client.guessed );
            REQUIRE( client.description == "Client: Protocol (SSH-2.0-OpenSSH_9.6)" );
            REQUIRE( client.streamCue == StreamCue::SshBanner );
            REQUIRE( server.description
                     == "Server: Protocol (SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10)" );
        }
    }

    GIVEN( "banners on another port, without CR, and of other versions" )
    {
        THEN( "they are told by their content, the lower port the server's" )
        {
            REQUIRE( fromClient( banner(), 2222 ).description
                     == "Client: Protocol (SSH-2.0-OpenSSH_9.6)" );
            REQUIRE( fromServer( banner(), 2222 ).description
                     == "Server: Protocol (SSH-2.0-OpenSSH_9.6)" );
            REQUIRE( fromClient( text( "SSH-2.0-dropbear\n" ), 2222 ).description
                     == "Client: Protocol (SSH-2.0-dropbear)" );
            REQUIRE( fromClient( banner( "SSH-1.99-Cisco-1.25" ) ).label == "SSHv2" );
            const auto v1 = fromClient( banner( "SSH-1.5-OpenSSH_2.0" ) );
            REQUIRE( v1.label == "SSHv1" );
            REQUIRE( v1.streamCue == StreamCue::None );
        }
    }

    GIVEN( "a banner with the client's KEXINIT behind it in one segment" )
    {
        THEN( "both are described" )
        {
            REQUIRE( fromClient( banner() + kexInit() ).description
                     == "Client: Protocol (SSH-2.0-OpenSSH_9.6), " + kKexInitText );
        }
    }

    GIVEN( "a banner cut before its line end, and one longer than a field" )
    {
        THEN( "the first ends in an ellipsis, the second is cut" )
        {
            REQUIRE( fromClient( text( "SSH-2.0-Open" ) ).description
                     == "Client: Protocol (SSH-2.0-Open" + kEllipsis + ")" );
            const auto longBanner = fromClient( banner( "SSH-2.0-" + std::string( 200, 'x' ) ) );
            REQUIRE( longBanner.description
                     == "Client: Protocol (SSH-2.0-" + std::string( 112, 'x' ) + kEllipsis + ")" );
        }
    }

    GIVEN( "text that only looks like a banner" )
    {
        THEN( "it is not SSH" )
        {
            REQUIRE( fromClient( text( "SSH-two-OpenSSH\r\n" ), 2222 ).label != "SSHv2" );
            REQUIRE( fromClient( text( "SSH-2.0\r\n" ), 2222 ).label != "SSHv2" );
            REQUIRE( fromClient( text( "SSH-2.0-" + std::string( 300, 'x' ) ), 2222 ).label
                     != "SSHv2" );
        }
    }
}

SCENARIO( "The binary packets of the key exchange are described", "[ssh]" )
{
    GIVEN( "the client's KEXINIT" )
    {
        THEN( "its key exchange, host key and cipher lists are shown shortened" )
        {
            const auto described = fromClient( kexInit() );
            REQUIRE( described.label == "SSHv2" );
            REQUIRE_FALSE( described.guessed );
            REQUIRE( described.description == "Client: " + kKexInitText );
            REQUIRE( fromServer( kexInit( "sntrup761x25519-sha512", 1 ) ).description
                     == "Server: Key Exchange Init kex=sntrup761x25519-sha512 hostkey=ssh-ed25519,"
                            + kEllipsis + " cipher=chacha20-poly1305@openssh.com," + kEllipsis
                            + " first_kex_packet_follows" );
        }
    }

    GIVEN( "the ECDH key exchange and NEWKEYS" )
    {
        THEN( "they are named, and NEWKEYS tells the stream" )
        {
            REQUIRE( fromClient( ecdhInit() ).description
                     == "Client: Elliptic Curve Diffie-Hellman Key Exchange Init" );
            const auto reply = fromServer( ecdhReply() + kNewKeys );
            REQUIRE( reply.description
                     == "Server: Elliptic Curve Diffie-Hellman Key Exchange Reply, New Keys" );
            REQUIRE( reply.streamCue == StreamCue::SshNewKeys );
            REQUIRE( fromClient( kNewKeys ).description == "Client: New Keys" );
        }
    }

    GIVEN( "NEWKEYS and an encrypted packet behind it in one segment" )
    {
        THEN( "the rest is an encrypted packet" )
        {
            const auto described = fromClient( kNewKeys + Bytes( 52, 0xE7 ), 2222 );
            REQUIRE( described.label == "SSHv2" );
            REQUIRE( described.description == "Client: New Keys, Encrypted packet (len=52)" );
            REQUIRE( described.streamCue == StreamCue::SshNewKeys );
        }
    }

    GIVEN( "the Diffie-Hellman group exchange" )
    {
        THEN( "its messages are told by their layout" )
        {
            REQUIRE( fromClient( packet( 34, u32( 2048 ) + u32( 3072 ) + u32( 8192 ) ) ).description
                     == "Client: Diffie-Hellman Group Exchange Request" );
            REQUIRE( fromServer( packet( 31, str( Bytes( 129, 0xFF ) ) + str( Bytes{ 2 } ) ) )
                         .description
                     == "Server: Diffie-Hellman Group Exchange Group" );
            REQUIRE( fromClient( packet( 32, str( Bytes( 128, 0x12 ) ) ) ).description
                     == "Client: Diffie-Hellman Group Exchange Init" );
            REQUIRE( fromServer( packet( 33, str( "k" ) + str( "f" ) + str( "s" ) ) ).description
                     == "Server: Diffie-Hellman Group Exchange Reply" );
            REQUIRE( fromClient( packet( 30, u32( 2048 ) ) ).description
                     == "Client: Diffie-Hellman Group Exchange Request (Old)" );
        }
    }

    GIVEN( "the other messages of the transport layer" )
    {
        THEN( "they are named" )
        {
            REQUIRE( fromServer( packet( 1, u32( 11 ) + str( "bye" ) + str( "" ) ) ).description
                     == "Server: Disconnect" );
            REQUIRE( fromClient( packet( 2, str( "pad" ) ) ).description == "Client: Ignore" );
            REQUIRE( fromClient( packet( 3, u32( 7 ) ) ).description == "Client: Unimplemented" );
            REQUIRE( fromClient( packet( 4, Bytes{ 0 } + str( "msg" ) + str( "" ) ) ).description
                     == "Client: Debug" );
            REQUIRE( fromClient( packet( 5, str( "ssh-userauth" ) ) ).description
                     == "Client: Service Request" );
            REQUIRE( fromServer( packet( 6, str( "ssh-userauth" ) ) ).description
                     == "Server: Service Accept" );
            REQUIRE( fromServer( packet( 7, u32( 1 ) + str( "server-sig-algs" ) + str( "a,b" ) ) )
                         .description
                     == "Server: Extension Information" );
        }
    }

    GIVEN( "more packets in a segment than are named" )
    {
        Bytes segment;
        for ( int i = 0; i < 10; ++i ) {
            segment = segment + packet( 2, str( "x" ) );
        }
        THEN( "the first eight are, then an ellipsis" )
        {
            std::string expected = "Client: ";
            for ( int i = 0; i < 8; ++i ) {
                expected += "Ignore, ";
            }
            REQUIRE( fromClient( segment ).description == expected + kEllipsis );
        }
    }
}

SCENARIO( "A truncated or malformed SSH packet is described as such", "[ssh]" )
{
    GIVEN( "a KEXINIT cut at the end of the segment" )
    {
        const auto message = kexInit();
        THEN( "it is described as far as it goes, then an ellipsis" )
        {
            REQUIRE( fromClient( prefix( message, 90 ) ).description
                     == "Client: Key Exchange Init kex=curve25519-sha256," + kEllipsis + " "
                            + kEllipsis );
            REQUIRE( fromClient( prefix( message, 30 ), 2222 ).description
                     == "Client: Key Exchange Init " + kEllipsis );
            REQUIRE( fromClient( kexInit() + prefix( kNewKeys, 3 ) ).description
                     == "Client: " + kKexInitText + ", Packet " + kEllipsis );
        }
    }

    GIVEN( "packets with lengths that do not fit, after a banner" )
    {
        auto padding = kNewKeys;
        padding[ 4 ] = 2;
        auto list = kexInit();
        list[ 25 ] = 0x7F; // the kex name-list's length beyond the packet
        THEN( "they are malformed" )
        {
            REQUIRE( fromClient( banner() + u32( 13 ) + Bytes( 12, 0 ) ).description
                     == "Client: Protocol (SSH-2.0-OpenSSH_9.6), Invalid packet length 13 "
                        "[Malformed Packet]" );
            REQUIRE( fromClient( banner() + padding ).description
                     == "Client: Protocol (SSH-2.0-OpenSSH_9.6), Invalid padding length 2 "
                        "[Malformed Packet]" );
            REQUIRE( fromClient( banner() + list ).description
                     == "Client: Protocol (SSH-2.0-OpenSSH_9.6), Key Exchange Init "
                        "[Malformed Packet]" );
        }
    }

    GIVEN( "bytes on port 22 that are no packet of the key exchange" )
    {
        THEN( "they are an encrypted packet, as far as the port tells" )
        {
            const auto described = fromClient( Bytes( 36, 0xC3 ) );
            REQUIRE( described.label == "SSH" );
            REQUIRE( described.guessed );
            REQUIRE( described.description == "Client: Encrypted packet (len=36)" );
            REQUIRE( fromServer( prefix( ecdhReply(), 40 ) ).description
                     == "Server: Encrypted packet (len=40)" );
        }
    }

    GIVEN( "the same bytes, or a packet that is cut, on another port" )
    {
        THEN( "they are not SSH" )
        {
            REQUIRE( fromClient( Bytes( 36, 0xC3 ), 2222 ).label.rfind( "SSH", 0 )
                     == std::string::npos );
            REQUIRE( fromClient( prefix( ecdhInit(), 30 ), 2222 ).label.rfind( "SSH", 0 )
                     == std::string::npos );
            REQUIRE( fromClient( packet( 99, str( "x" ) ), 2222 ).label.rfind( "SSH", 0 )
                     == std::string::npos );
        }
    }
}

SCENARIO( "An SSH connection is followed through its phases", "[ssh]" )
{
    GIVEN( "a connection on port 2222, the client's NEWKEYS before the server's" )
    {
        const auto packets = inStream(
            {
                { false, banner() },
                { true, banner() },
                { true, kexInit() },
                { false, kexInit() },
                { true, ecdhInit() },
                { true, kNewKeys },
                { false, ecdhReply() },
                { true, Bytes( 44, 0x9C ) },
                { false, kNewKeys + Bytes( 28, 0x9D ) },
                { false, Bytes( 52, 0x9E ) },
                { true, prefix( ecdhReply(), 40 ) },
            },
            2222 );

        THEN( "each direction is encrypted after its NEWKEYS" )
        {
            for ( const auto& pkt : packets ) {
                REQUIRE( pkt.protocol == "SSHv2" );
                REQUIRE( pkt.protocolRecognised );
            }
            REQUIRE( descriptionOf( packets[ 0 ] ) == "Server: Protocol (SSH-2.0-OpenSSH_9.6)" );
            REQUIRE( descriptionOf( packets[ 2 ] ) == "Client: " + kKexInitText );
            REQUIRE( descriptionOf( packets[ 6 ] )
                     == "Server: Elliptic Curve Diffie-Hellman Key Exchange Reply" );
            REQUIRE( descriptionOf( packets[ 7 ] ) == "Client: Encrypted packet (len=44)" );
            REQUIRE( descriptionOf( packets[ 8 ] )
                     == "Server: New Keys, Encrypted packet (len=28)" );
            REQUIRE( descriptionOf( packets[ 9 ] ) == "Server: Encrypted packet (len=52)" );
            REQUIRE( descriptionOf( packets[ 10 ] ) == "Client: Encrypted packet (len=40)" );
        }
    }

    GIVEN( "packets before NEWKEYS that do not read as SSH on their own" )
    {
        auto list = kexInit();
        list[ 25 ] = 0x7F;
        const auto packets = inStream(
            {
                { true, banner() },
                { true, prefix( ecdhInit(), 30 ) },
                { true, list },
                { true, u32( 13 ) + Bytes( 12, 0 ) },
            },
            2222 );

        THEN( "the stream's phase reads them as SSH, cut or malformed" )
        {
            for ( const auto& pkt : packets ) {
                REQUIRE( pkt.protocol == "SSHv2" );
            }
            REQUIRE( descriptionOf( packets[ 1 ] )
                     == "Client: Elliptic Curve Diffie-Hellman Key Exchange Init " + kEllipsis );
            REQUIRE( descriptionOf( packets[ 2 ] ) == "Client: Key Exchange Init " + kEllipsis );
            REQUIRE( descriptionOf( packets[ 3 ] )
                     == "Client: Invalid packet length 13 [Malformed Packet]" );
        }
    }

    GIVEN( "a connection on port 22 whose key exchange the capture did not see" )
    {
        const auto packets
            = inStream( { { true, Bytes( 36, 0xC3 ) }, { false, Bytes( 60, 0x3C ) } }, kSshPort );

        THEN( "its packets are taken for encrypted ones, by the port" )
        {
            REQUIRE( packets[ 0 ].protocol == "SSH" );
            REQUIRE_FALSE( packets[ 0 ].protocolRecognised );
            REQUIRE( descriptionOf( packets[ 1 ] ) == "Server: Encrypted packet (len=60)" );
        }
    }
}

SCENARIO( "SSH is framed for the TCP Reassembly as far as its phase allows", "[ssh]" )
{
    StreamState state;
    const Stream stream{ 0, &state, 0 };
    const auto message = kexInit();

    GIVEN( "a banner" )
    {
        THEN( "it is framed to its line end, on any port" )
        {
            const auto line = banner();
            const auto whole = tcpMessageExtent( line.data(), line.size(), kClientPort, 2222 );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == line.size() );
            REQUIRE( std::string( whole.label ) == "SSHv2" );
            const auto cut = tcpMessageExtent( line.data(), 10, kClientPort, 2222 );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == 11 );
        }
    }

    GIVEN( "a binary packet of a stream that showed no banner" )
    {
        THEN( "it is not framed, as it may be an encrypted one" )
        {
            REQUIRE(
                tcpMessageExtent( message.data(), 100, kClientPort, kSshPort, 0, &stream ).framer
                == 0 );
        }
    }

    GIVEN( "a binary packet after the banner" )
    {
        state.protocols = StreamState::kSshBannerSeen;
        THEN( "it is framed by its packet_length" )
        {
            const auto cut
                = tcpMessageExtent( message.data(), 100, kClientPort, kSshPort, 0, &stream );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == message.size() );
            const auto header
                = tcpMessageExtent( message.data(), 3, kClientPort, 2222, 0, &stream );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 4 );
            // NEWKEYS takes all after it, which is encrypted.
            const auto keys = kNewKeys + Bytes( 40, 0xAB );
            const auto newKeys
                = tcpMessageExtent( keys.data(), keys.size(), kClientPort, kSshPort, 0, &stream );
            REQUIRE( newKeys.complete() );
            REQUIRE( newKeys.length == keys.size() );
            // A length the unencrypted phase does not allow begins no packet.
            const auto bad = u32( 13 ) + Bytes( 12, 0 );
            REQUIRE(
                tcpMessageExtent( bad.data(), bad.size(), kClientPort, kSshPort, 0, &stream ).framer
                == 0 );
        }
    }

    GIVEN( "a direction after its NEWKEYS" )
    {
        state.protocols
            = static_cast<uint8_t>( StreamState::kSshBannerSeen | StreamState::sshEncrypted( 0 ) );
        THEN( "all its bytes are whole, the other direction's still framed" )
        {
            const auto encrypted
                = tcpMessageExtent( message.data(), 100, kClientPort, kSshPort, 0, &stream );
            REQUIRE( encrypted.complete() );
            REQUIRE( encrypted.length == 100 );
            const Stream other{ 0, &state, 1 };
            REQUIRE( tcpMessageExtent( message.data(), 100, kSshPort, kClientPort, 0, &other )
                         .needsMore );
        }
    }
}

SCENARIO( "Mangled SSH never breaks the describer", "[ssh][fuzz]" )
{
    const std::vector<Bytes> messages = {
        banner(),
        kexInit(),
        kexInit( "x", 1 ),
        ecdhInit(),
        ecdhReply(),
        kNewKeys,
        packet( 1, u32( 11 ) + str( "bye" ) + str( "" ) ),
        packet( 2, str( "pad" ) ),
        packet( 3, u32( 7 ) ),
        packet( 4, Bytes{ 0 } + str( "msg" ) + str( "" ) ),
        packet( 5, str( "ssh-userauth" ) ),
        packet( 7, u32( 2 ) + str( "a" ) + str( "b" ) + str( "c" ) + str( "d" ) ),
        packet( 30, u32( 2048 ) ),
        packet( 31, str( Bytes( 9, 0xFF ) ) + str( Bytes{ 2 } ) ),
        packet( 32, str( "e" ) ),
        packet( 33, str( "k" ) + str( "f" ) + str( "s" ) ),
        packet( 34, u32( 1 ) + u32( 2 ) + u32( 3 ) ),
    };
    StreamState state;
    auto check = [ &state ]( const Bytes& bytes ) {
        for ( const auto& result :
              { fromClient( bytes ), fromServer( bytes ), fromClient( bytes, 2222 ) } ) {
            REQUIRE( result.description.find( '\n' ) == std::string::npos );
            REQUIRE( result.description.size() < 4096 );
        }
        for ( const int phase : { 0, int( StreamState::kSshBannerSeen ),
                                  StreamState::kSshBannerSeen | StreamState::sshEncrypted( 0 ) } ) {
            state.protocols = static_cast<uint8_t>( phase );
            const Stream stream{ 0, &state, 0 };
            const auto extent
                = tcpMessageExtent( bytes.data(), bytes.size(), kClientPort, kSshPort, 0, &stream );
            REQUIRE( ( extent.framer == 0 || extent.length > 0 ) );
        }
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each is described in one line, as SSH on its port" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto cut = prefix( message, n );
                    check( cut );
                    if ( n > 0 ) {
                        REQUIRE( fromClient( cut ).label.rfind( "SSH", 0 ) == 0 );
                    }
                    if ( n == message.size() ) {
                        INFO( fromClient( cut ).description );
                        REQUIRE( fromClient( cut ).label == "SSHv2" );
                        REQUIRE( fromClient( cut ).description.find( "Malformed" )
                                 == std::string::npos );
                        // An ellipsis shortens a name-list, but none says it is cut.
                        REQUIRE( fromClient( cut ).description.find( " " + kEllipsis )
                                 == std::string::npos );
                    }
                }
            }
        }
    }

    GIVEN( "every single byte of each message set to telling values" )
    {
        THEN( "the description is one line" )
        {
            for ( const auto& message : messages ) {
                for ( size_t i = 0; i < message.size(); ++i ) {
                    for ( int value : { 0x00, 0x01, 0x04, 0x0A, 0x14, 0x15, 0x7F, 0x80, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        check( mutated );
                    }
                }
            }
        }
    }

    GIVEN( "segments of several messages with random bytes changed, cut anywhere" )
    {
        Bytes segment = banner();
        for ( const auto& message : messages ) {
            segment = segment + message;
        }
        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 22 );
            for ( int round = 0; round < 5000; ++round ) {
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
