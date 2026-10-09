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
 * @file dhcp_ntp_test.cpp
 * @brief BDD tests for the DHCP, DHCPv6 and NTP descriptions, through the
 *        Payload Describer: a DHCP exchange, its options walked within
 *        their bounds (pads, the end option, overloaded fields, lengths that
 *        run past the message), DHCPv6 messages and relays, NTP modes.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

Bytes be16( size_t v )
{
    return { static_cast<uint8_t>( v >> 8 ), static_cast<uint8_t>( v ) };
}

Bytes be32( uint32_t v )
{
    return be16( v >> 16 ) + be16( v & 0xFFFF );
}

Bytes text( const std::string& s )
{
    return Bytes( s.begin(), s.end() );
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

PayloadDescription overUdp( const Bytes& payload, uint16_t srcPort, uint16_t dstPort )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), srcPort, dstPort );
}

// ── DHCP ─────────────────────────────────────────────────────────────────

constexpr uint8_t kBootRequest = 1;
constexpr uint8_t kBootReply = 2;
constexpr uint32_t kXid = 0x3903F326;

const Bytes kNoAddress{ 0, 0, 0, 0 };
const Bytes kLeased{ 192, 168, 1, 50 };
const Bytes kServer{ 192, 168, 1, 1 };
const Bytes kClientMac{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };

/// The fields of a BOOTP header (RFC 2131, 2) that the tests set.
struct Header {
    uint8_t op = kBootRequest;
    Bytes ciaddr = kNoAddress;
    Bytes yiaddr = kNoAddress;
    uint8_t htype = 1; ///< Ethernet
    uint8_t hlen = 6;
    Bytes sname = Bytes( 64, 0 );
    Bytes file = Bytes( 128, 0 );
};

/// A DHCP message: @p header, the magic cookie and @p options.
Bytes dhcp( const Header& header, const Bytes& options, bool cookie = true )
{
    Bytes chaddr = kClientMac;
    chaddr.resize( 16, 0 );
    return Bytes{ header.op, header.htype, header.hlen, 0 } + be32( kXid ) + be16( 0 )
           + be16( 0x8000 ) + header.ciaddr + header.yiaddr + kNoAddress + kNoAddress + chaddr
           + header.sname + header.file + ( cookie ? be32( 0x63825363 ) : Bytes{} ) + options;
}

Bytes option( uint8_t code, const Bytes& value )
{
    return Bytes{ code, static_cast<uint8_t>( value.size() ) } + value;
}

Bytes messageType( uint8_t type )
{
    return option( 53, { type } );
}

const Bytes kEnd{ 255 };

Header reply( const Bytes& yiaddr = kLeased )
{
    Header h;
    h.op = kBootReply;
    h.yiaddr = yiaddr;
    return h;
}

PayloadDescription fromClient( const Bytes& message )
{
    return overUdp( message, 68, 67 );
}

PayloadDescription fromServer( const Bytes& message )
{
    return overUdp( message, 67, 68 );
}

// ── DHCPv6 ───────────────────────────────────────────────────────────────

/// A DUID-LLT (RFC 8415, 11.2) of the client MAC.
const Bytes kDuid = be16( 1 ) + be16( 1 ) + be32( 0x1C39CF88 ) + kClientMac;

Bytes option6( uint16_t code, const Bytes& value )
{
    return be16( code ) + be16( value.size() ) + value;
}

/// A client/server message of @p type with transaction id 0x1a2b3c.
Bytes dhcpv6( uint8_t type, const Bytes& options )
{
    return Bytes{ type, 0x1A, 0x2B, 0x3C } + options;
}

Bytes address6( uint8_t last )
{
    Bytes a( 16, 0 );
    a[ 0 ] = 0x20;
    a[ 1 ] = 0x01;
    a[ 2 ] = 0x0d;
    a[ 3 ] = 0xb8;
    a[ 15 ] = last;
    return a;
}

/// A Relay-forw message from link 2001:db8::1 carrying @p relayed.
Bytes relayForward( const Bytes& relayed )
{
    return Bytes{ 12, 0 } + address6( 1 ) + address6( 2 ) + option6( 9, relayed );
}

// ── NTP ──────────────────────────────────────────────────────────────────

/// A 48-byte NTP header of @p version and @p mode, @p stratum and
/// @p referenceId.
Bytes ntp( unsigned version, unsigned mode, uint8_t stratum, const Bytes& referenceId = kNoAddress )
{
    Bytes packet{ static_cast<uint8_t>( ( version << 3 ) | mode ), stratum, 6, 0xEC };
    packet = packet + be32( 0 ) + be32( 0 ) + referenceId;
    packet.resize( 48, 0 );
    return packet;
}

} // namespace

SCENARIO( "A DHCP exchange names each message, its client and its address", "[dhcp]" )
{
    GIVEN( "a Discover, Offer, Request and ACK for the same lease" )
    {
        const auto discover
            = fromClient( dhcp( {}, messageType( 1 ) + option( 12, text( "laptop" ) )
                                        + option( 55, { 1, 3, 6 } ) + kEnd ) );
        const auto offer = fromServer( dhcp( reply(), messageType( 2 ) + option( 54, kServer )
                                                          + option( 51, be32( 86400 ) ) + kEnd ) );
        const auto request
            = fromClient( dhcp( {}, messageType( 3 ) + option( 50, kLeased ) + option( 54, kServer )
                                        + option( 12, text( "laptop" ) ) + kEnd ) );
        const auto ack
            = fromServer( dhcp( reply(), messageType( 5 ) + option( 54, kServer ) + kEnd ) );

        THEN( "each is DHCP, named with its transaction id, client MAC and address" )
        {
            REQUIRE( discover.label == "DHCP" );
            REQUIRE( !discover.guessed );
            REQUIRE( discover.description
                     == "DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55, "
                        "Host Name: laptop" );
            REQUIRE( offer.description
                     == "DHCP Offer - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55" );
            REQUIRE( request.description
                     == "DHCP Request - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55, Host Name: laptop" );
            REQUIRE( ack.description
                     == "DHCP ACK - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55" );
        }
    }

    GIVEN( "a NAK, which assigns no address" )
    {
        THEN( "only the client is named" )
        {
            REQUIRE( fromServer( dhcp( reply( kNoAddress ), messageType( 6 ) + kEnd ) ).description
                     == "DHCP NAK - Transaction ID 0x3903f326 for 00:11:22:33:44:55" );
        }
    }

    GIVEN( "a Release of the address the client holds" )
    {
        Header release;
        release.ciaddr = kLeased;

        THEN( "the client's own address is shown" )
        {
            REQUIRE( fromClient( dhcp( release, messageType( 7 ) + kEnd ) ).description
                     == "DHCP Release - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55" );
        }
    }

    GIVEN( "the other message types and one that has no name" )
    {
        THEN( "they are named as Wireshark names them" )
        {
            const std::pair<uint8_t, std::string> cases[] = {
                { 4, "DHCP Decline" },
                { 8, "DHCP Inform" },
                { 9, "DHCP Force Renew" },
                { 10, "DHCP Lease query" },
                { 200, "DHCP Unknown Message Type (0xc8)" },
            };
            for ( const auto& [ type, name ] : cases ) {
                const auto described = fromClient( dhcp( {}, messageType( type ) + kEnd ) );
                REQUIRE( described.description.rfind( name + " - Transaction ID", 0 ) == 0 );
            }
        }
    }

    GIVEN( "a BOOTP message: no magic cookie, no options" )
    {
        THEN( "it is named a Boot Request or Boot Reply" )
        {
            REQUIRE( fromClient( dhcp( {}, {}, false ) ).description
                     == "Boot Request - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
            REQUIRE( fromServer( dhcp( reply(), {}, false ) ).description
                     == "Boot Reply - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55" );
        }
    }

    GIVEN( "a client whose hardware address is not Ethernet's" )
    {
        Header infiniband;
        infiniband.htype = 32;
        infiniband.hlen = 0;

        THEN( "no MAC is shown" )
        {
            REQUIRE( fromClient( dhcp( infiniband, messageType( 1 ) + kEnd ) ).description
                     == "DHCP Discover - Transaction ID 0x3903f326" );
        }
    }
}

SCENARIO( "DHCP options are walked within their bounds", "[dhcp]" )
{
    GIVEN( "pads before the message type" )
    {
        THEN( "they are skipped" )
        {
            REQUIRE(
                fromClient( dhcp( {}, Bytes{ 0, 0, 0 } + messageType( 1 ) + kEnd ) ).description
                == "DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "a host name behind the end option" )
    {
        THEN( "it is not read" )
        {
            REQUIRE( fromClient( dhcp( {}, messageType( 1 ) + kEnd + option( 12, text( "x" ) ) ) )
                         .description
                     == "DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "an option whose length runs past the message" )
    {
        const auto message = dhcp( {}, messageType( 3 ) + Bytes{ 12, 200, 'a', 'b' } );

        THEN( "the options before it count, the cut one does not" )
        {
            REQUIRE( fromClient( message ).description
                     == "DHCP Request - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "options without an end option" )
    {
        THEN( "they are read to the end of the message" )
        {
            REQUIRE(
                fromClient( dhcp( {}, messageType( 1 ) + option( 12, text( "pc" ) ) ) ).description
                == "DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55, "
                   "Host Name: pc" );
        }
    }

    GIVEN( "a requested address or message type of the wrong length" )
    {
        THEN( "it is ignored" )
        {
            REQUIRE( fromClient( dhcp( {}, option( 53, { 3, 3 } ) + option( 50, { 10, 0, 0 } ) ) )
                         .description
                     == "Boot Request - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "a host name with control bytes, longer than the field cap" )
    {
        const auto name = text( "a\nb" ) + Bytes( 200, 'x' );

        THEN( "it is escaped and cut with an ellipsis" )
        {
            const auto described = fromClient( dhcp( {}, messageType( 1 ) + option( 12, name ) ) );
            REQUIRE( described.description.find( "Host Name: a\\x0Abxxx" ) != std::string::npos );
            REQUIRE( described.description.size() < 220 );
            REQUIRE(
                described.description.compare( described.description.size() - 3, 3, "\xe2\x80\xa6" )
                == 0 );
        }
    }

    GIVEN( "options overloaded into the file and sname fields" )
    {
        Header header;
        header.file = messageType( 3 ) + option( 50, kLeased ) + kEnd;
        header.file.resize( 128, 0 );
        header.sname = option( 12, text( "laptop" ) ) + kEnd;
        header.sname.resize( 64, 0 );

        THEN( "they are read there too, after the options field" )
        {
            REQUIRE( fromClient( dhcp( header, option( 52, { 3 } ) + kEnd ) ).description
                     == "DHCP Request - Transaction ID 0x3903f326, 192.168.1.50 for "
                        "00:11:22:33:44:55, Host Name: laptop" );
        }
        THEN( "without the overload option they are a file and server name, not options" )
        {
            REQUIRE( fromClient( dhcp( header, kEnd ) ).description
                     == "Boot Request - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "an overload option within an overloaded field" )
    {
        Header header;
        header.file = option( 52, { 2 } ) + messageType( 1 ) + kEnd;
        header.file.resize( 128, 0 );
        header.sname = option( 12, text( "never" ) ) + kEnd;
        header.sname.resize( 64, 0 );

        THEN( "it does not overload another field" )
        {
            REQUIRE( fromClient( dhcp( header, option( 52, { 1 } ) + kEnd ) ).description
                     == "DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }
}

SCENARIO( "A DHCP message cut short is described as far as it goes", "[dhcp]" )
{
    const auto request = dhcp( {}, messageType( 3 ) + option( 50, kLeased ) + kEnd );

    GIVEN( "a message cut inside its header" )
    {
        THEN( "the transaction id is shown once it is there" )
        {
            REQUIRE( fromClient( prefix( request, 7 ) ).description.empty() );
            REQUIRE( fromClient( prefix( request, 7 ) ).label == "DHCP" );
            REQUIRE( fromClient( prefix( request, 8 ) ).description
                     == "Boot Request - Transaction ID 0x3903f326" );
            REQUIRE( fromClient( prefix( request, 34 ) ).description
                     == "Boot Request - Transaction ID 0x3903f326 from 00:11:22:33:44:55" );
        }
    }

    GIVEN( "a payload on the DHCP ports that is no BOOTP message" )
    {
        THEN( "it is DHCP by its port, without a description" )
        {
            const auto described = fromClient( text( "hello, this is not BOOTP" ) );
            REQUIRE( described.label == "DHCP" );
            REQUIRE( described.description.empty() );
        }
    }
}

SCENARIO( "DHCPv6 names its message types", "[dhcpv6]" )
{
    GIVEN( "a Solicit with a client identifier and an Advertise" )
    {
        const auto solicit
            = overUdp( dhcpv6( 1, option6( 8, be16( 0 ) ) + option6( 1, kDuid ) ), 546, 547 );
        const auto advertise
            = overUdp( dhcpv6( 2, option6( 2, kDuid ) + option6( 1, kDuid ) ), 547, 546 );

        THEN( "they are DHCPv6, named with their transaction id and client DUID" )
        {
            REQUIRE( solicit.label == "DHCPv6" );
            REQUIRE( !solicit.guessed );
            REQUIRE( solicit.description
                     == "Solicit XID: 0x1a2b3c CID: 000100011c39cf88001122334455" );
            REQUIRE( advertise.description
                     == "Advertise XID: 0x1a2b3c CID: 000100011c39cf88001122334455" );
        }
    }

    GIVEN( "every client and server message type" )
    {
        THEN( "each is named as Wireshark names it" )
        {
            const char* const names[] = {
                "Solicit",
                "Advertise",
                "Request",
                "Confirm",
                "Renew",
                "Rebind",
                "Reply",
                "Release",
                "Decline",
                "Reconfigure",
                "Information-request",
            };
            for ( uint8_t type = 1; type <= 11; ++type ) {
                const auto described = overUdp( dhcpv6( type, {} ), 546, 547 );
                REQUIRE( described.description
                         == std::string( names[ type - 1 ] ) + " XID: 0x1a2b3c" );
            }
            REQUIRE( overUdp( dhcpv6( 99, {} ), 546, 547 ).description
                     == "Unknown (99) XID: 0x1a2b3c" );
        }
    }

    GIVEN( "a Solicit relayed by a relay agent" )
    {
        const auto relayed = relayForward( dhcpv6( 1, option6( 1, kDuid ) ) );

        THEN( "the relay names its link and the message it carries" )
        {
            REQUIRE( overUdp( relayed, 547, 547 ).description
                     == "Relay-forw L: 2001:db8::1, Solicit XID: 0x1a2b3c CID: "
                        "000100011c39cf88001122334455" );
        }
    }

    GIVEN( "a client identifier whose length runs past the message" )
    {
        const auto cut = dhcpv6( 1, be16( 1 ) + be16( 100 ) + kDuid );

        THEN( "it is not shown" )
        {
            REQUIRE( overUdp( cut, 546, 547 ).description == "Solicit XID: 0x1a2b3c" );
        }
    }

    GIVEN( "a message shorter than its header" )
    {
        THEN( "it is DHCPv6 by its port, without a description" )
        {
            const auto described = overUdp( { 1, 0x1A }, 546, 547 );
            REQUIRE( described.label == "DHCPv6" );
            REQUIRE( described.description.empty() );
        }
    }
}

SCENARIO( "NTP shows version, mode and stratum", "[ntp]" )
{
    GIVEN( "a client request and the server's reply" )
    {
        const auto request = overUdp( ntp( 4, 3, 0 ), 50123, 123 );
        const auto reply = overUdp( ntp( 4, 4, 2, { 192, 0, 2, 1 } ), 123, 50123 );

        THEN( "they are NTP, with the stratum the server tells" )
        {
            REQUIRE( request.label == "NTP" );
            REQUIRE( request.description == "NTP Version 4, client" );
            REQUIRE( reply.label == "NTP" );
            REQUIRE( reply.description == "NTP Version 4, server, stratum 2" );
        }
    }

    GIVEN( "a primary server and a kiss-o'-death" )
    {
        THEN( "the reference identifier is shown with the stratum" )
        {
            REQUIRE( overUdp( ntp( 4, 4, 1, text( "GPS" ) + Bytes{ 0 } ), 123, 123 ).description
                     == "NTP Version 4, server, stratum 1 (GPS)" );
            REQUIRE( overUdp( ntp( 4, 4, 0, text( "RATE" ) ), 123, 123 ).description
                     == "NTP Version 4, server, stratum 0 (RATE)" );
            REQUIRE( overUdp( ntp( 4, 4, 1, { 'G', 0x01, 'S', 0 } ), 123, 123 ).description
                     == "NTP Version 4, server, stratum 1" );
        }
    }

    GIVEN( "the other modes" )
    {
        THEN( "each is named as Wireshark names it" )
        {
            REQUIRE( overUdp( ntp( 3, 1, 3 ), 123, 123 ).description
                     == "NTP Version 3, symmetric active, stratum 3" );
            REQUIRE( overUdp( ntp( 3, 2, 3 ), 123, 123 ).description
                     == "NTP Version 3, symmetric passive, stratum 3" );
            REQUIRE( overUdp( ntp( 4, 5, 2 ), 123, 123 ).description
                     == "NTP Version 4, broadcast, stratum 2" );
            REQUIRE( overUdp( ntp( 4, 0, 2 ), 123, 123 ).description
                     == "NTP Version 4, reserved, stratum 2" );
            REQUIRE( overUdp( { ( 2 << 3 ) | 6, 0x01, 0, 1 }, 50000, 123 ).description
                     == "NTP Version 2, control" );
            REQUIRE( overUdp( { ( 2 << 3 ) | 7, 0, 3, 42 }, 50000, 123 ).description
                     == "NTP Version 2, private" );
        }
    }

    GIVEN( "a packet shorter than the NTP header, or of no NTP version" )
    {
        THEN( "it is NTP by its port, without a description" )
        {
            REQUIRE( overUdp( prefix( ntp( 4, 3, 0 ), 47 ), 50123, 123 ).description.empty() );
            const auto noVersion = overUdp( ntp( 0, 3, 0 ), 50123, 123 );
            REQUIRE( noVersion.label == "NTP" );
            REQUIRE( noVersion.description.empty() );
            REQUIRE( overUdp( ntp( 5, 3, 0 ), 50123, 123 ).description.empty() );
        }
    }
}

SCENARIO( "A malformed DHCP, DHCPv6 or NTP message is never read beyond the payload",
          "[dhcp][dhcpv6][ntp]" )
{
    struct Sample {
        Bytes message;
        uint16_t srcPort;
        uint16_t dstPort;
    };
    Header overloaded;
    overloaded.file = messageType( 3 ) + option( 12, text( "host" ) ) + kEnd;
    overloaded.file.resize( 128, 0 );
    const std::vector<Sample> samples{
        { dhcp( {},
                messageType( 3 ) + option( 50, kLeased ) + option( 12, text( "laptop" ) ) + kEnd ),
          68, 67 },
        { dhcp( overloaded, option( 52, { 3 } ) + kEnd ), 68, 67 },
        { relayForward( dhcpv6( 1, option6( 1, kDuid ) ) ), 547, 547 },
        { relayForward( relayForward( dhcpv6( 3, option6( 1, kDuid ) ) ) ), 547, 547 },
        { ntp( 4, 4, 1, text( "GPS" ) + Bytes{ 0 } ), 123, 123 },
    };

    GIVEN( "messages with random bytes changed, cut anywhere" )
    {
        THEN( "the description is one line of bounded length" )
        {
            std::mt19937 random( 48 );
            for ( int round = 0; round < 5000; ++round ) {
                const auto& sample = samples[ random() % samples.size() ];
                auto mutated = sample.message;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto cut = prefix( mutated, random() % ( mutated.size() + 1 ) );
                const auto described = overUdp( cut, sample.srcPort, sample.dstPort );
                REQUIRE( described.description.find( '\n' ) == std::string::npos );
                REQUIRE( described.description.size() < 1024 );
            }
        }
    }
}
