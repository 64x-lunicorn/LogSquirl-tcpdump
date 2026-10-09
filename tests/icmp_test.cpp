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
 * @file icmp_test.cpp
 * @brief BDD tests for how ICMP and ICMPv6 messages are described in Info:
 * echo ids and sequence numbers, the codes of error messages and the packet
 * they quote, and the targets and flags of neighbor discovery.
 */

#include <catch2/catch.hpp>

#include "pcapbuilder.h"

#include <random>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/** An ICMP or ICMPv6 header: type, code, checksum 0, then @p rest (4 bytes) and @p body. */
Bytes icmp( uint8_t type, uint8_t code, uint32_t rest, const Bytes& body = {} )
{
    Bytes b{ type, code, 0, 0 };
    putBE32( b, rest );
    return b + body;
}

/** An echo message's rest of header: identifier and sequence number. */
uint32_t idSeq( uint16_t id, uint16_t seq )
{
    return ( static_cast<uint32_t>( id ) << 16 ) | seq;
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

/** An IPv6 header from 2001:db8::@p src to 2001:db8::@p dst around @p payload. */
Bytes ipv6Between( uint8_t src, uint8_t dst, uint8_t nextHeader, const Bytes& payload )
{
    Bytes b{ 0x60, 0, 0, 0 };
    putBE16( b, static_cast<uint16_t>( payload.size() ) );
    b.push_back( nextHeader );
    b.push_back( 64 );
    return b + address6( src ) + address6( dst ) + payload;
}

/** A link-layer address option of @p type (1 source, 2 target). */
Bytes linkLayerOption( uint8_t type )
{
    return { type, 1, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb };
}

Bytes prefix( const Bytes& b, size_t n )
{
    return Bytes( b.begin(), b.begin() + static_cast<std::ptrdiff_t>( std::min( n, b.size() ) ) );
}

PacketRecord only( const Bytes& frame )
{
    auto result = parse( pcapOf( { frame } ) );
    REQUIRE( result.packets.size() == 1 );
    return result.packets[ 0 ];
}

PacketRecord overIpv4( const Bytes& message )
{
    return only( eth( EthertypeIpv4, ipv4( IpProtoIcmp, message ) ) );
}

PacketRecord overIpv6( const Bytes& message )
{
    return only( eth( EthertypeIpv6, ipv6( IpProtoIcmpv6, message ) ) );
}

/** The packet a router quotes: an IPv4 header and the first 8 bytes of its transport. */
Bytes quotedIpv4( uint8_t protocol, const Bytes& transport )
{
    Ipv4Options o;
    o.src[ 0 ] = 10, o.src[ 1 ] = 0, o.src[ 2 ] = 0, o.src[ 3 ] = 1;
    o.dst[ 0 ] = 192, o.dst[ 1 ] = 168, o.dst[ 2 ] = 1, o.dst[ 3 ] = 5;
    // The total length is the original packet's, longer than the quote.
    o.totalLength = 20 + static_cast<int>( transport.size() ) + 100;
    return ipv4( protocol, prefix( transport, 8 ), o );
}

const char* const kArrow = " \xe2\x86\x92 ";

} // namespace

SCENARIO( "Echo messages show their identifier and sequence number", "[icmp]" )
{
    GIVEN( "an ICMP echo request and its reply" )
    {
        const auto request = overIpv4( icmp( 8, 0, idSeq( 0x1234, 7 ), text( "ping" ) ) );
        const auto reply = overIpv4( icmp( 0, 0, idSeq( 0x1234, 7 ), text( "ping" ) ) );

        THEN( "both name the id in hexadecimal and the sequence number, like Wireshark" )
        {
            REQUIRE( request.protocol == "ICMP" );
            REQUIRE( request.info == "Echo (ping) request id=0x1234, seq=7" );
            REQUIRE( reply.info == "Echo (ping) reply id=0x1234, seq=7" );
        }
    }

    GIVEN( "an ICMPv6 echo request and its reply" )
    {
        const auto request = overIpv6( icmp( 128, 0, idSeq( 0x00ab, 65535 ) ) );
        const auto reply = overIpv6( icmp( 129, 0, idSeq( 0x00ab, 65535 ) ) );

        THEN( "they read like ICMP's" )
        {
            REQUIRE( request.protocol == "ICMPv6" );
            REQUIRE( request.info == "Echo (ping) request id=0x00ab, seq=65535" );
            REQUIRE( reply.info == "Echo (ping) reply id=0x00ab, seq=65535" );
        }
    }

    GIVEN( "an ICMP timestamp request" )
    {
        THEN( "it shows its id and sequence number too" )
        {
            REQUIRE( overIpv4( icmp( 13, 0, idSeq( 1, 2 ), Bytes( 12, 0 ) ) ).info
                     == "Timestamp request id=0x0001, seq=2" );
        }
    }
}

SCENARIO( "ICMP error messages name their code and the packet they quote", "[icmp]" )
{
    GIVEN( "a port unreachable quoting a UDP datagram" )
    {
        const auto pkt
            = overIpv4( icmp( 3, 3, 0, quotedIpv4( IpProtoUdp, udp( 51234, 53, text( "q" ) ) ) ) );

        THEN( "Info names the code, the datagram's addresses, ports and protocol" )
        {
            REQUIRE( pkt.protocol == "ICMP" );
            REQUIRE(
                pkt.info
                == std::string( "Destination unreachable (Port unreachable) for 10.0.0.1:51234" )
                       + kArrow + "192.168.1.5:53 UDP" );
            REQUIRE_FALSE( pkt.transport );
            REQUIRE( pkt.srcPort == 0 );
        }
    }

    GIVEN( "a TTL exceeded quoting the first 8 bytes of a TCP segment" )
    {
        const auto pkt = overIpv4(
            icmp( 11, 0, 0, quotedIpv4( IpProtoTcp, tcp( 51234, 443, text( "x" ) ) ) ) );

        THEN( "the ports are read from the 8 bytes a router quotes" )
        {
            REQUIRE( pkt.info
                     == std::string( "Time exceeded (TTL exceeded in transit) for 10.0.0.1:51234" )
                            + kArrow + "192.168.1.5:443 TCP" );
        }
    }

    GIVEN( "a fragmentation needed with the next hop's MTU" )
    {
        const auto pkt = overIpv4(
            icmp( 3, 4, 1400, quotedIpv4( IpProtoTcp, tcp( 51234, 443, Bytes( 1500, 0 ) ) ) ) );

        THEN( "Info names the MTU" )
        {
            REQUIRE( pkt.info
                     == std::string( "Destination unreachable (Fragmentation needed, mtu=1400) "
                                     "for 10.0.0.1:51234" )
                            + kArrow + "192.168.1.5:443 TCP" );
        }
    }

    GIVEN( "a host unreachable quoting an ICMP echo request" )
    {
        const auto pkt
            = overIpv4( icmp( 3, 1, 0, quotedIpv4( IpProtoIcmp, icmp( 8, 0, idSeq( 1, 1 ) ) ) ) );

        THEN( "the quoted packet has addresses and protocol, but no ports" )
        {
            REQUIRE( pkt.info
                     == std::string( "Destination unreachable (Host unreachable) for 10.0.0.1" )
                            + kArrow + "192.168.1.5 ICMP" );
        }
    }

    GIVEN( "a redirect" )
    {
        const auto pkt
            = overIpv4( icmp( 5, 1, 0x0A0000FE, quotedIpv4( IpProtoUdp, udp( 1, 2 ) ) ) );

        THEN( "Info names the gateway to use" )
        {
            REQUIRE(
                pkt.info
                == std::string( "Redirect (Redirect for host) gateway=10.0.0.254 for 10.0.0.1:1" )
                       + kArrow + "192.168.1.5:2 UDP" );
        }
    }

    GIVEN( "an unreachable with a code that has no name" )
    {
        THEN( "the code is shown as a number" )
        {
            REQUIRE( overIpv4( icmp( 3, 99, 0 ) ).info == "Destination unreachable (code=99)" );
        }
    }

    GIVEN( "an ICMP type that has no name" )
    {
        THEN( "type and code are shown as numbers" )
        {
            REQUIRE( overIpv4( icmp( 42, 1, 0 ) ).info == "Type=42 Code=1" );
            REQUIRE( overIpv6( icmp( 200, 3, 0 ) ).info == "Type=200 Code=3" );
        }
    }

    GIVEN( "an ICMPv6 port unreachable quoting a UDP datagram" )
    {
        const auto quoted = ipv6Between( 1, 2, IpProtoUdp, udp( 5353, 53, text( "query" ) ) );
        const auto pkt = overIpv6( icmp( 1, 4, 0, quoted ) );

        THEN( "the quoted IPv6 addresses are bracketed before their ports" )
        {
            REQUIRE( pkt.protocol == "ICMPv6" );
            REQUIRE( pkt.info
                     == std::string( "Destination unreachable (Port unreachable) for "
                                     "[2001:db8::1]:5353" )
                            + kArrow + "[2001:db8::2]:53 UDP" );
        }
    }

    GIVEN( "an ICMPv6 packet too big quoting a TCP segment behind an extension header" )
    {
        const auto quoted = ipv6Between(
            1, 2, 0, ipv6Options( IpProtoTcp, tcp( 40000, 443, Bytes( 1400, 0 ) ) ) );
        const auto pkt = overIpv6( icmp( 2, 0, 1280, prefix( quoted, 1232 ) ) );

        THEN( "the extension header is walked to the ports" )
        {
            REQUIRE( pkt.info
                     == std::string( "Packet too big mtu=1280 for [2001:db8::1]:40000" ) + kArrow
                            + "[2001:db8::2]:443 TCP" );
        }
    }

    GIVEN( "an ICMPv6 time exceeded and a parameter problem" )
    {
        const auto quoted = ipv6Between( 1, 2, IpProtoIcmpv6, icmp( 128, 0, idSeq( 1, 1 ) ) );

        THEN( "both name their code" )
        {
            REQUIRE(
                overIpv6( icmp( 3, 0, 0, quoted ) ).info
                == std::string( "Time exceeded (Hop limit exceeded in transit) for 2001:db8::1" )
                       + kArrow + "2001:db8::2 ICMPv6" );
            REQUIRE( overIpv6( icmp( 4, 1, 40, quoted ) ).info
                     == std::string( "Parameter problem (Unrecognized Next Header type) for "
                                     "2001:db8::1" )
                            + kArrow + "2001:db8::2 ICMPv6" );
        }
    }
}

SCENARIO( "A cut quoted packet is described as far as it goes", "[icmp]" )
{
    const auto quoted = quotedIpv4( IpProtoUdp, udp( 51234, 53 ) );

    GIVEN( "a port unreachable whose quote is cut at every length" )
    {
        THEN( "the addresses need the IP header, the ports 4 bytes of UDP" )
        {
            for ( size_t n = 0; n <= quoted.size(); ++n ) {
                INFO( "quote cut to " << n << " bytes" );
                const auto info = overIpv4( icmp( 3, 3, 0, prefix( quoted, n ) ) ).info;
                if ( n < 20 ) {
                    REQUIRE( info == "Destination unreachable (Port unreachable)" );
                }
                else if ( n < 24 ) {
                    REQUIRE( info
                             == std::string( "Destination unreachable (Port unreachable) for "
                                             "10.0.0.1" )
                                    + kArrow + "192.168.1.5 UDP" );
                }
                else {
                    REQUIRE( info
                             == std::string( "Destination unreachable (Port unreachable) for "
                                             "10.0.0.1:51234" )
                                    + kArrow + "192.168.1.5:53 UDP" );
                }
            }
        }
    }

    GIVEN( "an ICMPv6 unreachable whose quote is cut inside the IPv6 header" )
    {
        const auto quoted6 = ipv6Between( 1, 2, IpProtoUdp, udp( 1, 2 ) );

        THEN( "nothing of it is shown" )
        {
            REQUIRE( overIpv6( icmp( 1, 3, 0, prefix( quoted6, 39 ) ) ).info
                     == "Destination unreachable (Address unreachable)" );
        }
    }

    GIVEN( "a quote that is a fragment after the first" )
    {
        Ipv4Options o;
        o.fragment = 100;
        const auto pkt = overIpv4( icmp( 11, 1, 0, ipv4( IpProtoUdp, udp( 1, 2 ), o ) ) );

        THEN( "it has addresses and protocol, but no ports" )
        {
            REQUIRE( pkt.info
                     == std::string( "Time exceeded (Fragment reassembly time exceeded) for "
                                     "192.168.1.1" )
                            + kArrow + "192.168.1.2 UDP" );
        }
    }

    GIVEN( "a quote that is itself an ICMP error quoting a packet" )
    {
        const auto inner
            = ipv4( IpProtoIcmp, icmp( 3, 3, 0, quotedIpv4( IpProtoUdp, udp( 1, 2 ) ) ) );
        const auto pkt = overIpv4( icmp( 3, 1, 0, inner ) );

        THEN( "only the outer quote is described" )
        {
            REQUIRE( pkt.info
                     == std::string( "Destination unreachable (Host unreachable) for 192.168.1.1" )
                            + kArrow + "192.168.1.2 ICMP" );
        }
    }

    GIVEN( "a quote that is not an IP packet" )
    {
        THEN( "nothing of it is shown" )
        {
            REQUIRE( overIpv4( icmp( 3, 3, 0, Bytes( 28, 0x55 ) ) ).info
                     == "Destination unreachable (Port unreachable)" );
        }
    }
}

SCENARIO( "Neighbor discovery shows targets, link-layer addresses and flags", "[icmp]" )
{
    GIVEN( "a neighbor solicitation with a source link-layer address" )
    {
        const auto pkt = overIpv6( icmp( 135, 0, 0, address6( 2 ) + linkLayerOption( 1 ) ) );

        THEN( "Info names the target and who asks, like Wireshark" )
        {
            REQUIRE( pkt.info == "Neighbor solicitation for 2001:db8::2 from 66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a neighbor advertisement with all flags and a target link-layer address" )
    {
        const auto pkt
            = overIpv6( icmp( 136, 0, 0xE0000000, address6( 2 ) + linkLayerOption( 2 ) ) );

        THEN( "Info names the target, the flags and the address" )
        {
            REQUIRE( pkt.info
                     == "Neighbor advertisement 2001:db8::2 (rtr, sol, ovr) is at "
                        "66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a neighbor advertisement without flags or options" )
    {
        THEN( "Info names the target only" )
        {
            REQUIRE( overIpv6( icmp( 136, 0, 0, address6( 9 ) ) ).info
                     == "Neighbor advertisement 2001:db8::9" );
        }
    }

    GIVEN( "a router solicitation with a source link-layer address" )
    {
        THEN( "Info names who asks" )
        {
            REQUIRE( overIpv6( icmp( 133, 0, 0, linkLayerOption( 1 ) ) ).info
                     == "Router solicitation from 66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a router advertisement with the managed and other flags and high preference" )
    {
        // Hop limit 64, flags M O Prf=01, lifetime 1800 s; reachable and retrans timers.
        const auto pkt
            = overIpv6( icmp( 134, 0, 0x40C80708, Bytes( 8, 0 ) + linkLayerOption( 1 ) ) );

        THEN( "Info names the flags, the router lifetime and the router's address" )
        {
            REQUIRE( pkt.info
                     == "Router advertisement (M, O, prf=high) lifetime=1800s from "
                        "66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a router advertisement without flags" )
    {
        THEN( "Info names the lifetime only" )
        {
            REQUIRE( overIpv6( icmp( 134, 0, 0x40000000, Bytes( 8, 0 ) ) ).info
                     == "Router advertisement lifetime=0s" );
        }
    }

    GIVEN( "a neighbor solicitation cut inside its target" )
    {
        THEN( "only its name is shown" )
        {
            REQUIRE( overIpv6( icmp( 135, 0, 0, Bytes( 15, 0 ) ) ).info
                     == "Neighbor solicitation" );
        }
    }

    GIVEN( "options with a length of 0 or running past the message" )
    {
        THEN( "the walk stops without reading beyond them" )
        {
            REQUIRE( overIpv6( icmp( 135, 0, 0, address6( 2 ) + Bytes{ 1, 0, 1, 2 } ) ).info
                     == "Neighbor solicitation for 2001:db8::2" );
            REQUIRE( overIpv6( icmp( 133, 0, 0, Bytes{ 1, 2, 1, 2, 3, 4, 5, 6 } ) ).info
                     == "Router solicitation" );
        }
    }

    GIVEN( "an MLDv2 report" )
    {
        THEN( "it is named" )
        {
            REQUIRE( overIpv6( icmp( 143, 0, 0 ) ).info == "Multicast listener report v2" );
        }
    }
}

SCENARIO( "A malformed ICMP message is never read beyond the packet", "[icmp]" )
{
    const std::vector<Bytes> messages{
        icmp( 3, 3, 0, quotedIpv4( IpProtoUdp, udp( 51234, 53 ) ) ),
        icmp( 11, 0, 0, quotedIpv4( IpProtoTcp, tcp( 1, 2 ) ) ),
        icmp( 5, 0, 0x0A000001, quotedIpv4( IpProtoIcmp, icmp( 3, 3, 0 ) ) ),
    };
    const std::vector<Bytes> messages6{
        icmp( 1, 4, 0, ipv6Between( 1, 2, 0, ipv6Options( IpProtoUdp, udp( 1, 2 ) ) ) ),
        icmp( 135, 0, 0, address6( 2 ) + linkLayerOption( 1 ) ),
        icmp( 136, 0, 0xE0000000, address6( 2 ) + linkLayerOption( 2 ) ),
        icmp( 134, 0, 0x40C80708, Bytes( 8, 0 ) + linkLayerOption( 1 ) ),
    };

    GIVEN( "messages with random bytes changed, cut anywhere" )
    {
        THEN( "Info is one line of bounded length" )
        {
            std::mt19937 random( 47 );
            for ( int round = 0; round < 5000; ++round ) {
                const bool v6 = round % 2 == 1;
                const auto& pool = v6 ? messages6 : messages;
                auto mutated = pool[ random() % pool.size() ];
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                // Keep the type, so that the message's own dissection is exercised.
                mutated[ 0 ] = pool[ random() % pool.size() ][ 0 ];
                const auto cut = prefix( mutated, 8 + random() % ( mutated.size() - 7 ) );
                const auto pkt = v6 ? overIpv6( cut ) : overIpv4( cut );
                REQUIRE( pkt.info.find( '\n' ) == std::string::npos );
                REQUIRE( pkt.info.size() < 512 );
            }
        }
    }
}
