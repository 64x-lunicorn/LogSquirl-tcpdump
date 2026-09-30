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
 * @file socks_test.cpp
 * @brief BDD tests for the SOCKS4/SOCKS5 handshake descriptions.
 */

#include <catch2/catch.hpp>

#include "pcapbuilder.h"

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kClientPort = 50000;
constexpr uint16_t kProxyPort = 1080;

/** The packet parsed from a TCP segment carrying @p payload between the two ports. */
PacketRecord segment( uint16_t srcPort, uint16_t dstPort, const Bytes& payload )
{
    auto result = parse(
        pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( srcPort, dstPort, payload ) ) ) } ) );
    REQUIRE( result.packets.size() == 1 );
    return result.packets[ 0 ];
}

PacketRecord toProxy( const Bytes& payload )
{
    return segment( kClientPort, kProxyPort, payload );
}

PacketRecord fromProxy( const Bytes& payload )
{
    return segment( kProxyPort, kClientPort, payload );
}

bool contains( const std::string& haystack, const std::string& needle )
{
    return haystack.find( needle ) != std::string::npos;
}

} // namespace

SCENARIO( "SOCKS codes are shown in hexadecimal", "[socks]" )
{
    GIVEN( "a SOCKS5 reply with status 0x0A from the proxy" )
    {
        auto pkt = fromProxy( { 0x05, 0x0A, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90 } );

        THEN( "the status reads 0x0A" )
        {
            REQUIRE( pkt.protocol == "SOCKS" );
            REQUIRE( contains( pkt.info, "Status: Unknown (0x0A)" ) );
            REQUIRE( contains( pkt.info, "Bound: 10.0.0.1:8080" ) );
        }
    }

    GIVEN( "a SOCKS5 reply with status Host Unreachable" )
    {
        auto pkt = fromProxy( { 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 } );

        THEN( "the status reads 0x04" )
        {
            REQUIRE( contains( pkt.info, "Status: Host Unreachable (0x04)" ) );
        }
    }

    GIVEN( "a SOCKS5 method choice of an unassigned method" )
    {
        auto pkt = fromProxy( { 0x05, 0x80 } );

        THEN( "the method reads 0x80" )
        {
            REQUIRE(
                contains( pkt.info, "SOCKS5 Server Choice, Version: 5, Method: Unknown (0x80)" ) );
        }
    }

    GIVEN( "a failed username/password authentication" )
    {
        auto pkt = fromProxy( { 0x01, 0x1B } );

        THEN( "the status reads 0x1B" )
        {
            REQUIRE( contains( pkt.info, "SOCKS5 Auth Response, Status: Failure (0x1B)" ) );
        }
    }

    GIVEN( "a client greeting offering an unassigned method" )
    {
        auto pkt = toProxy( { 0x05, 0x02, 0x00, 0x8C } );

        THEN( "the method reads 0x8C" )
        {
            REQUIRE(
                contains( pkt.info, "Methods: 2 [No Authentication (0x00), Unknown (0x8C)]" ) );
        }
    }
}

SCENARIO( "Only well-formed SOCKS messages are labelled", "[socks]" )
{
    GIVEN( "data from the proxy that starts with 0x05 but is no SOCKS message" )
    {
        auto pkt = fromProxy( text( "\x05hello world" ) );

        THEN( "it is not labelled a SOCKS5 server choice" )
        {
            REQUIRE_FALSE( contains( pkt.info, "SOCKS" ) );
        }
    }

    GIVEN( "a method choice followed by more data" )
    {
        auto pkt = fromProxy( { 0x05, 0x00, 0x41 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( pkt.info, "SOCKS5" ) );
        }
    }

    GIVEN( "a connect request whose domain is longer than the segment" )
    {
        auto pkt = toProxy( { 0x05, 0x01, 0x00, 0x03, 50, 'a', 'b', 0x00, 0x50 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( pkt.info, "SOCKS5" ) );
        }
    }

    GIVEN( "a SOCKS5 reply with an invalid address type" )
    {
        auto pkt = fromProxy( { 0x05, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( pkt.info, "SOCKS5" ) );
        }
    }

    GIVEN( "an auth request whose lengths do not add up" )
    {
        auto pkt = toProxy( { 0x01, 0x03, 'b', 'o', 'b', 0x09, 'x' } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( pkt.info, "Auth Request" ) );
        }
    }

    GIVEN( "a SOCKS4 request without the terminating NUL of its user id" )
    {
        auto pkt = toProxy( { 0x04, 0x01, 0x00, 0x50, 10, 0, 0, 1, 'b', 'o', 'b' } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( pkt.info, "SOCKS4" ) );
        }
    }

    GIVEN( "a SOCKS5 greeting sent by the proxy instead of to it" )
    {
        auto pkt = fromProxy( { 0x05, 0x01, 0x00 } );

        THEN( "it is not labelled a client greeting" )
        {
            REQUIRE_FALSE( contains( pkt.info, "Client Greeting" ) );
        }
    }
}

SCENARIO( "SOCKS messages are described with their fields", "[socks]" )
{
    GIVEN( "a SOCKS5 connect request to a domain" )
    {
        auto pkt = toProxy( { 0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.',
                              'c', 'o', 'm', 0x01, 0xBB } );

        THEN( "the destination is shown" )
        {
            REQUIRE( contains( pkt.info, "SOCKS5 Connect, Version: 5, Command: Connect (0x01), "
                                         "Address Type: Domain, Destination: example.com:443" ) );
        }
    }

    GIVEN( "a SOCKS5 UDP associate request to an IPv6 address" )
    {
        Bytes msg{ 0x05, 0x03, 0x00, 0x04 };
        Bytes addr( 16, 0 );
        addr[ 0 ] = 0x20;
        addr[ 1 ] = 0x01;
        addr[ 15 ] = 1;
        msg = msg + addr + Bytes{ 0x00, 0x35 };
        auto pkt = toProxy( msg );

        THEN( "the command and destination are shown" )
        {
            REQUIRE( contains( pkt.info, "Command: UDP Associate (0x03)" ) );
            REQUIRE( contains( pkt.info, "Destination: 2001:0:0:0:0:0:0:1:53" ) );
        }
    }

    GIVEN( "a username/password request" )
    {
        auto pkt = toProxy( { 0x01, 0x03, 'b', 'o', 'b', 0x04, 's', '"', 0x0A, '\\' } );

        THEN( "user name and password are shown, with special characters escaped" )
        {
            REQUIRE(
                contains( pkt.info, R"(SOCKS5 Auth Request, User: "bob", Pass: "s\"\x0A\\")" ) );
        }
    }

    GIVEN( "a successful authentication" )
    {
        auto pkt = fromProxy( { 0x01, 0x00 } );

        THEN( "success is shown" )
        {
            REQUIRE( contains( pkt.info, "SOCKS5 Auth Response, Status: Success (0x00)" ) );
        }
    }

    GIVEN( "a SOCKS4a request with a user id and a domain" )
    {
        auto pkt = toProxy(
            { 0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 'b', 'o', 'b', 0x00, 'h', 'o', 's', 't', 0x00 } );

        THEN( "user id and domain are shown" )
        {
            REQUIRE( contains( pkt.info, "SOCKS4, Version: 4, Command: Connect (0x01), "
                                         "Destination: 0.0.0.1:80, User: \"bob\", Domain: host" ) );
        }
    }

    GIVEN( "a SOCKS4 reply granting the request" )
    {
        auto pkt = fromProxy( { 0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0 } );

        THEN( "the grant is shown" )
        {
            REQUIRE( contains( pkt.info, "SOCKS4 Reply, Status: Request Granted (0x5A)" ) );
        }
    }
}
