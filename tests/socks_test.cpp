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
 * @brief BDD tests for the SOCKS4/SOCKS5 handshake descriptions, through the
 *        Payload Describer: a payload and its ports, no frame around them.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"

#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint16_t kClientPort = 50000;
constexpr uint16_t kProxyPort = 1080;

Bytes text( const std::string& s )
{
    return Bytes( s.begin(), s.end() );
}

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

/** What the describer says about a TCP @p payload sent between the two ports. */
PayloadDescription segment( uint16_t srcPort, uint16_t dstPort, const Bytes& payload )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), srcPort, dstPort );
}

PayloadDescription toProxy( const Bytes& payload )
{
    return segment( kClientPort, kProxyPort, payload );
}

PayloadDescription fromProxy( const Bytes& payload )
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
        const auto described = fromProxy( { 0x05, 0x0A, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90 } );

        THEN( "the status reads 0x0A" )
        {
            REQUIRE( described.label == "SOCKS" );
            REQUIRE( contains( described.description, "Status: Unknown (0x0A)" ) );
            REQUIRE( contains( described.description, "Bound: 10.0.0.1:8080" ) );
        }
    }

    GIVEN( "a SOCKS5 reply with status Host Unreachable" )
    {
        const auto described = fromProxy( { 0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0 } );

        THEN( "the status reads 0x04" )
        {
            REQUIRE( contains( described.description, "Status: Host Unreachable (0x04)" ) );
        }
    }

    GIVEN( "a SOCKS5 method choice of an unassigned method" )
    {
        const auto described = fromProxy( { 0x05, 0x80 } );

        THEN( "the method reads 0x80" )
        {
            REQUIRE( contains( described.description,
                               "SOCKS5 Server Choice, Version: 5, Method: Unknown (0x80)" ) );
        }
    }

    GIVEN( "a failed username/password authentication" )
    {
        const auto described = fromProxy( { 0x01, 0x1B } );

        THEN( "the status reads 0x1B" )
        {
            REQUIRE(
                contains( described.description, "SOCKS5 Auth Response, Status: Failure (0x1B)" ) );
        }
    }

    GIVEN( "a client greeting offering an unassigned method" )
    {
        const auto described = toProxy( { 0x05, 0x02, 0x00, 0x8C } );

        THEN( "the method reads 0x8C" )
        {
            REQUIRE( contains( described.description,
                               "Methods: 2 [No Authentication (0x00), Unknown (0x8C)]" ) );
        }
    }
}

SCENARIO( "Only well-formed SOCKS messages are labelled", "[socks]" )
{
    GIVEN( "data from the proxy that starts with 0x05 but is no SOCKS message" )
    {
        const auto described = fromProxy( text( "\x05hello world" ) );

        THEN( "it is not labelled a SOCKS5 server choice" )
        {
            REQUIRE_FALSE( contains( described.description, "SOCKS" ) );
        }
    }

    GIVEN( "a method choice followed by more data" )
    {
        const auto described = fromProxy( { 0x05, 0x00, 0x41 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( described.description, "SOCKS5" ) );
        }
    }

    GIVEN( "a connect request whose domain is longer than the segment" )
    {
        const auto described = toProxy( { 0x05, 0x01, 0x00, 0x03, 50, 'a', 'b', 0x00, 0x50 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( described.description, "SOCKS5" ) );
        }
    }

    GIVEN( "a SOCKS5 reply with an invalid address type" )
    {
        const auto described = fromProxy( { 0x05, 0x00, 0x00, 0x07, 0, 0, 0, 0, 0, 0 } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( described.description, "SOCKS5" ) );
        }
    }

    GIVEN( "an auth request whose lengths do not add up" )
    {
        const auto described = toProxy( { 0x01, 0x03, 'b', 'o', 'b', 0x09, 'x' } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( described.description, "Auth Request" ) );
        }
    }

    GIVEN( "a SOCKS4 request without the terminating NUL of its user id" )
    {
        const auto described = toProxy( { 0x04, 0x01, 0x00, 0x50, 10, 0, 0, 1, 'b', 'o', 'b' } );

        THEN( "it is not labelled" )
        {
            REQUIRE_FALSE( contains( described.description, "SOCKS4" ) );
        }
    }

    GIVEN( "a SOCKS5 greeting sent by the proxy instead of to it" )
    {
        const auto described = fromProxy( { 0x05, 0x01, 0x00 } );

        THEN( "it is not labelled a client greeting" )
        {
            REQUIRE_FALSE( contains( described.description, "Client Greeting" ) );
        }
    }
}

SCENARIO( "SOCKS messages are described with their fields", "[socks]" )
{
    GIVEN( "a SOCKS5 connect request to a domain" )
    {
        const auto described = toProxy( { 0x05, 0x01, 0x00, 0x03, 11, 'e', 'x', 'a', 'm', 'p', 'l',
                                          'e', '.', 'c', 'o', 'm', 0x01, 0xBB } );

        THEN( "the destination is shown" )
        {
            REQUIRE( contains( described.description,
                               "SOCKS5 Connect, Version: 5, Command: Connect (0x01), "
                               "Address Type: Domain, Destination: example.com:443" ) );
        }
    }

    GIVEN( "a SOCKS5 connect request to an IPv4 address" )
    {
        const auto described = toProxy( { 0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB } );

        THEN( "the command, address type and destination are shown" )
        {
            REQUIRE( described.label == "SOCKS" );
            REQUIRE( described.description
                     == "SOCKS5 Connect, Version: 5, Command: Connect (0x01), "
                        "Address Type: IPv4, Destination: 93.184.216.34:443" );
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
        const auto described = toProxy( msg );

        THEN( "the command and destination are shown" )
        {
            REQUIRE( contains( described.description, "Command: UDP Associate (0x03)" ) );
            REQUIRE( contains( described.description, "Destination: [2001::1]:53" ) );
        }
    }

    GIVEN( "a username/password request" )
    {
        const auto described = toProxy( { 0x01, 0x03, 'b', 'o', 'b', 0x04, 's', '"', 0x0A, '\\' } );

        THEN( "user name and password are shown, with special characters escaped" )
        {
            REQUIRE( contains( described.description,
                               R"(SOCKS5 Auth Request, User: "bob", Pass: "s\"\x0A\\")" ) );
        }
    }

    GIVEN( "a successful authentication" )
    {
        const auto described = fromProxy( { 0x01, 0x00 } );

        THEN( "success is shown" )
        {
            REQUIRE(
                contains( described.description, "SOCKS5 Auth Response, Status: Success (0x00)" ) );
        }
    }

    GIVEN( "a SOCKS4 connect request without a user id" )
    {
        const auto described = toProxy( { 0x04, 0x01, 0x00, 0x50, 10, 0, 0, 1, 0x00 } );

        THEN( "the destination is shown, and no user" )
        {
            REQUIRE( described.label == "SOCKS" );
            REQUIRE( described.description
                     == "SOCKS4, Version: 4, Command: Connect (0x01), Destination: 10.0.0.1:80" );
        }
    }

    GIVEN( "a SOCKS4a request with a user id and a domain" )
    {
        const auto described = toProxy(
            { 0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 'b', 'o', 'b', 0x00, 'h', 'o', 's', 't', 0x00 } );

        THEN( "user id and domain are shown" )
        {
            REQUIRE( contains( described.description,
                               "SOCKS4, Version: 4, Command: Connect (0x01), "
                               "Destination: 0.0.0.1:80, User: \"bob\", Domain: host" ) );
        }
    }

    GIVEN( "a SOCKS4 reply granting the request" )
    {
        const auto described = fromProxy( { 0x00, 0x5A, 0x00, 0x00, 0, 0, 0, 0 } );

        THEN( "the grant is shown" )
        {
            REQUIRE(
                contains( described.description, "SOCKS4 Reply, Status: Request Granted (0x5A)" ) );
        }
    }
}
