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
 * @file wire_bytes_test.cpp
 * @brief BDD tests for formatting the fields of a packet as they lie on the wire.
 */

#include <catch2/catch.hpp>

#include <array>

#include "wire_bytes.h"

using namespace tcpdump;

namespace {

/// The IPv6 address of the eight 16-bit @p groups, formatted.
std::string ipv6Of( const std::array<uint16_t, 8>& groups )
{
    std::array<uint8_t, 16> bytes{};
    for ( size_t i = 0; i < groups.size(); ++i ) {
        bytes[ 2 * i ] = static_cast<uint8_t>( groups[ i ] >> 8 );
        bytes[ 2 * i + 1 ] = static_cast<uint8_t>( groups[ i ] & 0xFF );
    }
    return formatIpv6( bytes.data() );
}

} // namespace

SCENARIO( "IPv4 and MAC addresses are formatted as Wireshark writes them", "[wire_bytes]" )
{
    const uint8_t ipv4[][ 4 ] = { { 0, 0, 0, 0 }, { 192, 168, 10, 9 }, { 255, 100, 99, 1 } };
    const uint8_t mac[ 6 ] = { 0x00, 0x1a, 0x2B, 0xc0, 0xff, 0x09 };

    THEN( "an IPv4 address in dotted decimal, without leading zeros" )
    {
        REQUIRE( formatIpv4( ipv4[ 0 ] ) == "0.0.0.0" );
        REQUIRE( formatIpv4( ipv4[ 1 ] ) == "192.168.10.9" );
        REQUIRE( formatIpv4( ipv4[ 2 ] ) == "255.100.99.1" );
    }

    THEN( "a MAC address as six lowercase hexadecimal pairs" )
    {
        REQUIRE( formatMac( mac ) == "00:1a:2b:c0:ff:09" );
    }
}

SCENARIO( "IPv6 addresses are formatted in RFC 5952 form", "[wire_bytes]" )
{
    GIVEN( "a link-local address" )
    {
        THEN( "its longest run of zero groups becomes ::" )
        {
            REQUIRE( ipv6Of( { 0xfe80, 0, 0, 0, 0, 0, 0, 1 } ) == "fe80::1" );
        }
    }

    GIVEN( "the unspecified and the loopback address" )
    {
        THEN( "they are :: and ::1" )
        {
            REQUIRE( ipv6Of( { 0, 0, 0, 0, 0, 0, 0, 0 } ) == "::" );
            REQUIRE( ipv6Of( { 0, 0, 0, 0, 0, 0, 0, 1 } ) == "::1" );
        }
    }

    GIVEN( "an address ending in zero groups" )
    {
        THEN( "the run is collapsed at the end" )
        {
            REQUIRE( ipv6Of( { 0xff02, 0x1, 0, 0, 0, 0, 0, 0 } ) == "ff02:1::" );
        }
    }

    GIVEN( "two runs of zero groups of the same length" )
    {
        THEN( "the leftmost one is collapsed" )
        {
            REQUIRE( ipv6Of( { 0x2001, 0xdb8, 0, 0, 1, 0, 0, 1 } ) == "2001:db8::1:0:0:1" );
        }
    }

    GIVEN( "two runs of zero groups of different lengths" )
    {
        THEN( "the longer one is collapsed" )
        {
            REQUIRE( ipv6Of( { 0x2001, 0, 0, 1, 0, 0, 0, 1 } ) == "2001:0:0:1::1" );
        }
    }

    GIVEN( "a single zero group" )
    {
        THEN( "it is not collapsed" )
        {
            REQUIRE( ipv6Of( { 0x2001, 0xdb8, 0, 1, 1, 1, 1, 1 } ) == "2001:db8:0:1:1:1:1:1" );
        }
    }

    GIVEN( "an address without zero groups" )
    {
        THEN( "every group is shown in lowercase without leading zeros" )
        {
            REQUIRE( ipv6Of( { 0x2001, 0xdb8, 0xabcd, 0x12, 0xff, 0xa, 0xbeef, 0x1 } )
                     == "2001:db8:abcd:12:ff:a:beef:1" );
        }
    }
}
