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
 * @file payload_describer_test.cpp
 * @brief BDD tests for the Payload Describer: payload bytes and ports in,
 *        label and description out, with no frame around them.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"

#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

PayloadDescription describe( Transport transport, const Bytes& payload, uint16_t srcPort,
                             uint16_t dstPort )
{
    return describePayload( transport, payload.data(), payload.size(), srcPort, dstPort );
}

} // namespace

SCENARIO( "The describer names a TCP payload from its bytes and ports alone", "[describer]" )
{
    GIVEN( "a SOCKS5 client greeting sent to a proxy port" )
    {
        const Bytes greeting{ 0x05, 0x02, 0x00, 0x02 };

        WHEN( "it is described" )
        {
            const auto described = describe( Transport::Tcp, greeting, 50000, 1080 );

            THEN( "the label is SOCKS and the description names the methods" )
            {
                REQUIRE( described.label == "SOCKS" );
                REQUIRE( described.description
                         == "SOCKS5 Client Greeting, Version: 5, Methods: 2 "
                            "[No Authentication (0x00), Username/Password (0x02)]" );
            }
        }
    }
}

SCENARIO( "The describer names a UDP payload from its bytes and ports alone", "[describer]" )
{
    GIVEN( "a DNS query for example.com sent to port 53" )
    {
        const Bytes query{ 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',
                           0x03, 'c',  'o',  'm',  0x00, 0x00, 0x01, 0x00, 0x01 };

        WHEN( "it is described" )
        {
            const auto described = describe( Transport::Udp, query, 54321, 53 );

            THEN( "the label is DNS and the description names the query" )
            {
                REQUIRE( described.label == "DNS" );
                REQUIRE( described.description == "Query example.com" );
            }
        }
    }
}
