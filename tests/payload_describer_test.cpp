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

#include <algorithm>
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

Bytes text( const std::string& s )
{
    return Bytes( s.begin(), s.end() );
}

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

bool contains( const std::string& haystack, const std::string& needle )
{
    return haystack.find( needle ) != std::string::npos;
}

bool isOneLine( const std::string& s )
{
    return std::none_of( s.begin(), s.end(), []( char c ) {
        const auto byte = static_cast<uint8_t>( c );
        return byte < 0x20 || byte == 0x7F;
    } );
}

/// Ports no detector knows, so that only the preview applies.
constexpr uint16_t kUnknownSrc = 49152;
constexpr uint16_t kUnknownDst = 60001;

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

    GIVEN( "a TLS handshake record carrying a Client Hello" )
    {
        const Bytes record{ 0x16, 0x03, 0x03, 0x00, 0x05, 0x01 };

        THEN( "the label is TLS and the description names the message" )
        {
            const auto described = describe( Transport::Tcp, record, 49152, 443 );
            REQUIRE( described.label == "TLS" );
            REQUIRE( described.description == "Client Hello" );
        }
    }

    GIVEN( "a TLS application data record" )
    {
        const Bytes record{ 0x17, 0x03, 0x03, 0x00, 0x10, 0xAB, 0xCD };

        THEN( "it is labelled TLS whatever the ports" )
        {
            const auto described = describe( Transport::Tcp, record, kUnknownSrc, kUnknownDst );
            REQUIRE( described.label == "TLS" );
            REQUIRE( described.description == "Application Data" );
        }
    }

    GIVEN( "an HTTP GET request" )
    {
        const auto request = text( "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" );

        THEN( "the label is HTTP and the description is the request line" )
        {
            const auto described = describe( Transport::Tcp, request, 53248, 80 );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description == "GET /index.html HTTP/1.1" );
        }
    }

    GIVEN( "an HTTP response" )
    {
        const auto response = text( "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n" );

        THEN( "the description is the status line" )
        {
            const auto described = describe( Transport::Tcp, response, 80, 53248 );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description == "HTTP/1.1 404 Not Found" );
        }
    }

    GIVEN( "an NMEA sentence on unknown ports" )
    {
        const auto sentence = text( "$GAGSV,2,2,08,21,41,270,11*76\r\n" );

        THEN( "the label is NMEA and the description is the sentence" )
        {
            const auto described = describe( Transport::Tcp, sentence, kUnknownSrc, kUnknownDst );
            REQUIRE( described.label == "NMEA" );
            REQUIRE( described.description == "$GAGSV,2,2,08,21,41,270,11*76" );
        }
    }

    GIVEN( "a TCP segment without payload to the SSH port" )
    {
        THEN( "the port names the protocol, and there is nothing to describe" )
        {
            const auto described = describe( Transport::Tcp, {}, 49152, 22 );
            REQUIRE( described.label == "SSH" );
            REQUIRE( described.description.empty() );
        }
    }
}

SCENARIO( "The detectors are tried in a fixed order", "[describer]" )
{
    GIVEN( "an ADB frame on port 5555 that starts with $WRTE, as an NMEA sentence would" )
    {
        // No comma after the five letters: not NMEA.  Enough text follows
        // for a preview.
        const auto frame
            = Bytes{ '$', 'W', 'R', 'T', 'E', 'J', 0x00, 0x02, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00 }
              + text( "07-08 10:29:23.549  7182  7413 W TAG: some log message here" );

        THEN( "NMEA does not claim it, and the port hint names ADB" )
        {
            const auto described = describe( Transport::Tcp, frame, 5555, 60217 );
            REQUIRE( described.label == "ADB" );
            REQUIRE( described.description.rfind( "$WRTEJ", 0 ) == 0 );
        }
    }

    GIVEN( "an HTTP CONNECT request sent to a proxy port" )
    {
        const auto request = text( "CONNECT example.com:443 HTTP/1.1\r\n\r\n" );

        THEN( "HTTP comes before SOCKS and wins" )
        {
            const auto described = describe( Transport::Tcp, request, 50000, 3128 );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description == "CONNECT example.com:443 HTTP/1.1" );
        }
    }

    GIVEN( "a payload on a proxy port that is neither HTTP nor a SOCKS message" )
    {
        THEN( "the port hint names SOCKS, with the payload previewed" )
        {
            const auto described = describe( Transport::Tcp, text( "hello proxy" ), 50000, 1080 );
            REQUIRE( described.label == "SOCKS" );
            REQUIRE( described.description == "hello proxy" );
        }
    }

    GIVEN( "a DNS-shaped payload on the NMEA-free NTP port" )
    {
        THEN( "the UDP port entries come before the content detectors" )
        {
            const auto described
                = describe( Transport::Udp, text( "$GPGGA,1,2,3*47\r\n" ), 40000, 123 );
            REQUIRE( described.label == "NTP" );
            REQUIRE( described.description.empty() );
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

SCENARIO( "A payload nobody recognises is previewed as text", "[describer]" )
{
    GIVEN( "120 characters of printable text on unknown ports" )
    {
        const std::string line = "07-08 10:29:23.549  7182  7413 W HERE_CARLO: "
                                 "[carlo] /workspace/coresdk/carlo/location_engine.cpp:42 "
                                 "initializing module";

        THEN( "the whole text is the description, with no label and no ellipsis" )
        {
            const auto described
                = describe( Transport::Tcp, text( line ), kUnknownSrc, kUnknownDst );
            REQUIRE( described.label.empty() );
            REQUIRE( described.description == line );
        }
    }

    GIVEN( "text with three binary bytes in the middle" )
    {
        const auto payload = text( "Hello" ) + Bytes{ 0x00, 0x01, 0x02 }
                             + text( "World and more text here to be above threshold!" );

        THEN( "the binary bytes show as dots between the text" )
        {
            const auto described = describe( Transport::Tcp, payload, kUnknownSrc, kUnknownDst );
            REQUIRE( described.description
                     == "Hello...World and more text here to be above threshold!" );
        }
    }

    GIVEN( "three printable bytes followed by fifty binary ones" )
    {
        Bytes payload = text( "ABC" );
        for ( int i = 0; i < 50; ++i ) {
            payload.push_back( static_cast<uint8_t>( i ) );
        }

        THEN( "there is no preview: it would be dots only" )
        {
            REQUIRE(
                describe( Transport::Tcp, payload, kUnknownSrc, kUnknownDst ).description.empty() );
        }
    }

    GIVEN( "a mostly binary payload that starts like a request" )
    {
        const auto payload = text( "GET" ) + Bytes( 5000, 0x00 );

        THEN( "it is neither HTTP nor previewed" )
        {
            const auto described = describe( Transport::Tcp, payload, kUnknownSrc, kUnknownDst );
            REQUIRE( described.label.empty() );
            REQUIRE( described.description.empty() );
        }
    }
}

SCENARIO( "Payload text is capped", "[describer]" )
{
    GIVEN( "1000 bytes of text" )
    {
        THEN( "the preview shows the first 200 characters and an ellipsis" )
        {
            const auto described = describe( Transport::Tcp, text( std::string( 1000, 'x' ) ),
                                             kUnknownSrc, kUnknownDst );
            REQUIRE( described.description == std::string( 200, 'x' ) + "\xe2\x80\xa6" );
        }
    }

    GIVEN( "exactly 200 bytes of text" )
    {
        const std::string exact( 200, 'y' );

        THEN( "the preview shows them all, without an ellipsis" )
        {
            REQUIRE( describe( Transport::Udp, text( exact ), kUnknownSrc, kUnknownDst ).description
                     == exact );
        }
    }

    GIVEN( "an HTTP request line of 300 bytes" )
    {
        const std::string line = "GET /" + std::string( 295, 'a' );

        THEN( "the description is its first 120 bytes" )
        {
            const auto described
                = describe( Transport::Tcp, text( line + "\r\n\r\n" ), kUnknownSrc, 80 );
            REQUIRE( described.label == "HTTP" );
            REQUIRE( described.description == line.substr( 0, 120 ) );
        }
    }
}

SCENARIO( "A description never breaks the one-line-per-packet format", "[describer]" )
{
    struct Case {
        const char* name;
        Transport transport;
        Bytes payload;
        uint16_t srcPort;
        uint16_t dstPort;
        std::string expectedLabel;
        std::string expectedText;
    };

    Bytes dns{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    dns = dns + Bytes{ 5, 'a', '\n', 'b', 0x1B, 'c', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1 };

    const std::vector<Case> cases{
        { "a DNS name with a newline and an escape character", Transport::Udp, dns, 40000, 53,
          "DNS", "Query a\\x0Ab\\x1Bc.com" },
        { "an HTTP request line with a control character", Transport::Tcp,
          text( "GET /\x1b[2J HTTP/1.1\r\n\r\n" ), 40000, 80, "HTTP", "GET /\\x1B[2J HTTP/1.1" },
        { "an SSDP response with a control character", Transport::Udp,
          text( "HTTP/1.1 200\x07OK\r\nST: x\r\n" ), 1900, 40000, "SSDP", "HTTP/1.1 200\\x07OK" },
        { "an NMEA sentence with a tab and a byte above 0x7F", Transport::Udp,
          text( "$GPGGA,1\t2,\xff*47\r\n" ), 40000, 10110, "NMEA", "$GPGGA,1\\x092,\\xFF*47" },
        { "a SOCKS5 password with a quote, a newline and a backslash",
          Transport::Tcp,
          { 0x01, 0x03, 'b', 'o', 'b', 0x04, 's', '"', 0x0A, '\\' },
          50000,
          1080,
          "SOCKS",
          R"(User: "bob", Pass: "s\"\x0A\\")" },
        { "a SOCKS5 destination domain with a newline",
          Transport::Tcp,
          { 0x05, 0x01, 0x00, 0x03, 3, 'a', 0x0A, 'b', 0x01, 0xBB },
          50000,
          1080,
          "SOCKS",
          "Destination: a\\x0Ab:443" },
        { "a SOCKS4a user id and domain with control bytes",
          Transport::Tcp,
          { 0x04, 0x01, 0x00, 0x50, 0, 0, 0, 1, 'b', 0x0D, 'b', 0x00, 'h', 0x0A, 's', 't', 0x00 },
          50000,
          1080,
          "SOCKS",
          R"(User: "b\x0Db", Domain: h\x0Ast)" },
        { "an mDNS name with a carriage return", Transport::Udp,
          Bytes{ 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
              + Bytes{ 2, 'a', '\r', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 1, 0, 1 },
          5353, 5353, "mDNS", "Query a\\x0D.local" },
        { "a payload of two lines of text", Transport::Tcp,
          text( "first line of the payload\r\nsecond line of the payload\n" ), kUnknownSrc,
          kUnknownDst, "", "first line of the payload..second line of the payload." },
    };

    for ( const auto& c : cases ) {
        GIVEN( c.name )
        {
            const auto described = describe( c.transport, c.payload, c.srcPort, c.dstPort );

            THEN( "the description is one line, with the control bytes escaped" )
            {
                REQUIRE( described.label == c.expectedLabel );
                REQUIRE( isOneLine( described.description ) );
                REQUIRE( contains( described.description, c.expectedText ) );
            }
        }
    }
}
