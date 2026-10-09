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
 * @file someip_test.cpp
 * @brief BDD tests for the SOME/IP detector: header fields and message
 *        types, several messages per datagram and segment, SOME/IP-SD
 *        entries and options, the ports and the heuristic, the name table,
 *        and messages mangled and cut anywhere.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "settings.h"
#include "someip.h"

#include <QFile>
#include <QTemporaryDir>

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kSdPort = 30490;
constexpr uint16_t kServicePort = 30501;
constexpr uint16_t kClientPort = 40001;

const std::string kEllipsis = "\xe2\x80\xa6";

enum : uint8_t {
    kRequest = 0x00,
    kRequestNoReturn = 0x01,
    kNotification = 0x02,
    kResponse = 0x80,
    kError = 0x81,
    kTpNotification = 0x22,
};

/// A SOME/IP message: its header, then @p payload.
Bytes someIp( uint16_t service, uint16_t method, uint8_t type, const Bytes& payload = {},
              uint8_t returnCode = 0, uint16_t client = 0x0010, uint16_t session = 0x0001,
              uint8_t protocolVersion = 1 )
{
    Bytes b;
    putBE16( b, service );
    putBE16( b, method );
    putBE32( b, static_cast<uint32_t>( 8 + payload.size() ) );
    putBE16( b, client );
    putBE16( b, session );
    b.push_back( protocolVersion );
    b.push_back( 1 ); // interface version
    b.push_back( type );
    b.push_back( returnCode );
    return b + payload;
}

/// An SD entry for a service: Find (0x00) or Offer (0x01).
Bytes serviceEntry( uint8_t type, uint16_t service, uint16_t instance, uint8_t major, uint32_t ttl,
                    uint32_t minor, uint8_t index1 = 0, uint8_t count1 = 0 )
{
    Bytes b{ type, index1, 0, static_cast<uint8_t>( count1 << 4 ) };
    putBE16( b, service );
    putBE16( b, instance );
    b.push_back( major );
    b.push_back( static_cast<uint8_t>( ttl >> 16 ) );
    putBE16( b, static_cast<uint16_t>( ttl ) );
    putBE32( b, minor );
    return b;
}

/// An SD entry for an eventgroup: Subscribe (0x06) or its Ack (0x07).
Bytes eventgroupEntry( uint8_t type, uint16_t service, uint16_t instance, uint16_t eventgroup,
                       uint32_t ttl, uint8_t index1 = 0, uint8_t count1 = 0 )
{
    Bytes b{ type, index1, 0, static_cast<uint8_t>( count1 << 4 ) };
    putBE16( b, service );
    putBE16( b, instance );
    b.push_back( 1 ); // major version
    b.push_back( static_cast<uint8_t>( ttl >> 16 ) );
    putBE16( b, static_cast<uint16_t>( ttl ) );
    b.push_back( 0 );
    b.push_back( 0 );
    putBE16( b, eventgroup );
    return b;
}

/// An IPv4 endpoint option (0x04), or another type of its shape.
Bytes ipv4Option( const Bytes& address, uint8_t l4, uint16_t port, uint8_t type = 0x04 )
{
    Bytes b;
    putBE16( b, 9 );
    b.push_back( type );
    b.push_back( 0 );
    b = b + address;
    b.push_back( 0 );
    b.push_back( l4 );
    putBE16( b, port );
    return b;
}

Bytes ipv6Option( const Bytes& address, uint8_t l4, uint16_t port )
{
    Bytes b;
    putBE16( b, 21 );
    b.push_back( 0x06 );
    b.push_back( 0 );
    b = b + address;
    b.push_back( 0 );
    b.push_back( l4 );
    putBE16( b, port );
    return b;
}

/// A SOME/IP-SD message with @p entries and @p options.
Bytes sd( const Bytes& entries, const Bytes& options = {}, uint16_t session = 1 )
{
    Bytes payload{ 0xC0, 0, 0, 0 }; // Reboot, Unicast
    putBE32( payload, static_cast<uint32_t>( entries.size() ) );
    payload = payload + entries;
    putBE32( payload, static_cast<uint32_t>( options.size() ) );
    payload = payload + options;
    return someIp( 0xFFFF, 0x8100, kNotification, payload, 0, 0x0000, session );
}

const Bytes kHost{ 192, 0, 2, 10 };

PayloadDescription overUdp( const Bytes& payload, uint16_t port = kSdPort )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), kClientPort, port );
}

PayloadDescription overTcp( const Bytes& payload, uint16_t port = kSdPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort, port );
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

} // namespace

SCENARIO( "SOME/IP messages are described by their header", "[someip]" )
{
    GIVEN( "a request on port 30490" )
    {
        const auto result = overUdp( someIp( 0x1234, 0x0001, kRequest, Bytes( 4, 0xAB ) ) );
        THEN( "its IDs, type and payload length are named" )
        {
            REQUIRE( result.label == "SOME/IP" );
            REQUIRE_FALSE( result.guessed );
            REQUIRE( result.description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 REQUEST, "
                        "4 bytes" );
        }
    }

    GIVEN( "each message type" )
    {
        THEN( "it is named as AUTOSAR names it, an error with its return code" )
        {
            REQUIRE( overUdp( someIp( 0x1234, 0x0002, kRequestNoReturn ) ).description
                     == "Service 0x1234 Method 0x0002 Client 0x0010 Session 0x0001 "
                        "REQUEST_NO_RETURN, 0 bytes" );
            REQUIRE( overUdp( someIp( 0x1234, 0x8001, kNotification, Bytes( 1, 1 ) ) ).description
                     == "Service 0x1234 Event 0x8001 Client 0x0010 Session 0x0001 NOTIFICATION, "
                        "1 byte" );
            REQUIRE( overUdp( someIp( 0x1234, 0x0001, kResponse, Bytes( 2, 0 ) ) ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 RESPONSE, "
                        "2 bytes" );
            REQUIRE( overUdp( someIp( 0x1234, 0x0001, kError, {}, 0x01 ) ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 ERROR "
                        "(E_NOT_OK), 0 bytes" );
            REQUIRE( overUdp( someIp( 0x1234, 0x0001, kResponse, {}, 0x04 ) ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 RESPONSE "
                        "(E_NOT_READY), 0 bytes" );
            REQUIRE( overUdp( someIp( 0x1234, 0x0001, kError, {}, 0x21 ) )
                         .description.find( "ERROR (Service Error 0x21)" )
                     != std::string::npos );
        }
    }

    GIVEN( "a segment of a SOME/IP-TP message" )
    {
        Bytes tp;
        putBE32( tp, 1392 | 0x01 ); // offset 1392, more segments
        const auto result
            = overUdp( someIp( 0x1234, 0x8002, kTpNotification, tp + Bytes( 1392, 0 ) ) );
        THEN( "its offset and the flag that more follow are named" )
        {
            REQUIRE( result.description
                     == "Service 0x1234 Event 0x8002 Client 0x0010 Session 0x0001 "
                        "TP_NOTIFICATION Offset=1392 More, 1392 bytes" );
        }
    }

    GIVEN( "several messages in one datagram" )
    {
        const auto datagram = someIp( 0x1234, 0x8001, kNotification, Bytes( 3, 0 ) )
                              + someIp( 0x1234, 0x8002, kNotification )
                              + someIp( 0x5678, 0x0001, kRequest, Bytes( 1, 0 ), 0, 0x0020, 7 );
        THEN( "all are named" )
        {
            REQUIRE( overUdp( datagram ).description
                     == "Service 0x1234 Event 0x8001 Client 0x0010 Session 0x0001 NOTIFICATION, "
                        "3 bytes; Service 0x1234 Event 0x8002 Client 0x0010 Session 0x0001 "
                        "NOTIFICATION, 0 bytes; Service 0x5678 Method 0x0001 Client 0x0020 "
                        "Session 0x0007 REQUEST, 1 byte" );
        }
    }

    GIVEN( "more messages than are named" )
    {
        Bytes datagram;
        for ( int i = 0; i < 12; ++i ) {
            datagram = datagram + someIp( 0x1234, 0x8001, kNotification );
        }
        THEN( "the first eight are, then an ellipsis" )
        {
            const auto description = overUdp( datagram ).description;
            size_t count = 0;
            for ( size_t at = 0; ( at = description.find( "Service", at ) ) != std::string::npos;
                  ++at ) {
                ++count;
            }
            REQUIRE( count == 8 );
            REQUIRE( description.substr( description.size() - kEllipsis.size() - 2 )
                     == "; " + kEllipsis );
        }
    }

    GIVEN( "messages over TCP, several in a segment" )
    {
        const auto segment = someIp( 0x1234, 0x0001, kRequest, Bytes( 4, 0 ) )
                             + someIp( 0x1234, 0x0001, kRequest, {}, 0, 0x0010, 2 );
        THEN( "all are named" )
        {
            const auto result = overTcp( segment, kServicePort );
            REQUIRE( result.label == "SOME/IP" );
            REQUIRE( result.description.find( "Session 0x0001 REQUEST, 4 bytes; " )
                     != std::string::npos );
            REQUIRE( result.description.find( "Session 0x0002 REQUEST, 0 bytes" )
                     != std::string::npos );
        }
        THEN( "the TCP Reassembly frames them by their Length" )
        {
            const auto whole
                = tcpMessageExtent( segment.data(), segment.size(), kClientPort, kServicePort );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == 20 );
            REQUIRE( std::string( whole.label ) == "SOME/IP" );
            const auto part = tcpMessageExtent( segment.data(), 22, kClientPort, kServicePort );
            REQUIRE( part.complete() );
            const auto cut = tcpMessageExtent( segment.data(), 17, kClientPort, kServicePort );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == 20 );
            const auto header = tcpMessageExtent( segment.data(), 5, kClientPort, kSdPort );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 6 );
            // Off SOME/IP's port, the header must be all there to be judged.
            REQUIRE( tcpMessageExtent( segment.data(), 5, kClientPort, kServicePort ).framer == 0 );
        }
    }

    GIVEN( "the magic cookies of a TCP connection" )
    {
        const auto cookie = someIp( 0xFFFF, 0x0000, kRequestNoReturn, {}, 0, 0xDEAD, 0xBEEF );
        THEN( "they are named as such" )
        {
            REQUIRE( overTcp( cookie + someIp( 0x1234, 0x0001, kRequest ), kServicePort )
                         .description.rfind( "Magic Cookie; Service 0x1234", 0 )
                     == 0 );
        }
    }
}

SCENARIO( "A truncated or malformed SOME/IP message is described as such", "[someip]" )
{
    const auto message = someIp( 0x1234, 0x0001, kRequest, Bytes( 20, 0 ) );

    GIVEN( "a message cut at the snaplen" )
    {
        THEN( "it is named as far as it goes, then an ellipsis" )
        {
            REQUIRE( overUdp( prefix( message, 30 ) ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 REQUEST, "
                        "20 bytes "
                            + kEllipsis );
            REQUIRE( overUdp( prefix( message, 10 ) ).description
                     == "Service 0x1234 Method 0x0001 " + kEllipsis );
            REQUIRE( overUdp( prefix( message, 5 ) ).description == "[Malformed Packet]" );
        }
    }

    GIVEN( "headers that break the rules" )
    {
        auto version2 = message;
        version2[ 12 ] = 2;
        auto badType = message;
        badType[ 14 ] = 0x07;
        auto shortLength = message;
        shortLength[ 7 ] = 4;
        THEN( "on SOME/IP's port they are malformed" )
        {
            REQUIRE( overUdp( version2 ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 REQUEST "
                        "Protocol Version 2 [Malformed Packet]" );
            REQUIRE( overUdp( badType ).description
                     == "Service 0x1234 Method 0x0001 Client 0x0010 Session 0x0001 Message Type "
                        "0x07 [Malformed Packet]" );
            REQUIRE( overUdp( shortLength ).description.find( "[Malformed Packet]" )
                     != std::string::npos );
        }
        THEN( "on another port they are no SOME/IP" )
        {
            for ( const auto& bad : { version2, badType, shortLength } ) {
                REQUIRE( overUdp( bad, kServicePort ).label != "SOME/IP" );
            }
        }
    }
}

SCENARIO( "SOME/IP-SD entries are named with their endpoint options", "[someip]" )
{
    GIVEN( "a Find Service for any instance and version" )
    {
        const auto result
            = overUdp( sd( serviceEntry( 0x00, 0x1234, 0xFFFF, 0xFF, 3, 0xFFFFFFFF ) ) );
        THEN( "it is labelled SOME/IP-SD and named" )
        {
            REQUIRE( result.label == "SOME/IP-SD" );
            REQUIRE( result.description == "Find Service 0x1234" );
        }
    }

    GIVEN( "an Offer Service with its IPv4 endpoints" )
    {
        const auto message
            = sd( serviceEntry( 0x01, 0x1234, 0x0001, 1, 3, 0, 0, 2 ),
                  ipv4Option( kHost, 0x11, 30501 ) + ipv4Option( kHost, 0x06, 30502 ) );
        THEN( "the entry lists its version, TTL and endpoints" )
        {
            REQUIRE( overUdp( message ).description
                     == "Offer Service 0x1234 Instance 0x0001 v1.0 TTL=3 (192.0.2.10:30501 UDP, "
                        "192.0.2.10:30502 TCP)" );
        }
    }

    GIVEN( "an offer withdrawn, eventgroup entries, IPv6 and multicast endpoints" )
    {
        Bytes v6( 16, 0 );
        v6[ 0 ] = 0x20;
        v6[ 1 ] = 0x01;
        v6[ 2 ] = 0x0d;
        v6[ 3 ] = 0xb8;
        v6[ 15 ] = 1;
        const auto entries = serviceEntry( 0x01, 0x1234, 0x0001, 1, 0, 2 )
                             + eventgroupEntry( 0x06, 0x1234, 0x0001, 0x0010, 3, 0, 1 )
                             + eventgroupEntry( 0x07, 0x1234, 0x0001, 0x0010, 3, 1, 1 )
                             + eventgroupEntry( 0x07, 0x1234, 0x0001, 0x0011, 0 )
                             + eventgroupEntry( 0x06, 0x1234, 0x0001, 0x0012, 0 );
        const auto options
            = ipv6Option( v6, 0x11, 40000 ) + ipv4Option( { 239, 0, 0, 1 }, 0x11, 30600, 0x14 );
        const auto result = overUdp( sd( entries, options ) );
        THEN( "each is named as Wireshark names it" )
        {
            REQUIRE( result.description
                     == "Stop Offer Service 0x1234 Instance 0x0001 v1.2, Subscribe Eventgroup "
                        "0x1234 Instance 0x0001 Eventgroup 0x0010 v1 TTL=3 ([2001:db8::1]:40000 "
                        "UDP), Subscribe Eventgroup Ack 0x1234 Instance 0x0001 Eventgroup 0x0010 "
                        "v1 TTL=3 (239.0.0.1:30600 UDP multicast), Subscribe Eventgroup Nack "
                        "0x1234 Instance 0x0001 Eventgroup 0x0011 v1, Stop Subscribe Eventgroup "
                        "0x1234 Instance 0x0001 Eventgroup 0x0012 v1" );
        }
    }

    GIVEN( "more entries than are named" )
    {
        Bytes entries;
        for ( int i = 0; i < 100; ++i ) {
            entries
                = entries
                  + serviceEntry( 0x00, static_cast<uint16_t>( i ), 0xFFFF, 0xFF, 3, 0xFFFFFFFF );
        }
        THEN( "the first eight are, then an ellipsis" )
        {
            const auto description = overUdp( sd( entries ) ).description;
            REQUIRE( description.rfind( "Find Service 0x0000, Find Service 0x0001", 0 ) == 0 );
            REQUIRE( description.find( "Find Service 0x0008" ) == std::string::npos );
            REQUIRE( description.substr( description.size() - kEllipsis.size() ) == kEllipsis );
        }
    }

    GIVEN( "no entries" )
    {
        THEN( "it says so" )
        {
            REQUIRE( overUdp( sd( {} ) ).description == "No entries" );
        }
    }

    GIVEN( "SD messages that break the rules" )
    {
        const auto offer = serviceEntry( 0x01, 0x1234, 0x0001, 1, 3, 0, 1, 1 );
        THEN( "an option index past the options is malformed" )
        {
            REQUIRE( overUdp( sd( offer, ipv4Option( kHost, 0x11, 1 ) ) ).description
                     == "Offer Service 0x1234 Instance 0x0001 v1.0 TTL=3 [Malformed Packet]" );
        }
        THEN( "an entries array of no whole entries is malformed" )
        {
            REQUIRE( overUdp( sd( prefix( offer, 10 ) ) ).description == "[Malformed Packet]" );
        }
        THEN( "an endpoint option of the wrong length is said to be" )
        {
            auto option = ipv4Option( kHost, 0x11, 1 );
            option[ 1 ] = 10;
            option.push_back( 0 );
            REQUIRE( overUdp( sd( serviceEntry( 0x01, 0x1234, 0x0001, 1, 3, 0, 0, 1 ), option ) )
                         .description.find( "([Malformed option])" )
                     != std::string::npos );
        }
        THEN( "a message cut in its options ends in an ellipsis" )
        {
            const auto message = sd( serviceEntry( 0x01, 0x1234, 0x0001, 1, 3, 0, 0, 1 ),
                                     ipv4Option( kHost, 0x11, 30501 ) );
            REQUIRE( overUdp( prefix( message, message.size() - 3 ) ).description
                     == "Offer Service 0x1234 Instance 0x0001 v1.0 TTL=3 " + kEllipsis );
        }
    }
}

SCENARIO( "SOME/IP is found on its port, configured ports, and by its header", "[someip]" )
{
    const auto message = someIp( 0x1234, 0x0001, kRequest, Bytes( 4, 0 ) );

    GIVEN( "a well-formed message on any port" )
    {
        THEN( "the header and its length tell it, over UDP and TCP" )
        {
            REQUIRE( overUdp( message, 50123 ).label == "SOME/IP" );
            REQUIRE( overTcp( message, 50123 ).label == "SOME/IP" );
        }
        THEN( "a byte more than its length makes it none" )
        {
            REQUIRE( overUdp( message + Bytes{ 0 }, 50123 ).label != "SOME/IP" );
        }
    }

    GIVEN( "a request with a return code other than E_OK" )
    {
        const auto odd = someIp( 0x1234, 0x0001, kRequest, {}, 0x01 );
        THEN( "only SOME/IP's port takes it" )
        {
            REQUIRE( overUdp( odd, 50123 ).label != "SOME/IP" );
            REQUIRE( overUdp( odd ).label == "SOME/IP" );
        }
    }

    GIVEN( "bytes that are no message on SOME/IP's port" )
    {
        THEN( "the port names them, a guess" )
        {
            const auto result = overUdp( Bytes{} );
            REQUIRE( result.label == "SOME/IP" );
            REQUIRE( result.guessed );
        }
    }

    GIVEN( "a port configured for SOME/IP" )
    {
        auto version2 = message;
        version2[ 12 ] = 2;
        SomeIpConfig config;
        config.ports = { 40000 };

        THEN( "a message the heuristic refuses is read there, and only while configured" )
        {
            REQUIRE( overUdp( version2, 40000 ).label != "SOME/IP" );
            {
                const SomeIpScope scope( config );
                const auto result = overUdp( version2, 40000 );
                REQUIRE( result.label == "SOME/IP" );
                REQUIRE( result.description.find( "[Malformed Packet]" ) != std::string::npos );
                REQUIRE( tcpMessageExtent( message.data(), 10, kClientPort, 40000 ).needsMore );
            }
            REQUIRE( overUdp( version2, 40000 ).label != "SOME/IP" );
        }
    }

    GIVEN( "the ports as the user writes them" )
    {
        THEN( "numbers from 1 to 65535 are taken, each once, the rest skipped" )
        {
            REQUIRE( parseSomeIpPorts( "30501, 30502 30501;0x7700 x 0 70000" )
                     == std::vector<uint16_t>{ 30501, 30502, 0x7700 } );
            REQUIRE( someIpPortsText( { 30501, 30502 } ) == "30501, 30502" );
            std::string many;
            for ( int i = 1; i <= 100; ++i ) {
                many += std::to_string( i ) + ",";
            }
            REQUIRE( parseSomeIpPorts( many ).size() == kMaxSomeIpPorts );
        }
    }
}

SCENARIO( "A name table names services, methods and eventgroups", "[someip]" )
{
    const std::string table = "# The navigation service\n"
                              "service 0x1234 Navigation\r\n"
                              "method 0x1234 0x0001 GetRoute\n"
                              "event 0x1234 32769 RouteChanged\n"
                              "eventgroup 0x1234 0x0010 Route\n"
                              "service 0x5678\n"
                              "colour 0x1234 0x0001 Blue\n"
                              "method nope 0x0001 X\n";

    GIVEN( "the text of a table" )
    {
        std::vector<std::string> problems;
        const auto names = parseSomeIpNames( table, &problems );
        THEN( "its names are read, and the lines that are none said" )
        {
            REQUIRE( names.services.at( 0x1234 ) == "Navigation" );
            REQUIRE( names.methods.at( 0x12340001 ) == "GetRoute" );
            REQUIRE( names.methods.at( 0x12348001 ) == "RouteChanged" );
            REQUIRE( names.eventgroups.at( 0x12340010 ) == "Route" );
            REQUIRE( problems
                     == std::vector<std::string>{
                         "line 6: no name", "line 7: neither service, method, event nor eventgroup",
                         "line 8: no service ID" } );
        }
        THEN( "the descriptions carry them" )
        {
            SomeIpConfig config;
            config.names = names;
            const SomeIpScope scope( config );
            REQUIRE( overUdp( someIp( 0x1234, 0x0001, kRequest ) ).description
                     == "Service 0x1234 (Navigation) Method 0x0001 (GetRoute) Client 0x0010 "
                        "Session 0x0001 REQUEST, 0 bytes" );
            REQUIRE( overUdp( sd( eventgroupEntry( 0x06, 0x1234, 0x0001, 0x0010, 3 ) ) ).description
                     == "Subscribe Eventgroup 0x1234 (Navigation) Instance 0x0001 Eventgroup "
                        "0x0010 (Route) v1 TTL=3" );
        }
    }

    GIVEN( "names that would break the line, or are too long" )
    {
        const auto names
            = parseSomeIpNames( "service 1 A\x01Z\nservice 2 " + std::string( 100, 'n' )
                                + "\nservice 3 Caf\xc3\xa9\n" );
        THEN( "a control character ends a name, a long one is cut, other bytes are escaped" )
        {
            REQUIRE( names.services.at( 1 ) == "A" );
            REQUIRE( names.services.at( 2 ).size() == kMaxSomeIpNameBytes );
            SomeIpConfig config;
            config.names = names;
            const SomeIpScope scope( config );
            REQUIRE( overUdp( someIp( 3, 1, kRequest ) )
                         .description.rfind( "Service 0x0003 (Caf\\xC3\\xA9)", 0 )
                     == 0 );
        }
    }

    GIVEN( "a table in a file, named in the options" )
    {
        QTemporaryDir dir;
        REQUIRE( dir.isValid() );
        const auto path = dir.filePath( "someip-names.txt" );
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( table.data(), static_cast<qint64>( table.size() ) );
        file.close();

        THEN( "it loads, and a file that is not there loads nothing" )
        {
            const auto names = loadSomeIpNames( path.toStdString() );
            REQUIRE( names );
            REQUIRE( names->services.at( 0x1234 ) == "Navigation" );
            REQUIRE_FALSE( loadSomeIpNames( dir.filePath( "missing.txt" ).toStdString() ) );
        }

        THEN( "a conversion names the IDs with it, on a configured port" )
        {
            Ipv4Options o;
            const auto frame
                = eth( EthertypeIpv4,
                       ipv4( IpProtoUdp,
                             udp( kClientPort, 40000,
                                  someIp( 0x1234, 0x0001, kRequest, {}, 0, 0x0010, 0x0001, 2 ) ),
                             o ) );
            const auto capturePath = dir.filePath( "someip.pcap" );
            QFile capture( capturePath );
            REQUIRE( capture.open( QIODevice::WriteOnly ) );
            const auto bytes = pcapOf( { frame } );
            capture.write( reinterpret_cast<const char*>( bytes.data() ),
                           static_cast<qint64>( bytes.size() ) );
            capture.close();

            ConversionOptions options;
            options.someIpPorts = { 40000 };
            options.someIpNamesFile = path;
            const auto result = convertPcap( capturePath, dir.path(), nullptr, {}, options );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            QFile output( result.outputPath );
            REQUIRE( output.open( QIODevice::ReadOnly ) );
            const auto text = output.readAll().toStdString();
            REQUIRE( text.find( "SOME/IP" ) != std::string::npos );
            REQUIRE( text.find( "Service 0x1234 (Navigation) Method 0x0001 (GetRoute)" )
                     != std::string::npos );

            const auto plain = convertPcap( capturePath, dir.path() );
            QFile plainOutput( plain.outputPath );
            REQUIRE( plainOutput.open( QIODevice::ReadOnly ) );
            REQUIRE( plainOutput.readAll().toStdString().find( "Navigation" )
                     == std::string::npos );
        }
    }
}

SCENARIO( "Mangled SOME/IP never breaks the describer", "[someip][fuzz]" )
{
    Bytes v6( 16, 0x20 );
    const std::vector<Bytes> messages = {
        someIp( 0x1234, 0x0001, kRequest, Bytes( 4, 0xAB ) ),
        someIp( 0x1234, 0x0001, kError, {}, 0x01 ),
        someIp( 0x1234, 0x8002, kTpNotification, Bytes{ 0, 0, 0x05, 0x71 } + Bytes( 16, 0 ) ),
        someIp( 0xFFFF, 0x0000, kRequestNoReturn, {}, 0, 0xDEAD, 0xBEEF ),
        sd( serviceEntry( 0x00, 0x1234, 0xFFFF, 0xFF, 3, 0xFFFFFFFF )
                + serviceEntry( 0x01, 0x1234, 0x0001, 1, 3, 0, 0, 2 )
                + eventgroupEntry( 0x06, 0x1234, 0x0001, 0x0010, 3, 2, 1 ),
            ipv4Option( kHost, 0x11, 30501 ) + ipv4Option( kHost, 0x06, 30502 )
                + ipv6Option( v6, 0x11, 40000 ) ),
    };
    auto check = []( const Bytes& bytes ) {
        for ( const auto& result : { overUdp( bytes ), overUdp( bytes, 50123 ), overTcp( bytes ),
                                     overTcp( bytes, 50123 ) } ) {
            REQUIRE( result.description.find( '\n' ) == std::string::npos );
            REQUIRE( result.description.size() < 4096 );
        }
        for ( const uint16_t port : { kSdPort, uint16_t{ 50123 } } ) {
            const auto extent = tcpMessageExtent( bytes.data(), bytes.size(), kClientPort, port );
            REQUIRE( ( extent.framer == 0 || extent.length > 0 ) );
        }
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each is described in one line, SOME/IP on its port" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto cut = prefix( message, n );
                    check( cut );
                    if ( n > 0 ) {
                        REQUIRE( overUdp( cut ).label.rfind( "SOME/IP", 0 ) == 0 );
                    }
                    if ( n == message.size() ) {
                        REQUIRE( overUdp( cut, 50123 ).label.rfind( "SOME/IP", 0 ) == 0 );
                        REQUIRE( overUdp( cut ).description.find( "Malformed" )
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
                    for ( int value : { 0x00, 0x01, 0x02, 0x0F, 0x10, 0x7F, 0x80, 0xC0, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        check( mutated );
                    }
                }
            }
        }
    }

    GIVEN( "datagrams of several messages with random bytes changed, cut anywhere" )
    {
        Bytes datagram;
        for ( const auto& message : messages ) {
            datagram = datagram + message;
        }
        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 30490 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = datagram;
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
