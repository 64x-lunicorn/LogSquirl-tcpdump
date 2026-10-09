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
 * @file dns_test.cpp
 * @brief BDD tests for the DNS descriptions, through the Payload Describer:
 *        questions and answers of each record type, name compression and
 *        pointers that loop or point astray, messages cut short, and DNS
 *        over TCP with its length prefix.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"

#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint16_t kClientPort = 54321;
constexpr uint16_t kDnsPort = 53;

/// Where the first question's name begins: right behind the header.
constexpr size_t kQuestionAt = 12;

constexpr uint16_t kA = 1;
constexpr uint16_t kNs = 2;
constexpr uint16_t kCname = 5;
constexpr uint16_t kSoa = 6;
constexpr uint16_t kPtr = 12;
constexpr uint16_t kMx = 15;
constexpr uint16_t kTxt = 16;
constexpr uint16_t kAaaa = 28;
constexpr uint16_t kSrv = 33;
constexpr uint16_t kHttps = 65;

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

Bytes be16( size_t v )
{
    return { static_cast<uint8_t>( v >> 8 ), static_cast<uint8_t>( v ) };
}

/// A name as labels, ending with the root label unless @p then (a pointer)
/// ends it.
Bytes name( const std::string& dotted, const Bytes& then = { 0 } )
{
    Bytes out;
    std::istringstream labels( dotted );
    std::string label;
    while ( std::getline( labels, label, '.' ) ) {
        out.push_back( static_cast<uint8_t>( label.size() ) );
        out.insert( out.end(), label.begin(), label.end() );
    }
    return out + then;
}

/// A compression pointer to @p offset.
Bytes pointer( size_t offset )
{
    return { static_cast<uint8_t>( 0xC0 | ( offset >> 8 ) ), static_cast<uint8_t>( offset ) };
}

Bytes header( uint16_t id, uint16_t flags, size_t questions, size_t answers )
{
    return be16( id ) + be16( flags ) + be16( questions ) + be16( answers ) + be16( 0 ) + be16( 0 );
}

constexpr uint16_t kQuery = 0x0100;    ///< recursion desired
constexpr uint16_t kResponse = 0x8180; ///< response, recursion desired and available

Bytes question( const Bytes& owner, uint16_t type )
{
    return owner + be16( type ) + be16( 1 );
}

Bytes answer( const Bytes& owner, uint16_t type, const Bytes& data )
{
    return owner + be16( type ) + be16( 1 ) + Bytes{ 0, 0, 0x0E, 0x10 } + be16( data.size() )
           + data;
}

/// A query for @p qname of @p type.
Bytes query( uint16_t id, const std::string& qname, uint16_t type )
{
    return header( id, kQuery, 1, 0 ) + question( name( qname ), type );
}

/// A response to a question for @p qname of @p type with @p answers,
/// @p count of them.
Bytes response( uint16_t id, const std::string& qname, uint16_t type, size_t count,
                const Bytes& answers, uint16_t flags = kResponse )
{
    return header( id, flags, 1, count ) + question( name( qname ), type ) + answers;
}

PayloadDescription overUdp( const Bytes& payload, uint16_t srcPort = kClientPort,
                            uint16_t dstPort = kDnsPort )
{
    return describePayload( Transport::Udp, payload.data(), payload.size(), srcPort, dstPort );
}

PayloadDescription overTcp( const Bytes& payload, uint16_t srcPort = kClientPort,
                            uint16_t dstPort = kDnsPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), srcPort, dstPort );
}

/// @p message behind its 2-byte length, as DNS over TCP sends it.
Bytes framed( const Bytes& message )
{
    return be16( message.size() ) + message;
}

/// The first @p n bytes of @p bytes, in a buffer of exactly that size.
Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

Bytes suffix( const Bytes& bytes, size_t from )
{
    return Bytes( bytes.begin() + static_cast<std::ptrdiff_t>( from ), bytes.end() );
}

bool startsWith( const std::string& s, const std::string& start )
{
    return s.compare( 0, start.size(), start ) == 0;
}

bool contains( const std::string& haystack, const std::string& needle )
{
    return haystack.find( needle ) != std::string::npos;
}

/// A response for www.example.com: a CNAME to example.com, compressed to
/// the question's name, and its address.
Bytes cnameResponse()
{
    const size_t exampleCom = kQuestionAt + 4; // behind "\3www"
    return response( 0x1A2B, "www.example.com", kA, 2,
                     answer( pointer( kQuestionAt ), kCname, pointer( exampleCom ) )
                         + answer( pointer( exampleCom ), kA, { 93, 184, 216, 34 } ) );
}

} // namespace

SCENARIO( "A DNS query names its transaction id, type and name", "[dns]" )
{
    struct Case {
        uint16_t type;
        std::string qname;
        std::string expected;
    };
    const std::vector<Case> cases{
        { kA, "example.com", "Standard query 0x1a2b A example.com" },
        { kAaaa, "example.com", "Standard query 0x1a2b AAAA example.com" },
        { kPtr, "34.216.184.93.in-addr.arpa",
          "Standard query 0x1a2b PTR 34.216.184.93.in-addr.arpa" },
        { kMx, "example.com", "Standard query 0x1a2b MX example.com" },
        { kTxt, "example.com", "Standard query 0x1a2b TXT example.com" },
        { kSrv, "_sip._udp.example.com", "Standard query 0x1a2b SRV _sip._udp.example.com" },
        { kCname, "www.example.com", "Standard query 0x1a2b CNAME www.example.com" },
        { kHttps, "example.com", "Standard query 0x1a2b HTTPS example.com" },
        { 255, "example.com", "Standard query 0x1a2b ANY example.com" },
        { 4321, "example.com", "Standard query 0x1a2b TYPE4321 example.com" },
    };

    for ( const auto& c : cases ) {
        GIVEN( "a query: " + c.expected )
        {
            const auto described = overUdp( query( 0x1A2B, c.qname, c.type ) );

            THEN( "it reads like Wireshark's" )
            {
                REQUIRE( described.label == "DNS" );
                REQUIRE( described.description == c.expected );
            }
        }
    }

    GIVEN( "a query for the root" )
    {
        const auto described = overUdp( header( 1, kQuery, 1, 0 ) + question( { 0 }, kNs ) );

        THEN( "the name is <Root>" )
        {
            REQUIRE( described.description == "Standard query 0x0001 NS <Root>" );
        }
    }

    GIVEN( "a NOTIFY and a dynamic update" )
    {
        const auto notify = header( 7, 0x2400, 1, 0 ) + question( name( "example.com" ), kSoa );
        const auto update = header( 8, 0x2800, 1, 0 ) + question( name( "example.com" ), kSoa );

        THEN( "the operation is named" )
        {
            REQUIRE( overUdp( notify ).description
                     == "Zone change notification 0x0007 SOA example.com" );
            REQUIRE( overUdp( update ).description == "Dynamic update 0x0008 SOA example.com" );
        }
    }
}

SCENARIO( "A DNS response lists its answers with their data", "[dns]" )
{
    const Bytes atQuestion = pointer( kQuestionAt );
    struct Case {
        std::string what;
        Bytes payload;
        std::string expected;
    };
    const std::vector<Case> cases{
        { "an address",
          response( 0x1A2B, "example.com", kA, 1, answer( atQuestion, kA, { 93, 184, 216, 34 } ) ),
          "Standard query response 0x1a2b A example.com A 93.184.216.34" },
        { "an IPv6 address",
          response( 0x1A2B, "example.com", kAaaa, 1,
                    answer( atQuestion, kAaaa,
                            { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } ) ),
          "Standard query response 0x1a2b AAAA example.com AAAA 2001:db8::1" },
        { "a CNAME and the address of its target", cnameResponse(),
          "Standard query response 0x1a2b A www.example.com CNAME example.com A 93.184.216.34" },
        { "a pointer record",
          response( 0x0002, "34.216.184.93.in-addr.arpa", kPtr, 1,
                    answer( atQuestion, kPtr, name( "example.com" ) ) ),
          "Standard query response 0x0002 PTR 34.216.184.93.in-addr.arpa PTR example.com" },
        { "a mail exchanger",
          response( 0x0003, "example.com", kMx, 1,
                    answer( atQuestion, kMx, be16( 10 ) + name( "mail", atQuestion ) ) ),
          "Standard query response 0x0003 MX example.com MX 10 mail.example.com" },
        { "a text record of two strings",
          response( 0x0004, "example.com", kTxt, 1,
                    answer( atQuestion, kTxt,
                            Bytes{ 11, 'v', '=', 's', 'p', 'f', '1', ' ', '-', 'a', 'l', 'l' }
                                + Bytes{ 3, 'a', '"', 'b' } ) ),
          R"(Standard query response 0x0004 TXT example.com TXT "v=spf1 -all" "a\"b")" },
        { "a service record",
          response( 0x0005, "_sip._udp.example.com", kSrv, 1,
                    answer( atQuestion, kSrv,
                            be16( 0 ) + be16( 5 ) + be16( 5060 )
                                + name( "sip", pointer( kQuestionAt + 10 ) ) ) ),
          "Standard query response 0x0005 SRV _sip._udp.example.com SRV 0 5 5060 sip.example.com" },
        { "a name server",
          response( 0x0006, "example.com", kNs, 1,
                    answer( atQuestion, kNs, name( "ns1", atQuestion ) ) ),
          "Standard query response 0x0006 NS example.com NS ns1.example.com" },
        { "a start of authority",
          response( 0x0007, "example.com", kSoa, 1,
                    answer( atQuestion, kSoa,
                            name( "ns1", atQuestion ) + name( "hostmaster", atQuestion )
                                + Bytes( 20, 0 ) ) ),
          "Standard query response 0x0007 SOA example.com SOA ns1.example.com" },
        { "a record of a type without data shown",
          response( 0x0008, "example.com", kHttps, 1, answer( atQuestion, kHttps, { 0, 1, 0 } ) ),
          "Standard query response 0x0008 HTTPS example.com HTTPS" },
        { "an unknown record type",
          response( 0x0009, "example.com", 4321, 1, answer( atQuestion, 4321, { 1, 2, 3 } ) ),
          "Standard query response 0x0009 TYPE4321 example.com TYPE4321" },
        { "a name that does not exist", response( 0x000A, "nx.example.com", kA, 0, {}, 0x8183 ),
          "Standard query response 0x000a A nx.example.com [NXDOMAIN]" },
        { "a server failure", response( 0x000B, "example.com", kA, 0, {}, 0x8182 ),
          "Standard query response 0x000b A example.com [SERVFAIL]" },
        { "a refusal", response( 0x000C, "example.com", kA, 0, {}, 0x8185 ),
          "Standard query response 0x000c A example.com [REFUSED]" },
        { "an unnamed response code", response( 0x000D, "example.com", kA, 0, {}, 0x818B ),
          "Standard query response 0x000d A example.com [RCODE=11]" },
    };

    for ( const auto& c : cases ) {
        GIVEN( "a response with " + c.what )
        {
            const auto described = overUdp( c.payload, kDnsPort, kClientPort );

            THEN( "the answers follow the question" )
            {
                REQUIRE( described.label == "DNS" );
                REQUIRE( described.description == c.expected );
            }
        }
    }

    GIVEN( "an mDNS announcement: answers without a question" )
    {
        const auto announcement = header( 0, 0x8400, 0, 1 )
                                  + answer( name( "_ipp._tcp.local" ), kPtr,
                                            name( "printer", pointer( kQuestionAt ) ) );
        const auto described = overUdp( announcement, 5353, 5353 );

        THEN( "the answers are listed" )
        {
            REQUIRE( described.label == "mDNS" );
            REQUIRE( described.description
                     == "Standard query response 0x0000 PTR printer._ipp._tcp.local" );
        }
    }
}

SCENARIO( "A DNS response with many answers lists a few and counts them", "[dns]" )
{
    Bytes answers;
    for ( uint8_t i = 1; i <= 6; ++i ) {
        answers = answers + answer( pointer( kQuestionAt ), kA, { 192, 0, 2, i } );
    }

    GIVEN( "six addresses" )
    {
        const auto described = overUdp( response( 1, "example.com", kA, 6, answers ) );

        THEN( "four are listed, then an ellipsis and the count" )
        {
            REQUIRE( described.description
                     == "Standard query response 0x0001 A example.com A 192.0.2.1 A 192.0.2.2 "
                        "A 192.0.2.3 A 192.0.2.4 \xe2\x80\xa6 (6 answers)" );
        }
    }

    GIVEN( "one answer cut off" )
    {
        const auto full = response( 1, "example.com", kA, 1,
                                    answer( pointer( kQuestionAt ), kA, { 1, 2, 3, 4 } ) );

        THEN( "the answer is counted in the singular" )
        {
            REQUIRE( overUdp( prefix( full, full.size() - 1 ) ).description
                     == "Standard query response 0x0001 A example.com (1 answer)" );
        }
    }
}

SCENARIO( "DNS name compression is followed only backwards and within the message", "[dns]" )
{
    GIVEN( "a name compressed in three steps" )
    {
        // The question's name, then an answer whose CNAME target points into
        // an earlier answer's name, which itself ends in a pointer.
        const auto ownerAt = kQuestionAt + name( "example.com" ).size() + 4;
        const auto message = response(
            1, "example.com", kA, 2,
            answer( name( "b", pointer( kQuestionAt ) ), kCname, name( "c", pointer( ownerAt ) ) )
                + answer( pointer( ownerAt ), kA, { 1, 2, 3, 4 } ) );

        THEN( "every name is put together" )
        {
            REQUIRE( overUdp( message ).description
                     == "Standard query response 0x0001 A example.com CNAME c.b.example.com "
                        "A 1.2.3.4" );
        }
    }

    GIVEN( "a question whose name points at itself" )
    {
        const auto message = header( 1, kQuery, 1, 0 ) + question( pointer( kQuestionAt ), kA );

        THEN( "the name is rejected" )
        {
            REQUIRE( overUdp( message ).description == "Standard query 0x0001" );
        }
    }

    GIVEN( "two pointers pointing at each other" )
    {
        // The answer's CNAME target at T points to the owner name at O < T,
        // which points forward to T.
        const auto ownerAt = kQuestionAt + name( "example.com" ).size() + 4;
        const auto targetAt = ownerAt + 2 + 10;
        const auto message = response( 1, "example.com", kA, 1,
                                       answer( pointer( targetAt ), kCname, pointer( ownerAt ) ) );

        THEN( "the loop is rejected and the answer only counted" )
        {
            REQUIRE( overUdp( message ).description
                     == "Standard query response 0x0001 A example.com (1 answer)" );
        }
    }

    GIVEN( "a pointer to a valid name further on" )
    {
        auto message = header( 1, kQuery, 1, 0 ) + question( pointer( kQuestionAt + 6 ), kA );
        message = message + name( "example.com" );

        THEN( "the forward pointer is rejected" )
        {
            REQUIRE( overUdp( message ).description == "Standard query 0x0001" );
        }
    }

    GIVEN( "a pointer beyond the message" )
    {
        const auto message = response(
            1, "example.com", kA, 1, answer( pointer( kQuestionAt ), kCname, pointer( 0x3FFF ) ) );

        THEN( "it is rejected without reading past the payload" )
        {
            REQUIRE( overUdp( message ).description
                     == "Standard query response 0x0001 A example.com (1 answer)" );
        }
    }

    GIVEN( "a name longer than 255 bytes" )
    {
        const std::string label( 63, 'x' );
        const auto message
            = header( 1, kQuery, 1, 0 )
              + question( name( label + "." + label + "." + label + "." + label ), kA );

        THEN( "it is rejected" )
        {
            REQUIRE( overUdp( message ).description == "Standard query 0x0001" );
        }
    }

    GIVEN( "a name of the longest length" )
    {
        const std::string label( 62, 'x' );
        const auto message
            = header( 1, kQuery, 1, 0 )
              + question( name( label + "." + label + "." + label + "." + label ), kA );

        THEN( "it is shown up to 120 bytes, then an ellipsis" )
        {
            REQUIRE( overUdp( message ).description
                     == "Standard query 0x0001 A " + label + "." + std::string( 57, 'x' )
                            + "\xe2\x80\xa6" );
        }
    }

    GIVEN( "a label of a reserved type (0x40, 0x80)" )
    {
        THEN( "the name is rejected" )
        {
            for ( uint8_t type : { 0x40, 0x80 } ) {
                const auto message
                    = header( 1, kQuery, 1, 0 ) + question( Bytes{ type, 'a', 0 }, kA );
                REQUIRE( overUdp( message ).description == "Standard query 0x0001" );
            }
        }
    }
}

SCENARIO( "A cut DNS message is described as far as it goes", "[dns]" )
{
    const auto message = cnameResponse();

    GIVEN( "the response cut at every possible length" )
    {
        THEN( "every prefix with a header is a response, and names only what it holds" )
        {
            for ( size_t n = 0; n <= message.size(); ++n ) {
                INFO( "cut to " << n << " bytes" );
                const auto described = overUdp( prefix( message, n ) );
                REQUIRE( described.label == "DNS" );
                if ( n < 12 ) {
                    REQUIRE( described.description.empty() );
                    continue;
                }
                REQUIRE( startsWith( described.description, "Standard query response 0x1a2b" ) );
                if ( contains( described.description, " A www" ) ) {
                    REQUIRE( contains( described.description, " A www.example.com" ) );
                }
                if ( contains( described.description, "CNAME" ) ) {
                    REQUIRE( contains( described.description, "CNAME example.com" ) );
                }
                if ( n < message.size() ) {
                    REQUIRE( contains( described.description, "(2 answers)" ) );
                }
            }
        }
    }
}

SCENARIO( "DNS over TCP is described like DNS over UDP", "[dns]" )
{
    GIVEN( "a query behind its length prefix, to port 53" )
    {
        const auto described = overTcp( framed( query( 0x1A2B, "example.com", kA ) ) );

        THEN( "it is labelled DNS and described" )
        {
            REQUIRE( described.label == "DNS" );
            REQUIRE( described.description == "Standard query 0x1a2b A example.com" );
        }
    }

    GIVEN( "a response from port 53" )
    {
        const auto described = overTcp( framed( cnameResponse() ), kDnsPort, kClientPort );

        THEN( "its answers are listed" )
        {
            REQUIRE( described.label == "DNS" );
            REQUIRE( described.description
                     == "Standard query response 0x1a2b A www.example.com CNAME example.com A "
                        "93.184.216.34" );
        }
    }

    GIVEN( "two queries in one segment" )
    {
        const auto segment
            = framed( query( 1, "example.com", kA ) ) + framed( query( 2, "example.com", kAaaa ) );

        THEN( "both are described, in order" )
        {
            REQUIRE( overTcp( segment ).description
                     == "Standard query 0x0001 A example.com, Standard query 0x0002 AAAA "
                        "example.com" );
        }
    }

    GIVEN( "a response split over two segments" )
    {
        const auto stream = framed( cnameResponse() );
        const size_t split = 2 + 12 + 21 + 6;

        THEN( "the first describes what it holds, the second is DNS by its port alone" )
        {
            const auto first = overTcp( prefix( stream, split ), kDnsPort, kClientPort );
            REQUIRE( first.label == "DNS" );
            REQUIRE( first.description
                     == "Standard query response 0x1a2b A www.example.com (2 answers)" );

            const auto second = overTcp( suffix( stream, split ), kDnsPort, kClientPort );
            REQUIRE( second.label == "DNS" );
            REQUIRE_FALSE( startsWith( second.description, "Standard" ) );
        }
    }

    GIVEN( "a segment of the length prefix alone" )
    {
        const auto described = overTcp( be16( 29 ) );

        THEN( "it is DNS by its port, without a description" )
        {
            REQUIRE( described.label == "DNS" );
            REQUIRE( described.description.empty() );
        }
    }

    GIVEN( "five queries in one segment" )
    {
        Bytes segment;
        for ( uint16_t id = 1; id <= 5; ++id ) {
            segment = segment + framed( query( id, "a.example", kA ) );
        }

        THEN( "four are described, then an ellipsis" )
        {
            REQUIRE( overTcp( segment ).description
                     == "Standard query 0x0001 A a.example, Standard query 0x0002 A a.example, "
                        "Standard query 0x0003 A a.example, Standard query 0x0004 A a.example, "
                        "\xe2\x80\xa6" );
        }
    }

    GIVEN( "a framed query on another port" )
    {
        THEN( "it is not taken for DNS" )
        {
            REQUIRE( overTcp( framed( query( 1, "example.com", kA ) ), 40000, 8080 ).label
                     != "DNS" );
        }
    }
}

SCENARIO( "A malformed DNS message is never read beyond the payload", "[dns]" )
{
    const auto message = cnameResponse();

    GIVEN( "every single byte of a response set to every value" )
    {
        THEN( "the description is a DNS message of one line" )
        {
            for ( size_t i = 0; i < message.size(); ++i ) {
                for ( int value : { 0x00, 0x01, 0x3F, 0x40, 0x7F, 0x80, 0xC0, 0xFE, 0xFF } ) {
                    auto mutated = message;
                    mutated[ i ] = static_cast<uint8_t>( value );
                    const auto described = overUdp( mutated );
                    REQUIRE( described.label == "DNS" );
                    REQUIRE( !described.description.empty() );
                    REQUIRE( described.description.find( '\n' ) == std::string::npos );
                }
            }
        }
    }

    GIVEN( "messages over UDP and TCP with random bytes changed, cut anywhere" )
    {
        const auto segment = framed( message ) + framed( query( 2, "example.org", kMx ) );

        THEN( "the describer reads them without fault and within the length policy" )
        {
            std::mt19937 random( 53 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = segment;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto cut = prefix( mutated, random() % mutated.size() );
                const auto tcp = overTcp( cut );
                const auto udp = overUdp( cut.size() > 2 ? suffix( cut, 2 ) : cut );
                for ( const auto& described : { tcp, udp } ) {
                    REQUIRE( described.description.find( '\n' ) == std::string::npos );
                    REQUIRE( described.description.size() < 4096 );
                }
            }
        }
    }
}
