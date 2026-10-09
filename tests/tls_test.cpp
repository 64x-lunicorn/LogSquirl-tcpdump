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
 * @file tls_test.cpp
 * @brief BDD tests for the TLS record descriptions, through the Payload
 *        Describer: the hello fields, several records in one segment, and
 *        records cut or lying about their length.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint16_t kClientPort = 50443;
constexpr uint16_t kServerPort = 443;

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

Bytes text( const std::string& s )
{
    return Bytes( s.begin(), s.end() );
}

Bytes be16( size_t v )
{
    return { static_cast<uint8_t>( v >> 8 ), static_cast<uint8_t>( v ) };
}

Bytes be24( size_t v )
{
    return { static_cast<uint8_t>( v >> 16 ), static_cast<uint8_t>( v >> 8 ),
             static_cast<uint8_t>( v ) };
}

/// @p body behind its 16-bit length.
Bytes vector16( const Bytes& body )
{
    return be16( body.size() ) + body;
}

/// @p body behind its 8-bit length.
Bytes vector8( const Bytes& body )
{
    return Bytes{ static_cast<uint8_t>( body.size() ) } + body;
}

Bytes extension( uint16_t type, const Bytes& data )
{
    return be16( type ) + vector16( data );
}

Bytes serverName( const std::string& host )
{
    return extension( 0x0000, vector16( Bytes{ 0x00 } + vector16( text( host ) ) ) );
}

Bytes supportedVersions( const Bytes& versions )
{
    return extension( 0x002B, vector8( versions ) );
}

Bytes alpn( const std::vector<std::string>& protocols )
{
    Bytes list;
    for ( const auto& protocol : protocols ) {
        list = list + vector8( text( protocol ) );
    }
    return extension( 0x0010, vector16( list ) );
}

/// A handshake message of @p type around @p body.
Bytes handshake( uint8_t type, const Bytes& body )
{
    return Bytes{ type } + be24( body.size() ) + body;
}

/// A TLS record of @p contentType around @p fragment.
Bytes record( uint8_t contentType, const Bytes& fragment )
{
    return Bytes{ contentType, 0x03, 0x03 } + vector16( fragment );
}

/// A ClientHello body: legacy version 1.2, a 32-byte session id, two
/// cipher suites, no compression, then @p extensions (none at all if
/// @p withExtensions is false).
Bytes clientHelloBody( const Bytes& extensions, bool withExtensions = true )
{
    Bytes body = Bytes{ 0x03, 0x03 } + Bytes( 32, 0x11 ) + vector8( Bytes( 32, 0x22 ) )
                 + vector16( { 0x13, 0x01, 0xC0, 0x2F } ) + vector8( { 0x00 } );
    if ( withExtensions ) {
        body = body + vector16( extensions );
    }
    return body;
}

Bytes clientHello( const Bytes& extensions )
{
    return record( 0x16, handshake( 0x01, clientHelloBody( extensions ) ) );
}

/// A ServerHello body with @p extensions, the legacy version 1.2.
Bytes serverHelloBody( const Bytes& extensions )
{
    return Bytes{ 0x03, 0x03 } + Bytes( 32, 0x33 ) + vector8( Bytes( 32, 0x22 ) )
           + Bytes{ 0x13, 0x01 } + Bytes{ 0x00 } + vector16( extensions );
}

/// A TLS 1.3 ClientHello as browsers send it: GREASE first, then the
/// server name, the versions and the application protocols.
Bytes tls13ClientHello()
{
    return clientHello( extension( 0x0A0A, {} ) + serverName( "example.com" )
                        + supportedVersions( { 0x1A, 0x1A, 0x03, 0x04, 0x03, 0x03 } )
                        + alpn( { "h2", "http/1.1" } )
                        + extension( 0x000D, { 0x00, 0x02, 0x04, 0x03 } ) );
}

PayloadDescription toServer( const Bytes& payload )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort,
                            kServerPort );
}

PayloadDescription fromServer( const Bytes& payload )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kServerPort,
                            kClientPort );
}

/// The first @p n bytes of @p bytes, in a buffer of exactly that size.
Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

bool startsWith( const std::string& s, const std::string& start )
{
    return s.compare( 0, start.size(), start ) == 0;
}

bool contains( const std::string& haystack, const std::string& needle )
{
    return haystack.find( needle ) != std::string::npos;
}

} // namespace

SCENARIO( "A ClientHello names the server, the version and the application protocols", "[tls]" )
{
    GIVEN( "a TLS 1.3 ClientHello with server name, supported versions and ALPN" )
    {
        const auto described = toServer( tls13ClientHello() );

        THEN( "the line names them in a fixed order, the highest version offered" )
        {
            REQUIRE( described.label == "TLS" );
            REQUIRE( described.description
                     == "Client Hello, SNI=example.com, TLS 1.3, ALPN=h2,http/1.1" );
        }
    }

    GIVEN( "a TLS 1.2 ClientHello with a server name only" )
    {
        const auto described = toServer( clientHello( serverName( "www.example.org" ) ) );

        THEN( "the version is the hello's own, and the absent ALPN is left out" )
        {
            REQUIRE( described.description == "Client Hello, SNI=www.example.org, TLS 1.2" );
        }
    }

    GIVEN( "a ClientHello without any extensions" )
    {
        const auto described
            = toServer( record( 0x16, handshake( 0x01, clientHelloBody( {}, false ) ) ) );

        THEN( "only its version is named" )
        {
            REQUIRE( described.description == "Client Hello, TLS 1.2" );
        }
    }

    GIVEN( "a ClientHello offering only GREASE versions" )
    {
        const auto described = toServer( clientHello( supportedVersions( { 0x2A, 0x2A } ) ) );

        THEN( "the version is the hello's own" )
        {
            REQUIRE( described.description == "Client Hello, TLS 1.2" );
        }
    }

    GIVEN( "a server name with bytes outside printable ASCII" )
    {
        const auto described = toServer( clientHello( serverName( "evil\n.com" ) ) );

        THEN( "they are escaped" )
        {
            REQUIRE( described.description == "Client Hello, SNI=evil\\x0A.com, TLS 1.2" );
        }
    }

    GIVEN( "an overlong server name" )
    {
        const auto described = toServer( clientHello( serverName( std::string( 300, 'a' ) ) ) );

        THEN( "it is cut with an ellipsis" )
        {
            REQUIRE(
                startsWith( described.description, "Client Hello, SNI=" + std::string( 120, 'a' )
                                                       + "\xe2\x80\xa6, TLS 1.2" ) );
        }
    }
}

SCENARIO( "A ServerHello names the negotiated version", "[tls]" )
{
    GIVEN( "a TLS 1.3 ServerHello" )
    {
        const auto hello = record(
            0x16, handshake( 0x02, serverHelloBody( extension( 0x002B, { 0x03, 0x04 } ) ) ) );

        THEN( "the version is the one the supported_versions extension selects" )
        {
            REQUIRE( fromServer( hello ).description == "Server Hello, TLS 1.3" );
        }
    }

    GIVEN( "a TLS 1.2 ServerHello" )
    {
        const auto hello
            = record( 0x16, handshake( 0x02, serverHelloBody( extension( 0xFF01, { 0x00 } ) ) ) );

        THEN( "the version is the hello's own" )
        {
            REQUIRE( fromServer( hello ).description == "Server Hello, TLS 1.2" );
        }
    }
}

SCENARIO( "A segment with several TLS records lists them in order", "[tls]" )
{
    const auto serverHello
        = record( 0x16, handshake( 0x02, serverHelloBody( extension( 0x002B, { 0x03, 0x04 } ) ) ) );
    const auto changeCipherSpec = record( 0x14, { 0x01 } );
    const auto applicationData = record( 0x17, Bytes( 40, 0xA5 ) );

    GIVEN( "a TLS 1.3 server flight: ServerHello, ChangeCipherSpec, Application Data" )
    {
        const auto described = fromServer( serverHello + changeCipherSpec + applicationData );

        THEN( "each record is named" )
        {
            REQUIRE( described.description
                     == "Server Hello, TLS 1.3, Change Cipher Spec, Application Data" );
        }
    }

    GIVEN( "a TLS 1.2 record carrying several handshake messages" )
    {
        const auto flight
            = record( 0x16, handshake( 0x02, serverHelloBody( {} ) )
                                + handshake( 0x0B, Bytes( 20, 0x30 ) ) + handshake( 0x0E, {} ) );

        THEN( "each message is named" )
        {
            REQUIRE( fromServer( flight ).description
                     == "Server Hello, TLS 1.2, Certificate, Server Hello Done" );
        }
    }

    GIVEN( "a handshake record after a ChangeCipherSpec" )
    {
        const auto finished = record( 0x16, Bytes( 40, 0x7E ) );

        THEN( "it is encrypted, not named by its first byte" )
        {
            REQUIRE( toServer( changeCipherSpec + finished ).description
                     == "Change Cipher Spec, Encrypted Handshake Message" );
        }
    }

    GIVEN( "more records than are listed" )
    {
        Bytes records;
        for ( int i = 0; i < 6; ++i ) {
            records = records + applicationData;
        }

        THEN( "the first four are named, then an ellipsis" )
        {
            REQUIRE( fromServer( records ).description
                     == "Application Data, Application Data, Application Data, "
                        "Application Data, \xe2\x80\xa6" );
        }
    }

    GIVEN( "a record followed by bytes that are no record" )
    {
        const auto described
            = fromServer( applicationData + Bytes{ 0x42, 0x42, 0x42, 0x42, 0x42 } );

        THEN( "only the record is named" )
        {
            REQUIRE( described.description == "Application Data" );
        }
    }

    GIVEN( "a record whose successor is cut within its header" )
    {
        const auto described = fromServer( applicationData + Bytes{ 0x17, 0x03 } );

        THEN( "only the whole record is named" )
        {
            REQUIRE( described.description == "Application Data" );
        }
    }
}

SCENARIO( "A cut or malformed TLS record is never read beyond the payload", "[tls]" )
{
    const auto hello = tls13ClientHello();

    GIVEN( "a ClientHello cut at every possible length" )
    {
        THEN( "every prefix that holds a handshake type is a Client Hello, and names "
              "only what it holds" )
        {
            for ( size_t n = 6; n <= hello.size(); ++n ) {
                INFO( "cut to " << n << " bytes" );
                const auto described = toServer( prefix( hello, n ) );
                REQUIRE( described.label == "TLS" );
                REQUIRE( startsWith( described.description, "Client Hello" ) );
                if ( contains( described.description, "SNI=" ) ) {
                    REQUIRE( contains( described.description, "SNI=example.com" ) );
                }
                if ( contains( described.description, "ALPN=" ) ) {
                    REQUIRE( contains( described.description, "ALPN=h2,http/1.1" ) );
                }
                if ( contains( described.description, "TLS 1." ) ) {
                    REQUIRE( contains( described.description, "TLS 1.3" ) );
                }
            }
        }
    }

    GIVEN( "a ClientHello cut within its ALPN extension" )
    {
        const auto cut = prefix( hello, hello.size() - 12 );

        THEN( "the server name and version read before the cut are named" )
        {
            REQUIRE( toServer( cut ).description == "Client Hello, SNI=example.com, TLS 1.3" );
        }
    }

    GIVEN( "a TLS 1.2 ClientHello cut before its extensions end" )
    {
        const auto full = clientHello( serverName( "example.com" ) + alpn( { "h2" } ) );
        const auto cut = prefix( full, full.size() - 2 );

        THEN( "its version is not guessed: a supported_versions extension may have followed" )
        {
            REQUIRE( toServer( cut ).description == "Client Hello, SNI=example.com" );
        }
    }

    GIVEN( "length fields that claim more than there is" )
    {
        auto lying = hello;
        // The extensions block: claims 0xFFFF bytes.
        const size_t extensionsAt = 5 + 4 + 2 + 32 + 33 + 6 + 2;
        lying[ extensionsAt ] = 0xFF;
        lying[ extensionsAt + 1 ] = 0xFF;

        THEN( "the fields within the payload are still read" )
        {
            REQUIRE( toServer( lying ).description
                     == "Client Hello, SNI=example.com, TLS 1.3, ALPN=h2,http/1.1" );
        }
    }

    GIVEN( "every single byte of a ClientHello set to every value" )
    {
        THEN( "the description is a Client Hello or no TLS at all" )
        {
            for ( size_t i = 0; i < hello.size(); ++i ) {
                for ( int value : { 0x00, 0x01, 0x7F, 0x80, 0xFE, 0xFF } ) {
                    auto mutated = hello;
                    mutated[ i ] = static_cast<uint8_t>( value );
                    const auto described = toServer( mutated );
                    if ( described.label == "TLS" ) {
                        REQUIRE( !described.description.empty() );
                    }
                }
            }
        }
    }

    GIVEN( "segments of hellos and records with random bytes changed, cut anywhere" )
    {
        const auto flight
            = hello
              + record( 0x16,
                        handshake( 0x02, serverHelloBody( extension( 0x002B, { 0x03, 0x04 } ) ) ) )
              + record( 0x14, { 0x01 } ) + record( 0x17, Bytes( 24, 0xA5 ) );

        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 43 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = flight;
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                }
                const auto described = toServer( prefix( mutated, random() % mutated.size() ) );
                REQUIRE( described.description.find( '\n' ) == std::string::npos );
            }
        }
    }

    GIVEN( "a record header alone" )
    {
        THEN( "it is not taken for TLS" )
        {
            REQUIRE( toServer( { 0x16, 0x03, 0x01, 0x02, 0x00 } ).label != "TLS" );
        }
    }
}
