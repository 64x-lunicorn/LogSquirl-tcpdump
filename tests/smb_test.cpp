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
 * @file smb_test.cpp
 * @brief BDD tests for the SMB detector: the NetBIOS Session Service
 *        framing, the SMB2/3 commands with their fields and NT status
 *        names, compounded requests, the SMB 3 transform headers, SMB1,
 *        framing for the TCP Reassembly, and messages mangled and cut
 *        anywhere.
 */

#include <catch2/catch.hpp>

#include "payload_describer.h"
#include "pcapbuilder.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint16_t kSmbPort = 445;
constexpr uint16_t kNbssPort = 139;
constexpr uint16_t kClientPort = 50000;

const std::string kEllipsis = "\xe2\x80\xa6";

void putLE64( Bytes& b, uint64_t v )
{
    putLE32( b, static_cast<uint32_t>( v ) );
    putLE32( b, static_cast<uint32_t>( v >> 32 ) );
}

/// @p s as UTF-16LE.
Bytes utf16( const std::string& s )
{
    Bytes b;
    for ( const char c : s ) {
        putLE16( b, static_cast<uint8_t>( c ) );
    }
    return b;
}

/// An SMB2 header of @p command, then @p body.
Bytes smb2( uint16_t command, const Bytes& body, bool response = false, uint32_t status = 0,
            uint32_t nextCommand = 0 )
{
    Bytes b{ 0xFE, 'S', 'M', 'B' };
    putLE16( b, 64 );
    putLE16( b, 1 );      // credit charge
    putLE32( b, status ); // status
    putLE16( b, command );
    putLE16( b, 1 ); // credits
    putLE32( b, response ? 0x00000001 : 0x00000000 );
    putLE32( b, nextCommand );
    putLE64( b, 7 ); // message id
    putLE32( b, 0xFEFF );
    putLE32( b, 1 );            // tree id
    putLE64( b, 0x1000040001 ); // session id
    b.resize( b.size() + 16 );  // signature
    return b + body;
}

/// @p message behind its NBSS session message header.
Bytes nbss( const Bytes& message )
{
    Bytes b{ 0x00 };
    b.push_back( static_cast<uint8_t>( message.size() >> 16 ) );
    putBE16( b, static_cast<uint16_t>( message.size() ) );
    return b + message;
}

/// The bodies of the requests that carry a field, laid out as MS-SMB2 2.2.
Bytes negotiateRequest( const std::vector<uint16_t>& dialects )
{
    Bytes b;
    putLE16( b, 36 );
    putLE16( b, static_cast<uint16_t>( dialects.size() ) );
    putLE16( b, 1 ); // security mode
    putLE16( b, 0 );
    putLE32( b, 0x7F ); // capabilities
    b.resize( b.size() + 16 + 8 );
    for ( const auto d : dialects ) {
        putLE16( b, d );
    }
    return b;
}

Bytes negotiateResponse( uint16_t dialect )
{
    Bytes b;
    putLE16( b, 65 );
    putLE16( b, 1 );
    putLE16( b, dialect );
    b.resize( 64 );
    return b;
}

/// A body whose name, @p name in UTF-16, starts right after the @p fixed
/// bytes before it; the offset and length at @p at.
Bytes withName( size_t fixed, size_t at, const std::string& name )
{
    Bytes b( fixed, 0 );
    const auto encoded = utf16( name );
    const auto offset = static_cast<uint16_t>( 64 + fixed );
    b[ at ] = static_cast<uint8_t>( offset );
    b[ at + 1 ] = static_cast<uint8_t>( offset >> 8 );
    b[ at + 2 ] = static_cast<uint8_t>( encoded.size() );
    b[ at + 3 ] = static_cast<uint8_t>( encoded.size() >> 8 );
    b[ 0 ] = static_cast<uint8_t>( fixed + 1 ); // structure size, odd: a buffer follows
    return b + encoded;
}

Bytes treeConnect( const std::string& path )
{
    return smb2( 0x03, withName( 8, 4, path ) );
}

Bytes create( const std::string& file )
{
    return smb2( 0x05, withName( 56, 44, file ) );
}

Bytes readOrWrite( uint16_t command, uint32_t length, uint64_t offset )
{
    Bytes b;
    putLE16( b, 49 );
    putLE16( b, 0 );
    putLE32( b, length );
    putLE64( b, offset );
    b.resize( 48 );
    return smb2( command, b );
}

Bytes ioctl( uint32_t code, bool response = false )
{
    Bytes b;
    putLE16( b, response ? 49 : 57 );
    putLE16( b, 0 );
    putLE32( b, code );
    b.resize( response ? 48 : 56 );
    return smb2( 0x0B, b, response );
}

Bytes find( uint8_t infoClass, const std::string& pattern )
{
    auto b = withName( 32, 24, pattern );
    b[ 2 ] = infoClass;
    return smb2( 0x0E, b );
}

/// An error response: the error body.
Bytes error( uint16_t command, uint32_t status )
{
    return smb2( command, { 9, 0, 0, 0, 0, 0, 0, 0, 0 }, true, status );
}

/// Commands compounded: each one's NextCommand points at the next.
Bytes compound( const std::vector<Bytes>& commands )
{
    Bytes all;
    for ( size_t i = 0; i < commands.size(); ++i ) {
        auto c = commands[ i ];
        if ( i + 1 < commands.size() ) {
            while ( c.size() % 8 ) {
                c.push_back( 0 );
            }
            c[ 20 ] = static_cast<uint8_t>( c.size() );
            c[ 21 ] = static_cast<uint8_t>( c.size() >> 8 );
        }
        all = all + c;
    }
    return all;
}

PayloadDescription onPort( const Bytes& payload, uint16_t port = kSmbPort )
{
    return describePayload( Transport::Tcp, payload.data(), payload.size(), kClientPort, port );
}

std::string described( const Bytes& message )
{
    const auto result = onPort( nbss( message ) );
    REQUIRE( result.label == "SMB2" );
    REQUIRE_FALSE( result.guessed );
    return result.description;
}

Bytes prefix( const Bytes& bytes, size_t n )
{
    return Bytes( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( n ) );
}

const Bytes kSessionSetup( 24, 0 );

} // namespace

SCENARIO( "SMB2 commands are named as Wireshark names them", "[smb]" )
{
    GIVEN( "a negotiation" )
    {
        THEN( "the dialects the client offers and the server picks are named" )
        {
            REQUIRE( described( smb2(
                         0x00, negotiateRequest( { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 } ) ) )
                     == "Negotiate Protocol Request Dialects: 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1" );
            REQUIRE( described( smb2( 0x00, negotiateResponse( 0x0311 ), true ) )
                     == "Negotiate Protocol Response Dialect: 3.1.1" );
        }
    }

    GIVEN( "a session setup that needs another round" )
    {
        THEN( "the response names its status" )
        {
            REQUIRE( described( smb2( 0x01, kSessionSetup ) ) == "Session Setup Request" );
            REQUIRE( described( error( 0x01, 0xC0000016 ) )
                     == "Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED" );
            REQUIRE( described( smb2( 0x01, kSessionSetup, true ) ) == "Session Setup Response" );
        }
    }

    GIVEN( "a tree connect and a create" )
    {
        THEN( "the share and the file are named from their UTF-16 names" )
        {
            REQUIRE( described( treeConnect( "\\\\server\\share" ) )
                     == "Tree Connect Request Tree: \\\\server\\share" );
            REQUIRE( described( create( "dir\\file.txt" ) )
                     == "Create Request File: dir\\file.txt" );
            REQUIRE( described( create( "" ) ) == "Create Request" );
            REQUIRE( described( error( 0x05, 0xC0000034 ) )
                     == "Create Response, Error: STATUS_OBJECT_NAME_NOT_FOUND" );
            REQUIRE( described( error( 0x03, 0xC0000022 ) )
                     == "Tree Connect Response, Error: STATUS_ACCESS_DENIED" );
        }
    }

    GIVEN( "a name that is not ASCII, or too long" )
    {
        Bytes umlaut;
        putLE16( umlaut, 0x00FC );
        putLE16( umlaut, 0xD83D ); // a surrogate pair
        putLE16( umlaut, 0xDE00 );
        putLE16( umlaut, 0xDC00 ); // an unpaired one
        putLE16( umlaut, 0x000A );
        auto body = withName( 56, 44, "" );
        body[ 46 ] = static_cast<uint8_t>( umlaut.size() );
        THEN( "it is UTF-8, control characters and unpaired surrogates escaped, cut with an "
              "ellipsis" )
        {
            REQUIRE( described( smb2( 0x05, body + umlaut ) )
                     == "Create Request File: \xc3\xbc\xf0\x9f\x98\x80\\uDC00\\x0A" );
            const std::string longName( 200, 'a' );
            REQUIRE( described( create( longName ) )
                     == "Create Request File: " + std::string( 120, 'a' ) + kEllipsis );
        }
    }

    GIVEN( "reads, writes, ioctls and finds" )
    {
        THEN( "their lengths, offsets, control codes and patterns are named" )
        {
            REQUIRE( described( readOrWrite( 0x08, 65536, 0 ) ) == "Read Request Len:65536 Off:0" );
            REQUIRE( described( smb2( 0x08, Bytes( 16, 0 ), true ) ) == "Read Response" );
            REQUIRE( described( readOrWrite( 0x09, 1024, 4096 ) )
                     == "Write Request Len:1024 Off:4096" );
            REQUIRE( described( ioctl( 0x00060194 ) ) == "Ioctl Request FSCTL_DFS_GET_REFERRALS" );
            REQUIRE( described( ioctl( 0x00140204, true ) )
                     == "Ioctl Response FSCTL_VALIDATE_NEGOTIATE_INFO" );
            REQUIRE( described( ioctl( 0x00123456 ) ) == "Ioctl Request 0x00123456" );
            REQUIRE( described( find( 0x25, "*" ) )
                     == "Find Request SMB2_FIND_ID_BOTH_DIRECTORY_INFO Pattern: *" );
            REQUIRE( described( error( 0x0E, 0x80000006 ) )
                     == "Find Response, Error: STATUS_NO_MORE_FILES" );
        }
    }

    GIVEN( "the commands without fields" )
    {
        THEN( "they are named, and an unknown status by its number" )
        {
            REQUIRE( described( smb2( 0x06, Bytes( 24, 0 ) ) ) == "Close Request" );
            REQUIRE( described( smb2( 0x0F, Bytes( 32, 0 ) ) ) == "Notify Request" );
            REQUIRE( described( error( 0x0F, 0x00000103 ) )
                     == "Notify Response, Error: STATUS_PENDING" );
            REQUIRE( described( smb2( 0x02, Bytes( 4, 0 ) ) ) == "Session Logoff Request" );
            REQUIRE( described( smb2( 0x12, Bytes( 24, 0 ), true ) ) == "Break Response" );
            REQUIRE( described( smb2( 0x13, {} ) ) == "Unknown command 0x0013 Request" );
            REQUIRE( described( error( 0x06, 0xC0001234 ) )
                     == "Close Response, Error: Unknown (0xC0001234)" );
            Bytes info( 40, 0 );
            info[ 2 ] = 0x01;
            info[ 3 ] = 0x12;
            REQUIRE( described( smb2( 0x10, info ) )
                     == "GetInfo Request FILE_INFO/SMB2_FILE_ALL_INFO" );
        }
    }
}

SCENARIO( "Several SMB commands in a segment are all named", "[smb]" )
{
    GIVEN( "compounded requests" )
    {
        const auto message = compound(
            { create( "a.txt" ), smb2( 0x10, Bytes( 40, 0 ) ), smb2( 0x06, Bytes( 24, 0 ) ) } );
        THEN( "every command is named" )
        {
            REQUIRE( described( message )
                     == "Create Request File: a.txt; GetInfo Request Info type 0x00; Close "
                        "Request" );
        }
    }

    GIVEN( "several messages in a segment, more commands than are named" )
    {
        Bytes segment;
        for ( int i = 0; i < 10; ++i ) {
            segment = segment + nbss( smb2( 0x0D, Bytes( 4, 0 ) ) );
        }
        Bytes compounded;
        std::vector<Bytes> commands( 10, smb2( 0x0D, Bytes( 4, 0 ) ) );
        THEN( "the first eight are named, then an ellipsis" )
        {
            std::string eight;
            for ( int i = 0; i < 8; ++i ) {
                eight += ( eight.empty() ? "" : "; " ) + std::string( "KeepAlive Request" );
            }
            REQUIRE( onPort( segment ).description == eight + "; " + kEllipsis );
            REQUIRE( described( compound( commands ) ) == eight + "; " + kEllipsis );
            REQUIRE( onPort( nbss( compound( std::vector<Bytes>( 8, commands[ 0 ] ) ) )
                             + nbss( commands[ 0 ] ) )
                         .description
                     == eight + "; " + kEllipsis );
        }
    }

    GIVEN( "encrypted, compressed and SMB1 messages" )
    {
        Bytes encrypted{ 0xFD, 'S', 'M', 'B' };
        encrypted.resize( 52 + 100, 0x5A );
        Bytes compressed{ 0xFC, 'S', 'M', 'B' };
        putLE32( compressed, 4096 );
        putLE16( compressed, 0x0002 );
        putLE16( compressed, 0x0000 );
        putLE32( compressed, 0 );
        compressed.resize( 16 + 50, 0x11 );
        Bytes smb1{ 0xFF, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18 };
        smb1.resize( 32 + 3, 0 );
        auto reply = smb1;
        reply[ 9 ] = 0x98;
        THEN( "they are named, SMB1 labelled SMB" )
        {
            REQUIRE( described( encrypted ) == "Encrypted SMB3" );
            REQUIRE( described( compressed ) == "Compressed SMB3, LZ77, Original size 4096" );
            const auto legacy = onPort( nbss( smb1 ) );
            REQUIRE( legacy.label == "SMB" );
            REQUIRE( legacy.description == "Negotiate Protocol Request" );
            REQUIRE( onPort( nbss( reply ) ).description == "Negotiate Protocol Response" );
            REQUIRE(
                onPort( nbss( smb1 ) + nbss( smb2( 0x00, negotiateResponse( 0x02FF ), true ) ) )
                    .description
                == "Negotiate Protocol Request; Negotiate Protocol Response Dialect: 2.x" );
        }
    }

    GIVEN( "NBSS session messages on port 139" )
    {
        const Bytes request{ 0x81, 0x00, 0x00, 0x04, 1, 2, 3, 4 };
        const Bytes positive{ 0x82, 0x00, 0x00, 0x00 };
        THEN( "they are named, labelled NBSS" )
        {
            const auto result = onPort( request, kNbssPort );
            REQUIRE( result.label == "NBSS" );
            REQUIRE( result.description == "Session request" );
            REQUIRE( onPort( positive, kNbssPort ).description == "Positive session response" );
            REQUIRE( onPort( nbss( create( "x" ) ), kNbssPort ).description
                     == "Create Request File: x" );
        }
    }

    GIVEN( "SMB on another port" )
    {
        THEN( "it is told by its protocol ID, and only by it" )
        {
            REQUIRE( onPort( nbss( create( "x" ) ), 8445 ).label == "SMB2" );
            REQUIRE( onPort( Bytes{ 0x82, 0x00, 0x00, 0x00 }, 8445 ).label != "NBSS" );
        }
    }

    GIVEN( "messages over TCP" )
    {
        const auto first = nbss( create( "dir\\file.txt" ) );
        const auto segment = first + nbss( smb2( 0x06, Bytes( 24, 0 ) ) );
        THEN( "the TCP Reassembly frames them by their NBSS length" )
        {
            const auto whole
                = tcpMessageExtent( segment.data(), segment.size(), kClientPort, kSmbPort );
            REQUIRE( whole.complete() );
            REQUIRE( whole.length == first.size() );
            REQUIRE( std::string( whole.label ) == "SMB2" );
            const auto cut = tcpMessageExtent( segment.data(), 70, kClientPort, kSmbPort );
            REQUIRE( cut.needsMore );
            REQUIRE( cut.length == first.size() );
            const auto header = tcpMessageExtent( segment.data(), 3, kClientPort, kSmbPort );
            REQUIRE( header.needsMore );
            REQUIRE( header.length == 4 );
            // Elsewhere a message is framed only with its protocol ID.
            REQUIRE( tcpMessageExtent( segment.data(), 70, kClientPort, 8445 ).framer != 0 );
            const Bytes other{ 0x00, 0x00, 0x00, 0x10, 'H', 'E', 'L', 'O' };
            REQUIRE( tcpMessageExtent( other.data(), other.size(), kClientPort, 8445 ).framer
                     == 0 );
            const auto onSmbPort
                = tcpMessageExtent( other.data(), other.size(), kClientPort, kSmbPort );
            REQUIRE( ( onSmbPort.framer == 0 || std::string( onSmbPort.label ) != "SMB2" ) );
        }
    }
}

SCENARIO( "A truncated or malformed SMB message is described as such", "[smb]" )
{
    GIVEN( "a message cut at the snaplen or the end of the segment" )
    {
        const auto message = nbss( create( "dir\\file.txt" ) );
        THEN( "it is named as far as it goes, then an ellipsis" )
        {
            REQUIRE( onPort( prefix( message, 4 + 64 + 10 ) ).description
                     == "Create Request " + kEllipsis );
            REQUIRE( onPort( prefix( message, 4 + 20 ) ).description == "Create " + kEllipsis );
            REQUIRE( onPort( prefix( message, 4 + 8 ) ).description == "Header " + kEllipsis );
            REQUIRE( onPort( prefix( message, 2 ) ).description == "Header " + kEllipsis );
        }
    }

    GIVEN( "a wrong header size, a NextCommand beyond the message, a name beyond it" )
    {
        auto size = create( "x" );
        size[ 4 ] = 63;
        auto next = create( "x" );
        next[ 20 ] = 0xF0;
        auto name = create( "x" );
        name[ 64 + 44 ] = 0xF0;
        auto dialects = smb2( 0x00, negotiateRequest( { 0x0202 } ) );
        dialects[ 64 + 2 ] = 9;
        THEN( "it is malformed" )
        {
            REQUIRE( described( size ) == "Invalid header size 63 [Malformed Packet]" );
            REQUIRE( described( next )
                     == "Create Request, Invalid NextCommand 240 [Malformed Packet]" );
            REQUIRE( described( name ) == "Create Request [Malformed Packet]" );
            REQUIRE( described( dialects ) == "Negotiate Protocol Request [Malformed Packet]" );
            REQUIRE( described( prefix( create( "x" ), 40 ) ) == "Header [Malformed Packet]" );
            REQUIRE( described( Bytes{ 0xFD, 'S', 'M', 'B', 0 } )
                     == "Encrypted SMB3 [Malformed Packet]" );
        }
    }

    GIVEN( "bytes on SMB's port that begin no NBSS message" )
    {
        THEN( "they are only guessed SMB, without a preview" )
        {
            const auto result = onPort( text( "hello there, not SMB" ) );
            REQUIRE( result.label == "SMB" );
            REQUIRE( result.guessed );
            REQUIRE( result.description.empty() );
            REQUIRE( onPort( nbss( create( "x" ) ) + Bytes{ 0x42, 0, 0, 0 } ).description
                     == "Create Request File: x; Unknown message type 0x42 [Malformed Packet]" );
        }
    }
}

SCENARIO( "Mangled SMB never breaks the describer", "[smb][fuzz]" )
{
    Bytes encrypted{ 0xFD, 'S', 'M', 'B' };
    encrypted.resize( 60, 0x5A );
    Bytes compressed{ 0xFC, 'S', 'M', 'B', 0, 0x10, 0, 0, 2, 0, 1, 0, 0, 0, 0, 0, 1, 2 };
    const Bytes smb1{ 0xFF, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0, 0 };
    const std::vector<Bytes> messages = {
        nbss( smb2( 0x00, negotiateRequest( { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 } ) ) ),
        nbss( smb2( 0x00, negotiateResponse( 0x0311 ), true ) ),
        nbss( error( 0x01, 0xC0000016 ) ),
        nbss( treeConnect( "\\\\server\\share" ) ),
        nbss( compound( { create( "dir\\file.txt" ), smb2( 0x10, Bytes( 40, 0 ) ),
                          smb2( 0x06, Bytes( 24, 0 ) ) } ) ),
        nbss( readOrWrite( 0x08, 65536, 0 ) ),
        nbss( readOrWrite( 0x09, 1024, 4096 ) ),
        nbss( ioctl( 0x00060194 ) ),
        nbss( find( 0x25, "*" ) ),
        nbss( encrypted ),
        nbss( compressed ),
        nbss( smb1 ),
        Bytes{ 0x81, 0x00, 0x00, 0x04, 1, 2, 3, 4 },
    };
    auto check = []( const Bytes& bytes ) {
        for ( const auto& result :
              { onPort( bytes ), onPort( bytes, kNbssPort ), onPort( bytes, 8445 ) } ) {
            REQUIRE( result.description.find( '\n' ) == std::string::npos );
            REQUIRE( result.description.size() < 4096 );
        }
        const auto extent = tcpMessageExtent( bytes.data(), bytes.size(), kClientPort, kSmbPort );
        REQUIRE( ( extent.framer == 0 || extent.length > 0 ) );
    };

    GIVEN( "every prefix of each message" )
    {
        THEN( "each is described in one line" )
        {
            for ( const auto& message : messages ) {
                for ( size_t n = 0; n <= message.size(); ++n ) {
                    const auto cut = prefix( message, n );
                    check( cut );
                    if ( n == message.size() ) {
                        const auto whole = onPort( cut, kNbssPort ).description;
                        INFO( whole );
                        REQUIRE( whole.find( "Malformed" ) == std::string::npos );
                        REQUIRE( whole.find( kEllipsis ) == std::string::npos );
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
                    for ( int value : { 0x00, 0x01, 0x02, 0x0F, 0x10, 0x40, 0x7F, 0x80, 0xFF } ) {
                        auto mutated = message;
                        mutated[ i ] = static_cast<uint8_t>( value );
                        check( mutated );
                    }
                }
            }
        }
    }

    GIVEN( "segments of several messages with random bytes changed, cut anywhere" )
    {
        Bytes segment;
        for ( const auto& message : messages ) {
            segment = segment + message;
        }
        THEN( "the describer reads them without fault" )
        {
            std::mt19937 random( 445 );
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = segment;
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
