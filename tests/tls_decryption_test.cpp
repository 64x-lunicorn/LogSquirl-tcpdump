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
 * @file tls_decryption_test.cpp
 * @brief BDD tests for the TLS Decryption, on the synthetic sessions of
 *        tests/corpus/tls-decrypt.pcap (tests/make_tls_decrypt_corpus.py):
 *        what is decrypted, what is left as it was, secrets that come late,
 *        and mutated records; and for HTTP/2 described from whole bytes.
 */

#include <catch2/catch.hpp>

#include "capture_reader.h"
#include "payload_describer.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tcp_reassembly.h"
#include "tls_decryption.h"
#include "tls_key_log.h"

#include <QFile>

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes readFile( const QString& name )
{
    QFile file( QStringLiteral( TCPDUMP_CORPUS_DIR ) + "/" + name );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto bytes = file.readAll();
    return Bytes( bytes.begin(), bytes.end() );
}

/// The key log of the synthetic sessions.
tls::KeyLog corpusKeys()
{
    const auto text = readFile( "tls-decrypt.keys" );
    tls::KeyLog keys;
    keys.addLines( reinterpret_cast<const char*>( text.data() ), text.size() );
    return keys;
}

/// Each packet's protocol and Info, as the Converter's steps leave them,
/// decrypted by @p decryption if there is one.
std::vector<std::string> lines( const Bytes& capture, TlsDecryption* decryption )
{
    MemorySource memory( capture.data(), capture.size() );
    HeadSource head( memory );
    const auto reader = makeCaptureReader( head );
    REQUIRE( reader->open() );
    StreamTracker tracker;
    TcpReassembly reassembly;
    StreamLabels labels;
    std::vector<std::string> out;
    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto stream = tracker.track( pkt );
        analyseTcp( pkt, stream );
        describeInStream( pkt, stream );
        const auto messages = reassembly.apply( pkt, stream, reader->payloadOf( pkt ) );
        if ( decryption ) {
            decryption->apply( pkt, stream, messages );
        }
        labels.apply( pkt, stream );
        out.push_back( pkt.protocol + "  " + pkt.info );
    }
    return out;
}

bool contains( const std::string& line, const std::string& part )
{
    return line.find( part ) != std::string::npos;
}

/// The lines of a session, by its client port.
std::vector<size_t> sessionLines( const std::vector<std::string>& all, const std::string& port )
{
    std::vector<size_t> found;
    for ( size_t i = 0; i < all.size(); ++i ) {
        if ( contains( all[ i ], port + " \xe2\x86\x92" )
             || contains( all[ i ], "\xe2\x86\x92 " + port ) ) {
            found.push_back( i );
        }
    }
    return found;
}

Bytes fromHex( const std::string& hex )
{
    Bytes bytes;
    for ( size_t i = 0; i + 1 < hex.size(); i += 2 ) {
        bytes.push_back( static_cast<uint8_t>( std::stoul( hex.substr( i, 2 ), nullptr, 16 ) ) );
    }
    return bytes;
}

Bytes h2Frame( uint8_t type, uint8_t flags, uint32_t stream, const Bytes& payload )
{
    Bytes frame{ static_cast<uint8_t>( payload.size() >> 16 ),
                 static_cast<uint8_t>( payload.size() >> 8 ),
                 static_cast<uint8_t>( payload.size() ),
                 type,
                 flags,
                 static_cast<uint8_t>( stream >> 24 ),
                 static_cast<uint8_t>( stream >> 16 ),
                 static_cast<uint8_t>( stream >> 8 ),
                 static_cast<uint8_t>( stream ) };
    frame.insert( frame.end(), payload.begin(), payload.end() );
    return frame;
}

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

std::string describe( Http2Direction& direction, const Bytes& bytes )
{
    return direction.describe( bytes.data(), bytes.size() );
}

// RFC 7541, C.4.1 and C.4.2: GET http://www.example.com/, and the same
// again with cache-control, the authority from the dynamic table.
const auto kFirstRequest = fromHex( "828684418cf1e3c2e5f23a6ba0ab90f4ff" );
const auto kSecondRequest = fromHex( "828684be5886a8eb10649cbf" );

constexpr uint8_t kHeaders = 0x1;
constexpr uint8_t kData = 0x0;
constexpr uint8_t kContinuation = 0x9;
constexpr uint8_t kEndStream = 0x1;
constexpr uint8_t kEndHeaders = 0x4;

} // namespace

SCENARIO( "TLS sessions are decrypted with the secrets of the key log", "[tls_decryption]" )
{
    const auto capture = readFile( "tls-decrypt.pcap" );
    const auto keys = corpusKeys();
    const auto plain = lines( capture, nullptr );

    GIVEN( "the synthetic sessions and their key log" )
    {
        TlsDecryption decryption(
            [ &keys ]( const uint8_t* random ) { return keys.find( random ); } );
        const auto decrypted = lines( capture, &decryption );
        REQUIRE( decrypted.size() == plain.size() );

        THEN( "the sessions with their secrets are decrypted, and HTTP described" )
        {
            REQUIRE( decryption.sessionsDecrypted() == 6 );
            const auto tls12 = sessionLines( decrypted, "50101" );
            REQUIRE(
                decrypted[ tls12[ 7 ] ]
                == "HTTP  50101 \xe2\x86\x92 443 [ACK, PSH] Seq=194 Ack=628 Win=64240 Len=117 | "
                   "TLS (decrypted) | GET www.example.com/index.html HTTP/1.1" );
            const auto h2 = sessionLines( decrypted, "50102" );
            REQUIRE( contains( decrypted[ h2[ 7 ] ], "HTTP2  " ) );
            REQUIRE( contains( decrypted[ h2[ 7 ] ],
                               "| TLS (decrypted) | SETTINGS[0], "
                               "HEADERS[3]: GET h2.example.org/index.html" ) );
        }

        THEN( "those without secrets, or with wrong ones, keep their lines" )
        {
            for ( const auto* port : { "50107", "50108" } ) {
                for ( const auto i : sessionLines( decrypted, port ) ) {
                    INFO( "line " << i + 1 );
                    REQUIRE( decrypted[ i ] == plain[ i ] );
                }
            }
        }

        THEN( "no line shows a secret" )
        {
            const auto text = readFile( "tls-decrypt.keys" );
            const std::string keyLog( text.begin(), text.end() );
            for ( const auto& line : decrypted ) {
                // A secret is the third field of a key log line; 16 hex
                // digits of it would give it away.
                size_t at = 0;
                while ( ( at = keyLog.find( '\n', at ) ) != std::string::npos ) {
                    const auto end = keyLog.find( '\n', at + 1 );
                    const auto entry = keyLog.substr( at + 1, end - at - 1 );
                    const auto space = entry.rfind( ' ' );
                    if ( space != std::string::npos && entry.size() > space + 16 ) {
                        REQUIRE_FALSE( contains( line, entry.substr( space + 1, 16 ) ) );
                    }
                    at = end;
                }
            }
        }
    }

    GIVEN( "no secrets at all" )
    {
        TlsDecryption decryption(
            []( const uint8_t* ) -> const tls::SessionSecrets* { return nullptr; } );
        const auto decrypted = lines( capture, &decryption );

        THEN( "every line is as without a key log" )
        {
            REQUIRE( decrypted == plain );
            REQUIRE( decryption.sessionsDecrypted() == 0 );
        }
    }

    GIVEN( "secrets that come into the key log late, as in a live capture" )
    {
        int asked = 0;
        TlsDecryption decryption( [ &keys, &asked ]( const uint8_t* random ) {
            // Not there for the first records that ask for them.
            return ++asked <= 2 ? nullptr : keys.find( random );
        } );
        const auto decrypted = lines( capture, &decryption );

        THEN( "the records after they came are decrypted" )
        {
            const auto tls12 = sessionLines( decrypted, "50101" );
            REQUIRE_FALSE( contains( decrypted[ tls12[ 5 ] ], kDecryptedMarker ) );
            REQUIRE_FALSE( contains( decrypted[ tls12[ 6 ] ], kDecryptedMarker ) );
            REQUIRE( contains( decrypted[ tls12[ 7 ] ], "GET www.example.com/index.html" ) );
            REQUIRE( decryption.sessionsDecrypted() == 6 );
        }
    }
}

SCENARIO( "Mutated TLS records are decrypted or left, within bounds", "[tls_decryption][fuzz]" )
{
    const auto capture = readFile( "tls-decrypt.pcap" );
    const auto keys = corpusKeys();

    GIVEN( "the synthetic capture with random bytes of its segments flipped" )
    {
        std::mt19937 random( 84 );
        constexpr size_t kHeaders = 24 + 16 + 14 + 20 + 20; // up to the first TCP payload

        THEN( "it converts, as many lines as packets, and the sessions stay bounded" )
        {
            for ( int round = 0; round < 300; ++round ) {
                auto mutated = capture;
                const auto flips = 1 + random() % 8;
                for ( unsigned f = 0; f < flips; ++f ) {
                    const auto at = kHeaders + random() % ( mutated.size() - kHeaders );
                    mutated[ at ] ^= static_cast<uint8_t>( 1 + random() % 255 );
                }
                TlsDecryption decryption( [ &keys ]( const uint8_t* clientRandom ) {
                    return keys.find( clientRandom );
                } );
                const auto converted = lines( mutated, &decryption );
                REQUIRE( converted.size() > 0 );
                REQUIRE( decryption.sessions() <= 8 );
                REQUIRE( decryption.http2Memory() <= TlsDecryption::kHttp2MemoryLimit );
            }
        }
    }
}

SCENARIO( "HTTP/2 from whole bytes is described with its header blocks", "[tls_decryption][http2]" )
{
    GIVEN( "the client's preface, SETTINGS and a request" )
    {
        Http2Direction client;
        const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        const auto bytes = Bytes( preface.begin(), preface.end() ) + h2Frame( 0x4, 0, 0, {} )
                           + h2Frame( kHeaders, kEndStream | kEndHeaders, 1, kFirstRequest );

        THEN( "the request is told" )
        {
            REQUIRE( describe( client, bytes )
                     == "Magic, SETTINGS[0], HEADERS[1]: GET www.example.com/" );
        }
    }

    GIVEN( "a header block over a HEADERS and a CONTINUATION frame" )
    {
        Http2Direction client;
        const Bytes first( kFirstRequest.begin(), kFirstRequest.begin() + 5 );
        const Bytes rest( kFirstRequest.begin() + 5, kFirstRequest.end() );
        const auto bytes
            = h2Frame( kHeaders, 0, 1, first ) + h2Frame( kContinuation, kEndHeaders, 1, rest );

        THEN( "the request is told on the HEADERS frame" )
        {
            REQUIRE( describe( client, bytes )
                     == "HEADERS[1]: GET www.example.com/, CONTINUATION[1]" );
        }
    }

    GIVEN( "a request frame split over two pieces of bytes, then one that builds on it" )
    {
        Http2Direction client;
        const auto frame = h2Frame( kHeaders, kEndStream | kEndHeaders, 1, kFirstRequest );
        const Bytes head( frame.begin(), frame.begin() + 12 );
        const Bytes tail( frame.begin() + 12, frame.end() );

        THEN( "the frame is named where it begins, and the dynamic table follows it" )
        {
            REQUIRE( describe( client, head ) == "HEADERS[1]" );
            REQUIRE( describe( client, tail ).empty() );
            REQUIRE( describe( client, h2Frame( kHeaders, kEndHeaders, 3, kSecondRequest ) )
                     == "HEADERS[3]: GET www.example.com/" );
        }
    }

    GIVEN( "DATA frames longer than the bytes at hand" )
    {
        Http2Direction server;
        const auto frame = h2Frame( kData, kEndStream, 1, Bytes( 3000, 'x' ) );

        THEN( "they are named once and passed over without being held" )
        {
            REQUIRE( describe( server, Bytes( frame.begin(), frame.begin() + 100 ) ) == "DATA[1]" );
            REQUIRE( server.memory() <= 9 );
            REQUIRE( describe( server, Bytes( frame.begin() + 100, frame.end() ) ).empty() );
            REQUIRE( describe( server, h2Frame( 0x6, 0, 0, Bytes( 8 ) ) ) == "PING[0]" );
        }
    }

    GIVEN( "a header block longer than the most decoded" )
    {
        Http2Direction client;
        const auto tooLong
            = h2Frame( kHeaders, 0, 1, Bytes( Http2Direction::kMaxHeaderBlockBytes + 1, 0x82 ) );

        THEN( "it is passed over, and later blocks are named only" )
        {
            REQUIRE( describe( client, tooLong ) == "HEADERS[1]" );
            REQUIRE( describe( client, h2Frame( kHeaders, kEndHeaders, 3, kFirstRequest ) )
                     == "HEADERS[3]" );
            REQUIRE( client.memory() <= 9 );
        }
    }

    GIVEN( "mutated frames" )
    {
        std::mt19937 random( 7541 );
        const auto stream = h2Frame( 0x4, 0, 0, Bytes( 12 ) )
                            + h2Frame( kHeaders, kEndHeaders, 1, kFirstRequest )
                            + h2Frame( kData, 0, 1, Bytes( 40, 'd' ) )
                            + h2Frame( kHeaders, kEndHeaders, 3, kSecondRequest );

        THEN( "they are described within bounds" )
        {
            for ( int round = 0; round < 2000; ++round ) {
                auto bytes = stream;
                const auto flips = 1 + random() % 4;
                for ( unsigned f = 0; f < flips; ++f ) {
                    bytes[ random() % bytes.size() ] ^= static_cast<uint8_t>( 1 + random() % 255 );
                }
                Http2Direction direction;
                size_t at = 0;
                while ( at < bytes.size() ) {
                    const auto n = std::min<size_t>( 1 + random() % 40, bytes.size() - at );
                    const Bytes piece( bytes.begin() + static_cast<std::ptrdiff_t>( at ),
                                       bytes.begin() + static_cast<std::ptrdiff_t>( at + n ) );
                    direction.describe( piece.data(), piece.size() );
                    at += n;
                    REQUIRE( direction.memory() <= 2 * ( Http2Direction::kMaxHeaderBlockBytes + 9 )
                                                       + HpackDecoder::kMaxTableSize );
                }
            }
        }
    }
}
