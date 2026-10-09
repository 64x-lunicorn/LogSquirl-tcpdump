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

#include <mbedtls/gcm.h>

#include <cstring>
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

/// A TLS 1.3 session with TLS_AES_128_GCM_SHA256 between a client (stream
/// direction 0, port 50000) and a server (direction 1, port 443), its
/// records protected here and fed straight to a TlsDecryption, one segment
/// of whole records at a time.
class Tls13Session {
public:
    Tls13Session()
    {
        for ( size_t i = 0; i < random_.size(); ++i ) {
            random_[ i ] = static_cast<uint8_t>( 0xA0 + i );
        }
        secrets_.clientHandshakeTraffic = secret( 1 );
        secrets_.serverHandshakeTraffic = secret( 2 );
        secrets_.clientTraffic = secret( 3 );
        secrets_.serverTraffic = secret( 4 );
        keys_[ 0 ].secret = secrets_.clientHandshakeTraffic;
        keys_[ 1 ].secret = secrets_.serverHandshakeTraffic;
    }

    TlsDecryption::Lookup lookup() const
    {
        return [ this ]( const uint8_t* random ) -> const tls::SessionSecrets* {
            return std::memcmp( random, random_.data(), random_.size() ) == 0 ? &secrets_ : nullptr;
        };
    }

    /// The ClientHello and the ServerHello, plaintext records.
    Bytes clientHello() const
    {
        Bytes body{ 0x03, 0x03 };
        body.insert( body.end(), random_.begin(), random_.end() );
        body = body + Bytes{ 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00, 0x00, 0x00 };
        return record( 0x16, handshakeMessage( 1, body ) );
    }
    Bytes serverHello() const
    {
        Bytes body{ 0x03, 0x03 };
        for ( uint8_t i = 0; i < 32; ++i ) {
            body.push_back( static_cast<uint8_t>( 0x50 + i ) );
        }
        body = body
               + Bytes{ 0x00, 0x13, 0x01, 0x00, 0x00, 0x06, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04 };
        return record( 0x16, handshakeMessage( 2, body ) );
    }

    /// A protected record of direction @p d, its content type @p inner.
    Bytes seal( unsigned d, uint8_t inner, const Bytes& plain )
    {
        auto& keys = keys_[ d ];
        const auto key = tls::hkdfExpandLabel( tls::Hash::Sha256, keys.secret, "key", {}, 16 );
        const auto iv = tls::hkdfExpandLabel( tls::Hash::Sha256, keys.secret, "iv", {}, 12 );
        uint8_t nonce[ 12 ];
        std::memcpy( nonce, iv.data(), sizeof( nonce ) );
        for ( int i = 0; i < 8; ++i ) {
            nonce[ 11 - i ] ^= static_cast<uint8_t>( keys.seq >> ( 8 * i ) );
        }
        ++keys.seq;
        auto inside = plain;
        inside.push_back( inner );
        const auto length = inside.size() + 16;
        Bytes out{ 0x17, 0x03, 0x03, static_cast<uint8_t>( length >> 8 ),
                   static_cast<uint8_t>( length ) };
        Bytes cipher( inside.size() );
        uint8_t tag[ 16 ];
        mbedtls_gcm_context gcm;
        mbedtls_gcm_init( &gcm );
        REQUIRE( mbedtls_gcm_setkey( &gcm, MBEDTLS_CIPHER_ID_AES, key.data(), 128 ) == 0 );
        REQUIRE( mbedtls_gcm_crypt_and_tag( &gcm, MBEDTLS_GCM_ENCRYPT, inside.size(), nonce,
                                            sizeof( nonce ), out.data(), out.size(), inside.data(),
                                            cipher.data(), sizeof( tag ), tag )
                 == 0 );
        mbedtls_gcm_free( &gcm );
        return out + cipher + Bytes( tag, tag + sizeof( tag ) );
    }

    /// Direction @p d's handshake is over: its records are protected by
    /// the application traffic keys from here on.
    void finished( unsigned d )
    {
        keys_[ d ].secret = d == 0 ? secrets_.clientTraffic : secrets_.serverTraffic;
        keys_[ d ].seq = 0;
    }

    /// The handshake up to the application data of both directions:
    /// EncryptedExtensions (ALPN @p alpn), Finished each.
    void handshake( TlsDecryption& decryption, const std::string& alpn )
    {
        feed( decryption, 0, clientHello() );
        Bytes extensions;
        if ( !alpn.empty() ) {
            const auto n = static_cast<uint8_t>( alpn.size() );
            extensions = Bytes{ 0x00, 0x10,
                                0x00, static_cast<uint8_t>( n + 3 ),
                                0x00, static_cast<uint8_t>( n + 1 ),
                                n }
                         + Bytes( alpn.begin(), alpn.end() );
        }
        const auto ee = handshakeMessage( 8, Bytes{ static_cast<uint8_t>( extensions.size() >> 8 ),
                                                    static_cast<uint8_t>( extensions.size() ) }
                                                 + extensions );
        feed( decryption, 1,
              serverHello() + seal( 1, 0x16, ee + handshakeMessage( 20, Bytes( 32, 0xF1 ) ) ) );
        finished( 1 );
        feed( decryption, 0, seal( 0, 0x16, handshakeMessage( 20, Bytes( 32, 0xF2 ) ) ) );
        finished( 0 );
    }

    /// The Info of a segment of direction @p d with @p bytes, whole records.
    std::string feed( TlsDecryption& decryption, unsigned d, const Bytes& bytes )
    {
        PacketRecord pkt;
        pkt.transport = Transport::Tcp;
        pkt.tcpFlags = 0x18;
        pkt.srcPort = d == 0 ? 50000 : 443;
        pkt.dstPort = d == 0 ? 443 : 50000;
        pkt.info = "segment";
        const Stream stream{ 0, &state_, d };
        decryption.apply( pkt, stream, ReassembledMessages{ { bytes.data(), bytes.size() }, 1 } );
        return pkt.info;
    }

    static Bytes handshakeMessage( uint8_t type, const Bytes& body )
    {
        return Bytes{ type, static_cast<uint8_t>( body.size() >> 16 ),
                      static_cast<uint8_t>( body.size() >> 8 ),
                      static_cast<uint8_t>( body.size() ) }
               + body;
    }

    static Bytes record( uint8_t type, const Bytes& fragment )
    {
        return Bytes{ type, 0x03, 0x03, static_cast<uint8_t>( fragment.size() >> 8 ),
                      static_cast<uint8_t>( fragment.size() ) }
               + fragment;
    }

private:
    struct Keys {
        tls::SecretBytes secret;
        uint64_t seq = 0;
    };

    static tls::SecretBytes secret( uint8_t fill )
    {
        const Bytes bytes( 32, fill );
        return tls::SecretBytes( bytes.data(), bytes.size() );
    }

    tls::ClientRandom random_{};
    tls::SessionSecrets secrets_;
    Keys keys_[ 2 ];
    StreamState state_;
};

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

SCENARIO( "HTTP/2 over TLS after a record that was lost or would not decrypt",
          "[tls_decryption][http2]" )
{
    Tls13Session session;
    TlsDecryption decryption( session.lookup() );
    session.handshake( decryption, "h2" );
    const std::string preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    REQUIRE( contains( session.feed( decryption, 0,
                                     session.seal( 0, 0x17,
                                                   Bytes( preface.begin(), preface.end() )
                                                       + h2Frame( 0x4, 0, 0, {} ) ) ),
                       "Magic, SETTINGS[0]" ) );

    // A DATA frame over two records, the second of which goes missing, then
    // a record that begins with a request.
    const auto data = h2Frame( kData, kEndStream, 1, Bytes( 100, 'd' ) );
    const Bytes head( data.begin(), data.begin() + 50 );
    const Bytes tail( data.begin() + 50, data.end() );
    const auto request = h2Frame( kHeaders, kEndStream | kEndHeaders, 3, kFirstRequest );
    REQUIRE( contains( session.feed( decryption, 0, session.seal( 0, 0x17, head ) ), "DATA[1]" ) );

    GIVEN( "the record with the rest of the frame lost" )
    {
        session.seal( 0, 0x17, tail ); // never sent
        const auto info = session.feed( decryption, 0, session.seal( 0, 0x17, request ) );

        THEN( "the next record is read from a frame's start, its headers no longer decoded" )
        {
            REQUIRE( contains( info, "TLS (decrypted) | HEADERS[3]" ) );
            REQUIRE_FALSE( contains( info, "GET" ) );
        }
    }

    GIVEN( "the record with the rest of the frame broken" )
    {
        auto broken = session.seal( 0, 0x17, tail );
        broken.back() ^= 0x01;
        session.feed( decryption, 0, broken );
        const auto info = session.feed( decryption, 0, session.seal( 0, 0x17, request ) );

        THEN( "the next record is read from a frame's start, its headers no longer decoded" )
        {
            REQUIRE( contains( info, "TLS (decrypted) | HEADERS[3]" ) );
            REQUIRE_FALSE( contains( info, "GET" ) );
        }
    }

    GIVEN( "the record lost in the same segment as the next" )
    {
        const auto lost = session.seal( 0, 0x17, tail );
        const auto info = session.feed( decryption, 0,
                                        session.seal( 0, 0x17, h2Frame( 0x6, 0, 0, Bytes( 8 ) ) )
                                            + lost + session.seal( 0, 0x17, request ) );

        THEN( "the record after it is read from a frame's start" )
        {
            REQUIRE( contains( info, "HEADERS[3]" ) );
        }
    }
}

SCENARIO( "TLS 1.3 handshake messages over more than one record", "[tls_decryption]" )
{
    Tls13Session session;
    TlsDecryption decryption( session.lookup() );
    session.feed( decryption, 0, session.clientHello() );

    GIVEN( "a Certificate whose second record begins with what reads as a Finished" )
    {
        const auto ee = Tls13Session::handshakeMessage( 8, Bytes{ 0x00, 0x00 } );
        auto certificate = Tls13Session::handshakeMessage( 11, Bytes( 200, 0x30 ) );
        const size_t cut = ee.size() + 100;
        const auto flight = ee + certificate;
        // The second record: 14 00 00 00, a Finished of no bytes, if read
        // as the start of a message.
        auto second = Bytes( flight.begin() + static_cast<std::ptrdiff_t>( cut ), flight.end() );
        second[ 0 ] = 0x14;
        second[ 1 ] = second[ 2 ] = second[ 3 ] = 0x00;
        session.feed(
            decryption, 1,
            session.serverHello()
                + session.seal( 1, 0x16,
                                Bytes( flight.begin(),
                                       flight.begin() + static_cast<std::ptrdiff_t>( cut ) ) ) );
        session.feed( decryption, 1, session.seal( 1, 0x16, second ) );
        const auto finished = session.feed(
            decryption, 1,
            session.seal( 1, 0x16,
                          Tls13Session::handshakeMessage( 15, Bytes( 20, 0x01 ) )
                              + Tls13Session::handshakeMessage( 20, Bytes( 32, 0xF1 ) ) ) );
        session.finished( 1 );
        const auto response = session.feed(
            decryption, 1,
            session.seal( 1, 0x17,
                          Bytes( { 'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', ' ',
                                   'O', 'K', '\r', '\n', '\r', '\n' } ) ) );

        THEN( "the keys change at the real Finished, and the records after it decrypt" )
        {
            REQUIRE( contains( finished, "TLS (decrypted) | Certificate Verify, Finished" ) );
            REQUIRE( contains( response, "TLS (decrypted) | HTTP/1.1 200 OK" ) );
        }
    }
}
