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
 * @file tls_crypto_test.cpp
 * @brief BDD tests for the TLS Decryption's cryptography: HKDF-Expand-Label
 *        and a record against the trace of RFC 8448, and the TLS 1.2 PRF
 *        against the published test vectors.
 */

#include <catch2/catch.hpp>

#include "tls_crypto.h"

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump::tls;

namespace {

using Bytes = std::vector<uint8_t>;

/// The bytes of the buffer an allocator gave back last.
std::vector<uint8_t> released;

/// Hands out what std::allocator does, and keeps what is given back.
template <typename T>
struct Recording : std::allocator<T> {
    using value_type = T;
    template <typename U>
    struct rebind {
        using other = Recording<U>;
    };
    Recording() = default;
    template <typename U>
    Recording( const Recording<U>& ) noexcept
    {
    }
    void deallocate( T* p, size_t n )
    {
        const auto* bytes = reinterpret_cast<const uint8_t*>( p );
        released.assign( bytes, bytes + n * sizeof( T ) );
        std::allocator<T>::deallocate( p, n );
    }
};

Bytes fromHex( const std::string& hex )
{
    Bytes bytes;
    for ( size_t i = 0; i + 1 < hex.size(); i += 2 ) {
        if ( hex[ i ] == ' ' ) {
            --i;
            continue;
        }
        bytes.push_back( static_cast<uint8_t>( std::stoul( hex.substr( i, 2 ), nullptr, 16 ) ) );
    }
    return bytes;
}

SecretBytes secret( const std::string& hex )
{
    const auto bytes = fromHex( hex );
    return SecretBytes( bytes.data(), bytes.size() );
}

Bytes bytesOf( const SecretBytes& s )
{
    return Bytes( s.data(), s.data() + s.size() );
}

// RFC 8448, 3: the client's handshake traffic secret of the simple 1-RTT
// handshake, and the server's.
const std::string kClientHandshakeSecret
    = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
const std::string kServerHandshakeSecret
    = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";

} // namespace

SCENARIO( "HKDF-Expand-Label derives the traffic keys of RFC 8448", "[tls][crypto]" )
{
    GIVEN( "the server's handshake traffic secret" )
    {
        const auto traffic = secret( kServerHandshakeSecret );

        THEN( "its key and IV are the trace's" )
        {
            REQUIRE( bytesOf( hkdfExpandLabel( Hash::Sha256, traffic, "key", {}, 16 ) )
                     == fromHex( "3fce516009c21727d0f2e4e86ee403bc" ) );
            REQUIRE( bytesOf( hkdfExpandLabel( Hash::Sha256, traffic, "iv", {}, 12 ) )
                     == fromHex( "5d313eb2671276ee13000b30" ) );
        }
    }

    GIVEN( "the client's handshake traffic secret" )
    {
        const auto traffic = secret( kClientHandshakeSecret );

        THEN( "its key, IV and finished key are the trace's" )
        {
            REQUIRE( bytesOf( hkdfExpandLabel( Hash::Sha256, traffic, "key", {}, 16 ) )
                     == fromHex( "dbfaa693d1762c5b666af5d950258d01" ) );
            REQUIRE( bytesOf( hkdfExpandLabel( Hash::Sha256, traffic, "iv", {}, 12 ) )
                     == fromHex( "5bd3c71b836e0b76bb73265f" ) );
            REQUIRE(
                bytesOf( hkdfExpandLabel( Hash::Sha256, traffic, "finished", {}, 32 ) )
                == fromHex( "b80ad01015fb2f0bd65ff7d4da5d6bf83f84821d1f87fdc7d3c75b5a7b42d9c4" ) );
        }
    }

    GIVEN( "a label too long for the HkdfLabel" )
    {
        THEN( "nothing is derived" )
        {
            REQUIRE( hkdfExpandLabel( Hash::Sha256, secret( kClientHandshakeSecret ),
                                      std::string( 250, 'x' ), {}, 16 )
                         .empty() );
        }
    }
}

SCENARIO( "A TLS 1.3 record of RFC 8448 decrypts with its keys", "[tls][crypto]" )
{
    GIVEN( "the client's Finished record and the client's handshake key and IV" )
    {
        const auto record = fromHex( "1703030035"
                                     "75ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f3"
                                     "8f80338ac98fc46deb384bd1caeacab6867d726c40546" );
        const auto key = secret( "dbfaa693d1762c5b666af5d950258d01" );
        const auto iv = fromHex( "5bd3c71b836e0b76bb73265f" );
        const auto cipher = RecordCipher::make( Cipher::Aes128Gcm, key );
        REQUIRE( cipher );

        WHEN( "it is opened with sequence number 0, the header as additional data" )
        {
            PlainBytes plain;
            const bool opened = cipher->open( iv.data(), { record.data(), 5 },
                                              { record.data() + 5, record.size() - 5 }, plain );

            THEN( "it holds the Finished message and its content type" )
            {
                REQUIRE( opened );
                REQUIRE(
                    Bytes( plain.begin(), plain.end() )
                    == fromHex(
                        "14000020a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61"
                        "16" ) );
            }
        }

        WHEN( "a byte of it is flipped" )
        {
            auto broken = record;
            broken[ 20 ] ^= 1;
            PlainBytes plain;

            THEN( "it does not open" )
            {
                REQUIRE_FALSE( cipher->open( iv.data(), { broken.data(), 5 },
                                             { broken.data() + 5, broken.size() - 5 }, plain ) );
                REQUIRE( plain.empty() );
            }
        }
    }

    GIVEN( "a key of the wrong length" )
    {
        THEN( "no cipher is made" )
        {
            REQUIRE_FALSE( RecordCipher::make( Cipher::Aes256Gcm, secret( "00112233" ) ) );
        }
    }
}

SCENARIO( "The TLS 1.2 PRF gives the published test vectors", "[tls][crypto]" )
{
    GIVEN( "the SHA-256 vector" )
    {
        const auto out = tls12Prf(
            Hash::Sha256, secret( "9bbe436ba940f017b17652849a71db35" ), "test label",
            [] {
                static const auto seed = fromHex( "a0ba9f936cda311827a6f796ffd5198c" );
                return ByteView{ seed.data(), seed.size() };
            }(),
            100 );

        THEN( "the output is the vector's" )
        {
            REQUIRE( bytesOf( out )
                     == fromHex( "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a"
                                 "6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab"
                                 "4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701"
                                 "87347b66" ) );
        }
    }

    GIVEN( "the SHA-384 vector" )
    {
        static const auto seed = fromHex( "cd665cf6a8447dd6ff8b27555edb7465" );
        const auto out = tls12Prf( Hash::Sha384, secret( "b80b733d6ceefcdc71566ea48e5567df" ),
                                   "test label", { seed.data(), seed.size() }, 148 );

        THEN( "the output is the vector's" )
        {
            REQUIRE( bytesOf( out )
                     == fromHex( "7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cd"
                                 "e9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd"
                                 "8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d918425"
                                 "9b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee6"
                                 "91c8f3a26854308d5eaa3be85e0990703d73e56f" ) );
        }
    }
}

SCENARIO( "SecretBytes wipe their bytes", "[tls][crypto]" )
{
    GIVEN( "a secret" )
    {
        auto s = secret( "0102030405" );

        WHEN( "it is cleared" )
        {
            s.clear();

            THEN( "nothing is left" )
            {
                REQUIRE( s.empty() );
            }
        }
    }
}

SCENARIO( "Plaintext buffers are wiped when they go", "[tls][crypto]" )
{
    GIVEN( "a buffer of plaintext with the wiping allocator" )
    {
        std::vector<uint8_t, WipingAllocator<uint8_t, Recording<uint8_t>>> plain( 16, 0xAB );
        plain.resize( 8 ); // what lies past size() is plaintext too

        WHEN( "it grows into a new buffer" )
        {
            released.clear();
            plain.resize( 4096, 0xCD );

            THEN( "the old one is given back wiped, all of it" )
            {
                REQUIRE( released.size() >= 16 );
                REQUIRE( std::all_of( released.begin(), released.end(),
                                      []( uint8_t b ) { return b == 0; } ) );
            }
        }

        WHEN( "it goes" )
        {
            released.clear();
            {
                auto gone = std::move( plain );
            }

            THEN( "it is given back wiped" )
            {
                REQUIRE( released.size() >= 16 );
                REQUIRE( std::all_of( released.begin(), released.end(),
                                      []( uint8_t b ) { return b == 0; } ) );
            }
        }
    }
}
