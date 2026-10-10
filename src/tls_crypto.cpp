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
 * @file tls_crypto.cpp
 * @brief Implementation of the TLS Decryption's cryptography over Mbed TLS.
 */

#include "tls_crypto.h"

#include <mbedtls/aes.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>

#include <algorithm>

namespace tcpdump::tls {

namespace {

const mbedtls_md_info_t* mdInfo( Hash hash )
{
    switch ( hash ) {
    case Hash::Sha1:
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA1 );
    case Hash::Sha256:
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 );
    case Hash::Sha384:
        return mbedtls_md_info_from_type( MBEDTLS_MD_SHA384 );
    }
    return nullptr;
}

/// The longest hash, SHA-384's.
constexpr size_t kMaxHashBytes = 48;

/// An HMAC context of Mbed TLS, freed when it goes.
class HmacContext {
public:
    HmacContext()
    {
        mbedtls_md_init( &ctx_ );
    }
    ~HmacContext()
    {
        mbedtls_md_free( &ctx_ );
    }
    HmacContext( const HmacContext& ) = delete;
    HmacContext& operator=( const HmacContext& ) = delete;

    bool start( Hash hash, const SecretBytes& key )
    {
        const auto* info = mdInfo( hash );
        return info != nullptr && mbedtls_md_setup( &ctx_, info, 1 ) == 0
               && mbedtls_md_hmac_starts( &ctx_, key.data(), key.size() ) == 0;
    }
    bool restart()
    {
        return mbedtls_md_hmac_reset( &ctx_ ) == 0;
    }
    bool update( const uint8_t* data, size_t len )
    {
        return len == 0 || mbedtls_md_hmac_update( &ctx_, data, len ) == 0;
    }
    bool finish( uint8_t* out )
    {
        return mbedtls_md_hmac_finish( &ctx_, out ) == 0;
    }

private:
    mbedtls_md_context_t ctx_;
};

} // namespace

void wipe( void* data, size_t len )
{
    if ( data != nullptr && len > 0 ) {
        mbedtls_platform_zeroize( data, len );
    }
}

size_t hashBytes( Hash hash )
{
    switch ( hash ) {
    case Hash::Sha1:
        return 20;
    case Hash::Sha256:
        return 32;
    case Hash::Sha384:
        return 48;
    }
    return 0;
}

SecretBytes hkdfExpandLabel( Hash hash, const SecretBytes& secret, const std::string& label,
                             ByteView context, size_t length )
{
    // struct { uint16 length; opaque label<7..255>; opaque context<0..255>; } HkdfLabel
    const std::string fullLabel = "tls13 " + label;
    if ( length > 0xFFFF || fullLabel.size() > 255 || context.size > 255 ) {
        return {};
    }
    std::vector<uint8_t> info;
    info.reserve( 4 + fullLabel.size() + context.size );
    info.push_back( static_cast<uint8_t>( length >> 8 ) );
    info.push_back( static_cast<uint8_t>( length ) );
    info.push_back( static_cast<uint8_t>( fullLabel.size() ) );
    info.insert( info.end(), fullLabel.begin(), fullLabel.end() );
    info.push_back( static_cast<uint8_t>( context.size ) );
    if ( context.size > 0 ) {
        info.insert( info.end(), context.data, context.data + context.size );
    }
    SecretBytes out( length );
    if ( mbedtls_hkdf_expand( mdInfo( hash ), secret.data(), secret.size(), info.data(),
                              info.size(), out.data(), out.size() )
         != 0 ) {
        return {};
    }
    return out;
}

SecretBytes tls12Prf( Hash hash, const SecretBytes& secret, const std::string& label, ByteView seed,
                      size_t length )
{
    // P_hash(secret, label + seed): HMAC(secret, A(i) + label + seed) for
    // A(0) = label + seed, A(i) = HMAC(secret, A(i-1)).
    const auto n = hashBytes( hash );
    HmacContext ctx;
    if ( n == 0 || !ctx.start( hash, secret ) ) {
        return {};
    }
    const auto* labelBytes = reinterpret_cast<const uint8_t*>( label.data() );
    uint8_t a[ kMaxHashBytes ];
    uint8_t block[ kMaxHashBytes ];
    SecretBytes out( length );
    bool ok = ctx.update( labelBytes, label.size() ) && ctx.update( seed.data, seed.size )
              && ctx.finish( a ); // A(1)
    for ( size_t done = 0; ok && done < length; ) {
        ok = ctx.restart() && ctx.update( a, n ) && ctx.update( labelBytes, label.size() )
             && ctx.update( seed.data, seed.size ) && ctx.finish( block );
        const auto take = std::min( n, length - done );
        std::copy( block, block + take, out.data() + done );
        done += take;
        ok = ok && ctx.restart() && ctx.update( a, n ) && ctx.finish( a ); // A(i+1)
    }
    wipe( a, sizeof( a ) );
    wipe( block, sizeof( block ) );
    if ( !ok ) {
        return {};
    }
    return out;
}

bool hmac( Hash hash, const SecretBytes& key, const std::vector<ByteView>& parts, uint8_t* out )
{
    HmacContext ctx;
    if ( !ctx.start( hash, key ) ) {
        return false;
    }
    for ( const auto& part : parts ) {
        if ( !ctx.update( part.data, part.size ) ) {
            return false;
        }
    }
    return ctx.finish( out );
}

size_t keyBytes( Cipher cipher )
{
    switch ( cipher ) {
    case Cipher::Aes128Gcm:
    case Cipher::Aes128Cbc:
        return 16;
    case Cipher::Aes256Gcm:
    case Cipher::Aes256Cbc:
    case Cipher::ChaCha20Poly1305:
        return 32;
    }
    return 0;
}

// ── RecordCipher ─────────────────────────────────────────────────────────

struct RecordCipher::Context {
    mbedtls_gcm_context gcm;
    mbedtls_chachapoly_context chachapoly;
    mbedtls_aes_context aes;

    Context()
    {
        mbedtls_gcm_init( &gcm );
        mbedtls_chachapoly_init( &chachapoly );
        mbedtls_aes_init( &aes );
    }
    ~Context()
    {
        mbedtls_gcm_free( &gcm );
        mbedtls_chachapoly_free( &chachapoly );
        mbedtls_aes_free( &aes );
    }
    Context( const Context& ) = delete;
    Context& operator=( const Context& ) = delete;
};

RecordCipher::RecordCipher( Cipher cipher )
    : cipher_( cipher )
    , context_( std::make_unique<Context>() )
{
}

RecordCipher::~RecordCipher() = default;

std::unique_ptr<RecordCipher> RecordCipher::make( Cipher cipher, const SecretBytes& key )
{
    if ( key.size() != keyBytes( cipher ) ) {
        return nullptr;
    }
    std::unique_ptr<RecordCipher> made( new RecordCipher( cipher ) );
    auto& ctx = *made->context_;
    const auto bits = static_cast<unsigned>( key.size() * 8 );
    int status = -1;
    switch ( cipher ) {
    case Cipher::Aes128Gcm:
    case Cipher::Aes256Gcm:
        status = mbedtls_gcm_setkey( &ctx.gcm, MBEDTLS_CIPHER_ID_AES, key.data(), bits );
        break;
    case Cipher::ChaCha20Poly1305:
        status = mbedtls_chachapoly_setkey( &ctx.chachapoly, key.data() );
        break;
    case Cipher::Aes128Cbc:
    case Cipher::Aes256Cbc:
        status = mbedtls_aes_setkey_dec( &ctx.aes, key.data(), bits );
        break;
    }
    return status == 0 ? std::move( made ) : nullptr;
}

bool RecordCipher::open( const uint8_t* nonce, ByteView aad, ByteView ciphertext,
                         PlainBytes& plaintext ) const
{
    if ( ciphertext.size < kTagBytes ) {
        return false;
    }
    const auto len = ciphertext.size - kTagBytes;
    const auto* tag = ciphertext.data + len;
    plaintext.resize( len );
    int status = -1;
    switch ( cipher_ ) {
    case Cipher::Aes128Gcm:
    case Cipher::Aes256Gcm:
        status
            = mbedtls_gcm_auth_decrypt( &context_->gcm, len, nonce, kNonceBytes, aad.data, aad.size,
                                        tag, kTagBytes, ciphertext.data, plaintext.data() );
        break;
    case Cipher::ChaCha20Poly1305:
        status
            = mbedtls_chachapoly_auth_decrypt( &context_->chachapoly, len, nonce, aad.data,
                                               aad.size, tag, ciphertext.data, plaintext.data() );
        break;
    default:
        break;
    }
    if ( status != 0 ) {
        plaintext.clear();
        return false;
    }
    return true;
}

bool RecordCipher::decryptCbc( const uint8_t* iv, ByteView ciphertext, PlainBytes& plaintext ) const
{
    if ( ( cipher_ != Cipher::Aes128Cbc && cipher_ != Cipher::Aes256Cbc )
         || ciphertext.size % kAesBlockBytes != 0 ) {
        return false;
    }
    uint8_t chain[ kAesBlockBytes ];
    std::copy( iv, iv + kAesBlockBytes, chain );
    plaintext.resize( ciphertext.size );
    if ( ciphertext.size > 0
         && mbedtls_aes_crypt_cbc( &context_->aes, MBEDTLS_AES_DECRYPT, ciphertext.size, chain,
                                   ciphertext.data, plaintext.data() )
                != 0 ) {
        plaintext.clear();
        return false;
    }
    return true;
}

} // namespace tcpdump::tls
