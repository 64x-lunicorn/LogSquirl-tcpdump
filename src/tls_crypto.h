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
 * @file tls_crypto.h
 * @brief The cryptography the TLS Decryption needs, over Mbed TLS: the key
 *        schedules of TLS 1.2 and 1.3, and the record ciphers.
 *
 * The only part of the plugin that sees Mbed TLS.  Secrets live in
 * SecretBytes, which wipes them when they go.  Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tcpdump::tls {

/// Overwrite @p len bytes at @p data with zeros, in a way the compiler
/// keeps.
void wipe( void* data, size_t len );

/**
 * An allocator that wipes what it gives back, all of it: a vector's bytes
 * past its size, and the old buffer when it grows, may hold plaintext too.
 */
template <typename T, typename Base = std::allocator<T>>
struct WipingAllocator : Base {
    using value_type = T;
    template <typename U>
    struct rebind {
        using other
            = WipingAllocator<U, typename std::allocator_traits<Base>::template rebind_alloc<U>>;
    };
    WipingAllocator() = default;
    template <typename U, typename B>
    WipingAllocator( const WipingAllocator<U, B>& other ) noexcept
        : Base( other )
    {
    }
    void deallocate( T* p, size_t n )
    {
        wipe( p, n * sizeof( T ) );
        Base::deallocate( p, n );
    }
    template <typename U, typename B>
    bool operator==( const WipingAllocator<U, B>& ) const noexcept
    {
        return true;
    }
    template <typename U, typename B>
    bool operator!=( const WipingAllocator<U, B>& ) const noexcept
    {
        return false;
    }
};

/// Decrypted bytes: wiped when they go, or move to a larger buffer.
using PlainBytes = std::vector<uint8_t, WipingAllocator<uint8_t>>;

/// Bytes of a secret (a key, a traffic secret), wiped when they go.
class SecretBytes {
public:
    SecretBytes() = default;
    explicit SecretBytes( size_t size )
        : bytes_( size )
    {
    }
    SecretBytes( const uint8_t* data, size_t size )
        : bytes_( data, data + size )
    {
    }
    SecretBytes( const SecretBytes& ) = default;
    SecretBytes( SecretBytes&& other ) noexcept
        : bytes_( std::move( other.bytes_ ) )
    {
    }
    SecretBytes& operator=( const SecretBytes& other )
    {
        if ( this != &other ) {
            clear();
            bytes_ = other.bytes_;
        }
        return *this;
    }
    SecretBytes& operator=( SecretBytes&& other ) noexcept
    {
        if ( this != &other ) {
            clear();
            bytes_ = std::move( other.bytes_ );
        }
        return *this;
    }
    ~SecretBytes()
    {
        clear();
    }

    /// Wipe the bytes and forget them.
    void clear()
    {
        wipe( bytes_.data(), bytes_.size() );
        bytes_.clear();
    }

    const uint8_t* data() const
    {
        return bytes_.data();
    }
    uint8_t* data()
    {
        return bytes_.data();
    }
    size_t size() const
    {
        return bytes_.size();
    }
    bool empty() const
    {
        return bytes_.empty();
    }
    ByteView view() const
    {
        return { bytes_.data(), bytes_.size() };
    }

private:
    std::vector<uint8_t> bytes_;
};

/// The hash of a cipher suite: its PRF's or HKDF's, or its MAC's.
enum class Hash : uint8_t { Sha1, Sha256, Sha384 };

/// Bytes of a @p hash value.
size_t hashBytes( Hash hash );

/**
 * HKDF-Expand-Label of TLS 1.3 (RFC 8446, 7.1): @p length bytes expanded
 * from @p secret with the label "tls13 " + @p label and @p context.
 * Empty if @p length or the label is too long for the HkdfLabel.
 */
SecretBytes hkdfExpandLabel( Hash hash, const SecretBytes& secret, const std::string& label,
                             ByteView context, size_t length );

/**
 * The PRF of TLS 1.2 (RFC 5246, 5): @p length bytes of P_hash over HMAC
 * with @p hash, from @p secret, @p label and @p seed.
 */
SecretBytes tls12Prf( Hash hash, const SecretBytes& secret, const std::string& label, ByteView seed,
                      size_t length );

/**
 * HMAC with @p hash and @p key over the @p parts, one after the other,
 * into @p out, hashBytes() of them; false if Mbed TLS fails.
 */
bool hmac( Hash hash, const SecretBytes& key, const std::vector<ByteView>& parts, uint8_t* out );

/// The AEAD ciphers of TLS records, and AES-CBC.
enum class Cipher : uint8_t { Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Aes128Cbc, Aes256Cbc };

/// Bytes of a @p cipher's key.
size_t keyBytes( Cipher cipher );

/// Bytes of an AEAD cipher's authentication tag.
constexpr size_t kTagBytes = 16;
/// Bytes of an AEAD nonce of TLS (RFC 8446, 5.3; RFC 5288, 3).
constexpr size_t kNonceBytes = 12;
/// Bytes of an AES block, and of a CBC record's explicit IV.
constexpr size_t kAesBlockBytes = 16;

/**
 * A key of one of the Cipher, set up once and used for every record of a
 * direction.  Holds the key schedule of Mbed TLS, not the key itself.
 */
class RecordCipher {
public:
    /// A cipher of kind @p cipher with @p key, keyBytes() long; null if
    /// it is not, or Mbed TLS refuses it.
    static std::unique_ptr<RecordCipher> make( Cipher cipher, const SecretBytes& key );

    ~RecordCipher();
    RecordCipher( const RecordCipher& ) = delete;
    RecordCipher& operator=( const RecordCipher& ) = delete;

    Cipher cipher() const
    {
        return cipher_;
    }

    /**
     * Decrypt and authenticate @p ciphertext, kTagBytes of tag behind it,
     * with the kNonceBytes at @p nonce and @p aad, into @p plaintext.
     * False if the tag does not match, or the cipher is no AEAD one.
     */
    bool open( const uint8_t* nonce, ByteView aad, ByteView ciphertext,
               PlainBytes& plaintext ) const;

    /**
     * Decrypt @p ciphertext, whole blocks, with the AES block at @p iv in
     * CBC mode into @p plaintext.  False if it is no whole number of
     * blocks, or the cipher is no CBC one.
     */
    bool decryptCbc( const uint8_t* iv, ByteView ciphertext, PlainBytes& plaintext ) const;

private:
    struct Context;
    explicit RecordCipher( Cipher cipher );

    Cipher cipher_;
    std::unique_ptr<Context> context_;
};

} // namespace tcpdump::tls
