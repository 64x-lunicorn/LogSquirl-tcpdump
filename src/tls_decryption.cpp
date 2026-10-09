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
 * @file tls_decryption.cpp
 * @brief Implementation of the TLS Decryption.
 */

#include "tls_decryption.h"

#include "payload_describer.h"
#include "tls_crypto.h"
#include "wire_bytes.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace tcpdump {

namespace {

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;

constexpr uint8_t kChangeCipherSpec = 0x14;
constexpr uint8_t kAlert = 0x15;
constexpr uint8_t kHandshake = 0x16;
constexpr uint8_t kApplicationData = 0x17;

constexpr size_t kRecordHeaderBytes = 5;
constexpr uint16_t kTls12 = 0x0303;
constexpr uint16_t kTls13 = 0x0304;

constexpr uint8_t kClientHello = 1;
constexpr uint8_t kServerHello = 2;
constexpr uint8_t kEncryptedExtensions = 8;
constexpr uint8_t kFinished = 20;
constexpr uint8_t kKeyUpdate = 24;

/// The random of a ServerHello that is a HelloRetryRequest (RFC 8446,
/// 4.1.3): SHA-256 of "HelloRetryRequest".
constexpr uint8_t kHelloRetryRandom[ tls::kRandomBytes ]
    = { 0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
        0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
        0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };

/// A cipher suite the decryption supports.
struct Suite {
    uint16_t id;
    bool tls13;
    tls::Cipher cipher;
    tls::Hash prf; ///< The PRF's hash (TLS 1.2), or HKDF's (TLS 1.3).
    tls::Hash mac; ///< The MAC's hash of a CBC suite.
};

using tls::Cipher;
using tls::Hash;

constexpr Suite kSuites[] = {
    // TLS 1.3 (RFC 8446, B.4)
    { 0x1301, true, Cipher::Aes128Gcm, Hash::Sha256, Hash::Sha256 },
    { 0x1302, true, Cipher::Aes256Gcm, Hash::Sha384, Hash::Sha384 },
    { 0x1303, true, Cipher::ChaCha20Poly1305, Hash::Sha256, Hash::Sha256 },
    // TLS 1.2 AES-GCM (RFC 5288, 5289): RSA, DHE_RSA, ECDHE_ECDSA, ECDHE_RSA
    { 0x009C, false, Cipher::Aes128Gcm, Hash::Sha256, Hash::Sha256 },
    { 0x009D, false, Cipher::Aes256Gcm, Hash::Sha384, Hash::Sha384 },
    { 0x009E, false, Cipher::Aes128Gcm, Hash::Sha256, Hash::Sha256 },
    { 0x009F, false, Cipher::Aes256Gcm, Hash::Sha384, Hash::Sha384 },
    { 0xC02B, false, Cipher::Aes128Gcm, Hash::Sha256, Hash::Sha256 },
    { 0xC02C, false, Cipher::Aes256Gcm, Hash::Sha384, Hash::Sha384 },
    { 0xC02F, false, Cipher::Aes128Gcm, Hash::Sha256, Hash::Sha256 },
    { 0xC030, false, Cipher::Aes256Gcm, Hash::Sha384, Hash::Sha384 },
    // TLS 1.2 ChaCha20-Poly1305 (RFC 7905)
    { 0xCCA8, false, Cipher::ChaCha20Poly1305, Hash::Sha256, Hash::Sha256 },
    { 0xCCA9, false, Cipher::ChaCha20Poly1305, Hash::Sha256, Hash::Sha256 },
    { 0xCCAA, false, Cipher::ChaCha20Poly1305, Hash::Sha256, Hash::Sha256 },
    // TLS 1.2 AES-CBC with HMAC-SHA1 (RFC 5246, 4492)
    { 0x002F, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha1 },
    { 0x0033, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha1 },
    { 0x0035, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha1 },
    { 0x0039, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha1 },
    { 0xC009, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha1 },
    { 0xC00A, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha1 },
    { 0xC013, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha1 },
    { 0xC014, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha1 },
    // TLS 1.2 AES-CBC with HMAC-SHA256/384 (RFC 5246, 5289)
    { 0x003C, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha256 },
    { 0x003D, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha256 },
    { 0x0067, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha256 },
    { 0x006B, false, Cipher::Aes256Cbc, Hash::Sha256, Hash::Sha256 },
    { 0xC023, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha256 },
    { 0xC024, false, Cipher::Aes256Cbc, Hash::Sha384, Hash::Sha384 },
    { 0xC027, false, Cipher::Aes128Cbc, Hash::Sha256, Hash::Sha256 },
    { 0xC028, false, Cipher::Aes256Cbc, Hash::Sha384, Hash::Sha384 },
};

const Suite* findSuite( uint16_t id )
{
    for ( const auto& suite : kSuites ) {
        if ( suite.id == id ) {
            return &suite;
        }
    }
    return nullptr;
}

bool isCbc( Cipher cipher )
{
    return cipher == Cipher::Aes128Cbc || cipher == Cipher::Aes256Cbc;
}

/// Bytes of the IV the key block or the key schedule gives a direction.
size_t ivBytes( const Suite& suite )
{
    if ( suite.tls13 || suite.cipher == Cipher::ChaCha20Poly1305 ) {
        return tls::kNonceBytes; // XORed with the sequence number
    }
    if ( isCbc( suite.cipher ) ) {
        return 0; // explicit, in each record
    }
    return 4; // GCM's salt, the record giving the rest (RFC 5288, 3)
}

void putBE64( uint8_t* p, uint64_t value )
{
    for ( int i = 7; i >= 0; --i ) {
        p[ i ] = static_cast<uint8_t>( value );
        value >>= 8;
    }
}

/// The nonce of a record: @p iv, kNonceBytes of it, XORed with @p seq
/// (RFC 8446, 5.3; RFC 7905, 2).
void xorNonce( const tls::SecretBytes& iv, uint64_t seq, uint8_t* nonce )
{
    std::copy( iv.data(), iv.data() + tls::kNonceBytes, nonce );
    uint8_t seqBytes[ 8 ];
    putBE64( seqBytes, seq );
    for ( size_t i = 0; i < 8; ++i ) {
        nonce[ tls::kNonceBytes - 8 + i ] ^= seqBytes[ i ];
    }
}

bool equalBytes( const uint8_t* a, const uint8_t* b, size_t len )
{
    return std::memcmp( a, b, len ) == 0;
}

/// What a protected record is called that could not be decrypted, as the
/// Payload Describer names it.
const char* protectedName( uint8_t type )
{
    switch ( type ) {
    case kHandshake:
        return "Encrypted Handshake Message";
    case kAlert:
        return "Alert";
    default:
        return "Application Data";
    }
}

/// @p parts joined with ", ", up to as many as the Payload Describer names
/// TLS records, then "…".
std::string joinParts( const std::vector<std::string>& parts )
{
    constexpr size_t kMaxParts = 4;
    std::string joined;
    for ( size_t i = 0; i < parts.size(); ++i ) {
        if ( i == kMaxParts ) {
            joined += ", \xe2\x80\xa6";
            break;
        }
        if ( i > 0 ) {
            joined += ", ";
        }
        joined += parts[ i ];
    }
    return joined;
}

/// Reads the fields of a handshake message, never beyond them.
class Reader {
public:
    explicit Reader( ByteView bytes )
        : p_( bytes.data )
        , left_( bytes.size )
    {
    }
    bool u8( uint8_t& v )
    {
        if ( left_ < 1 ) {
            return false;
        }
        v = *p_;
        skip( 1 );
        return true;
    }
    bool u16( uint16_t& v )
    {
        if ( left_ < 2 ) {
            return false;
        }
        v = readBE16( p_ );
        skip( 2 );
        return true;
    }
    bool u24( uint32_t& v )
    {
        if ( left_ < 3 ) {
            return false;
        }
        v = static_cast<uint32_t>( p_[ 0 ] ) << 16 | readBE16( p_ + 1 );
        skip( 3 );
        return true;
    }
    bool bytes( size_t n, ByteView& out )
    {
        if ( left_ < n ) {
            return false;
        }
        out = { p_, n };
        skip( n );
        return true;
    }
    bool skip( size_t n )
    {
        if ( left_ < n ) {
            return false;
        }
        p_ += n;
        left_ -= n;
        return true;
    }
    bool vector8( ByteView& out )
    {
        uint8_t n = 0;
        return u8( n ) && bytes( n, out );
    }
    bool vector16( ByteView& out )
    {
        uint16_t n = 0;
        return u16( n ) && bytes( n, out );
    }
    size_t left() const
    {
        return left_;
    }

private:
    const uint8_t* p_;
    size_t left_;
};

/// Call @p onMessage(type, body) for each whole handshake message in @p bytes.
template <typename OnMessage>
void forEachHandshakeMessage( ByteView bytes, OnMessage onMessage )
{
    Reader reader( bytes );
    uint8_t type = 0;
    uint32_t length = 0;
    ByteView body;
    while ( reader.u8( type ) && reader.u24( length ) && reader.bytes( length, body ) ) {
        onMessage( type, body );
    }
}

/// Call @p onExtension(type, data) for each extension of a hello's or
/// EncryptedExtensions' list at the reader.
template <typename OnExtension>
void forEachExtension( Reader& reader, OnExtension onExtension )
{
    ByteView list;
    if ( !reader.vector16( list ) ) {
        return;
    }
    Reader extensions( list );
    uint16_t type = 0;
    ByteView data;
    while ( extensions.u16( type ) && extensions.vector16( data ) ) {
        onExtension( type, data );
    }
}

/// An ALPN extension (RFC 7301) that names h2, the protocol chosen.
bool alpnIsH2( ByteView data )
{
    Reader reader( data );
    ByteView list;
    ByteView protocol;
    if ( !reader.vector16( list ) ) {
        return false;
    }
    Reader protocols( list );
    return protocols.vector8( protocol ) && protocol.size == 2
           && std::memcmp( protocol.data, "h2", 2 ) == 0;
}

/**
 * TLS 1.3: the handshake messages of a direction's decrypted records, put
 * together across records.  A message is held until it is whole, up to
 * kMaxMessageBytes; a longer one is passed over, by its type only.
 */
class HandshakeMessages {
public:
    /// Longest handshake message held: EncryptedExtensions, Finished and
    /// KeyUpdate, which are read, are far shorter.
    static constexpr uint32_t kMaxMessageBytes = 16 * 1024;

    /// Call @p onMessage(type, body) for each message @p bytes complete;
    /// the body of one passed over is empty.
    template <typename OnMessage>
    void add( ByteView bytes, OnMessage onMessage )
    {
        size_t at = 0;
        while ( at < bytes.size ) {
            if ( skip_ > 0 ) {
                const auto n = std::min<size_t>( skip_, bytes.size - at );
                skip_ -= static_cast<uint32_t>( n );
                at += n;
                continue;
            }
            if ( held_.size() < kHeaderBytes ) {
                const auto n = std::min( kHeaderBytes - held_.size(), bytes.size - at );
                held_.insert( held_.end(), bytes.data + at, bytes.data + at + n );
                at += n;
                if ( held_.size() < kHeaderBytes ) {
                    break;
                }
            }
            const uint32_t length = static_cast<uint32_t>( held_[ 1 ] ) << 16
                                    | static_cast<uint32_t>( held_[ 2 ] ) << 8 | held_[ 3 ];
            if ( length > kMaxMessageBytes ) {
                onMessage( held_[ 0 ], ByteView{ held_.data(), 0 } );
                skip_ = length;
                reset();
                continue;
            }
            const auto n
                = std::min<size_t>( kHeaderBytes + length - held_.size(), bytes.size - at );
            held_.insert( held_.end(), bytes.data + at, bytes.data + at + n );
            at += n;
            if ( held_.size() == kHeaderBytes + length ) {
                onMessage( held_[ 0 ], ByteView{ held_.data() + kHeaderBytes, length } );
                reset();
            }
        }
    }

    /// Records went missing: the next one begins a message.
    void lost()
    {
        reset();
        skip_ = 0;
    }

private:
    static constexpr size_t kHeaderBytes = 4;

    void reset()
    {
        tls::PlainBytes().swap( held_ );
    }

    tls::PlainBytes held_; ///< The message begun, its header first.
    uint32_t skip_ = 0;    ///< Bytes of a long message still to pass over.
};

} // namespace

// ── A session ────────────────────────────────────────────────────────────

/// One direction of a session: its keys and sequence number.
struct TlsDecryption::Direction {
    std::unique_ptr<tls::RecordCipher> cipher;
    tls::SecretBytes iv;
    tls::SecretBytes macKey; ///< TLS 1.2 CBC.
    /// TLS 1.3: the traffic secret of the keys, which a key update
    /// derives the next from.
    tls::SecretBytes secret;
    /// TLS 1.3: the application traffic secret, while the handshake's
    /// keys protect the direction.
    tls::SecretBytes nextSecret;
    uint64_t seq = 0;
    bool encrypted = false;   ///< Its records are protected.
    bool application = false; ///< TLS 1.3: by the application traffic keys.
    uint8_t failures = 0;     ///< Records in a row that did not decrypt.
    /// Records the last one decrypted came after, lost or not decrypted.
    uint64_t skipped = 0;
    /// Application data went missing since the last that was described:
    /// HTTP/2 is read from a frame's start again (Http2Direction::resync()).
    bool lost = false;
    HandshakeMessages handshake; ///< TLS 1.3: the encrypted handshake.
    std::unique_ptr<Http2Direction> http2;
    size_t http2Charged = 0; ///< Counted in http2Memory_.
};

/// A TLS session on a TCP stream, from its ClientHello on.
struct TlsDecryption::Session {
    tls::ClientRandom clientRandom{};
    std::array<uint8_t, tls::kRandomBytes> serverRandom{};
    unsigned client = 0;      ///< The direction of the ClientHello.
    bool serverHello = false; ///< A ServerHello with a supported suite came.
    const Suite* suite = nullptr;
    bool encryptThenMac = false; ///< TLS 1.2 CBC: RFC 7366 was agreed.
    bool keyed = false;          ///< Keys were set up from the key log.
    bool http2 = false;          ///< The application data is HTTP/2.
    bool decrypted = false;      ///< A record was decrypted.
    /// The key log's bytes read when it had no secrets for the session;
    /// -1 if it was not looked for in vain.
    int64_t missedAt = -1;
    std::list<int>::iterator recent; ///< Its place in recent_.
    uint8_t fins = 0;                ///< Bit 1 << d: direction d sent its FIN.
    Direction dir[ 2 ];
};

namespace {

/// The keys of a TLS 1.3 traffic @p secret (RFC 8446, 7.3): the cipher
/// into @p cipher, the IV into @p iv; false if they could not be made.
bool tls13Keys( const Suite& suite, const tls::SecretBytes& secret,
                std::unique_ptr<tls::RecordCipher>& cipher, tls::SecretBytes& iv )
{
    const auto key
        = tls::hkdfExpandLabel( suite.prf, secret, "key", {}, tls::keyBytes( suite.cipher ) );
    iv = tls::hkdfExpandLabel( suite.prf, secret, "iv", {}, tls::kNonceBytes );
    cipher = key.empty() || iv.empty() ? nullptr : tls::RecordCipher::make( suite.cipher, key );
    return cipher != nullptr;
}

} // namespace

TlsDecryption::TlsDecryption( Lookup lookup, KeyLogBytes keyLogBytes, size_t maxSessions )
    : lookup_( std::move( lookup ) )
    , keyLogBytes_( std::move( keyLogBytes ) )
    , maxSessions_( std::max<size_t>( maxSessions, 1 ) )
{
}

TlsDecryption::~TlsDecryption() = default;

void TlsDecryption::erase( int streamId )
{
    const auto it = sessions_.find( streamId );
    if ( it == sessions_.end() ) {
        return;
    }
    for ( const auto& direction : it->second->dir ) {
        http2Memory_ -= direction.http2Charged;
    }
    recent_.erase( it->second->recent );
    sessions_.erase( it );
}

void TlsDecryption::handshake( const Stream& stream, ByteView fragment )
{
    forEachHandshakeMessage( fragment, [ & ]( uint8_t type, ByteView body ) {
        Reader hello( body );
        uint16_t legacyVersion = 0;
        ByteView random;
        if ( ( type != kClientHello && type != kServerHello ) || !hello.u16( legacyVersion )
             || !hello.bytes( tls::kRandomBytes, random ) ) {
            return;
        }
        if ( type == kClientHello ) {
            // A new session, or the second ClientHello after a
            // HelloRetryRequest, with the same random.
            erase( stream.id );
            if ( sessions_.size() >= maxSessions_ ) {
                erase( recent_.front() ); // its connection's end was not captured, or is far
            }
            auto session = std::make_unique<Session>();
            std::copy( random.data, random.data + random.size, session->clientRandom.begin() );
            session->client = stream.direction;
            session->recent = recent_.insert( recent_.end(), stream.id );
            sessions_.emplace( stream.id, std::move( session ) );
            return;
        }

        const auto it = sessions_.find( stream.id );
        if ( it == sessions_.end() || it->second->client == stream.direction ) {
            return;
        }
        auto& session = *it->second;
        if ( equalBytes( random.data, kHelloRetryRandom, tls::kRandomBytes ) ) {
            return; // a HelloRetryRequest: the next ServerHello is the one
        }
        ByteView sessionId;
        uint16_t suiteId = 0;
        uint8_t compression = 0;
        if ( !hello.vector8( sessionId ) || !hello.u16( suiteId ) || !hello.u8( compression ) ) {
            return;
        }
        uint16_t version = legacyVersion;
        bool encryptThenMac = false;
        bool h2 = false;
        forEachExtension( hello, [ & ]( uint16_t extension, ByteView data ) {
            uint16_t selected = 0;
            if ( extension == 0x002B && Reader( data ).u16( selected ) ) {
                version = selected; // supported_versions
            }
            else if ( extension == 0x0016 ) {
                encryptThenMac = true;
            }
            else if ( extension == 0x0010 ) {
                h2 = alpnIsH2( data );
            }
        } );
        const auto* suite = findSuite( suiteId );
        if ( suite == nullptr || ( version != kTls12 && version != kTls13 )
             || suite->tls13 != ( version == kTls13 ) ) {
            return; // not one the decryption supports
        }
        std::copy( random.data, random.data + random.size, session.serverRandom.begin() );
        session.suite = suite;
        session.serverHello = true;
        session.encryptThenMac = encryptThenMac && isCbc( suite->cipher );
        session.http2 = h2;
        if ( suite->tls13 ) {
            // Every record after the ServerHello is protected.
            session.dir[ 0 ].encrypted = true;
            session.dir[ 1 ].encrypted = true;
        }
    } );
}

void TlsDecryption::apply( PacketRecord& pkt, const Stream& stream,
                           const ReassembledMessages& messages )
{
    if ( pkt.transport != Transport::Tcp || !stream.state || stream.id < 0 ) {
        return;
    }
    const auto flags = pkt.tcpFlags;
    if ( ( flags & kTcpSyn ) && !( flags & kTcpAck ) ) {
        erase( stream.id ); // a new connection on the ports
    }
    if ( messages.bytes.data != nullptr && messages.bytes.size > 0 ) {
        const auto it = sessions_.find( stream.id );
        if ( it != sessions_.end() ) {
            recent_.splice( recent_.end(), recent_, it->second->recent );
        }
        records( pkt, stream, messages );
    }
    if ( flags & kTcpRst ) {
        erase( stream.id );
    }
    else if ( flags & kTcpFin ) {
        const auto it = sessions_.find( stream.id );
        if ( it != sessions_.end() ) {
            it->second->fins |= static_cast<uint8_t>( 1u << stream.direction );
            if ( it->second->fins == 3 ) {
                erase( stream.id );
            }
        }
    }
}

bool TlsDecryption::setTrafficSecret( Session& session, Direction& direction,
                                      tls::SecretBytes secret )
{
    direction.seq = 0;
    direction.secret = std::move( secret );
    if ( !tls13Keys( *session.suite, direction.secret, direction.cipher, direction.iv ) ) {
        direction.cipher.reset();
        return false;
    }
    return true;
}

bool TlsDecryption::ensureKeys( Session& session )
{
    if ( session.keyed ) {
        return true;
    }
    if ( !session.serverHello || !lookup_ ) {
        return false;
    }
    if ( keyLogBytes_ && session.missedAt >= 0 && keyLogBytes_() == session.missedAt ) {
        return false; // nothing was added to the key log since
    }
    const auto* secrets = lookup_( session.clientRandom.data() );
    if ( secrets == nullptr ) {
        session.missedAt = keyLogBytes_ ? keyLogBytes_() : -1;
        return false;
    }
    const auto& suite = *session.suite;
    if ( suite.tls13 ) {
        bool any = false;
        for ( unsigned d = 0; d < 2; ++d ) {
            const bool client = d == session.client;
            const auto& handshake
                = client ? secrets->clientHandshakeTraffic : secrets->serverHandshakeTraffic;
            const auto& traffic = client ? secrets->clientTraffic : secrets->serverTraffic;
            auto& direction = session.dir[ d ];
            if ( !handshake.empty() ) {
                any = setTrafficSecret( session, direction, handshake ) || any;
            }
            direction.nextSecret = traffic;
            any = any || !traffic.empty();
        }
        session.keyed = any;
        return any;
    }

    // TLS 1.2 (RFC 5246, 6.3): the key block from the master secret.
    if ( secrets->masterSecret.empty() ) {
        return false;
    }
    const auto macBytes = isCbc( suite.cipher ) ? tls::hashBytes( suite.mac ) : 0;
    const auto keyBytes = tls::keyBytes( suite.cipher );
    const auto ivLength = ivBytes( suite );
    uint8_t seed[ 2 * tls::kRandomBytes ];
    std::copy( session.serverRandom.begin(), session.serverRandom.end(), seed );
    std::copy( session.clientRandom.begin(), session.clientRandom.end(), seed + tls::kRandomBytes );
    const auto block
        = tls::tls12Prf( suite.prf, secrets->masterSecret, "key expansion",
                         { seed, sizeof( seed ) }, 2 * ( macBytes + keyBytes + ivLength ) );
    if ( block.empty() ) {
        return false;
    }
    const auto* p = block.data();
    for ( unsigned i = 0; i < 2; ++i ) { // the client's first, then the server's
        auto& direction = session.dir[ i == 0 ? session.client : 1 - session.client ];
        direction.macKey = tls::SecretBytes( p + i * macBytes, macBytes );
        const tls::SecretBytes key( p + 2 * macBytes + i * keyBytes, keyBytes );
        direction.iv = tls::SecretBytes( p + 2 * ( macBytes + keyBytes ) + i * ivLength, ivLength );
        direction.cipher = tls::RecordCipher::make( suite.cipher, key );
        if ( !direction.cipher ) {
            return false;
        }
    }
    session.keyed = true;
    return true;
}

bool TlsDecryption::decrypt( Session& session, Direction& direction, uint8_t type, uint16_t version,
                             ByteView fragment, tls::PlainBytes& plain, uint8_t& inner )
{
    const auto& suite = *session.suite;
    if ( suite.tls13 ) {
        // RFC 8446, 5.2: the record header is the additional data, the
        // content type the last non-zero byte of the plaintext.
        const uint8_t header[ kRecordHeaderBytes ]
            = { type, static_cast<uint8_t>( version >> 8 ), static_cast<uint8_t>( version ),
                static_cast<uint8_t>( fragment.size >> 8 ), static_cast<uint8_t>( fragment.size ) };
        uint8_t nonce[ tls::kNonceBytes ];
        auto open
            = [ & ]( const tls::RecordCipher& cipher, const tls::SecretBytes& iv, uint64_t seq ) {
                  xorNonce( iv, seq, nonce );
                  return cipher.open( nonce, { header, sizeof( header ) }, fragment, plain );
              };
        bool opened = false;
        for ( uint64_t k = 0; direction.cipher && !opened && k <= kSequenceLookahead; ++k ) {
            if ( open( *direction.cipher, direction.iv, direction.seq + k ) ) {
                direction.seq += k + 1;
                direction.skipped = k;
                opened = true;
            }
        }
        if ( !opened && !direction.application && !direction.nextSecret.empty() ) {
            // The handshake may have ended unseen: try the application keys.
            std::unique_ptr<tls::RecordCipher> cipher;
            tls::SecretBytes iv;
            if ( tls13Keys( suite, direction.nextSecret, cipher, iv ) ) {
                for ( uint64_t k = 0; !opened && k <= kSequenceLookahead; ++k ) {
                    if ( open( *cipher, iv, k ) ) {
                        setTrafficSecret( session, direction, std::move( direction.nextSecret ) );
                        direction.nextSecret.clear();
                        direction.application = true;
                        direction.seq = k + 1;
                        direction.skipped = k;
                        opened = true;
                    }
                }
            }
        }
        if ( !opened ) {
            return false;
        }
        while ( !plain.empty() && plain.back() == 0 ) {
            plain.pop_back();
        }
        if ( plain.empty() ) {
            return false; // no content type: a record no TLS 1.3 peer sends
        }
        inner = plain.back();
        plain.pop_back();
        return true;
    }

    // TLS 1.2: the sequence number, type, version and plaintext length are
    // the additional data, or what the MAC covers (RFC 5246, 6.2.3).
    inner = type;
    auto additional = [ & ]( uint64_t seq, size_t length, uint8_t* out ) {
        putBE64( out, seq );
        out[ 8 ] = type;
        out[ 9 ] = static_cast<uint8_t>( version >> 8 );
        out[ 10 ] = static_cast<uint8_t>( version );
        out[ 11 ] = static_cast<uint8_t>( length >> 8 );
        out[ 12 ] = static_cast<uint8_t>( length );
    };
    uint8_t aad[ 13 ];
    if ( !isCbc( suite.cipher ) ) {
        const bool gcm = suite.cipher != Cipher::ChaCha20Poly1305;
        const size_t explicitBytes = gcm ? 8 : 0; // GCM's explicit nonce (RFC 5288, 3)
        if ( fragment.size < explicitBytes + tls::kTagBytes ) {
            return false;
        }
        const ByteView ciphertext{ fragment.data + explicitBytes, fragment.size - explicitBytes };
        const auto length = ciphertext.size - tls::kTagBytes;
        uint8_t nonce[ tls::kNonceBytes ];
        for ( uint64_t k = 0; k <= kSequenceLookahead; ++k ) {
            const auto seq = direction.seq + k;
            if ( gcm ) {
                std::copy( direction.iv.data(), direction.iv.data() + 4, nonce );
                std::copy( fragment.data, fragment.data + 8, nonce + 4 );
            }
            else {
                xorNonce( direction.iv, seq, nonce );
            }
            additional( seq, length, aad );
            if ( direction.cipher->open( nonce, { aad, sizeof( aad ) }, ciphertext, plain ) ) {
                direction.seq = seq + 1;
                direction.skipped = k;
                return true;
            }
        }
        return false;
    }

    // AES-CBC with HMAC: the IV first; padding, its length in each of its
    // bytes; the MAC over the plaintext (RFC 5246, 6.2.3.2), or over the
    // IV and ciphertext with encrypt-then-MAC (RFC 7366, 3).
    const auto macBytes = tls::hashBytes( suite.mac );
    uint8_t mac[ 48 ];
    auto stripPadding = [ & ]( size_t tail ) {
        if ( plain.size() < tail + 1 ) {
            return false;
        }
        const size_t padding = plain.back();
        if ( plain.size() < tail + padding + 1 ) {
            return false;
        }
        for ( size_t i = 0; i <= padding; ++i ) {
            if ( plain[ plain.size() - 1 - i ] != padding ) {
                return false;
            }
        }
        plain.resize( plain.size() - padding - 1 );
        return true;
    };
    if ( session.encryptThenMac ) {
        if ( fragment.size < 2 * tls::kAesBlockBytes + macBytes ) {
            return false;
        }
        const ByteView body{ fragment.data, fragment.size - macBytes };
        for ( uint64_t k = 0; k <= kSequenceLookahead; ++k ) {
            const auto seq = direction.seq + k;
            additional( seq, body.size, aad );
            if ( !tls::hmac( suite.mac, direction.macKey, { { aad, sizeof( aad ) }, body }, mac )
                 || !equalBytes( mac, body.data + body.size, macBytes ) ) {
                continue;
            }
            if ( !direction.cipher->decryptCbc(
                     body.data,
                     { body.data + tls::kAesBlockBytes, body.size - tls::kAesBlockBytes }, plain )
                 || !stripPadding( 0 ) ) {
                return false;
            }
            direction.seq = seq + 1;
            direction.skipped = k;
            return true;
        }
        return false;
    }
    if ( fragment.size < 2 * tls::kAesBlockBytes ) {
        return false;
    }
    if ( !direction.cipher->decryptCbc(
             fragment.data,
             { fragment.data + tls::kAesBlockBytes, fragment.size - tls::kAesBlockBytes }, plain )
         || !stripPadding( macBytes ) ) {
        return false;
    }
    const auto length = plain.size() - macBytes;
    for ( uint64_t k = 0; k <= kSequenceLookahead; ++k ) {
        const auto seq = direction.seq + k;
        additional( seq, length, aad );
        if ( tls::hmac( suite.mac, direction.macKey,
                        { { aad, sizeof( aad ) }, { plain.data(), length } }, mac )
             && equalBytes( mac, plain.data() + length, macBytes ) ) {
            plain.resize( length );
            direction.seq = seq + 1;
            direction.skipped = k;
            return true;
        }
    }
    return false;
}

void TlsDecryption::lost( Session& session, Direction& direction, uint8_t type )
{
    direction.handshake.lost();
    // TLS 1.3 hides a record's type: those after the handshake are taken
    // for application data.
    if ( session.suite->tls13 ? direction.application : type == kApplicationData ) {
        direction.lost = true;
    }
}

void TlsDecryption::afterHandshake( Session& session, unsigned d, ByteView messages )
{
    auto& direction = session.dir[ d ];
    bool finished = false;
    bool keyUpdate = false;
    direction.handshake.add( messages, [ & ]( uint8_t type, ByteView body ) {
        if ( type == kFinished && !direction.application ) {
            finished = true;
        }
        else if ( type == kKeyUpdate && direction.application ) {
            keyUpdate = true;
        }
        else if ( type == kEncryptedExtensions && d != session.client ) {
            Reader extensions( body );
            forEachExtension( extensions, [ & ]( uint16_t extension, ByteView data ) {
                if ( extension == 0x0010 && alpnIsH2( data ) ) {
                    session.http2 = true;
                }
            } );
        }
    } );
    const auto& suite = *session.suite;
    if ( finished ) {
        // The direction's next record is protected by the application keys.
        direction.application = true;
        if ( direction.nextSecret.empty() && lookup_ ) {
            if ( const auto* secrets = lookup_( session.clientRandom.data() ) ) {
                direction.nextSecret
                    = d == session.client ? secrets->clientTraffic : secrets->serverTraffic;
            }
        }
        if ( direction.nextSecret.empty() ) {
            direction.cipher.reset();
            direction.secret.clear();
        }
        else {
            setTrafficSecret( session, direction, std::move( direction.nextSecret ) );
            direction.nextSecret.clear();
        }
    }
    else if ( keyUpdate && !direction.secret.empty() ) {
        // RFC 8446, 7.2: the next secret from the current one.
        auto next = tls::hkdfExpandLabel( suite.prf, direction.secret, "traffic upd", {},
                                          tls::hashBytes( suite.prf ) );
        setTrafficSecret( session, direction, std::move( next ) );
    }
}

std::pair<const char*, std::string> TlsDecryption::application( Session& session, unsigned d,
                                                                const tls::PlainBytes& data,
                                                                const std::vector<size_t>& resyncs,
                                                                const PacketRecord& pkt )
{
    static constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    constexpr size_t kPrefaceBytes = sizeof( kPreface ) - 1;
    if ( !session.http2 && d == session.client && data.size() >= kPrefaceBytes
         && std::memcmp( data.data(), kPreface, kPrefaceBytes ) == 0 ) {
        session.http2 = true;
    }
    if ( session.http2 ) {
        auto& direction = session.dir[ d ];
        if ( !direction.http2 ) {
            direction.http2 = std::make_unique<Http2Direction>();
        }
        // The bytes between where data went missing are described each
        // from a frame's start.
        std::string description;
        size_t from = 0;
        for ( size_t i = 0; i <= resyncs.size(); ++i ) {
            const auto to = i < resyncs.size() ? resyncs[ i ] : data.size();
            if ( to > from ) {
                const auto piece = direction.http2->describe( data.data() + from, to - from );
                if ( !piece.empty() ) {
                    description += ( description.empty() ? "" : ", " ) + piece;
                }
            }
            if ( i < resyncs.size() ) {
                direction.http2->resync();
            }
            from = std::max( from, to );
        }
        auto charge = [ & ] {
            const auto memory = direction.http2->memory();
            http2Memory_ = http2Memory_ - direction.http2Charged + memory;
            direction.http2Charged = memory;
        };
        charge();
        if ( http2Memory_ > kHttp2MemoryLimit ) {
            direction.http2->abandonHeaders();
            charge();
        }
        return { "HTTP2", description.empty() ? "Continuation" : description };
    }
    const auto described
        = describePayload( Transport::Tcp, data.data(), data.size(), pkt.srcPort, pkt.dstPort );
    if ( !described.label.empty() && !described.guessed && !described.preview
         && !described.description.empty() ) {
        return { described.label == "HTTP" ? "HTTP" : "TLS", described.description };
    }
    return { "TLS", "Application Data" };
}

void TlsDecryption::records( PacketRecord& pkt, const Stream& stream,
                             const ReassembledMessages& messages )
{
    const auto* p = messages.bytes.data;
    const auto n = messages.bytes.size;
    const auto d = stream.direction;
    std::vector<std::string> parts;
    tls::PlainBytes application;
    std::vector<size_t> resyncs; ///< Where in it application data went missing.
    size_t applicationPart = SIZE_MAX;
    tls::PlainBytes plain; // wiped when it goes or grows
    bool decrypted = false;

    for ( size_t at = 0; n - at >= kRecordHeaderBytes; ) {
        const uint8_t type = p[ at ];
        const uint16_t version = readBE16( p + at + 1 );
        const uint16_t length = readBE16( p + at + 3 );
        if ( type < kChangeCipherSpec || type > kApplicationData || p[ at + 1 ] != 3
             || n - at - kRecordHeaderBytes < length ) {
            break; // no whole record: the rest is left as it was described
        }
        const ByteView record{ p + at, kRecordHeaderBytes + length };
        const ByteView fragment{ p + at + kRecordHeaderBytes, length };
        at += record.size;

        const auto it = sessions_.find( stream.id );
        auto* session = it == sessions_.end() ? nullptr : it->second.get();
        const bool isProtected
            = session && session->serverHello && session->dir[ d ].encrypted
              && ( session->suite->tls13 ? type == kApplicationData : type != kChangeCipherSpec );
        if ( !isProtected ) {
            parts.push_back( describePayload( Transport::Tcp, record.data, record.size, pkt.srcPort,
                                              pkt.dstPort )
                                 .description );
            if ( type == kHandshake ) {
                handshake( stream, fragment );
            }
            else if ( type == kChangeCipherSpec && session && session->serverHello
                      && !session->suite->tls13 ) {
                session->dir[ d ].encrypted = true; // TLS 1.2: protected from here on
                session->dir[ d ].seq = 0;
            }
            continue;
        }

        auto& direction = session->dir[ d ];
        uint8_t inner = 0;
        if ( direction.failures >= kMaxFailures || !ensureKeys( *session )
             || !decrypt( *session, direction, type, version, fragment, plain, inner ) ) {
            if ( session->keyed && direction.failures < kMaxFailures ) {
                ++direction.failures;
            }
            lost( *session, direction, type );
            parts.emplace_back( protectedName( type ) );
            continue;
        }
        direction.failures = 0;
        if ( direction.skipped > 0 ) {
            lost( *session, direction, type );
        }
        decrypted = true;
        if ( !session->decrypted ) {
            session->decrypted = true;
            ++sessionsDecrypted_;
        }
        switch ( inner ) {
        case kHandshake:
            parts.push_back( describeTlsHandshake( plain.data(), plain.size() ) );
            if ( session->suite->tls13 ) {
                afterHandshake( *session, d, { plain.data(), plain.size() } );
            }
            break;
        case kAlert:
            parts.push_back( describeTlsAlert( plain.data(), plain.size() ) );
            break;
        case kApplicationData:
            if ( applicationPart == SIZE_MAX ) {
                applicationPart = parts.size();
                parts.emplace_back();
            }
            if ( direction.lost ) {
                resyncs.push_back( application.size() );
                direction.lost = false;
            }
            application.insert( application.end(), plain.begin(), plain.end() );
            break;
        default:
            parts.emplace_back( "Change Cipher Spec" );
            break;
        }
    }
    if ( !decrypted ) {
        return;
    }

    const char* label = "TLS";
    if ( applicationPart != SIZE_MAX ) {
        const auto it = sessions_.find( stream.id );
        if ( it != sessions_.end() ) {
            auto described = this->application( *it->second, d, application, resyncs, pkt );
            label = described.first;
            parts[ applicationPart ] = std::move( described.second );
        }
    }
    auto description = std::string( kDecryptedMarker ) + kDescriptionSeparator + joinParts( parts );
    if ( messages.segments > 1 ) {
        description += " [reassembled from " + std::to_string( messages.segments ) + " segments]";
    }
    redescribe( pkt, label, description );
}

} // namespace tcpdump
