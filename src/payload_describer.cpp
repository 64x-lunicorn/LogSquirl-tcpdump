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
 * @file payload_describer.cpp
 * @brief The application-protocol detectors, and the order they are tried in.
 *
 * Every detector has the same shape: the payload and its ports in, a
 * description out if it recognises the payload.  Each transport has a table
 * of detectors; the first match wins, and the last entry of each table, the
 * port hint with the payload preview, always answers.
 */

#include "payload_describer.h"

#include "protocol_names.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace tcpdump {

namespace {

// ── Payload text ─────────────────────────────────────────────────────────

/// Format a protocol code as "0xNN".
std::string hexCode( uint8_t code )
{
    char buf[ 8 ];
    std::snprintf( buf, sizeof( buf ), "0x%02X", code );
    return buf;
}

/// Payload bytes as text: printable ASCII as is, anything else as \xNN, so
/// that a field can neither break the line nor hide what it contains.
/// Within quotes, '"' is escaped too.
std::string escapeBytes( const uint8_t* p, size_t len, bool quoted )
{
    std::string out;
    out.reserve( len );
    for ( size_t i = 0; i < len; ++i ) {
        const auto c = p[ i ];
        if ( c == '\\' || ( quoted && c == '"' ) ) {
            out += '\\';
            out += static_cast<char>( c );
        }
        else if ( c >= 0x20 && c < 0x7F ) {
            out += static_cast<char>( c );
        }
        else {
            out += "\\x" + hexCode( c ).substr( 2 );
        }
    }
    return out;
}

std::string quotedBytes( const uint8_t* p, size_t len )
{
    return '"' + escapeBytes( p, len, true ) + '"';
}

/// Longest first line, in bytes, before it is cut.
constexpr size_t kMaxFirstLineBytes = 120;

/// The first line of a payload, up to CR/LF and at most kMaxFirstLineBytes
/// bytes, escaped.
std::string firstLine( const uint8_t* payload, size_t len )
{
    size_t end = 0;
    while ( end < len && end < kMaxFirstLineBytes && payload[ end ] != '\r'
            && payload[ end ] != '\n' ) {
        ++end;
    }
    return escapeBytes( payload, end, false );
}

/// Longest payload preview, in characters, before it is cut with an ellipsis.
constexpr size_t kMaxPreviewChars = 200;

/// ASCII letter, independent of the C locale (unlike std::isalpha).
bool isAsciiAlpha( uint8_t c )
{
    return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
}

// ── HTTP ─────────────────────────────────────────────────────────────────

/// Detect HTTP request or response from payload start.
std::string detectHttp( const uint8_t* payload, size_t len )
{
    if ( len < 4 )
        return {};

    // HTTP methods
    auto startsWith = [ & ]( const char* prefix ) {
        auto pLen = std::strlen( prefix );
        return len >= pLen && std::memcmp( payload, prefix, pLen ) == 0;
    };

    if ( startsWith( "GET " ) || startsWith( "POST " ) || startsWith( "PUT " )
         || startsWith( "DELETE " ) || startsWith( "HEAD " ) || startsWith( "PATCH " )
         || startsWith( "OPTIONS " ) || startsWith( "CONNECT " ) ) {
        return firstLine( payload, len );
    }

    if ( startsWith( "HTTP/" ) ) {
        return firstLine( payload, len ); // the status line
    }

    return {};
}

// ── DNS ──────────────────────────────────────────────────────────────────

/// Detect DNS query/response and return a description.
std::string detectDns( const uint8_t* payload, size_t len )
{
    // DNS header is 12 bytes minimum
    if ( len < 12 )
        return {};

    auto flags = readBE16( payload + 2 );
    bool isResponse = ( flags & 0x8000 ) != 0;
    auto qdcount = readBE16( payload + 4 );

    // Try to extract the queried domain name
    std::string qname;
    size_t offset = 12;
    while ( offset < len ) {
        auto labelLen = payload[ offset ];
        if ( labelLen == 0 )
            break;
        if ( labelLen > 63 || offset + labelLen >= len )
            break;
        if ( !qname.empty() )
            qname += '.';
        qname += escapeBytes( payload + offset + 1, labelLen, false );
        offset += labelLen + 1;
    }

    std::string desc = isResponse ? "Response" : "Query";
    if ( qdcount > 0 && !qname.empty() ) {
        desc += " " + qname;
    }
    if ( isResponse ) {
        auto rcode = flags & 0x000F;
        if ( rcode == 3 )
            desc += " [NXDOMAIN]";
        else if ( rcode != 0 )
            desc += " [RCODE=" + std::to_string( rcode ) + "]";
        auto ancount = readBE16( payload + 6 );
        if ( ancount > 0 )
            desc += " (" + std::to_string( ancount ) + " answers)";
    }
    return desc;
}

// ── NMEA ─────────────────────────────────────────────────────────────────

/// Detect NMEA 0183 sentences in payload (GPS: $GPGGA, $GNGSA, $GPGSV, etc.)
/// Requires the mandatory comma after the 5-char sentence ID to avoid false
/// positives on ADB protocol frames like $WRTE which also match $ + 5 alpha.
std::string detectNmea( const uint8_t* payload, size_t len )
{
    // Scan for '$' + 5 alpha chars + ',' (NMEA 0183 mandatory format)
    for ( size_t i = 0; i + 7 < len; ++i ) {
        if ( payload[ i ] == '$' && isAsciiAlpha( payload[ i + 1 ] )
             && isAsciiAlpha( payload[ i + 2 ] ) && isAsciiAlpha( payload[ i + 3 ] )
             && isAsciiAlpha( payload[ i + 4 ] ) && isAsciiAlpha( payload[ i + 5 ] )
             && payload[ i + 6 ] == ',' ) {
            // Found an NMEA sentence — extract until CR/LF
            return firstLine( payload + i, len - i );
        }
    }
    return {};
}

// ── Payload preview ──────────────────────────────────────────────────────

/// Build an ASCII preview of a payload: printable bytes as themselves,
/// every other byte as a dot, at most kMaxPreviewChars characters followed
/// by an ellipsis.  Returns empty if the payload is predominantly binary
/// (less than 40% printable), where a preview would only be dots.
std::string payloadPreview( const uint8_t* payload, size_t len )
{
    auto isPrintable = []( uint8_t c ) { return c >= 0x20 && c < 0x7F; };

    const auto printable
        = static_cast<size_t>( std::count_if( payload, payload + len, isPrintable ) );
    if ( printable == 0 || printable * 10 < len * 4 ) {
        return {};
    }

    const size_t shown = std::min( len, kMaxPreviewChars );
    std::string preview;
    preview.reserve( shown + 3 );
    for ( size_t i = 0; i < shown; ++i ) {
        preview += isPrintable( payload[ i ] ) ? static_cast<char>( payload[ i ] ) : '.';
    }
    if ( len > shown ) {
        preview += "\xe2\x80\xa6"; // …
    }
    return preview;
}

// ── Binary fields ────────────────────────────────────────────────────────

/// Reads the fields of a binary message (TLS, QUIC) from its bytes, never
/// beyond them.  A read that does not fit fails and leaves the reader as it
/// was.
class FieldReader {
public:
    FieldReader( const uint8_t* data, size_t len, bool complete = true )
        : data_( data )
        , len_( len )
        , complete_( complete )
    {
    }

    bool u8( uint8_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        value = data_[ pos_++ ];
        return true;
    }

    bool u16( uint16_t& value )
    {
        if ( len_ - pos_ < 2 ) {
            return false;
        }
        value = readBE16( data_ + pos_ );
        pos_ += 2;
        return true;
    }

    bool u24( uint32_t& value )
    {
        if ( len_ - pos_ < 3 ) {
            return false;
        }
        value = ( static_cast<uint32_t>( data_[ pos_ ] ) << 16 ) | readBE16( data_ + pos_ + 1 );
        pos_ += 3;
        return true;
    }

    bool u32( uint32_t& value )
    {
        if ( len_ - pos_ < 4 ) {
            return false;
        }
        value = readBE32( data_ + pos_ );
        pos_ += 4;
        return true;
    }

    /// A QUIC variable-length integer (RFC 9000, 16): its first two bits
    /// say whether it takes 1, 2, 4 or 8 bytes.
    bool varint( uint64_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        const size_t n = size_t{ 1 } << ( data_[ pos_ ] >> 6 );
        if ( len_ - pos_ < n ) {
            return false;
        }
        value = data_[ pos_ ] & 0x3F;
        for ( size_t i = 1; i < n; ++i ) {
            value = ( value << 8 ) | data_[ pos_ + i ];
        }
        pos_ += n;
        return true;
    }

    bool skip( size_t n )
    {
        if ( len_ - pos_ < n ) {
            return false;
        }
        pos_ += n;
        return true;
    }

    /// Skip a field behind its 8-bit length.
    bool skipVector8()
    {
        uint8_t n = 0;
        return u8( n ) && skip( n );
    }

    /// The next @p n bytes as a reader of their own: as many of them as
    /// there are, so a cut message is read as far as it goes.
    FieldReader take( size_t n )
    {
        const size_t available = std::min( n, len_ - pos_ );
        FieldReader part( data_ + pos_, available, available == n );
        pos_ += available;
        return part;
    }

    /// The next 8- or 16-bit length and the bytes it counts.
    bool takeVector8( FieldReader& part )
    {
        uint8_t n = 0;
        if ( !u8( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    bool takeVector16( FieldReader& part )
    {
        uint16_t n = 0;
        if ( !u16( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    /// All the bytes this reader was taken for are there.
    bool complete() const
    {
        return complete_;
    }

    /// All its bytes are there and read.
    bool readToEnd() const
    {
        return complete_ && pos_ == len_;
    }

    size_t remaining() const
    {
        return len_ - pos_;
    }
    const uint8_t* here() const
    {
        return data_ + pos_;
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
    bool complete_;
};

// ── TLS ──────────────────────────────────────────────────────────────────

/// Most bytes of a hello field (a server name, the protocol list) shown,
/// the same cap as a first line's.
constexpr size_t kMaxTlsFieldBytes = kMaxFirstLineBytes;

/// Most records and handshake messages named in one segment.
constexpr size_t kMaxTlsMessages = 4;

/// A protocol version as "TLS 1.3".
std::string tlsVersionName( uint16_t version )
{
    switch ( version ) {
    case 0x0300:
        return "SSL 3.0";
    case 0x0301:
        return "TLS 1.0";
    case 0x0302:
        return "TLS 1.1";
    case 0x0303:
        return "TLS 1.2";
    case 0x0304:
        return "TLS 1.3";
    default: {
        char buf[ 16 ];
        std::snprintf( buf, sizeof( buf ), "TLS 0x%04X", version );
        return buf;
    }
    }
}

/// A GREASE value (RFC 8701), sent to keep servers tolerant, not meant.
bool isGrease( uint16_t value )
{
    return ( value & 0x0F0F ) == 0x0A0A && ( value >> 8 ) == ( value & 0xFF );
}

/// @p len bytes as text, at most kMaxTlsFieldBytes of them, then an ellipsis.
std::string tlsField( const uint8_t* p, size_t len )
{
    if ( len <= kMaxTlsFieldBytes ) {
        return escapeBytes( p, len, false );
    }
    return escapeBytes( p, kMaxTlsFieldBytes, false ) + "\xe2\x80\xa6";
}

/// The host name of a server_name extension (RFC 6066), or empty.
std::string tlsServerName( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector16( list ) ) {
        return {};
    }
    uint8_t type = 0;
    FieldReader name( nullptr, 0 );
    while ( list.u8( type ) && list.takeVector16( name ) && name.complete() ) {
        if ( type == 0 ) { // host_name
            return tlsField( name.here(), name.remaining() );
        }
    }
    return {};
}

/// The protocols of an ALPN extension (RFC 7301), as "h2,http/1.1".
std::string tlsAlpn( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector16( list ) ) {
        return {};
    }
    std::string protocols;
    size_t shown = 0;
    FieldReader protocol( nullptr, 0 );
    while ( list.takeVector8( protocol ) && protocol.complete() ) {
        if ( shown + protocol.remaining() > kMaxTlsFieldBytes ) {
            return protocols + ( protocols.empty() ? "" : "," ) + "\xe2\x80\xa6";
        }
        if ( !protocols.empty() ) {
            protocols += ',';
        }
        protocols += escapeBytes( protocol.here(), protocol.remaining(), false );
        shown += protocol.remaining();
    }
    return protocols;
}

/// The highest version of a ClientHello's supported_versions extension
/// (RFC 8446), GREASE aside; 0 if it names none.
uint16_t tlsHighestVersion( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector8( list ) ) {
        return 0;
    }
    uint16_t highest = 0;
    uint16_t version = 0;
    while ( list.u16( version ) ) {
        if ( !isGrease( version ) ) {
            highest = std::max( highest, version );
        }
    }
    return highest;
}

/// The extensions of a hello, read as far as they are there, each one
/// whole; @p onExtension(type, data) is called for each.  True if all of
/// them were read, so that a field one of them would have named is known
/// to be absent.
template <typename OnExtension>
bool readTlsExtensions( FieldReader& hello, OnExtension onExtension )
{
    if ( hello.readToEnd() ) {
        return true; // a hello without extensions
    }
    FieldReader extensions( nullptr, 0 );
    if ( !hello.takeVector16( extensions ) ) {
        return false;
    }
    uint16_t type = 0;
    FieldReader data( nullptr, 0 );
    while ( extensions.u16( type ) && extensions.takeVector16( data ) && data.complete() ) {
        onExtension( type, data );
    }
    return extensions.readToEnd();
}

/// "Client Hello, SNI=example.com, TLS 1.3, ALPN=h2,http/1.1": the fields
/// a ClientHello holds, each left out if absent or cut off.  The version is
/// the highest the client offers.
std::string tlsClientHello( FieldReader hello )
{
    std::string description = "Client Hello";
    uint16_t legacyVersion = 0;
    if ( !hello.u16( legacyVersion ) || !hello.skip( 32 ) || !hello.skipVector8() ) {
        return description;
    }
    uint16_t cipherSuitesLength = 0;
    if ( !hello.u16( cipherSuitesLength ) || !hello.skip( cipherSuitesLength )
         || !hello.skipVector8() ) {
        return description;
    }

    std::string serverName;
    std::string protocols;
    uint16_t version = 0;
    const bool allRead = readTlsExtensions( hello, [ & ]( uint16_t type, FieldReader data ) {
        if ( type == 0x0000 && serverName.empty() ) {
            serverName = tlsServerName( data );
        }
        else if ( type == 0x002B && version == 0 ) {
            version = tlsHighestVersion( data );
        }
        else if ( type == 0x0010 && protocols.empty() ) {
            protocols = tlsAlpn( data );
        }
    } );
    if ( version == 0 && allRead ) {
        version = legacyVersion;
    }

    if ( !serverName.empty() ) {
        description += ", SNI=" + serverName;
    }
    if ( version != 0 ) {
        description += ", " + tlsVersionName( version );
    }
    if ( !protocols.empty() ) {
        description += ", ALPN=" + protocols;
    }
    return description;
}

/// "Server Hello, TLS 1.3": the version the server chose, if it is there.
std::string tlsServerHello( FieldReader hello )
{
    std::string description = "Server Hello";
    uint16_t legacyVersion = 0;
    if ( !hello.u16( legacyVersion ) || !hello.skip( 32 ) || !hello.skipVector8()
         || !hello.skip( 2 + 1 ) ) { // cipher suite, compression method
        return description;
    }
    uint16_t version = 0;
    const bool allRead = readTlsExtensions( hello, [ & ]( uint16_t type, FieldReader data ) {
        uint16_t selected = 0;
        if ( type == 0x002B && data.u16( selected ) ) {
            version = selected;
        }
    } );
    if ( version == 0 && allRead ) {
        version = legacyVersion;
    }
    if ( version != 0 ) {
        description += ", " + tlsVersionName( version );
    }
    return description;
}

/// The name of a handshake message, with the fields of the hellos.
std::string tlsHandshakeMessage( uint8_t type, FieldReader body )
{
    switch ( type ) {
    case 0:
        return "Hello Request";
    case 1:
        return tlsClientHello( body );
    case 2:
        return tlsServerHello( body );
    case 4:
        return "New Session Ticket";
    case 8:
        return "Encrypted Extensions";
    case 11:
        return "Certificate";
    case 12:
        return "Server Key Exchange";
    case 13:
        return "Certificate Request";
    case 14:
        return "Server Hello Done";
    case 15:
        return "Certificate Verify";
    case 16:
        return "Client Key Exchange";
    case 20:
        return "Finished";
    default:
        return "Handshake";
    }
}

/// A TLS record header: a content type TLS knows and protocol version 3.x.
bool isTlsRecordHeader( const uint8_t* p )
{
    return p[ 0 ] >= 0x14 && p[ 0 ] <= 0x17 && p[ 1 ] == 0x03;
}

/// Describe the TLS records of a segment, in order: "Server Hello, TLS 1.3,
/// Change Cipher Spec, Application Data".  The payload must begin with a
/// record; the records are named up to kMaxTlsMessages, then an ellipsis.
/// A record cut short is named as far as it goes, and ends the list.
std::string detectTls( const uint8_t* payload, size_t len )
{
    // A record header, and a handshake record's message type.
    if ( len < 6 || !isTlsRecordHeader( payload ) ) {
        return {};
    }

    std::vector<std::string> names;
    bool afterChangeCipherSpec = false;
    FieldReader segment( payload, len );
    while ( names.size() <= kMaxTlsMessages && segment.remaining() >= 5
            && isTlsRecordHeader( segment.here() ) ) {
        uint8_t contentType = 0;
        uint16_t length = 0;
        segment.u8( contentType );
        segment.skip( 2 );
        segment.u16( length );
        auto fragment = segment.take( length );

        switch ( contentType ) {
        case 0x14:
            names.emplace_back( "Change Cipher Spec" );
            afterChangeCipherSpec = true;
            break;
        case 0x15:
            names.emplace_back( "Alert" );
            break;
        case 0x16: {
            if ( afterChangeCipherSpec ) {
                // The Finished message, encrypted with the new keys.
                names.emplace_back( "Encrypted Handshake Message" );
                break;
            }
            uint8_t type = 0;
            uint32_t messageLength = 0;
            if ( !fragment.u8( type ) ) {
                names.emplace_back( "Handshake" );
                break;
            }
            if ( !fragment.u24( messageLength ) ) {
                names.push_back( tlsHandshakeMessage( type, FieldReader( nullptr, 0, false ) ) );
                break;
            }
            for ( ;; ) {
                auto message = fragment.take( messageLength );
                names.push_back( tlsHandshakeMessage( type, message ) );
                if ( !message.complete() || names.size() > kMaxTlsMessages || !fragment.u8( type )
                     || !fragment.u24( messageLength ) ) {
                    break;
                }
            }
            break;
        }
        default:
            names.emplace_back( "Application Data" );
            break;
        }

        if ( !fragment.complete() ) {
            break;
        }
    }

    if ( names.size() > kMaxTlsMessages ) {
        names.resize( kMaxTlsMessages );
        names.emplace_back( "\xe2\x80\xa6" );
    }
    std::string description;
    for ( const auto& name : names ) {
        if ( !description.empty() ) {
            description += ", ";
        }
        description += name;
    }
    return description;
}

// ── QUIC ─────────────────────────────────────────────────────────────────

constexpr uint8_t kQuicLongHeader = 0x80; ///< The header form bit: a long header.
constexpr uint8_t kQuicFixedBit = 0x40;   ///< Set in every QUIC v1 and v2 packet.

constexpr uint32_t kQuicV1 = 0x00000001;
constexpr uint32_t kQuicV2 = 0x6B3343CF;

/// Longest connection ID of QUIC v1 and v2; the version-independent
/// header (RFC 8999) allows 255 bytes, in a Version Negotiation packet.
constexpr size_t kMaxQuicCidBytes = 20;

/// Most packets of one datagram named, the same cap as TLS records'.
constexpr size_t kMaxQuicPackets = kMaxTlsMessages;

/// Most versions of a Version Negotiation packet named.
constexpr size_t kMaxQuicVersions = 8;

/// A draft version of the IETF drafts that already have the long header of
/// QUIC v1 (separate connection ID lengths): draft-22 to draft-34.
bool isQuicDraft( uint32_t version )
{
    return ( version >> 8 ) == 0xFF0000 && ( version & 0xFF ) >= 22 && ( version & 0xFF ) <= 34;
}

/// A version whose packets the describer can read: v1, v2 and the drafts.
bool isKnownQuicVersion( uint32_t version )
{
    return version == kQuicV1 || version == kQuicV2 || isQuicDraft( version );
}

/// A version as "1", "2", "draft-29", or "0x1A2A3A4A".
std::string quicVersionName( uint32_t version )
{
    if ( version == kQuicV1 ) {
        return "1";
    }
    if ( version == kQuicV2 ) {
        return "2";
    }
    if ( isQuicDraft( version ) ) {
        return "draft-" + std::to_string( version & 0xFF );
    }
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "0x%08X", version );
    return buf;
}

/// The name of a long header packet type; QUIC v2 (RFC 9369) numbers them
/// differently from v1 and the drafts.
const char* quicLongPacketName( uint32_t version, uint8_t firstByte )
{
    static const char* const kV1[] = { "Initial", "0-RTT", "Handshake", "Retry" };
    static const char* const kV2[] = { "Retry", "Initial", "0-RTT", "Handshake" };
    const auto type = static_cast<size_t>( ( firstByte >> 4 ) & 0x03 );
    return version == kQuicV2 ? kV2[ type ] : kV1[ type ];
}

/// Connection ID bytes in hex, as Wireshark shows them.
std::string quicCid( const uint8_t* p, size_t len )
{
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve( 2 * len );
    for ( size_t i = 0; i < len; ++i ) {
        out += kDigits[ p[ i ] >> 4 ];
        out += kDigits[ p[ i ] & 0x0F ];
    }
    return out;
}

/// The fields every long header starts with (RFC 8999, 5.1).
struct QuicLongHeader {
    uint8_t firstByte = 0;
    uint32_t version = 0;
    FieldReader dcid{ nullptr, 0 };
    FieldReader scid{ nullptr, 0 };
};

/// Read a long header's version-independent fields: true if the packet
/// begins with a long header of a known version, or with a Version
/// Negotiation packet's, whose connection IDs are whole.
bool readQuicLongHeader( FieldReader& packet, QuicLongHeader& header )
{
    if ( !packet.u8( header.firstByte ) || !( header.firstByte & kQuicLongHeader )
         || !packet.u32( header.version ) ) {
        return false;
    }
    const bool negotiation = header.version == 0;
    if ( !negotiation
         && ( !( header.firstByte & kQuicFixedBit ) || !isKnownQuicVersion( header.version ) ) ) {
        return false;
    }
    if ( !packet.takeVector8( header.dcid ) || !header.dcid.complete()
         || !packet.takeVector8( header.scid ) || !header.scid.complete() ) {
        return false;
    }
    return negotiation
           || ( header.dcid.remaining() <= kMaxQuicCidBytes
                && header.scid.remaining() <= kMaxQuicCidBytes );
}

/// ", DCID=…, SCID=…", each left out if empty.
std::string quicCids( const QuicLongHeader& header )
{
    std::string out;
    if ( header.dcid.remaining() > 0 ) {
        out += ", DCID=" + quicCid( header.dcid.here(), header.dcid.remaining() );
    }
    if ( header.scid.remaining() > 0 ) {
        out += ", SCID=" + quicCid( header.scid.here(), header.scid.remaining() );
    }
    return out;
}

/// "Version Negotiation, DCID=…, SCID=…, Versions=1,draft-29": the versions
/// the server supports, if they are a whole list holding one this describer
/// knows; a client never sends such a packet, so anything less is no QUIC.
std::string quicVersionNegotiation( const QuicLongHeader& header, FieldReader versions )
{
    if ( versions.remaining() == 0 || versions.remaining() % 4 != 0 ) {
        return {};
    }
    std::string names;
    bool known = false;
    size_t named = 0;
    uint32_t version = 0;
    while ( versions.u32( version ) ) {
        known = known || isKnownQuicVersion( version );
        if ( named == kMaxQuicVersions ) {
            names += ",\xe2\x80\xa6";
        }
        if ( named++ < kMaxQuicVersions ) {
            names += ( names.empty() ? "" : "," ) + quicVersionName( version );
        }
    }
    if ( !known ) {
        return {};
    }
    return "Version Negotiation" + quicCids( header ) + ", Versions=" + names;
}

/// Skip the rest of a long header packet after its connection IDs: true if
/// another packet may follow it in the datagram (RFC 9000, 12.2).
bool skipQuicLongPacket( FieldReader& packet, uint32_t version, uint8_t firstByte )
{
    const std::string name = quicLongPacketName( version, firstByte );
    if ( name == "Retry" ) {
        return false; // A Retry has no length: it fills the datagram.
    }
    uint64_t length = 0;
    if ( name == "Initial" ) {
        if ( !packet.varint( length ) || length > packet.remaining()
             || !packet.skip( static_cast<size_t>( length ) ) ) {
            return false;
        }
    }
    return packet.varint( length ) && length <= packet.remaining()
           && packet.skip( static_cast<size_t>( length ) );
}

/// Describe a QUIC datagram from the public header of its packets:
/// "Initial, Handshake, Version 1, DCID=…, SCID=…".  Only a datagram that
/// begins with a long header of a known version, or with a Version
/// Negotiation packet, is QUIC by its bytes alone; a short header's is told
/// by its stream (describeInStream).  The packets are encrypted: their
/// type is all there is to name.  Packets coalesced behind the first are
/// named up to kMaxQuicPackets, a short header one as Protected Payload.
std::string detectQuic( const uint8_t* payload, size_t len )
{
    FieldReader datagram( payload, len );
    QuicLongHeader first;
    if ( !readQuicLongHeader( datagram, first ) ) {
        return {};
    }
    if ( first.version == 0 ) {
        return quicVersionNegotiation( first, datagram.take( datagram.remaining() ) );
    }

    std::vector<std::string> names{ quicLongPacketName( first.version, first.firstByte ) };
    bool more = skipQuicLongPacket( datagram, first.version, first.firstByte );
    while ( more && datagram.remaining() > 0 && names.size() <= kMaxQuicPackets ) {
        const uint8_t firstByte = *datagram.here();
        if ( ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) == kQuicFixedBit ) {
            names.emplace_back( "Protected Payload" ); // fills the datagram
            break;
        }
        QuicLongHeader next;
        if ( !readQuicLongHeader( datagram, next ) || next.version != first.version ) {
            break; // Padding, or bytes that are no packet
        }
        names.emplace_back( quicLongPacketName( next.version, next.firstByte ) );
        more = skipQuicLongPacket( datagram, next.version, next.firstByte );
    }

    if ( names.size() > kMaxQuicPackets ) {
        names.resize( kMaxQuicPackets );
        names.emplace_back( "\xe2\x80\xa6" );
    }
    std::string description;
    for ( const auto& name : names ) {
        description += ( description.empty() ? "" : ", " ) + name;
    }
    return description + ", Version " + quicVersionName( first.version ) + quicCids( first );
}

// ── SOCKS ────────────────────────────────────────────────────────────────

bool isSocksPort( uint16_t port )
{
    return port == 1080 || port == 1081 || port == 3128 || port == 9050 || port == 9051;
}

const char* socks5MethodName( uint8_t method )
{
    switch ( method ) {
    case 0x00:
        return "No Authentication";
    case 0x01:
        return "GSSAPI";
    case 0x02:
        return "Username/Password";
    case 0xFF:
        return "No Acceptable Methods";
    default:
        return "Unknown";
    }
}

std::string socks5Method( uint8_t method )
{
    return std::string( socks5MethodName( method ) ) + " (" + hexCode( method ) + ")";
}

/// The address of a SOCKS5 request or reply at @p p (address type first),
/// if the message ends exactly behind it: "<type>", "<host>:<port>".
bool socks5Address( const uint8_t* p, size_t len, std::string& type, std::string& address )
{
    if ( len < 1 ) {
        return false;
    }
    switch ( p[ 0 ] ) {
    case 0x01:
        if ( len != 1 + 4 + 2 ) {
            return false;
        }
        type = "IPv4";
        address = formatIpv4( p + 1 ) + ":" + std::to_string( readBE16( p + 5 ) );
        return true;
    case 0x03: {
        if ( len < 2 ) {
            return false;
        }
        const size_t nameLen = p[ 1 ];
        if ( nameLen == 0 || len != 2 + nameLen + 2 ) {
            return false;
        }
        type = "Domain";
        address = escapeBytes( p + 2, nameLen, false ) + ":"
                  + std::to_string( readBE16( p + 2 + nameLen ) );
        return true;
    }
    case 0x04:
        if ( len != 1 + 16 + 2 ) {
            return false;
        }
        type = "IPv6";
        address = "[" + formatIpv6( p + 1 ) + "]:" + std::to_string( readBE16( p + 17 ) );
        return true;
    default:
        return false;
    }
}

/// A SOCKS message sent by the client to the proxy, or empty if the payload
/// does not have the exact shape of one.
std::string socksClientMessage( const uint8_t* p, size_t len )
{
    if ( len < 2 ) {
        return {};
    }

    // SOCKS5 greeting (RFC 1928): 05 <nmethods> <methods...>
    if ( p[ 0 ] == 0x05 && p[ 1 ] > 0 && len == 2 + static_cast<size_t>( p[ 1 ] ) ) {
        std::string methods;
        for ( size_t i = 2; i < len; ++i ) {
            if ( !methods.empty() ) {
                methods += ", ";
            }
            methods += socks5Method( p[ i ] );
        }
        return "SOCKS5 Client Greeting, Version: 5, Methods: " + std::to_string( p[ 1 ] ) + " ["
               + methods + "]";
    }

    // SOCKS5 request: 05 <cmd> 00 <atyp> <address> <port>
    if ( p[ 0 ] == 0x05 && len >= 4 && p[ 2 ] == 0x00 && p[ 1 ] >= 0x01 && p[ 1 ] <= 0x03 ) {
        std::string type;
        std::string address;
        if ( socks5Address( p + 3, len - 3, type, address ) ) {
            static const char* const kCommands[] = { "Connect", "Bind", "UDP Associate" };
            return "SOCKS5 Connect, Version: 5, Command: " + std::string( kCommands[ p[ 1 ] - 1 ] )
                   + " (" + hexCode( p[ 1 ] ) + "), Address Type: " + type
                   + ", Destination: " + address;
        }
        return {};
    }

    // Username/password request (RFC 1929): 01 <ulen> <user> <plen> <password>
    if ( p[ 0 ] == 0x01 ) {
        const size_t userLen = p[ 1 ];
        if ( len < 2 + userLen + 1 ) {
            return {};
        }
        const size_t passLen = p[ 2 + userLen ];
        if ( len != 2 + userLen + 1 + passLen ) {
            return {};
        }
        return "SOCKS5 Auth Request, User: " + quotedBytes( p + 2, userLen )
               + ", Pass: " + quotedBytes( p + 3 + userLen, passLen );
    }

    // SOCKS4 / SOCKS4a request: 04 <cmd> <port> <ip> <userid> 00 [<domain> 00]
    if ( p[ 0 ] == 0x04 && len >= 9 && ( p[ 1 ] == 0x01 || p[ 1 ] == 0x02 ) && p[ len - 1 ] == 0 ) {
        const auto* userEnd = static_cast<const uint8_t*>( std::memchr( p + 8, 0, len - 8 ) );
        const auto userLen = static_cast<size_t>( userEnd - ( p + 8 ) );
        const size_t domainStart = 8 + userLen + 1;
        // SOCKS4a: the address 0.0.0.x (x != 0) says a domain follows.
        const bool socks4a = p[ 4 ] == 0 && p[ 5 ] == 0 && p[ 6 ] == 0 && p[ 7 ] != 0;
        size_t domainLen = 0;
        if ( socks4a ) {
            if ( domainStart >= len ) {
                return {};
            }
            domainLen = len - 1 - domainStart;
            if ( domainLen == 0 || std::memchr( p + domainStart, 0, domainLen ) != nullptr ) {
                return {};
            }
        }
        else if ( domainStart != len ) {
            return {};
        }

        std::string result
            = "SOCKS4, Version: 4, Command: " + std::string( p[ 1 ] == 0x01 ? "Connect" : "Bind" )
              + " (" + hexCode( p[ 1 ] ) + "), Destination: " + formatIpv4( p + 4 ) + ":"
              + std::to_string( readBE16( p + 2 ) );
        if ( userLen > 0 ) {
            result += ", User: " + quotedBytes( p + 8, userLen );
        }
        if ( socks4a ) {
            result += ", Domain: " + escapeBytes( p + domainStart, domainLen, false );
        }
        return result;
    }

    return {};
}

/// A SOCKS message sent by the proxy to the client, or empty if the payload
/// does not have the exact shape of one.
std::string socksServerMessage( const uint8_t* p, size_t len )
{
    if ( len < 2 ) {
        return {};
    }

    // SOCKS5 method choice: 05 <method>
    if ( p[ 0 ] == 0x05 && len == 2 ) {
        return "SOCKS5 Server Choice, Version: 5, Method: " + socks5Method( p[ 1 ] );
    }

    // SOCKS5 reply: 05 <status> 00 <atyp> <address> <port>
    if ( p[ 0 ] == 0x05 && len >= 4 && p[ 2 ] == 0x00 ) {
        std::string type;
        std::string address;
        if ( !socks5Address( p + 3, len - 3, type, address ) ) {
            return {};
        }
        static const char* const kStatus[] = {
            "Succeeded",           "General Failure",       "Not Allowed by Ruleset",
            "Network Unreachable", "Host Unreachable",      "Connection Refused",
            "TTL Expired",         "Command Not Supported", "Address Type Not Supported",
        };
        const auto code = p[ 1 ];
        const char* status
            = code < sizeof( kStatus ) / sizeof( kStatus[ 0 ] ) ? kStatus[ code ] : "Unknown";
        return "SOCKS5 Reply, Version: 5, Status: " + std::string( status ) + " (" + hexCode( code )
               + "), Bound: " + address;
    }

    // Username/password response (RFC 1929): 01 <status>
    if ( p[ 0 ] == 0x01 && len == 2 ) {
        return "SOCKS5 Auth Response, Status: "
               + std::string( p[ 1 ] == 0x00 ? "Success" : "Failure" ) + " (" + hexCode( p[ 1 ] )
               + ")";
    }

    // SOCKS4 reply: 00 <status> <port> <ip>
    if ( p[ 0 ] == 0x00 && len == 8 && p[ 1 ] >= 0x5A && p[ 1 ] <= 0x5D ) {
        static const char* const kStatus[] = {
            "Request Granted",
            "Request Rejected",
            "Failed, Cannot Connect to identd",
            "Failed, identd Mismatch",
        };
        std::string result = "SOCKS4 Reply, Status: " + std::string( kStatus[ p[ 1 ] - 0x5A ] )
                             + " (" + hexCode( p[ 1 ] ) + ")";
        const auto port = readBE16( p + 2 );
        const auto ip = formatIpv4( p + 4 );
        if ( port != 0 || ip != "0.0.0.0" ) {
            result += ", Bound: " + ip + ":" + std::to_string( port );
        }
        return result;
    }

    return {};
}

/// Detect SOCKS4/SOCKS5 handshake messages (RFC 1928, RFC 1929, SOCKS4/4a).
/// Only on a known proxy port, and only a payload with the exact shape of a
/// message the client sends to that port, or the proxy sends from it.
/// User names and passwords are shown: they cross the wire in clear text.
std::string detectSocks( const uint8_t* payload, size_t len, uint16_t srcPort, uint16_t dstPort )
{
    std::string message;
    if ( isSocksPort( dstPort ) ) {
        message = socksClientMessage( payload, len );
    }
    if ( message.empty() && isSocksPort( srcPort ) ) {
        message = socksServerMessage( payload, len );
    }
    return message;
}

// ── The detectors of a transport ─────────────────────────────────────────

/// What a detector looks at.
struct Payload {
    const uint8_t* data;
    size_t len;
    uint16_t srcPort;
    uint16_t dstPort;
    Transport transport;
};

/// A detector: the description of the payload if it recognises it.
using Detector = std::optional<PayloadDescription> ( * )( const Payload& );

/// A description with the given label and text.
std::optional<PayloadDescription> described( const char* label, std::string description )
{
    PayloadDescription result;
    result.label = label;
    result.description = std::move( description );
    return result;
}

/// A description with the given label, if the detector found anything.
std::optional<PayloadDescription> describedIfAny( const char* label, std::string description )
{
    if ( description.empty() ) {
        return std::nullopt;
    }
    return described( label, std::move( description ) );
}

std::optional<PayloadDescription> tlsRecord( const Payload& p )
{
    return describedIfAny( "TLS", detectTls( p.data, p.len ) );
}

std::optional<PayloadDescription> httpMessage( const Payload& p )
{
    return describedIfAny( "HTTP", detectHttp( p.data, p.len ) );
}

std::optional<PayloadDescription> quicPacket( const Payload& p )
{
    return describedIfAny( "QUIC", detectQuic( p.data, p.len ) );
}

std::optional<PayloadDescription> nmeaSentence( const Payload& p )
{
    return describedIfAny( "NMEA", detectNmea( p.data, p.len ) );
}

std::optional<PayloadDescription> socksMessage( const Payload& p )
{
    return describedIfAny( "SOCKS", detectSocks( p.data, p.len, p.srcPort, p.dstPort ) );
}

/// The last resort: the protocol the ports suggest, and a preview of the
/// payload's text.  Always answers, possibly with nothing.
std::optional<PayloadDescription> portHintAndPreview( const Payload& p )
{
    PayloadDescription result;
    auto proto = servicePortName( p.transport, p.srcPort );
    if ( !proto ) {
        proto = servicePortName( p.transport, p.dstPort );
    }
    if ( proto ) {
        result.label = proto;
    }
    result.description = payloadPreview( p.data, p.len );
    return result;
}

/// The TCP detectors, in the order they are tried.
constexpr Detector kTcpDetectors[]
    = { tlsRecord, httpMessage, nmeaSentence, socksMessage, portHintAndPreview };

bool onPort( const Payload& p, uint16_t port )
{
    return p.srcPort == port || p.dstPort == port;
}

/// DNS on port 53, mDNS on port 5353: named by the port, described if the
/// payload parses as a DNS message.
std::optional<PayloadDescription> dnsMessage( const Payload& p )
{
    const bool mdns = onPort( p, 5353 );
    if ( !mdns && !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return described( mdns ? "mDNS" : "DNS", detectDns( p.data, p.len ) );
}

/// SSDP on port 1900: HTTP-shaped messages.
std::optional<PayloadDescription> ssdpMessage( const Payload& p )
{
    if ( !onPort( p, 1900 ) ) {
        return std::nullopt;
    }
    return described( "SSDP", detectHttp( p.data, p.len ) );
}

std::optional<PayloadDescription> ntpPacket( const Payload& p )
{
    if ( !onPort( p, 123 ) ) {
        return std::nullopt;
    }
    return described( "NTP", {} );
}

std::optional<PayloadDescription> dhcpPacket( const Payload& p )
{
    if ( !onPort( p, 67 ) && !onPort( p, 68 ) ) {
        return std::nullopt;
    }
    return described( "DHCP", {} );
}

/// The UDP detectors, in the order they are tried: ports first, then content.
constexpr Detector kUdpDetectors[] = { dnsMessage, ssdpMessage,  ntpPacket,         dhcpPacket,
                                       quicPacket, nmeaSentence, portHintAndPreview };

/// The detectors of a transport, as a range.
template <size_t N>
std::pair<const Detector*, const Detector*> detectorsOf( const Detector ( &table )[ N ] )
{
    return { table, table + N };
}

/// The description as one line: a control character a detector let
/// through, a newline above all, is escaped as \xNN.  The detectors escape
/// the payload text they quote, so this normally changes nothing; the
/// guarantee that one packet is one line rests here, not on each of them.
std::string oneLine( std::string description )
{
    auto isControl = []( char c ) {
        const auto byte = static_cast<uint8_t>( c );
        return byte < 0x20 || byte == 0x7F;
    };
    if ( std::none_of( description.begin(), description.end(), isControl ) ) {
        return description;
    }
    std::string escaped;
    escaped.reserve( description.size() + 8 );
    for ( const char c : description ) {
        if ( isControl( c ) ) {
            escaped += "\\x" + hexCode( static_cast<uint8_t>( c ) ).substr( 2 );
        }
        else {
            escaped += c;
        }
    }
    return escaped;
}

} // namespace

// ── The describer ────────────────────────────────────────────────────────

PayloadDescription describePayload( Transport transport, const uint8_t* payload, size_t len,
                                    uint16_t srcPort, uint16_t dstPort )
{
    const Payload p{ payload, len, srcPort, dstPort, transport };
    const auto [ first, last ]
        = transport == Transport::Tcp ? detectorsOf( kTcpDetectors ) : detectorsOf( kUdpDetectors );
    for ( auto detect = first; detect != last; ++detect ) {
        if ( auto result = ( *detect )( p ) ) {
            result->description = oneLine( std::move( result->description ) );
            return *result;
        }
    }
    return {};
}

void describeInStream( PacketRecord& pkt, const Stream& stream )
{
    if ( pkt.transport != Transport::Udp || !stream.state ) {
        return;
    }
    auto& quic = stream.state->quic;
    FieldReader head( pkt.payloadHead.data(), pkt.payloadHeadLen );

    if ( pkt.protocol == "QUIC" ) {
        // A long header the describer named: the connection ID its sender
        // chose is the one the other side sends short headers to.
        QuicLongHeader header;
        if ( readQuicLongHeader( head, header ) ) {
            quic.seen = true;
            if ( header.version != 0 ) {
                quic.dcidLength[ 1 - stream.direction ]
                    = static_cast<int8_t>( header.scid.remaining() );
            }
        }
        return;
    }

    // A short header: the fixed bit without the long header bit, and room
    // for a packet number and the 16 bytes header protection samples.
    const auto dcidLength = quic.dcidLength[ stream.direction ];
    const size_t minimumLength = 1 + std::max<int>( dcidLength, 0 ) + 4 + 16;
    uint8_t firstByte = 0;
    if ( !quic.seen || !head.u8( firstByte )
         || ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) != kQuicFixedBit
         || pkt.payloadLen < minimumLength ) {
        return;
    }
    std::string description = "Protected Payload";
    if ( dcidLength > 0 && head.remaining() >= static_cast<size_t>( dcidLength ) ) {
        description += ", DCID=" + quicCid( head.here(), static_cast<size_t>( dcidLength ) );
    }
    pkt.protocol = "QUIC";
    pkt.info = pkt.info.substr( 0, pkt.info.find( kDescriptionSeparator ) ) + kDescriptionSeparator
               + description;
}

} // namespace tcpdump
