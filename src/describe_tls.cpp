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
 * @file describe_tls.cpp
 * @brief The TLS detector of the Payload Describer.
 */

#include "describe_common.h"

#include <algorithm>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── TLS ──────────────────────────────────────────────────────────────────

namespace {

/// Most bytes of a hello field (a server name, the protocol list) shown.
constexpr size_t kMaxTlsFieldBytes = kMaxFieldBytes;

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
            return fieldText( name.here(), name.remaining() );
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
    case 5:
        return "End Of Early Data";
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
    case 24:
        return "Key Update";
    default:
        return "Handshake";
    }
}

/// A TLS record header: a content type TLS knows and protocol version 3.x.
bool isTlsRecordHeader( const uint8_t* p )
{
    return p[ 0 ] >= 0x14 && p[ 0 ] <= 0x17 && p[ 1 ] == 0x03;
}

} // namespace

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

    return joinNames( std::move( names ), kMaxTlsMessages );
}

} // namespace tcpdump::describer

// ── Decrypted records, for the TLS Decryption ────────────────────────────

namespace tcpdump {

using namespace describer;

/// The handshake messages of a decrypted record, up to kMaxTlsMessages,
/// then an ellipsis.
std::string describeTlsHandshake( const uint8_t* data, size_t len )
{
    std::vector<std::string> names;
    FieldReader fragment( data, len );
    uint8_t type = 0;
    uint32_t length = 0;
    bool more = false;
    while ( fragment.u8( type ) ) {
        if ( names.size() == kMaxTlsMessages ) {
            more = true;
            break;
        }
        if ( !fragment.u24( length ) ) {
            names.push_back( tlsHandshakeMessage( type, FieldReader( nullptr, 0, false ) ) );
            break;
        }
        auto message = fragment.take( length );
        names.push_back( tlsHandshakeMessage( type, message ) );
        if ( !message.complete() ) {
            break;
        }
    }
    if ( names.empty() ) {
        return "Handshake";
    }
    return joinNames( std::move( names ), kMaxTlsMessages, more );
}

/// A decrypted alert, "Alert: close_notify", by its description's name
/// (RFC 8446, 6).
std::string describeTlsAlert( const uint8_t* data, size_t len )
{
    if ( len != 2 ) {
        return "Alert";
    }
    switch ( data[ 1 ] ) {
    case 0:
        return "Alert: close_notify";
    case 10:
        return "Alert: unexpected_message";
    case 20:
        return "Alert: bad_record_mac";
    case 22:
        return "Alert: record_overflow";
    case 40:
        return "Alert: handshake_failure";
    case 42:
        return "Alert: bad_certificate";
    case 46:
        return "Alert: certificate_unknown";
    case 48:
        return "Alert: unknown_ca";
    case 50:
        return "Alert: decode_error";
    case 51:
        return "Alert: decrypt_error";
    case 70:
        return "Alert: protocol_version";
    case 80:
        return "Alert: internal_error";
    case 90:
        return "Alert: user_canceled";
    case 100:
        return "Alert: no_renegotiation";
    case 109:
        return "Alert: missing_extension";
    case 112:
        return "Alert: unrecognized_name";
    case 116:
        return "Alert: certificate_required";
    case 120:
        return "Alert: no_application_protocol";
    default:
        return "Alert: " + std::to_string( data[ 1 ] );
    }
}

} // namespace tcpdump

namespace tcpdump::describer {

/// The TLS record a segment begins with: its header and fragment, or
/// nothing if the bytes there are no record header (RFC 8446, 5.1).  A
/// fragment longer than 2^14 + 2048 bytes, the most a TLS 1.2 ciphertext
/// may take, is no record's.  Fewer bytes than a header's are taken for one
/// if those there fit.
std::optional<size_t> frameTlsRecord( const uint8_t* payload, size_t len )
{
    constexpr size_t kHeaderBytes = 5;
    constexpr uint16_t kMaxFragment = 16384 + 2048;
    if ( len == 0 || payload[ 0 ] < 0x14 || payload[ 0 ] > 0x17
         || ( len >= 2 && payload[ 1 ] != 0x03 ) || ( len >= 3 && payload[ 2 ] > 0x04 ) ) {
        return std::nullopt;
    }
    if ( len < kHeaderBytes ) {
        return kHeaderBytes;
    }
    const uint16_t length = readBE16( payload + 3 );
    if ( length > kMaxFragment ) {
        return std::nullopt;
    }
    return kHeaderBytes + length;
}

} // namespace tcpdump::describer
