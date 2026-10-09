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

#include "wire_bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>

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

/// The first line of a payload, up to CR/LF and at most 120 bytes, escaped.
std::string firstLine( const uint8_t* payload, size_t len )
{
    size_t end = 0;
    while ( end < len && end < 120 && payload[ end ] != '\r' && payload[ end ] != '\n' ) {
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

// ── Port hint and preview ────────────────────────────────────────────────

/// Map well-known ports to protocol names.
const char* portToProtocol( uint16_t port )
{
    switch ( port ) {
    case 20:
        return "FTP-DATA";
    case 21:
        return "FTP";
    case 22:
        return "SSH";
    case 23:
        return "Telnet";
    case 25:
        return "SMTP";
    case 53:
        return "DNS";
    case 80:
        return "HTTP";
    case 110:
        return "POP3";
    case 143:
        return "IMAP";
    case 443:
        return "HTTPS";
    case 993:
        return "IMAPS";
    case 995:
        return "POP3S";
    case 1080:
        return "SOCKS";
    case 3306:
        return "MySQL";
    case 5432:
        return "PostgreSQL";
    case 5555:
        return "ADB";
    case 8080:
    case 8443:
        return "HTTP-Alt";
    case 6379:
        return "Redis";
    case 27017:
        return "MongoDB";
    case 1883:
        return "MQTT";
    case 5672:
        return "AMQP";
    case 9092:
        return "Kafka";
    default:
        return nullptr;
    }
}

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

// ── TLS ──────────────────────────────────────────────────────────────────

/// Detect TLS record and return a description (e.g. "ClientHello", "ServerHello").
std::string detectTls( const uint8_t* payload, size_t len )
{
    // TLS record header: ContentType(1) Version(2) Length(2)
    if ( len < 6 )
        return {};

    auto contentType = payload[ 0 ];
    auto versionMajor = payload[ 1 ];
    // Handshake content type = 0x16, version 0x0301..0x0304
    if ( contentType == 0x16 && versionMajor == 0x03 ) {
        // Handshake message type at offset 5
        auto hsType = payload[ 5 ];
        switch ( hsType ) {
        case 1:
            return "Client Hello";
        case 2:
            return "Server Hello";
        case 11:
            return "Certificate";
        case 12:
            return "Server Key Exchange";
        case 14:
            return "Server Hello Done";
        case 16:
            return "Client Key Exchange";
        case 20:
            return "Finished";
        default:
            return "Handshake";
        }
    }
    if ( contentType == 0x17 && versionMajor == 0x03 ) {
        return "Application Data";
    }
    if ( contentType == 0x15 && versionMajor == 0x03 ) {
        return "Alert";
    }
    if ( contentType == 0x14 && versionMajor == 0x03 ) {
        return "Change Cipher Spec";
    }
    return {};
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
        address = formatIpv6( p + 1 ) + ":" + std::to_string( readBE16( p + 17 ) );
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
    auto proto = portToProtocol( p.srcPort );
    if ( !proto ) {
        proto = portToProtocol( p.dstPort );
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
constexpr Detector kUdpDetectors[]
    = { dnsMessage, ssdpMessage, ntpPacket, dhcpPacket, nmeaSentence, portHintAndPreview };

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
    const Payload p{ payload, len, srcPort, dstPort };
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

} // namespace tcpdump
