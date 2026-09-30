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
 * @file pcap_parser.cpp
 * @brief Implementation of the pcap file parser.
 *
 * Parses pcap (libpcap) files with Ethernet, Raw IP, and Linux cooked
 * capture link layers.  Extracts IPv4/IPv6, TCP, UDP, ICMP, and ARP
 * protocol fields from each packet.
 */

#include "pcap_parser.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace tcpdump {

namespace {

// ── Byte-order helpers ───────────────────────────────────────────────────

/// Read a uint16 in the file's byte order.
uint16_t read16( const uint8_t* p, bool swap )
{
    uint16_t v;
    std::memcpy( &v, p, 2 );
    if ( swap ) {
        v = static_cast<uint16_t>( ( v >> 8 ) | ( v << 8 ) );
    }
    return v;
}

/// Read a uint32 in the file's byte order.
uint32_t read32( const uint8_t* p, bool swap )
{
    uint32_t v;
    std::memcpy( &v, p, 4 );
    if ( swap ) {
        v = ( ( v >> 24 ) & 0xFF ) | ( ( v >> 8 ) & 0xFF00 ) | ( ( v << 8 ) & 0xFF0000 )
            | ( ( v << 24 ) & 0xFF000000 );
    }
    return v;
}

/// Read a int32 in the file's byte order.
int32_t readS32( const uint8_t* p, bool swap )
{
    uint32_t u = read32( p, swap );
    int32_t result;
    std::memcpy( &result, &u, 4 );
    return result;
}

// ── Network byte order (big-endian) helpers ──────────────────────────────

/// Read a big-endian uint16 (network byte order — always big-endian).
uint16_t readBE16( const uint8_t* p )
{
    return static_cast<uint16_t>( ( p[ 0 ] << 8 ) | p[ 1 ] );
}

/// Read a big-endian uint32 (network byte order).
uint32_t readBE32( const uint8_t* p )
{
    return ( static_cast<uint32_t>( p[ 0 ] ) << 24 ) | ( static_cast<uint32_t>( p[ 1 ] ) << 16 )
           | ( static_cast<uint32_t>( p[ 2 ] ) << 8 ) | p[ 3 ];
}

// ── MAC address formatting ───────────────────────────────────────────────

std::string formatMac( const uint8_t* p )
{
    char buf[ 18 ];
    std::snprintf( buf, sizeof( buf ), "%02x:%02x:%02x:%02x:%02x:%02x", p[ 0 ], p[ 1 ], p[ 2 ],
                   p[ 3 ], p[ 4 ], p[ 5 ] );
    return buf;
}

// ── IPv4 address formatting ─────────────────────────────────────────────

std::string formatIpv4( const uint8_t* p )
{
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "%u.%u.%u.%u", p[ 0 ], p[ 1 ], p[ 2 ], p[ 3 ] );
    return buf;
}

// ── IPv6 address formatting ─────────────────────────────────────────────

std::string formatIpv6( const uint8_t* p )
{
    char buf[ 40 ];
    std::snprintf( buf, sizeof( buf ), "%x:%x:%x:%x:%x:%x:%x:%x", readBE16( p ), readBE16( p + 2 ),
                   readBE16( p + 4 ), readBE16( p + 6 ), readBE16( p + 8 ), readBE16( p + 10 ),
                   readBE16( p + 12 ), readBE16( p + 14 ) );
    return buf;
}

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

// ── TCP flags as info string ─────────────────────────────────────────────

std::string tcpFlagStr( uint8_t flags )
{
    std::string result = "[";
    bool first = true;
    auto add = [ & ]( const char* name ) {
        if ( !first )
            result += ", ";
        result += name;
        first = false;
    };
    if ( flags & 0x02 )
        add( "SYN" );
    if ( flags & 0x10 )
        add( "ACK" );
    if ( flags & 0x01 )
        add( "FIN" );
    if ( flags & 0x04 )
        add( "RST" );
    if ( flags & 0x08 )
        add( "PSH" );
    if ( flags & 0x20 )
        add( "URG" );
    result += "]";
    return result;
}

// ── Application-layer protocol detection ─────────────────────────────────

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

/// The first line of a payload, up to CR/LF and at most 120 bytes, escaped.
std::string firstLine( const uint8_t* payload, size_t len )
{
    size_t end = 0;
    while ( end < len && end < 120 && payload[ end ] != '\r' && payload[ end ] != '\n' ) {
        ++end;
    }
    return escapeBytes( payload, end, false );
}

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

std::string quotedBytes( const uint8_t* p, size_t len )
{
    return '"' + escapeBytes( p, len, true ) + '"';
}

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

/// Longest payload preview, in characters, before it is cut with an ellipsis.
constexpr size_t kMaxPreviewChars = 200;

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

/// ASCII letter, independent of the C locale (unlike std::isalpha).
bool isAsciiAlpha( uint8_t c )
{
    return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
}

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

// ── Parse transport layer (TCP / UDP / ICMP) ─────────────────────────────

void parseTransport( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    if ( pkt.ipProtocol == IpProtoTcp && remaining >= 20 ) {
        pkt.protocol = "TCP";
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
        pkt.tcpSeq = readBE32( data + 4 );
        pkt.tcpAck = readBE32( data + 8 );
        pkt.tcpFlags = data[ 13 ];
        pkt.tcpWindow = readBE16( data + 14 );

        auto dataOffset = static_cast<uint8_t>( ( data[ 12 ] >> 4 ) * 4 );
        if ( dataOffset <= remaining ) {
            pkt.payloadLen = static_cast<uint32_t>( remaining - dataOffset );
        }

        // Build base TCP info line
        std::ostringstream oss;
        oss << pkt.srcPort << " \xe2\x86\x92 " << pkt.dstPort << " " << tcpFlagStr( pkt.tcpFlags )
            << " Seq=" << pkt.tcpSeq << " Ack=" << pkt.tcpAck << " Win=" << pkt.tcpWindow;
        if ( pkt.payloadLen > 0 ) {
            oss << " Len=" << pkt.payloadLen;
        }

        // Application-layer detection on TCP payload
        const uint8_t* payload = data + dataOffset;
        size_t payloadSize = ( dataOffset <= remaining ) ? remaining - dataOffset : 0;

        if ( payloadSize > 0 ) {
            // Try TLS
            auto tls = detectTls( payload, payloadSize );
            if ( !tls.empty() ) {
                pkt.protocol = "TLS";
                oss << " [" << tls << "]";
            }
            else {
                // Try HTTP
                auto http = detectHttp( payload, payloadSize );
                if ( !http.empty() ) {
                    pkt.protocol = "HTTP";
                    oss << " | " << http;
                }
                else {
                    // Try NMEA GPS sentences
                    auto nmea = detectNmea( payload, payloadSize );
                    if ( !nmea.empty() ) {
                        pkt.protocol = "NMEA";
                        oss << " | " << nmea;
                    }
                    else {
                        // Try SOCKS proxy handshake
                        auto socks = detectSocks( payload, payloadSize, pkt.srcPort, pkt.dstPort );
                        if ( !socks.empty() ) {
                            pkt.protocol = "SOCKS";
                            oss << " | " << socks;
                        }
                        else {
                            // Port-based protocol hint
                            auto proto = portToProtocol( pkt.srcPort );
                            if ( !proto )
                                proto = portToProtocol( pkt.dstPort );
                            if ( proto )
                                pkt.protocol = proto;

                            // ASCII payload preview for non-empty data
                            auto preview = payloadPreview( payload, payloadSize );
                            if ( !preview.empty() ) {
                                oss << " | " << preview;
                            }
                        }
                    }
                }
            }
        }
        else {
            // No payload — still apply port-based hint if it's a control packet
            auto proto = portToProtocol( pkt.srcPort );
            if ( !proto )
                proto = portToProtocol( pkt.dstPort );
            if ( proto )
                pkt.protocol = proto;
        }

        pkt.info = oss.str();
    }
    else if ( pkt.ipProtocol == IpProtoUdp && remaining >= 8 ) {
        pkt.protocol = "UDP";
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
        auto udpLen = readBE16( data + 4 );
        pkt.payloadLen = ( udpLen > 8 ) ? static_cast<uint32_t>( udpLen - 8 ) : 0;

        const uint8_t* payload = data + 8;
        size_t payloadSize = ( remaining > 8 ) ? remaining - 8 : 0;
        payloadSize = std::min( payloadSize, static_cast<size_t>( pkt.payloadLen ) );

        std::ostringstream oss;
        oss << pkt.srcPort << " \xe2\x86\x92 " << pkt.dstPort << " Len=" << pkt.payloadLen;

        // DNS detection (port 53 or port 5353 for mDNS)
        if ( pkt.srcPort == 53 || pkt.dstPort == 53 || pkt.srcPort == 5353
             || pkt.dstPort == 5353 ) {
            pkt.protocol = ( pkt.srcPort == 5353 || pkt.dstPort == 5353 ) ? "mDNS" : "DNS";
            auto dns = detectDns( payload, payloadSize );
            if ( !dns.empty() ) {
                oss << " " << dns;
            }
        }
        else if ( pkt.dstPort == 1900 || pkt.srcPort == 1900 ) {
            pkt.protocol = "SSDP";
            auto http = detectHttp( payload, payloadSize );
            if ( !http.empty() )
                oss << " | " << http;
        }
        else if ( pkt.dstPort == 123 || pkt.srcPort == 123 ) {
            pkt.protocol = "NTP";
        }
        else if ( pkt.dstPort == 67 || pkt.dstPort == 68 || pkt.srcPort == 67
                  || pkt.srcPort == 68 ) {
            pkt.protocol = "DHCP";
        }
        else {
            // Try NMEA in UDP payload
            auto nmea = detectNmea( payload, payloadSize );
            if ( !nmea.empty() ) {
                pkt.protocol = "NMEA";
                oss << " | " << nmea;
            }
            else {
                auto proto = portToProtocol( pkt.srcPort );
                if ( !proto )
                    proto = portToProtocol( pkt.dstPort );
                if ( proto )
                    pkt.protocol = proto;

                if ( payloadSize > 0 ) {
                    auto preview = payloadPreview( payload, payloadSize );
                    if ( !preview.empty() )
                        oss << " | " << preview;
                }
            }
        }

        pkt.info = oss.str();
    }
    else if ( pkt.ipProtocol == IpProtoIcmp && remaining >= 8 ) {
        pkt.protocol = "ICMP";
        auto type = data[ 0 ];
        auto code = data[ 1 ];

        std::ostringstream oss;
        switch ( type ) {
        case 0:
            oss << "Echo reply";
            break;
        case 3:
            oss << "Destination unreachable (code=" << static_cast<int>( code ) << ")";
            break;
        case 8:
            oss << "Echo request";
            break;
        case 11:
            oss << "Time exceeded";
            break;
        default:
            oss << "Type=" << static_cast<int>( type ) << " Code=" << static_cast<int>( code );
            break;
        }
        pkt.info = oss.str();
    }
    else if ( pkt.ipProtocol == IpProtoIcmpv6 && remaining >= 8 ) {
        pkt.protocol = "ICMPv6";
        auto type = data[ 0 ];

        std::ostringstream oss;
        switch ( type ) {
        case 128:
            oss << "Echo request";
            break;
        case 129:
            oss << "Echo reply";
            break;
        case 133:
            oss << "Router solicitation";
            break;
        case 134:
            oss << "Router advertisement";
            break;
        case 135:
            oss << "Neighbor solicitation";
            break;
        case 136:
            oss << "Neighbor advertisement";
            break;
        default:
            oss << "Type=" << static_cast<int>( type );
            break;
        }
        pkt.info = oss.str();
    }
    else {
        pkt.protocol = "IP(" + std::to_string( pkt.ipProtocol ) + ")";
        pkt.info = "Protocol " + std::to_string( pkt.ipProtocol );
    }
}

// ── Parse IPv4 header ────────────────────────────────────────────────────

void parseIpv4( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    if ( remaining < 20 ) {
        pkt.protocol = "IPv4";
        pkt.info = "Truncated IPv4 header";
        return;
    }

    auto ihl = static_cast<uint8_t>( ( data[ 0 ] & 0x0F ) * 4 );
    if ( ihl < 20 || ihl > remaining ) {
        pkt.protocol = "IPv4";
        pkt.info = "Invalid IHL";
        return;
    }

    pkt.ipTtl = data[ 8 ];
    pkt.ipProtocol = data[ 9 ];
    pkt.srcIp = formatIpv4( data + 12 );
    pkt.dstIp = formatIpv4( data + 16 );

    // Use the IP total length field, not raw remaining bytes, to exclude
    // link-layer padding (e.g. Ethernet FCS, SLL2 trailer).  A total length
    // of 0, or one too small for the header, is what TSO/GSO hands to the
    // capture for outgoing packets: like Wireshark, take the captured bytes.
    size_t totalLen = readBE16( data + 2 );
    if ( totalLen < ihl || totalLen > remaining ) {
        totalLen = remaining;
    }

    parseTransport( pkt, data + ihl, totalLen - ihl );
}

// ── Parse IPv6 header ────────────────────────────────────────────────────

void parseIpv6( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    if ( remaining < 40 ) {
        pkt.protocol = "IPv6";
        pkt.info = "Truncated IPv6 header";
        return;
    }

    pkt.ipProtocol = data[ 6 ];
    pkt.ipTtl = data[ 7 ]; // Hop limit
    pkt.srcIp = formatIpv6( data + 8 );
    pkt.dstIp = formatIpv6( data + 24 );

    // Use the IPv6 payload length field, not raw remaining bytes, to exclude
    // link-layer padding (e.g. Ethernet FCS, SLL2 trailer).
    // A payload length of 0 is a jumbogram, or a TSO/GSO packet captured on
    // its way out: take the captured bytes.
    auto payloadLen = static_cast<size_t>( readBE16( data + 4 ) );
    if ( payloadLen == 0 || payloadLen > remaining - 40 ) {
        payloadLen = remaining - 40;
    }

    parseTransport( pkt, data + 40, payloadLen );
}

// ── Parse ARP ────────────────────────────────────────────────────────────

void parseArp( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    pkt.protocol = "ARP";
    if ( remaining < 28 ) {
        pkt.info = "Truncated ARP";
        return;
    }

    auto opcode = readBE16( data + 6 );
    auto senderIp = formatIpv4( data + 14 );
    auto targetIp = formatIpv4( data + 24 );

    if ( opcode == 1 ) {
        pkt.info = "Who has " + targetIp + "? Tell " + senderIp;
    }
    else if ( opcode == 2 ) {
        pkt.info = senderIp + " is at " + formatMac( data + 8 );
    }
    else {
        pkt.info = "Opcode " + std::to_string( opcode );
    }

    pkt.srcIp = senderIp;
    pkt.dstIp = targetIp;
}

/// Dissect one captured packet of the given link-layer type into @p pkt.
void dissect( PacketRecord& pkt, uint32_t linkType, const uint8_t* pktData, size_t pktRemaining )
{
    uint16_t etherType = 0;
    const uint8_t* networkData = nullptr;
    size_t networkRemaining = 0;

    if ( linkType == DltEthernet && pktRemaining >= 14 ) {
        pkt.dstMac = formatMac( pktData );
        pkt.srcMac = formatMac( pktData + 6 );
        etherType = readBE16( pktData + 12 );
        pkt.etherType = etherType;
        networkData = pktData + 14;
        networkRemaining = pktRemaining - 14;

        // Handle VLAN tag (802.1Q)
        if ( etherType == EthertypeVlan && networkRemaining >= 4 ) {
            etherType = readBE16( networkData + 2 );
            pkt.etherType = etherType;
            networkData += 4;
            networkRemaining -= 4;
        }
    }
    else if ( linkType == DltRaw && pktRemaining >= 1 ) {
        // Raw IP — determine version from first nibble
        auto version = static_cast<uint8_t>( pktData[ 0 ] >> 4 );
        etherType = ( version == 6 ) ? EthertypeIpv6 : EthertypeIpv4;
        pkt.etherType = etherType;
        networkData = pktData;
        networkRemaining = pktRemaining;
    }
    else if ( linkType == DltLinuxSll && pktRemaining >= 16 ) {
        // Linux cooked capture v1: 16-byte header, ethertype at offset 14
        etherType = readBE16( pktData + 14 );
        pkt.etherType = etherType;
        networkData = pktData + 16;
        networkRemaining = pktRemaining - 16;
    }
    else if ( linkType == DltLinuxSll2 && pktRemaining >= 20 ) {
        // Linux cooked capture v2: 20-byte header, ethertype at offset 0
        etherType = readBE16( pktData );
        pkt.etherType = etherType;
        networkData = pktData + 20;
        networkRemaining = pktRemaining - 20;
    }
    else if ( linkType == DltNull && pktRemaining >= 4 ) {
        // BSD loopback: 4-byte family
        uint32_t family = read32( pktData, false );
        etherType = ( family == 2 ) ? EthertypeIpv4 : EthertypeIpv6;
        pkt.etherType = etherType;
        networkData = pktData + 4;
        networkRemaining = pktRemaining - 4;
    }
    else {
        pkt.protocol = "Unknown";
        pkt.info = "Unsupported link-layer type " + std::to_string( linkType );
    }

    // Parse network and transport layers
    if ( networkData ) {
        if ( etherType == EthertypeIpv4 ) {
            parseIpv4( pkt, networkData, networkRemaining );
        }
        else if ( etherType == EthertypeIpv6 ) {
            parseIpv6( pkt, networkData, networkRemaining );
        }
        else if ( etherType == EthertypeArp ) {
            parseArp( pkt, networkData, networkRemaining );
        }
        else {
            char hex[ 8 ];
            std::snprintf( hex, sizeof( hex ), "%04X", etherType );
            pkt.protocol = std::string( "ETH(0x" ) + hex + ")";
            pkt.info = std::string( "EtherType 0x" ) + hex;
        }
    }
}

/// Scan forward to find the pcap magic number.
/// tcpdump via adb often prepends stderr text (e.g. "tcpdump: listening…")
/// before the binary pcap data.  We search the first 4 KB for the magic.
size_t findPcapMagicOffset( const uint8_t* data, size_t size )
{
    for ( size_t i = 0; i + 4 <= size && i <= kMaxPreamble; ++i ) {
        uint32_t candidate;
        std::memcpy( &candidate, data + i, 4 );
        if ( candidate == PcapMagicLE || candidate == PcapMagicBE || candidate == PcapNgMagic ) {
            return i;
        }
    }
    return size; // not found
}

} // anonymous namespace

// ── Byte sources ─────────────────────────────────────────────────────────

bool ByteSource::skip( uint64_t n )
{
    uint8_t scratch[ 4096 ];
    while ( n > 0 ) {
        const auto chunk = static_cast<size_t>( std::min<uint64_t>( n, sizeof( scratch ) ) );
        const auto got = read( scratch, chunk );
        if ( got == 0 ) {
            return false;
        }
        n -= got;
    }
    return true;
}

size_t MemorySource::read( uint8_t* dst, size_t n )
{
    n = std::min( n, size_ - pos_ );
    if ( n > 0 ) {
        std::memcpy( dst, data_ + pos_, n );
        pos_ += n;
    }
    return n;
}

bool MemorySource::skip( uint64_t n )
{
    if ( n > size_ - pos_ ) {
        pos_ = size_;
        return false;
    }
    pos_ += static_cast<size_t>( n );
    return true;
}

// ── PcapReader ───────────────────────────────────────────────────────────

size_t PcapReader::read( uint8_t* dst, size_t n )
{
    size_t got = 0;
    if ( headPos_ < head_.size() ) {
        got = std::min( n, head_.size() - headPos_ );
        std::memcpy( dst, head_.data() + headPos_, got );
        headPos_ += got;
    }
    while ( got < n ) {
        const auto more = source_.read( dst + got, n - got );
        if ( more == 0 ) {
            break;
        }
        got += more;
    }
    bytesRead_ += got;
    return got;
}

bool PcapReader::skip( uint64_t n )
{
    if ( headPos_ < head_.size() ) {
        const auto fromHead
            = static_cast<size_t>( std::min<uint64_t>( n, head_.size() - headPos_ ) );
        headPos_ += fromHead;
        bytesRead_ += fromHead;
        n -= fromHead;
    }
    if ( n == 0 ) {
        return true;
    }
    const bool ok = source_.skip( n );
    bytesRead_ += n; // on failure the source is at its end anyway
    return ok;
}

bool PcapReader::open()
{
    // Read what may hold a text preamble and the global header.
    head_.resize( kMaxPreamble + 4 + 24 );
    size_t filled = 0;
    while ( filled < head_.size() ) {
        const auto got = source_.read( head_.data() + filled, head_.size() - filled );
        if ( got == 0 ) {
            break;
        }
        filled += got;
    }
    head_.resize( filled );

    if ( filled < 24 ) {
        error_ = "File too small to be a valid pcap (< 24 bytes)";
        return false;
    }

    // Try to find pcap magic — may be past a text preamble from tcpdump stderr
    const size_t magicOffset = findPcapMagicOffset( head_.data(), filled );
    if ( magicOffset + 24 > filled ) {
        error_ = "Not a valid pcap file (no pcap magic found)";
        return false;
    }
    const uint8_t* data = head_.data() + magicOffset;

    uint32_t magic;
    std::memcpy( &magic, data, 4 );
    if ( magic == PcapMagicLE ) {
        swap_ = false;
    }
    else if ( magic == PcapMagicBE ) {
        swap_ = true;
    }
    else if ( magic == PcapNgMagic ) {
        error_ = "pcap-ng format is not yet supported";
        return false;
    }
    else {
        error_ = "Not a valid pcap file (unknown magic number)";
        return false;
    }

    header_.magicNumber = magic;
    header_.versionMajor = read16( data + 4, swap_ );
    header_.versionMinor = read16( data + 6, swap_ );
    header_.thiszone = readS32( data + 8, swap_ );
    header_.sigfigs = read32( data + 12, swap_ );
    header_.snaplen = read32( data + 16, swap_ );
    header_.network = read32( data + 20, swap_ );

    headPos_ = magicOffset + 24;
    bytesRead_ = headPos_;
    open_ = true;
    return true;
}

bool PcapReader::next( PacketRecord& pkt )
{
    if ( !open_ ) {
        return false;
    }

    // Packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
    uint8_t recordHeader[ 16 ];
    const auto got = read( recordHeader, sizeof( recordHeader ) );
    if ( got < sizeof( recordHeader ) ) {
        truncated_ = got > 0;
        open_ = false;
        return false;
    }
    const auto tsSec = read32( recordHeader, swap_ );
    const auto tsUsec = read32( recordHeader + 4, swap_ );
    const auto inclLen = read32( recordHeader + 8, swap_ );
    const auto origLen = read32( recordHeader + 12, swap_ );

    // Only the first kMaxDissectedBytes are looked at; the rest is skipped,
    // so that a corrupt huge length costs no memory.
    const auto kept = static_cast<size_t>( std::min<uint32_t>( inclLen, kMaxDissectedBytes ) );
    packet_.resize( kept );
    if ( read( packet_.data(), kept ) < kept || !skip( inclLen - kept ) ) {
        // The file ends inside this record: stop, as the capture was cut off.
        truncated_ = true;
        open_ = false;
        return false;
    }

    pkt = PacketRecord();
    pkt.number = ++packetCount_;
    pkt.timestampSec = tsSec;
    pkt.timestampUsec = tsUsec;
    pkt.capturedLen = inclLen;
    pkt.originalLen = origLen;
    dissect( pkt, header_.network, packet_.data(), kept );
    return true;
}

// ── Whole-buffer convenience ─────────────────────────────────────────────

ParseResult parsePcap( const uint8_t* data, size_t size )
{
    ParseResult result;
    MemorySource source( data, size );
    PcapReader reader( source );
    if ( !reader.open() ) {
        result.error = reader.error();
        return result;
    }
    result.header = reader.header();

    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        result.packets.push_back( std::move( pkt ) );
    }
    result.truncated = reader.truncated();
    result.ok = true;
    return result;
}

} // namespace tcpdump
