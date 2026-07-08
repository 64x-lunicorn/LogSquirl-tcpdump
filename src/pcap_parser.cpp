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
#include <cstring>
#include <fstream>
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
        v = ( ( v >> 24 ) & 0xFF ) | ( ( v >> 8 ) & 0xFF00 )
            | ( ( v << 8 ) & 0xFF0000 ) | ( ( v << 24 ) & 0xFF000000 );
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
    return ( static_cast<uint32_t>( p[ 0 ] ) << 24 )
           | ( static_cast<uint32_t>( p[ 1 ] ) << 16 )
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
    std::snprintf( buf, sizeof( buf ), "%x:%x:%x:%x:%x:%x:%x:%x",
                   readBE16( p ), readBE16( p + 2 ), readBE16( p + 4 ), readBE16( p + 6 ),
                   readBE16( p + 8 ), readBE16( p + 10 ), readBE16( p + 12 ),
                   readBE16( p + 14 ) );
    return buf;
}

// ── TCP flags as info string ─────────────────────────────────────────────

std::string tcpFlagStr( uint8_t flags )
{
    std::string result = "[";
    bool first = true;
    auto add = [&]( const char* name ) {
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

/// Detect HTTP request or response from payload start.
std::string detectHttp( const uint8_t* payload, size_t len )
{
    if ( len < 4 )
        return {};

    // HTTP methods
    auto startsWith = [&]( const char* prefix ) {
        auto pLen = std::strlen( prefix );
        return len >= pLen && std::memcmp( payload, prefix, pLen ) == 0;
    };

    if ( startsWith( "GET " ) || startsWith( "POST " ) || startsWith( "PUT " )
         || startsWith( "DELETE " ) || startsWith( "HEAD " ) || startsWith( "PATCH " )
         || startsWith( "OPTIONS " ) || startsWith( "CONNECT " ) ) {
        // Extract the request line (up to \r\n or end)
        std::string line;
        for ( size_t i = 0; i < len && i < 120; ++i ) {
            if ( payload[ i ] == '\r' || payload[ i ] == '\n' )
                break;
            line += static_cast<char>( payload[ i ] );
        }
        return line;
    }

    if ( startsWith( "HTTP/" ) ) {
        // Response status line
        std::string line;
        for ( size_t i = 0; i < len && i < 120; ++i ) {
            if ( payload[ i ] == '\r' || payload[ i ] == '\n' )
                break;
            line += static_cast<char>( payload[ i ] );
        }
        return line;
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
        qname.append( reinterpret_cast<const char*>( payload + offset + 1 ), labelLen );
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

/// Build ASCII preview of payload, skipping leading binary bytes.
/// Starts from the first printable run of >= 3 chars (to skip binary headers).
/// Non-printable runs are collapsed to a single space instead of dots.
/// Returns empty if the payload is predominantly binary.
std::string payloadPreview( const uint8_t* payload, size_t len )
{
    // Find the first interesting printable run (skip binary protocol headers)
    size_t start = 0;
    bool foundStart = false;
    for ( size_t i = 0; i + 2 < len; ++i ) {
        if ( payload[ i ] >= 0x20 && payload[ i ] < 0x7F && payload[ i + 1 ] >= 0x20
             && payload[ i + 1 ] < 0x7F && payload[ i + 2 ] >= 0x20
             && payload[ i + 2 ] < 0x7F ) {
            start = i;
            foundStart = true;
            break;
        }
        if ( i > 128 )
            return {}; // too much binary, give up
    }
    if ( !foundStart )
        return {};

    std::string preview;
    size_t printableCount = 0;
    bool inBinaryRun = false;

    for ( size_t i = start; i < len; ++i ) {
        auto c = payload[ i ];
        if ( c >= 0x20 && c < 0x7F ) {
            inBinaryRun = false;
            preview += static_cast<char>( c );
            printableCount++;
        }
        else if ( c == '\r' || c == '\n' ) {
            if ( !inBinaryRun ) {
                preview += ' ';
                inBinaryRun = true;
            }
        }
        else {
            // Non-printable byte — collapse consecutive ones to a single space
            if ( !inBinaryRun ) {
                preview += ' ';
                inBinaryRun = true;
            }
        }
    }

    // Skip if less than 40% printable (too binary to be useful)
    if ( printableCount == 0
         || static_cast<double>( printableCount ) / ( len - start ) < 0.4 ) {
        return {};
    }

    // Trim trailing whitespace
    while ( !preview.empty() && preview.back() == ' ' ) {
        preview.pop_back();
    }

    return preview;
}

/// Detect NMEA 0183 sentences in payload (GPS: $GPGGA, $GNGSA, $GPGSV, etc.)
/// Requires the mandatory comma after the 5-char sentence ID to avoid false
/// positives on ADB protocol frames like $WRTE which also match $ + 5 alpha.
std::string detectNmea( const uint8_t* payload, size_t len )
{
    // Scan for '$' + 5 alpha chars + ',' (NMEA 0183 mandatory format)
    for ( size_t i = 0; i + 7 < len; ++i ) {
        if ( payload[ i ] == '$' && std::isalpha( payload[ i + 1 ] )
             && std::isalpha( payload[ i + 2 ] ) && std::isalpha( payload[ i + 3 ] )
             && std::isalpha( payload[ i + 4 ] ) && std::isalpha( payload[ i + 5 ] )
             && payload[ i + 6 ] == ',' ) {
            // Found an NMEA sentence — extract until '*' checksum or CR/LF
            std::string sentence;
            for ( size_t j = i; j < len && j < i + 120; ++j ) {
                auto c = payload[ j ];
                if ( c == '\r' || c == '\n' ) {
                    break;
                }
                sentence += static_cast<char>( c );
            }
            return sentence;
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
        if ( pkt.srcPort == 53 || pkt.dstPort == 53
             || pkt.srcPort == 5353 || pkt.dstPort == 5353 ) {
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
        else if ( pkt.dstPort == 67 || pkt.dstPort == 68
                  || pkt.srcPort == 67 || pkt.srcPort == 68 ) {
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

    parseTransport( pkt, data + ihl, remaining - ihl );
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

    parseTransport( pkt, data + 40, remaining - 40 );
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

} // anonymous namespace

// ── Public API ───────────────────────────────────────────────────────────

/// Scan forward to find the pcap magic number.
/// tcpdump via adb often prepends stderr text (e.g. "tcpdump: listening…")
/// before the binary pcap data.  We search the first 4 KB for the magic.
static size_t findPcapMagicOffset( const uint8_t* data, size_t size )
{
    constexpr size_t kMaxScan = 4096;
    const size_t limit = std::min( size - 4, kMaxScan );
    for ( size_t i = 0; i + 4 <= size && i <= limit; ++i ) {
        uint32_t candidate;
        std::memcpy( &candidate, data + i, 4 );
        if ( candidate == PcapMagicLE || candidate == PcapMagicBE
             || candidate == PcapNgMagic ) {
            return i;
        }
    }
    return size; // not found
}

ParseResult parsePcap( const uint8_t* data, size_t size )
{
    ParseResult result;

    if ( size < 24 ) {
        result.error = "File too small to be a valid pcap (< 24 bytes)";
        return result;
    }

    // Try to find pcap magic — may be past a text preamble from tcpdump stderr
    size_t magicOffset = findPcapMagicOffset( data, size );
    if ( magicOffset + 24 > size ) {
        result.error = "Not a valid pcap file (no pcap magic found)";
        return result;
    }

    // Adjust data pointer past preamble
    data += magicOffset;
    size -= magicOffset;

    uint32_t magic;
    std::memcpy( &magic, data, 4 );

    bool swap = false;
    if ( magic == PcapMagicLE ) {
        swap = false;
    }
    else if ( magic == PcapMagicBE ) {
        swap = true;
    }
    else if ( magic == PcapNgMagic ) {
        result.error = "pcap-ng format is not yet supported";
        return result;
    }
    else {
        result.error = "Not a valid pcap file (unknown magic number)";
        return result;
    }

    // Parse global header
    auto& hdr = result.header;
    hdr.magicNumber = magic;
    hdr.versionMajor = read16( data + 4, swap );
    hdr.versionMinor = read16( data + 6, swap );
    hdr.thiszone = readS32( data + 8, swap );
    hdr.sigfigs = read32( data + 12, swap );
    hdr.snaplen = read32( data + 16, swap );
    hdr.network = read32( data + 20, swap );

    // Walk packet records
    size_t offset = 24;
    uint32_t pktNum = 0;

    while ( offset + 16 <= size ) {
        // Packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        auto tsSec = read32( data + offset, swap );
        auto tsUsec = read32( data + offset + 4, swap );
        auto inclLen = read32( data + offset + 8, swap );
        auto origLen = read32( data + offset + 12, swap );

        offset += 16;

        // Sanity check: captured length must not exceed remaining data
        if ( inclLen > size - offset ) {
            break; // Truncated file — stop parsing
        }

        pktNum++;
        PacketRecord pkt;
        pkt.number = pktNum;
        pkt.timestampSec = tsSec;
        pkt.timestampUsec = tsUsec;
        pkt.capturedLen = inclLen;
        pkt.originalLen = origLen;

        // Store raw packet data
        pkt.rawData.assign( data + offset, data + offset + inclLen );

        const uint8_t* pktData = data + offset;
        size_t pktRemaining = inclLen;

        // Parse based on link-layer type
        uint16_t etherType = 0;
        const uint8_t* networkData = nullptr;
        size_t networkRemaining = 0;

        if ( hdr.network == DltEthernet && pktRemaining >= 14 ) {
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
        else if ( hdr.network == DltRaw && pktRemaining >= 1 ) {
            // Raw IP — determine version from first nibble
            auto version = static_cast<uint8_t>( pktData[ 0 ] >> 4 );
            etherType = ( version == 6 ) ? EthertypeIpv6 : EthertypeIpv4;
            pkt.etherType = etherType;
            networkData = pktData;
            networkRemaining = pktRemaining;
        }
        else if ( hdr.network == DltLinuxSll && pktRemaining >= 16 ) {
            // Linux cooked capture v1: 16-byte header, ethertype at offset 14
            etherType = readBE16( pktData + 14 );
            pkt.etherType = etherType;
            networkData = pktData + 16;
            networkRemaining = pktRemaining - 16;
        }
        else if ( hdr.network == DltLinuxSll2 && pktRemaining >= 20 ) {
            // Linux cooked capture v2: 20-byte header, ethertype at offset 0
            etherType = readBE16( pktData );
            pkt.etherType = etherType;
            networkData = pktData + 20;
            networkRemaining = pktRemaining - 20;
        }
        else if ( hdr.network == DltNull && pktRemaining >= 4 ) {
            // BSD loopback: 4-byte family
            uint32_t family = read32( pktData, false );
            etherType = ( family == 2 ) ? EthertypeIpv4 : EthertypeIpv6;
            pkt.etherType = etherType;
            networkData = pktData + 4;
            networkRemaining = pktRemaining - 4;
        }
        else {
            pkt.protocol = "Unknown";
            pkt.info = "Unsupported link-layer type " + std::to_string( hdr.network );
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
                pkt.protocol = "ETH(0x" + ([&] {
                    char b[ 5 ];
                    std::snprintf( b, sizeof( b ), "%04X", etherType );
                    return std::string( b );
                })() + ")";
                pkt.info = "EtherType 0x" + ([&] {
                    char b[ 5 ];
                    std::snprintf( b, sizeof( b ), "%04X", etherType );
                    return std::string( b );
                })();
            }
        }

        result.packets.push_back( std::move( pkt ) );
        offset += inclLen;
    }

    result.ok = true;
    return result;
}

ParseResult parsePcapFile( const std::string& filePath )
{
    std::ifstream file( filePath, std::ios::binary | std::ios::ate );
    if ( !file.is_open() ) {
        ParseResult result;
        result.error = "Cannot open file: " + filePath;
        return result;
    }

    auto fileSize = static_cast<size_t>( file.tellg() );
    file.seekg( 0, std::ios::beg );

    std::vector<uint8_t> buffer( fileSize );
    if ( !file.read( reinterpret_cast<char*>( buffer.data() ),
                     static_cast<std::streamsize>( fileSize ) ) ) {
        ParseResult result;
        result.error = "Failed to read file: " + filePath;
        return result;
    }

    return parsePcap( buffer.data(), buffer.size() );
}

} // namespace tcpdump
