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

#include "payload_describer.h"
#include "wire_bytes.h"

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

// ── MAC address formatting ───────────────────────────────────────────────

std::string formatMac( const uint8_t* p )
{
    char buf[ 18 ];
    std::snprintf( buf, sizeof( buf ), "%02x:%02x:%02x:%02x:%02x:%02x", p[ 0 ], p[ 1 ], p[ 2 ],
                   p[ 3 ], p[ 4 ], p[ 5 ] );
    return buf;
}

// ── Parse transport layer (TCP / UDP / ICMP) ─────────────────────────────

/// Separates the transport summary from the description of the payload.
constexpr const char* kDescriptionSeparator = " | ";

/// Ask the describer what the @p len captured payload bytes are: its label
/// becomes the packet's protocol, its description follows the transport
/// summary in @p oss.
void describePayloadOf( PacketRecord& pkt, std::ostringstream& oss, Transport transport,
                        const uint8_t* payload, size_t len )
{
    const auto described = describePayload( transport, payload, len, pkt.srcPort, pkt.dstPort );
    if ( !described.label.empty() ) {
        pkt.protocol = described.label;
    }
    if ( !described.description.empty() ) {
        oss << kDescriptionSeparator << described.description;
    }
}

/// Parse the transport layer from the @p remaining captured bytes at
/// @p data.  @p wireLen is its length on the wire according to the IP
/// header, more than @p remaining if the capture was cut at the snaplen.
void parseTransport( PacketRecord& pkt, const uint8_t* data, size_t remaining, size_t wireLen )
{
    wireLen = std::max( wireLen, remaining );
    if ( pkt.ipProtocol == IpProtoTcp && remaining >= 20 ) {
        pkt.protocol = "TCP";
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
        pkt.tcpSeq = readBE32( data + 4 );
        pkt.tcpAck = readBE32( data + 8 );
        pkt.tcpFlags = data[ 13 ];
        pkt.tcpWindow = readBE16( data + 14 );

        const auto dataOffset = static_cast<size_t>( data[ 12 ] >> 4 ) * 4;

        // Build base TCP info line
        std::ostringstream oss;
        oss << pkt.srcPort << " \xe2\x86\x92 " << pkt.dstPort << " "
            << formatTcpFlags( pkt.tcpFlags ) << " Seq=" << pkt.tcpSeq << " Ack=" << pkt.tcpAck
            << " Win=" << pkt.tcpWindow;

        // A header shorter than its 20 fixed bytes is malformed: where the
        // payload starts is unknown, so none is taken, like Wireshark.
        if ( dataOffset < 20 ) {
            oss << " [bogus TCP header length (" << dataOffset << ", must be at least 20)]";
            pkt.info = oss.str();
            return;
        }

        // Len is the payload on the wire, as Wireshark shows it; only the
        // captured part of it can be looked at.
        const size_t payloadSize = ( dataOffset <= remaining ) ? remaining - dataOffset : 0;
        pkt.payloadLen = static_cast<uint32_t>( wireLen >= dataOffset ? wireLen - dataOffset : 0 );
        if ( pkt.payloadLen > 0 ) {
            oss << " Len=" << pkt.payloadLen;
        }

        describePayloadOf( pkt, oss, Transport::Tcp, data + std::min( dataOffset, remaining ),
                           payloadSize );
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

        describePayloadOf( pkt, oss, Transport::Udp, payload, payloadSize );
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

// ── IP fragments ─────────────────────────────────────────────────────────

/// Describe a fragment after the first, which holds no transport header.
void describeFragment( PacketRecord& pkt, const char* ipVersion, uint8_t protocol, size_t offset,
                       uint32_t id, int idBytes )
{
    char idHex[ 16 ];
    std::snprintf( idHex, sizeof( idHex ), "0x%0*X", idBytes * 2, id );
    pkt.protocol = ipVersion;
    pkt.info = "Fragment of IP protocol " + std::to_string( protocol ) + " (offset "
               + std::to_string( offset ) + ", ID " + idHex + ")";
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
    // A total length beyond the captured bytes is a capture cut at the
    // snaplen: the lengths shown still come from the header.
    size_t totalLen = readBE16( data + 2 );
    if ( totalLen < ihl ) {
        totalLen = remaining;
    }
    const size_t capturedLen = std::min( totalLen, remaining );

    // Only the first fragment starts with the transport header; the data
    // of a later one merely continues it.
    const auto fragmentOffset = static_cast<size_t>( readBE16( data + 6 ) & 0x1FFF ) * 8;
    if ( fragmentOffset != 0 ) {
        describeFragment( pkt, "IPv4", pkt.ipProtocol, fragmentOffset, readBE16( data + 4 ), 2 );
        return;
    }

    parseTransport( pkt, data + ihl, capturedLen - ihl, totalLen - ihl );
}

// ── Parse IPv6 header ────────────────────────────────────────────────────

void parseIpv6( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    if ( remaining < 40 ) {
        pkt.protocol = "IPv6";
        pkt.info = "Truncated IPv6 header";
        return;
    }

    pkt.ipTtl = data[ 7 ]; // Hop limit
    pkt.srcIp = formatIpv6( data + 8 );
    pkt.dstIp = formatIpv6( data + 24 );

    // Use the IPv6 payload length field, not raw remaining bytes, to exclude
    // link-layer padding (e.g. Ethernet FCS, SLL2 trailer).  A payload
    // length of 0 is a jumbogram, or a TSO/GSO packet captured on its way
    // out: take the captured bytes.  One beyond the captured bytes is a
    // capture cut at the snaplen: the lengths shown still come from it.
    auto payloadLen = static_cast<size_t>( readBE16( data + 4 ) );
    if ( payloadLen == 0 ) {
        payloadLen = remaining - 40;
    }
    const size_t wireEnd = 40 + payloadLen;
    const size_t end = std::min( wireEnd, remaining );

    // Walk the extension headers to the upper-layer protocol.  Each one is
    // checked against the end of the packet before it is read.
    uint8_t next = data[ 6 ];
    size_t offset = 40;
    for ( int headers = 0; headers < 16; ++headers ) {
        size_t length = 0;
        switch ( next ) {
        case 0:  // Hop-by-hop options
        case 43: // Routing
        case 60: // Destination options
            if ( end - offset >= 2 ) {
                length = ( static_cast<size_t>( data[ offset + 1 ] ) + 1 ) * 8;
            }
            break;
        case 51: // Authentication header: length in 32-bit words, minus 2
            if ( end - offset >= 2 ) {
                length = ( static_cast<size_t>( data[ offset + 1 ] ) + 2 ) * 4;
            }
            break;
        case 44: // Fragment
            length = 8;
            break;
        default: // The upper-layer protocol, or one this parser does not walk
            pkt.ipProtocol = next;
            parseTransport( pkt, data + offset, end - offset, wireEnd - offset );
            return;
        }

        if ( length == 0 || length > end - offset ) {
            pkt.ipProtocol = next;
            pkt.protocol = "IPv6";
            pkt.info = "Truncated IPv6 extension header " + std::to_string( next );
            return;
        }
        const auto* header = data + offset;
        const auto headerType = next;
        next = header[ 0 ];
        offset += length;

        if ( headerType == 44 ) {
            // Only the first fragment starts with the upper-layer header.
            const auto fragmentOffset = static_cast<size_t>( readBE16( header + 2 ) >> 3 ) * 8;
            if ( fragmentOffset != 0 ) {
                pkt.ipProtocol = next;
                describeFragment( pkt, "IPv6", next, fragmentOffset, readBE32( header + 4 ), 4 );
                return;
            }
        }
    }

    pkt.ipProtocol = next;
    pkt.protocol = "IPv6";
    pkt.info = "Too many IPv6 extension headers";
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
/// @p swap: the file is in the other byte order than this host.
void dissect( PacketRecord& pkt, uint32_t linkType, bool swap, const uint8_t* pktData,
              size_t pktRemaining )
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
    else if ( ( linkType == DltNull || linkType == DltLoop ) && pktRemaining >= 4 ) {
        // BSD loopback: a 4-byte address family, in the byte order of the
        // capturing host (DLT_NULL), which the file was written in, or in
        // network byte order (DLT_LOOP).  Families are small numbers, so one
        // that only fits in the upper half is in the other byte order, as
        // Wireshark also assumes.
        uint32_t family = linkType == DltLoop ? readBE32( pktData ) : read32( pktData, swap );
        if ( ( family & 0xFFFF0000 ) != 0 ) {
            family = read32( reinterpret_cast<const uint8_t*>( &family ), true );
        }
        networkData = pktData + 4;
        networkRemaining = pktRemaining - 4;
        switch ( family ) {
        case 2: // AF_INET
            etherType = EthertypeIpv4;
            break;
        case 10: // AF_INET6: Linux
        case 23: // Windows
        case 24: // NetBSD, OpenBSD, BSD/OS
        case 28: // FreeBSD, DragonFly BSD
        case 30: // macOS, iOS
            etherType = EthertypeIpv6;
            break;
        default:
            networkData = nullptr;
            pkt.protocol = "Loopback";
            pkt.info = "Address family " + std::to_string( family );
            break;
        }
        pkt.etherType = etherType;
    }
    else {
        pkt.protocol = "Unknown";
        pkt.info = "Unsupported link-layer type " + std::to_string( linkType );
    }

    // Strip VLAN tags: 802.1Q, and 802.1ad (QinQ) service tags stacked
    // around it.  Each tag is 2 bytes of tag control, then the EtherType of
    // what follows.
    for ( int tags = 0; networkData && tags < 8 && networkRemaining >= 4
                        && ( etherType == EthertypeVlan || etherType == EthertypeQinQ
                             || etherType == EthertypeQinQLegacy );
          ++tags ) {
        etherType = readBE16( networkData + 2 );
        pkt.etherType = etherType;
        networkData += 4;
        networkRemaining -= 4;
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

bool isPcapMagic( uint32_t magic )
{
    return magic == PcapMagicLE || magic == PcapMagicBE || magic == PcapNsMagicLE
           || magic == PcapNsMagicBE;
}

/// A byte of the text tcpdump writes to stderr.
bool isPreambleText( uint8_t c )
{
    return ( c >= 0x20 && c < 0x7F ) || c == '\t' || c == '\r' || c == '\n';
}

/// Whether the 24 bytes at @p p hold a pcap global header this parser reads:
/// a pcap magic and format version 2.x, x <= 4 (all libpcap ever wrote).
bool isPcapHeader( const uint8_t* p )
{
    uint32_t magic;
    std::memcpy( &magic, p, 4 );
    if ( !isPcapMagic( magic ) ) {
        return false;
    }
    const bool swap = magic == PcapMagicBE || magic == PcapNsMagicBE;
    return read16( p + 4, swap ) == 2 && read16( p + 6, swap ) <= 4;
}

/// Whether @p p (at least 12 bytes) starts a pcap-ng section header block.
bool isPcapNgHeader( const uint8_t* p )
{
    uint32_t magic;
    uint32_t byteOrder;
    std::memcpy( &magic, p, 4 );
    std::memcpy( &byteOrder, p + 8, 4 );
    return magic == PcapNgMagic && ( byteOrder == 0x1A2B3C4D || byteOrder == 0x4D3C2B1A );
}

/**
 * Find the pcap global header in the first bytes of a file.
 *
 * tcpdump run through adb (`adb exec-out tcpdump -w -`) mixes its stderr,
 * e.g. "tcpdump: listening on …", into the output ahead of the capture.
 * The header is therefore looked for behind up to kMaxPreamble bytes of
 * text.  Past offset 0 it is only accepted when everything before it is
 * text and it is a valid pcap header, not merely the 4 magic bytes: a
 * stray magic in binary data, or in the text, must not be taken for a
 * capture.  At offset 0 the magic decides, so that an unsupported version
 * is reported as such.
 *
 * @return The offset of the header, or @p size if there is none; @p error
 *         then says why.
 */
size_t findPcapHeader( const uint8_t* data, size_t size, std::string& error )
{
    for ( size_t i = 0; i + 24 <= size && i <= kMaxPreamble; ++i ) {
        uint32_t magic;
        std::memcpy( &magic, data + i, 4 );
        if ( i == 0 && isPcapMagic( magic ) ) {
            return 0;
        }
        if ( ( i == 0 && magic == PcapNgMagic ) || isPcapNgHeader( data + i ) ) {
            error = "pcap-ng format is not yet supported";
            return size;
        }
        if ( isPcapHeader( data + i ) ) {
            return i;
        }
        if ( !isPreambleText( data[ i ] ) ) {
            break; // binary data that is no pcap header: no text preamble
        }
    }
    error = "Not a valid pcap file (no pcap magic found)";
    return size;
}

} // anonymous namespace

// ── Link-layer types ─────────────────────────────────────────────────────

std::string linkTypeName( uint32_t linkType )
{
    switch ( linkType ) {
    case DltNull:
        return "BSD Loopback";
    case DltEthernet:
        return "Ethernet";
    case DltRaw:
        return "Raw IP";
    case DltLoop:
        return "OpenBSD Loopback";
    case DltLinuxSll:
        return "Linux SLL";
    case DltLinuxSll2:
        return "Linux SLL2";
    default:
        return std::to_string( linkType );
    }
}

// ── TCP flags ────────────────────────────────────────────────────────────

std::string formatTcpFlags( uint8_t flags )
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
    if ( first )
        result += "none";
    result += "]";
    return result;
}

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
    // An empty record reads into a buffer whose data() may be null, and
    // memcpy() must not be given a null pointer even for 0 bytes.
    if ( n == 0 ) {
        return 0;
    }
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
    head_.resize( kMaxPreamble + 24 );
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

    // Find the header — may be past a text preamble from tcpdump stderr
    const size_t headerOffset = findPcapHeader( head_.data(), filled, error_ );
    if ( headerOffset == filled ) {
        return false;
    }
    const uint8_t* data = head_.data() + headerOffset;

    uint32_t magic;
    std::memcpy( &magic, data, 4 );
    swap_ = magic == PcapMagicBE || magic == PcapNsMagicBE;

    header_.magicNumber = magic;
    header_.versionMajor = read16( data + 4, swap_ );
    header_.versionMinor = read16( data + 6, swap_ );
    header_.thiszone = readS32( data + 8, swap_ );
    header_.sigfigs = read32( data + 12, swap_ );
    header_.snaplen = read32( data + 16, swap_ );
    header_.network = read32( data + 20, swap_ );
    header_.nanoseconds = magic == PcapNsMagicLE || magic == PcapNsMagicBE;
    if ( header_.versionMajor != 2 || header_.versionMinor > 4 ) {
        error_ = "Unsupported pcap format version " + std::to_string( header_.versionMajor ) + "."
                 + std::to_string( header_.versionMinor );
        return false;
    }

    headPos_ = headerOffset + 24;
    bytesRead_ = headPos_;
    open_ = true;
    headerRead_ = true;
    return true;
}

std::vector<uint32_t> PcapReader::linkTypes() const
{
    if ( !headerRead_ ) {
        return {};
    }
    return { header_.network };
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
    const auto tsFraction = read32( recordHeader + 4, swap_ );
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
    // The fraction is kept in nanoseconds.  A corrupt one of a second or
    // more is carried into the seconds.
    const uint64_t fractionNs
        = header_.nanoseconds ? tsFraction : static_cast<uint64_t>( tsFraction ) * 1000;
    pkt.timestampSec = tsSec + static_cast<uint32_t>( fractionNs / 1000000000 );
    pkt.timestampNsec = static_cast<uint32_t>( fractionNs % 1000000000 );
    pkt.capturedLen = inclLen;
    pkt.originalLen = origLen;
    pkt.linkType = header_.network;
    pkt.precision = precision();
    dissect( pkt, pkt.linkType, swap_, packet_.data(), kept );
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
