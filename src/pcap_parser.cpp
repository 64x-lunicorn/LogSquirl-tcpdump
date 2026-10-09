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
 * Parses pcap (libpcap) files, and the packets of any capture, with
 * Ethernet, Raw IP, Linux cooked capture and BSD loopback link layers, and
 * those of link_layers.h (802.11, PPP, Cisco HDLC, PPPoE).
 * Extracts IPv4/IPv6, TCP, UDP, ICMP, and ARP protocol fields from each
 * packet, unwrapping VXLAN, GRE and IP-in-IP tunnels to the packet inside.
 */

#include "pcap_parser.h"

#include "icmp.h"
#include "link_layers.h"
#include "packet_layers.h"
#include "payload_describer.h"
#include "protocol_names.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

namespace tcpdump {

namespace {

/// The bytes dissectPacket() is dissecting on this thread, from which the
/// payload's offset is taken (PacketRecord::payloadOffset); empty outside it.
thread_local ByteView tDissected;

/// Sets tDissected for the time a packet is dissected.
class Dissecting {
public:
    Dissecting( const uint8_t* data, size_t len )
    {
        tDissected = { data, len };
    }
    ~Dissecting()
    {
        tDissected = {};
    }
    Dissecting( const Dissecting& ) = delete;
    Dissecting& operator=( const Dissecting& ) = delete;
};

// ── Byte-order helpers ───────────────────────────────────────────────────

/// Read a int32 in the file's byte order.
int32_t readS32( const uint8_t* p, bool swap )
{
    uint32_t u = read32( p, swap );
    int32_t result;
    std::memcpy( &result, &u, 4 );
    return result;
}

/// The largest value of an Ethernet type field that is the length of an
/// IEEE 802.3 frame rather than an EtherType.
constexpr uint16_t kMax8023Length = 1500;

// ── Parse transport layer (TCP / UDP / ICMP) ─────────────────────────────

/// Ask the describer what the @p len captured payload bytes are: its label
/// becomes the packet's protocol, its description follows the transport
/// summary in @p oss.  The first bytes are kept in @p pkt for when its
/// stream is known.
void describePayloadOf( PacketRecord& pkt, std::ostringstream& oss, Transport transport,
                        const uint8_t* payload, size_t len )
{
    pkt.payloadHeadLen = std::min( len, kPayloadHeadBytes );
    std::copy_n( payload, pkt.payloadHeadLen, pkt.payloadHead.begin() );
    const auto at = reinterpret_cast<uintptr_t>( payload );
    const auto begin = reinterpret_cast<uintptr_t>( tDissected.data );
    if ( tDissected.data != nullptr && at >= begin && at - begin <= tDissected.size
         && len <= tDissected.size - ( at - begin ) ) {
        pkt.payloadOffset = static_cast<uint32_t>( at - begin );
        pkt.payloadCaptured = static_cast<uint32_t>( len );
    }
    auto described = describePayload( transport, payload, len, pkt.srcPort, pkt.dstPort );
    if ( !described.label.empty() ) {
        pkt.protocol = described.label;
    }
    pkt.protocolRecognised = !described.label.empty() && !described.guessed;
    pkt.streamCue = described.streamCue;
    pkt.sipCalls = std::move( described.sipCalls );
    if ( !described.description.empty() ) {
        oss << kDescriptionSeparator << described.description;
        pkt.previewBytes = described.preview ? described.description.size() : 0;
    }
    if ( auto* layers = pkt.layers; layers && len > 0 ) {
        layers->layer( described.label.empty() ? "Data" : described.label, payload, len );
        if ( !described.description.empty() ) {
            layers->field( "Description", described.description, payload, len );
        }
        layers->field( "Length", std::to_string( len ) + " bytes", nullptr, 0 );
    }
}

/// A layer of the @p len bytes at @p data that no dissector reads further.
void dataLayer( PacketRecord& pkt, const uint8_t* data, size_t len, const char* name = "Data" )
{
    if ( auto* layers = pkt.layers; layers && len > 0 ) {
        layers->layer( name, data, len );
        layers->field( "Length", std::to_string( len ) + " bytes", nullptr, 0 );
    }
}

// ── Tunnels (defined below the network layer they unwrap to) ─────────────

void parseIpInIp( PacketRecord& pkt, const char* network, const uint8_t* data, size_t remaining );
void parseGre( PacketRecord& pkt, const uint8_t* data, size_t remaining );
void parseVxlan( PacketRecord& pkt, const uint8_t* data, size_t remaining );

/// The transport layer of a packet quoted in an ICMP error: its protocol's
/// name and the ports of a TCP or UDP header, the first 4 of the 8 bytes a
/// router quotes.  Nothing else of it is read.
void parseQuotedTransport( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    pkt.protocol = ipProtocolLabel( pkt.ipProtocol );
    if ( ( pkt.ipProtocol == IpProtoTcp || pkt.ipProtocol == IpProtoUdp ) && remaining >= 4 ) {
        pkt.transport = pkt.ipProtocol == IpProtoTcp ? Transport::Tcp : Transport::Udp;
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
    }
}

/// Parse the transport layer from the @p remaining captured bytes at
/// @p data, carried by @p network ("IPv4" or "IPv6").  @p wireLen is its
/// length on the wire according to the IP header, more than @p remaining
/// if the capture was cut at the snaplen.  Of a @p quoted packet, only
/// protocol and ports are read (parseQuotedTransport), and no tunnel is
/// unwrapped.
void parseTransport( PacketRecord& pkt, const char* network, const uint8_t* data, size_t remaining,
                     size_t wireLen, bool quoted )
{
    if ( quoted ) {
        parseQuotedTransport( pkt, data, remaining );
        return;
    }
    wireLen = std::max( wireLen, remaining );
    if ( pkt.ipProtocol == IpProtoTcp && remaining >= 20 ) {
        pkt.protocol = "TCP";
        pkt.transport = Transport::Tcp;
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
        pkt.tcpSeq = readBE32( data + 4 );
        pkt.tcpAck = readBE32( data + 8 );
        pkt.tcpFlags = data[ 13 ];
        pkt.tcpWindow = readBE16( data + 14 );

        const auto dataOffset = static_cast<size_t>( data[ 12 ] >> 4 ) * 4;
        pkt.tcpHeaderLen = static_cast<uint8_t>( dataOffset );
        if ( auto* layers = pkt.layers ) {
            layers->layer( "Transmission Control Protocol", data,
                           std::max<size_t>( dataOffset, 20 ) );
            layers->field( "Source Port", std::to_string( pkt.srcPort ), data, 2 );
            layers->field( "Destination Port", std::to_string( pkt.dstPort ), data + 2, 2 );
            layers->field( "Sequence Number", std::to_string( pkt.tcpSeq ), data + 4, 4 );
            layers->field( "Acknowledgment Number", std::to_string( pkt.tcpAck ), data + 8, 4 );
            layers->field( "Header Length", std::to_string( dataOffset ) + " bytes", data + 12, 1 );
            layers->field( "Flags",
                           hexField( readBE16( data + 12 ) & 0x0FFF, 3 ) + " "
                               + formatTcpFlags( pkt.tcpFlags ),
                           data + 12, 2 );
            layers->field( "Window", std::to_string( pkt.tcpWindow ), data + 14, 2 );
            layers->field( "Checksum", hexField( readBE16( data + 16 ), 4 ), data + 16, 2 );
            layers->field( "Urgent Pointer", std::to_string( readBE16( data + 18 ) ), data + 18,
                           2 );
            if ( dataOffset > 20 ) {
                layers->field( "Options", std::to_string( dataOffset - 20 ) + " bytes", data + 20,
                               dataOffset - 20 );
            }
        }

        // Build base TCP info line
        std::ostringstream oss;
        oss << pkt.srcPort << " \xe2\x86\x92 " << pkt.dstPort << " "
            << formatTcpFlags( pkt.tcpFlags ) << " "
            << formatTcpNumbers( pkt.tcpSeq,
                                 ( pkt.tcpFlags & 0x10 ) ? std::optional<uint32_t>( pkt.tcpAck )
                                                         : std::nullopt,
                                 pkt.tcpWindow );

        // A header shorter than its 20 fixed bytes is malformed: where the
        // payload starts is unknown, so none is taken, like Wireshark.
        if ( dataOffset < 20 ) {
            oss << " [bogus TCP header length (" << dataOffset << ", must be at least 20)]";
            pkt.info = oss.str();
            return;
        }

        const auto options = parseTcpOptions( data + 20, std::min( dataOffset, remaining ) - 20 );
        pkt.tcpWindowShift = options.windowShift;
        pkt.tcpTimestamps = options.timestamps;

        // Len is the payload on the wire, as Wireshark shows it; only the
        // captured part of it can be looked at.
        const size_t payloadSize = ( dataOffset <= remaining ) ? remaining - dataOffset : 0;
        pkt.payloadLen = static_cast<uint32_t>( wireLen >= dataOffset ? wireLen - dataOffset : 0 );
        if ( pkt.payloadLen > 0 ) {
            oss << " Len=" << pkt.payloadLen;
        }
        // A SYN's options follow, as Wireshark appends them; on other
        // segments the timestamps only, if asked for (showTcpTimestamps()).
        if ( pkt.tcpFlags & 0x02 ) {
            oss << options.info;
        }

        describePayloadOf( pkt, oss, Transport::Tcp, data + std::min( dataOffset, remaining ),
                           payloadSize );
        pkt.info = oss.str();
    }
    else if ( pkt.ipProtocol == IpProtoUdp && remaining >= 8 ) {
        pkt.protocol = "UDP";
        pkt.transport = Transport::Udp;
        pkt.srcPort = readBE16( data );
        pkt.dstPort = readBE16( data + 2 );
        auto udpLen = readBE16( data + 4 );
        pkt.payloadLen = ( udpLen > 8 ) ? static_cast<uint32_t>( udpLen - 8 ) : 0;
        if ( auto* layers = pkt.layers ) {
            layers->layer( "User Datagram Protocol", data, 8 );
            layers->field( "Source Port", std::to_string( pkt.srcPort ), data, 2 );
            layers->field( "Destination Port", std::to_string( pkt.dstPort ), data + 2, 2 );
            layers->field( "Length", std::to_string( udpLen ), data + 4, 2 );
            layers->field( "Checksum", hexField( readBE16( data + 6 ), 4 ), data + 6, 2 );
        }

        const uint8_t* payload = data + 8;
        size_t payloadSize = ( remaining > 8 ) ? remaining - 8 : 0;
        payloadSize = std::min( payloadSize, static_cast<size_t>( pkt.payloadLen ) );

        // VXLAN is told by its destination port alone, as RFC 7348 has it:
        // the source port is a hash of the inner flow.
        if ( pkt.dstPort == kVxlanPort && payloadSize >= 8 ) {
            parseVxlan( pkt, payload, payloadSize );
            return;
        }

        std::ostringstream oss;
        oss << pkt.srcPort << " \xe2\x86\x92 " << pkt.dstPort << " Len=" << pkt.payloadLen;

        describePayloadOf( pkt, oss, Transport::Udp, payload, payloadSize );
        pkt.info = oss.str();
    }
    else if ( ( pkt.ipProtocol == IpProtoIcmp || pkt.ipProtocol == IpProtoIcmpv6 )
              && remaining >= 8 ) {
        const bool v6 = pkt.ipProtocol == IpProtoIcmpv6;
        pkt.protocol = v6 ? "ICMPv6" : "ICMP";
        pkt.info = v6 ? describeIcmpv6( data, remaining ) : describeIcmp( data, remaining );
        if ( auto* layers = pkt.layers ) {
            layers->layer( v6 ? "Internet Control Message Protocol v6"
                              : "Internet Control Message Protocol",
                           data, remaining );
            layers->field( "Type", std::to_string( data[ 0 ] ), data, 1 );
            layers->field( "Code", std::to_string( data[ 1 ] ), data + 1, 1 );
            layers->field( "Checksum", hexField( readBE16( data + 2 ), 4 ), data + 2, 2 );
            layers->field( "Message", pkt.info, data + 4, remaining - 4 );
        }
    }
    else if ( pkt.ipProtocol == IpProtoGre ) {
        parseGre( pkt, data, remaining );
    }
    else if ( ( pkt.ipProtocol == IpProtoIpip && remaining >= 1 && data[ 0 ] >> 4 == 4 )
              || ( pkt.ipProtocol == IpProtoIpv6Encap && remaining >= 1 && data[ 0 ] >> 4 == 6 ) ) {
        parseIpInIp( pkt, network, data, remaining );
    }
    else {
        // A protocol not dissected further: its name, if it has one.
        pkt.protocol = ipProtocolLabel( pkt.ipProtocol );
        pkt.info = "Protocol " + std::to_string( pkt.ipProtocol );
        dataLayer( pkt, data, remaining );
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

/// The fields of the IPv4 header at @p data, @p ihl bytes of it.
void describeIpv4Header( PacketLayers& layers, const uint8_t* data, size_t ihl )
{
    const auto flags = data[ 6 ] >> 5;
    std::string flagNames = hexField( static_cast<uint64_t>( flags ), 1 );
    if ( flags & 0x2 ) {
        flagNames += " Don't fragment";
    }
    if ( flags & 0x1 ) {
        flagNames += " More fragments";
    }
    layers.layer( "Internet Protocol Version 4", data, ihl );
    layers.field( "Version", "4", data, 1 );
    layers.field( "Header Length", std::to_string( ihl ) + " bytes", data, 1 );
    layers.field( "Differentiated Services", hexField( data[ 1 ], 2 ), data + 1, 1 );
    layers.field( "Total Length", std::to_string( readBE16( data + 2 ) ), data + 2, 2 );
    layers.field( "Identification", hexField( readBE16( data + 4 ), 4 ), data + 4, 2 );
    layers.field( "Flags", flagNames, data + 6, 1 );
    layers.field( "Fragment Offset", std::to_string( ( readBE16( data + 6 ) & 0x1FFF ) * 8 ),
                  data + 6, 2 );
    layers.field( "Time to Live", std::to_string( data[ 8 ] ), data + 8, 1 );
    layers.field( "Protocol", ipProtocolField( data[ 9 ] ), data + 9, 1 );
    layers.field( "Header Checksum", hexField( readBE16( data + 10 ), 4 ), data + 10, 2 );
    layers.field( "Source Address", formatIpv4( data + 12 ), data + 12, 4 );
    layers.field( "Destination Address", formatIpv4( data + 16 ), data + 16, 4 );
    if ( ihl > 20 ) {
        layers.field( "Options", std::to_string( ihl - 20 ) + " bytes", data + 20, ihl - 20 );
    }
}

void parseIpv4( PacketRecord& pkt, const uint8_t* data, size_t remaining, bool quoted = false )
{
    if ( remaining < 20 ) {
        pkt.protocol = "IPv4";
        pkt.info = "Truncated IPv4 header";
        dataLayer( pkt, data, remaining, "Internet Protocol Version 4 (truncated)" );
        return;
    }

    auto ihl = static_cast<uint8_t>( ( data[ 0 ] & 0x0F ) * 4 );
    if ( ihl < 20 || ihl > remaining ) {
        pkt.protocol = "IPv4";
        pkt.info = "Invalid IHL";
        dataLayer( pkt, data, remaining, "Internet Protocol Version 4 (invalid header length)" );
        return;
    }
    if ( pkt.layers ) {
        describeIpv4Header( *pkt.layers, data, ihl );
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
        dataLayer( pkt, data + ihl, capturedLen - ihl, "Fragment Data" );
        return;
    }

    parseTransport( pkt, "IPv4", data + ihl, capturedLen - ihl, totalLen - ihl, quoted );
}

// ── Parse IPv6 header ────────────────────────────────────────────────────

/// The layer name of IPv6 extension header @p type, one parseIpv6() walks.
const char* extensionHeaderName( uint8_t type )
{
    switch ( type ) {
    case 0:
        return "IPv6 Hop-by-Hop Options";
    case 43:
        return "IPv6 Routing Header";
    case 44:
        return "IPv6 Fragment Header";
    case 51:
        return "Authentication Header";
    default:
        return "IPv6 Destination Options";
    }
}

void parseIpv6( PacketRecord& pkt, const uint8_t* data, size_t remaining, bool quoted = false )
{
    if ( remaining < 40 ) {
        pkt.protocol = "IPv6";
        pkt.info = "Truncated IPv6 header";
        dataLayer( pkt, data, remaining, "Internet Protocol Version 6 (truncated)" );
        return;
    }

    pkt.ipTtl = data[ 7 ]; // Hop limit
    pkt.srcIp = formatIpv6( data + 8 );
    pkt.dstIp = formatIpv6( data + 24 );
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Internet Protocol Version 6", data, 40 );
        layers->field( "Version", "6", data, 1 );
        layers->field( "Traffic Class", hexField( ( readBE16( data ) >> 4 ) & 0xFF, 2 ), data, 2 );
        layers->field( "Flow Label", hexField( readBE32( data ) & 0xFFFFF, 5 ), data + 1, 3 );
        layers->field( "Payload Length", std::to_string( readBE16( data + 4 ) ), data + 4, 2 );
        layers->field( "Next Header", ipProtocolField( data[ 6 ] ), data + 6, 1 );
        layers->field( "Hop Limit", std::to_string( data[ 7 ] ), data + 7, 1 );
        layers->field( "Source Address", pkt.srcIp, data + 8, 16 );
        layers->field( "Destination Address", pkt.dstIp, data + 24, 16 );
    }

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
            parseTransport( pkt, "IPv6", data + offset, end - offset, wireEnd - offset, quoted );
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
        if ( auto* layers = pkt.layers ) {
            layers->layer( extensionHeaderName( headerType ), header, length );
            layers->field( "Next Header", ipProtocolField( next ), header, 1 );
            layers->field( "Length", std::to_string( length ) + " bytes", header + 1, 1 );
        }

        if ( headerType == 44 ) {
            // Only the first fragment starts with the upper-layer header.
            const auto fragmentOffset = static_cast<size_t>( readBE16( header + 2 ) >> 3 ) * 8;
            if ( fragmentOffset != 0 ) {
                pkt.ipProtocol = next;
                describeFragment( pkt, "IPv6", next, fragmentOffset, readBE32( header + 4 ), 4 );
                dataLayer( pkt, data + offset, end - offset, "Fragment Data" );
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
        dataLayer( pkt, data, remaining, "Address Resolution Protocol (truncated)" );
        return;
    }

    auto opcode = readBE16( data + 6 );
    auto senderIp = formatIpv4( data + 14 );
    auto targetIp = formatIpv4( data + 24 );
    if ( auto* layers = pkt.layers ) {
        const char* opName = opcode == 1 ? "request " : opcode == 2 ? "reply " : "";
        layers->layer( "Address Resolution Protocol", data, 28 );
        layers->field( "Hardware Type", std::to_string( readBE16( data ) ), data, 2 );
        layers->field( "Protocol Type", etherTypeField( readBE16( data + 2 ) ), data + 2, 2 );
        layers->field( "Hardware Size", std::to_string( data[ 4 ] ), data + 4, 1 );
        layers->field( "Protocol Size", std::to_string( data[ 5 ] ), data + 5, 1 );
        layers->field( "Opcode", opName + ( "(" + std::to_string( opcode ) + ")" ), data + 6, 2 );
        layers->field( "Sender MAC Address", formatMac( data + 8 ), data + 8, 6 );
        layers->field( "Sender IP Address", senderIp, data + 14, 4 );
        layers->field( "Target MAC Address", formatMac( data + 18 ), data + 18, 6 );
        layers->field( "Target IP Address", targetIp, data + 24, 4 );
    }

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

// ── Network layer ────────────────────────────────────────────────────────

/**
 * Dissect what EtherType @p etherType names, @p remaining captured bytes at
 * @p data, into @p pkt: VLAN tags (802.1Q, and 802.1ad QinQ service tags
 * stacked around it) are stripped, a PPPoE frame is unwrapped, then the
 * network and transport layers are parsed.  Behind an @p ethernet header
 * the type field may be an IEEE 802.3 length instead.
 */
void parseNetwork( PacketRecord& pkt, uint16_t etherType, const uint8_t* data, size_t remaining,
                   bool ethernet )
{
    // Each VLAN tag is 2 bytes of tag control, then the EtherType of what
    // follows.
    for ( int tags = 0; tags < 8 && remaining >= 4
                        && ( etherType == EthertypeVlan || etherType == EthertypeQinQ
                             || etherType == EthertypeQinQLegacy );
          ++tags ) {
        const auto tagType = etherType;
        etherType = readBE16( data + 2 );
        pkt.etherType = etherType;
        if ( auto* layers = pkt.layers ) {
            const auto tci = readBE16( data );
            layers->layer( tagType == EthertypeVlan ? "802.1Q Virtual LAN" : "802.1ad Virtual LAN",
                           data, 4 );
            layers->field( "Priority", std::to_string( tci >> 13 ), data, 1 );
            layers->field( "ID", std::to_string( tci & 0x0FFF ), data, 2 );
            layers->field( "Type", etherTypeField( etherType ), data + 2, 2 );
        }
        data += 4;
        remaining -= 4;
    }

    // PPPoE: a session's PPP frame carries the network layer, a discovery
    // message none.
    if ( etherType == EthertypePppoeDiscovery || etherType == EthertypePppoeSession ) {
        const auto network = dissectPppoe( pkt, data, remaining );
        if ( !network ) {
            return;
        }
        etherType = network->etherType;
        pkt.etherType = etherType;
        data = network->data;
        remaining = network->len;
    }

    if ( etherType == EthertypeIpv4 ) {
        parseIpv4( pkt, data, remaining );
    }
    else if ( etherType == EthertypeIpv6 ) {
        parseIpv6( pkt, data, remaining );
    }
    else if ( etherType == EthertypeArp ) {
        parseArp( pkt, data, remaining );
    }
    else if ( etherType <= kMax8023Length && ethernet ) {
        // An IEEE 802.3 frame: the field is the length of its LLC data
        pkt.protocol = "LLC";
        pkt.info = "802.3 frame, length " + std::to_string( etherType );
        dataLayer( pkt, data, remaining, "Logical-Link Control" );
    }
    else {
        // An EtherType not dissected further: its name, if it has one.
        char hex[ 8 ];
        std::snprintf( hex, sizeof( hex ), "%04X", etherType );
        const auto* name = etherTypeName( etherType );
        pkt.protocol = name ? name : std::string( "ETH(0x" ) + hex + ")";
        pkt.info = std::string( "EtherType 0x" ) + hex;
        dataLayer( pkt, data, remaining );
    }
}

/// Dissect an Ethernet frame, @p remaining captured bytes at @p data, into
/// @p pkt: its MAC addresses, and what it carries, by parseNetwork().
void parseEthernet( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    if ( remaining < 14 ) {
        pkt.protocol = "Ethernet";
        pkt.info = "Truncated Ethernet header";
        dataLayer( pkt, data, remaining, "Ethernet II (truncated)" );
        return;
    }
    pkt.dstMac = formatMac( data );
    pkt.srcMac = formatMac( data + 6 );
    pkt.etherType = readBE16( data + 12 );
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Ethernet II", data, 14 );
        layers->field( "Destination", pkt.dstMac, data, 6 );
        layers->field( "Source", pkt.srcMac, data + 6, 6 );
        layers->field( "Type",
                       pkt.etherType <= kMax8023Length ? "Length " + std::to_string( pkt.etherType )
                                                       : etherTypeField( pkt.etherType ),
                       data + 12, 2 );
    }
    parseNetwork( pkt, pkt.etherType, data + 14, remaining - 14, true );
}

// ── Tunnels ──────────────────────────────────────────────────────────────

/**
 * Enter the tunnel @p name: what was dissected so far becomes the tunnel's
 * outer packet, its addresses kept in pkt.tunnels, its transport fields
 * cleared for the packet inside.  Beyond kMaxTunnels the tunnel is not
 * entered: @p pkt is described as the tunnel, labelled @p protocol, and
 * false returned.
 */
bool enterTunnel( PacketRecord& pkt, std::string name, const char* protocol )
{
    if ( pkt.tunnels.size() >= kMaxTunnels ) {
        pkt.protocol = protocol;
        pkt.info = name + " not dissected: more than " + std::to_string( kMaxTunnels )
                   + " nested tunnels";
        return false;
    }
    pkt.tunnels.push_back( { std::move( name ), pkt.srcIp, pkt.dstIp } );
    pkt.srcIp.clear();
    pkt.dstIp.clear();
    pkt.ipProtocol = 0;
    pkt.transport.reset();
    pkt.srcPort = 0;
    pkt.dstPort = 0;
    pkt.payloadLen = 0;
    return true;
}

/// An IPv4 (protocol 4) or IPv6 (protocol 41) packet inside one of
/// @p network, the version of which the caller has checked.
void parseIpInIp( PacketRecord& pkt, const char* network, const uint8_t* data, size_t remaining )
{
    const bool inner6 = pkt.ipProtocol == IpProtoIpv6Encap;
    if ( !enterTunnel( pkt, std::string( inner6 ? "IPv6" : "IPv4" ) + "-in-" + network,
                       ipProtocolName( pkt.ipProtocol ) ) ) {
        return;
    }
    if ( inner6 ) {
        parseIpv6( pkt, data, remaining );
    }
    else {
        parseIpv4( pkt, data, remaining );
    }
}

/// A GRE packet (RFC 2784, with RFC 2890's key and sequence number).  The
/// packet it carries is dissected for IPv4, IPv6 and Ethernet (transparent
/// Ethernet bridging, as NVGRE and gretap use); every other protocol type,
/// PPTP's enhanced GRE (version 1) and RFC 1701's source routing leave the
/// GRE packet itself to be shown.
void parseGre( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    constexpr uint16_t kChecksum = 0x8000;
    constexpr uint16_t kRouting = 0x4000;
    constexpr uint16_t kKey = 0x2000;
    constexpr uint16_t kSequence = 0x1000;

    pkt.protocol = "GRE";
    if ( remaining < 4 ) {
        pkt.info = "Truncated GRE header";
        return;
    }
    const auto flags = readBE16( data );
    const auto protocolType = readBE16( data + 2 );
    if ( auto* layers = pkt.layers ) {
        const size_t headerLen = 4 + ( ( flags & ( kChecksum | kRouting ) ) ? 4 : 0 )
                                 + ( ( flags & kKey ) ? 4 : 0 ) + ( ( flags & kSequence ) ? 4 : 0 );
        layers->layer( "Generic Routing Encapsulation", data, headerLen );
        layers->field( "Flags and Version", hexField( flags, 4 ), data, 2 );
        layers->field( "Protocol Type", etherTypeField( protocolType ), data + 2, 2 );
    }
    char type[ 8 ];
    std::snprintf( type, sizeof( type ), "%04X", protocolType );
    const auto version = flags & 0x0007;
    if ( version != 0 ) {
        pkt.info = "GRE version " + std::to_string( version ) + ", protocol type 0x" + type;
        return;
    }
    if ( flags & kRouting ) {
        pkt.info = std::string( "GRE with source routing, protocol type 0x" ) + type;
        return;
    }

    std::string name = "GRE";
    size_t offset = ( flags & kChecksum ) ? 8 : 4;
    if ( ( flags & kKey ) && remaining >= offset + 4 ) {
        char key[ 16 ];
        std::snprintf( key, sizeof( key ), "0x%08X", readBE32( data + offset ) );
        name += std::string( " key=" ) + key;
        if ( auto* layers = pkt.layers ) {
            layers->field( "Key", key, data + offset, 4 );
        }
    }
    offset += ( ( flags & kKey ) ? 4 : 0 ) + ( ( flags & kSequence ) ? 4 : 0 );
    if ( remaining < offset ) {
        pkt.info = "Truncated GRE header";
        return;
    }

    if ( protocolType != EthertypeIpv4 && protocolType != EthertypeIpv6
         && protocolType != EthertypeTransparentBridging ) {
        pkt.info = name + ", protocol type 0x" + type;
        return;
    }
    if ( !enterTunnel( pkt, std::move( name ), "GRE" ) ) {
        return;
    }
    if ( protocolType == EthertypeTransparentBridging ) {
        parseEthernet( pkt, data + offset, remaining - offset );
    }
    else {
        parseNetwork( pkt, protocolType, data + offset, remaining - offset, false );
    }
}

/// A VXLAN packet (RFC 7348), at least its 8-byte header, and the Ethernet
/// frame it carries.  The VNI is named when the I flag says it is valid.
void parseVxlan( PacketRecord& pkt, const uint8_t* data, size_t remaining )
{
    constexpr uint8_t kVniValid = 0x08;
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Virtual eXtensible Local Area Network", data, 8 );
        layers->field( "Flags", hexField( data[ 0 ], 2 ), data, 1 );
        layers->field( "VNI", std::to_string( readBE32( data + 4 ) >> 8 ), data + 4, 3 );
    }
    std::string name = "VXLAN";
    if ( data[ 0 ] & kVniValid ) {
        const auto vni = readBE32( data + 4 ) >> 8;
        name += " VNI " + std::to_string( vni );
    }
    if ( !enterTunnel( pkt, std::move( name ), "VXLAN" ) ) {
        return;
    }
    parseEthernet( pkt, data + 8, remaining - 8 );
}

} // anonymous namespace

void dissectQuotedPacket( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    if ( len == 0 ) {
        return;
    }
    if ( data[ 0 ] >> 4 == 4 ) {
        parseIpv4( pkt, data, len, true );
    }
    else if ( data[ 0 ] >> 4 == 6 ) {
        parseIpv6( pkt, data, len, true );
    }
}

void dissectPacket( PacketRecord& pkt, uint32_t linkType, bool swap, const uint8_t* pktData,
                    size_t pktRemaining )
{
    const Dissecting dissecting( pktData, pktRemaining );
    uint16_t etherType = 0;
    const uint8_t* networkData = nullptr;
    size_t networkRemaining = 0;

    if ( linkType == DltEthernet && pktRemaining >= 14 ) {
        parseEthernet( pkt, pktData, pktRemaining );
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
        if ( auto* layers = pkt.layers ) {
            const size_t addressLen = std::min<size_t>( readBE16( pktData + 4 ), 8 );
            layers->layer( "Linux cooked capture v1", pktData, 16 );
            layers->field( "Packet Type", std::to_string( readBE16( pktData ) ), pktData, 2 );
            layers->field( "Link-layer Address Type", std::to_string( readBE16( pktData + 2 ) ),
                           pktData + 2, 2 );
            layers->field( "Link-layer Address Length", std::to_string( addressLen ), pktData + 4,
                           2 );
            if ( addressLen == 6 ) {
                layers->field( "Source", formatMac( pktData + 6 ), pktData + 6, 6 );
            }
            layers->field( "Protocol", etherTypeField( etherType ), pktData + 14, 2 );
        }
        networkData = pktData + 16;
        networkRemaining = pktRemaining - 16;
    }
    else if ( linkType == DltLinuxSll2 && pktRemaining >= 20 ) {
        // Linux cooked capture v2: 20-byte header, ethertype at offset 0
        etherType = readBE16( pktData );
        pkt.etherType = etherType;
        networkData = pktData + 20;
        networkRemaining = pktRemaining - 20;
        if ( auto* layers = pkt.layers ) {
            layers->layer( "Linux cooked capture v2", pktData, 20 );
            layers->field( "Protocol", etherTypeField( etherType ), pktData, 2 );
            layers->field( "Interface Index", std::to_string( readBE32( pktData + 4 ) ),
                           pktData + 4, 4 );
            layers->field( "Link-layer Address Type", std::to_string( readBE16( pktData + 8 ) ),
                           pktData + 8, 2 );
            layers->field( "Packet Type", std::to_string( pktData[ 10 ] ), pktData + 10, 1 );
            layers->field( "Link-layer Address Length", std::to_string( pktData[ 11 ] ),
                           pktData + 11, 1 );
            if ( pktData[ 11 ] == 6 ) {
                layers->field( "Source", formatMac( pktData + 12 ), pktData + 12, 6 );
            }
        }
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
        if ( auto* layers = pkt.layers ) {
            layers->layer( "Null/Loopback", pktData, 4 );
            layers->field( "Family", std::to_string( family ), pktData, 4 );
        }
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
    else if ( dissectsLinkLayer( linkType ) ) {
        if ( const auto network = dissectLinkLayer( pkt, linkType, pktData, pktRemaining ) ) {
            etherType = network->etherType;
            pkt.etherType = etherType;
            networkData = network->data;
            networkRemaining = network->len;
        }
    }
    else {
        pkt.protocol = "Unknown";
        pkt.info = "Unsupported link-layer type " + std::to_string( linkType );
        dataLayer( pkt, pktData, pktRemaining );
    }

    if ( networkData ) {
        parseNetwork( pkt, etherType, networkData, networkRemaining, false );
    }
}

namespace {

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

/// Whether @p p (at least 12 bytes) starts a pcapng section header block.
bool isPcapNgHeader( const uint8_t* p )
{
    uint32_t magic;
    uint32_t byteOrder;
    std::memcpy( &magic, p, 4 );
    std::memcpy( &byteOrder, p + 8, 4 );
    return magic == PcapNgMagic && ( byteOrder == 0x1A2B3C4D || byteOrder == 0x4D3C2B1A );
}

} // anonymous namespace

// ── Format detection ─────────────────────────────────────────────────────

CaptureStart findCaptureStart( const uint8_t* data, size_t size, size_t& offset,
                               CaptureFormat& format, std::string& error )
{
    error = "Not a valid pcap or pcapng file (no pcap magic found)";
    for ( size_t i = 0; i <= kMaxPreamble; ++i ) {
        if ( i + 24 > size ) {
            offset = i + 24; // the header that may start here
            return CaptureStart::NeedMore;
        }
        uint32_t magic;
        std::memcpy( &magic, data + i, 4 );
        if ( ( i == 0 && isPcapMagic( magic ) ) || isPcapHeader( data + i ) ) {
            format = CaptureFormat::Pcap;
            offset = i;
            return CaptureStart::Found;
        }
        if ( ( i == 0 && magic == PcapNgMagic ) || isPcapNgHeader( data + i ) ) {
            format = CaptureFormat::Pcapng;
            offset = i;
            return CaptureStart::Found;
        }
        if ( !isPreambleText( data[ i ] ) ) {
            break; // binary data that is no capture header: no text preamble
        }
    }
    return CaptureStart::None;
}

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
    case DltPpp:
        return "PPP";
    case DltPppSerial:
        return "PPP HDLC";
    case DltPppEther:
        return "PPPoE";
    case DltCiscoHdlc:
        return "Cisco HDLC";
    case DltIeee80211:
        return "802.11";
    case DltIeee80211Radio:
        return "802.11 Radiotap";
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

std::string formatTcpNumbers( uint32_t seq, std::optional<uint32_t> ack, uint32_t window )
{
    return "Seq=" + std::to_string( seq ) + ( ack ? " Ack=" + std::to_string( *ack ) : "" )
           + " Win=" + std::to_string( window );
}

TcpOptions parseTcpOptions( const uint8_t* options, size_t len )
{
    constexpr uint8_t kEndOfOptions = 0;
    constexpr uint8_t kNop = 1;
    constexpr uint8_t kMss = 2;
    constexpr uint8_t kWindowScale = 3;
    constexpr uint8_t kSackPermitted = 4;
    constexpr uint8_t kTimestamps = 8;
    /// RFC 7323's largest shift count; Wireshark shows a larger one as 14.
    constexpr uint8_t kMaxWindowShift = 14;

    TcpOptions result;
    size_t at = 0;
    while ( at < len && options[ at ] != kEndOfOptions ) {
        if ( options[ at ] == kNop ) {
            ++at;
            continue;
        }
        if ( at + 1 >= len || options[ at + 1 ] < 2 || options[ at + 1 ] > len - at ) {
            break;
        }
        const uint8_t* option = options + at;
        const uint8_t length = option[ 1 ];
        if ( option[ 0 ] == kMss && length == 4 ) {
            result.mss = readBE16( option + 2 );
            result.info += " MSS=" + std::to_string( *result.mss );
        }
        else if ( option[ 0 ] == kWindowScale && length == 3 ) {
            result.windowShift = option[ 2 ];
            result.info
                += " WS=" + std::to_string( 1u << std::min( option[ 2 ], kMaxWindowShift ) );
        }
        else if ( option[ 0 ] == kSackPermitted ) {
            // Wireshark names it before it checks its length.
            result.sackPermitted = true;
            result.info += " SACK_PERM";
        }
        else if ( option[ 0 ] == kTimestamps && length == 10 ) {
            result.timestamps = TcpTimestamps{ readBE32( option + 2 ), readBE32( option + 6 ) };
            result.info += " TSval=" + std::to_string( result.timestamps->value )
                           + " TSecr=" + std::to_string( result.timestamps->echoReply );
        }
        at += length;
    }
    return result;
}

size_t tcpFieldsEnd( const std::string& info )
{
    const auto at = info.find( kDescriptionSeparator );
    return at == std::string::npos ? info.size() : at;
}

void showTcpTimestamps( PacketRecord& pkt )
{
    if ( pkt.transport != Transport::Tcp || !pkt.tcpTimestamps || ( pkt.tcpFlags & 0x02 ) ) {
        return;
    }
    pkt.info.insert( tcpFieldsEnd( pkt.info ),
                     " TSval=" + std::to_string( pkt.tcpTimestamps->value )
                         + " TSecr=" + std::to_string( pkt.tcpTimestamps->echoReply ) );
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

const std::vector<uint8_t>& HeadSource::peek( size_t n )
{
    while ( head_.size() < n ) {
        const auto filled = head_.size();
        head_.resize( n );
        const auto got = source_.read( head_.data() + filled, n - filled );
        head_.resize( filled + got );
        if ( got == 0 ) {
            break;
        }
    }
    return head_;
}

size_t HeadSource::read( uint8_t* dst, size_t n )
{
    if ( n == 0 ) {
        return 0;
    }
    if ( head_.empty() ) {
        return source_.read( dst, n );
    }
    const auto got = std::min( n, head_.size() );
    std::memcpy( dst, head_.data(), got );
    head_.erase( head_.begin(), head_.begin() + static_cast<std::ptrdiff_t>( got ) );
    return got;
}

bool HeadSource::ready()
{
    return !head_.empty() || source_.ready();
}

bool HeadSource::skip( uint64_t n )
{
    const auto fromHead = static_cast<size_t>( std::min<uint64_t>( n, head_.size() ) );
    head_.erase( head_.begin(), head_.begin() + static_cast<std::ptrdiff_t>( fromHead ) );
    n -= fromHead;
    return n == 0 || source_.skip( n );
}

// ── CaptureReader ────────────────────────────────────────────────────────

size_t CaptureReader::read( uint8_t* dst, size_t n )
{
    // An empty record reads into a buffer whose data() may be null, and
    // memcpy() must not be given a null pointer even for 0 bytes.
    if ( n == 0 ) {
        return 0;
    }
    size_t got = 0;
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

ByteView CaptureReader::payloadOf( const PacketRecord& pkt ) const
{
    if ( pkt.payloadCaptured == 0 || pkt.payloadOffset > packet_.size()
         || pkt.payloadCaptured > packet_.size() - pkt.payloadOffset ) {
        return {};
    }
    return { packet_.data() + pkt.payloadOffset, pkt.payloadCaptured };
}

bool CaptureReader::skip( uint64_t n )
{
    const bool ok = n == 0 || source_.skip( n );
    bytesRead_ += n; // on failure the source is at its end anyway
    return ok;
}

ReaderCheckpoint CaptureReader::checkpoint() const
{
    return { packetCount_, bytesRead_, nullptr };
}

bool CaptureReader::resume( const ReaderCheckpoint& checkpoint )
{
    if ( checkpoint.offset < bytesRead_ || !skip( checkpoint.offset - bytesRead_ ) ) {
        return false;
    }
    packetCount_ = checkpoint.packetsBefore;
    return true;
}

// ── PcapReader ───────────────────────────────────────────────────────────

bool PcapReader::open()
{
    uint8_t data[ 24 ];
    if ( !skip( start_ ) || read( data, sizeof( data ) ) < sizeof( data ) ) {
        error_ = "Not a valid pcap file (cut off inside the global header)";
        return false;
    }

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

    open_ = true;
    headerRead_ = true;
    return true;
}

bool PcapReader::resume( const ReaderCheckpoint& checkpoint )
{
    // The global header that open() read is all a pcap's records need.
    if ( !open_ || !CaptureReader::resume( checkpoint ) ) {
        open_ = false;
        return false;
    }
    return true;
}

CaptureHeaders PcapReader::headers() const
{
    CaptureHeaders headers;
    if ( headerRead_ ) {
        headers.records.push_back( { start_, 24 } );
    }
    return headers;
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
    const auto recordStart = bytesRead();
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

    recordOffset_ = recordStart;
    recordLength_ = sizeof( recordHeader ) + static_cast<uint64_t>( inclLen );
    pkt = PacketRecord();
    pkt.number = ++packetCount_;
    // The fraction is kept in nanoseconds.  A corrupt one of a second or
    // more is carried into the seconds.
    const uint64_t fractionNs
        = header_.nanoseconds ? tsFraction : static_cast<uint64_t>( tsFraction ) * 1000;
    pkt.timestampSec = static_cast<int64_t>( tsSec + fractionNs / 1000000000 );
    pkt.timestampNsec = static_cast<uint32_t>( fractionNs % 1000000000 );
    pkt.capturedLen = inclLen;
    pkt.originalLen = origLen;
    pkt.linkType = header_.network;
    pkt.precision = precision();
    dissectPacket( pkt, pkt.linkType, swap_, packet_.data(), kept );
    return true;
}

} // namespace tcpdump
