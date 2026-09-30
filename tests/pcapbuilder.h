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
 * @file pcapbuilder.h
 * @brief Compact builders for synthetic packets and pcap files, for tests.
 *
 * Each layer function wraps a payload in one protocol header, so a packet
 * reads inside out: eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 1, 2 ) ) ).
 * Pure C++, so that the fuzz harness can use it without Qt.
 */

#pragma once

#include "pcap_parser.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump_test {

using Bytes = std::vector<uint8_t>;

inline void putBE16( Bytes& b, uint16_t v )
{
    b.push_back( static_cast<uint8_t>( v >> 8 ) );
    b.push_back( static_cast<uint8_t>( v & 0xFF ) );
}

inline void putBE32( Bytes& b, uint32_t v )
{
    putBE16( b, static_cast<uint16_t>( v >> 16 ) );
    putBE16( b, static_cast<uint16_t>( v & 0xFFFF ) );
}

inline void putLE16( Bytes& b, uint16_t v )
{
    b.push_back( static_cast<uint8_t>( v & 0xFF ) );
    b.push_back( static_cast<uint8_t>( v >> 8 ) );
}

inline void putLE32( Bytes& b, uint32_t v )
{
    putLE16( b, static_cast<uint16_t>( v & 0xFFFF ) );
    putLE16( b, static_cast<uint16_t>( v >> 16 ) );
}

inline Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

inline Bytes text( const std::string& s )
{
    return Bytes( s.begin(), s.end() );
}

/** Ethernet II header (dst 00:11:22:33:44:55, src 66:77:88:99:aa:bb). */
inline Bytes eth( uint16_t etherType, const Bytes& payload )
{
    Bytes b{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB };
    putBE16( b, etherType );
    return b + payload;
}

/** An 802.1Q / 802.1ad tag: TCI, then the inner EtherType. */
inline Bytes vlanTag( uint16_t vlanId, uint16_t innerEtherType, const Bytes& payload )
{
    Bytes b;
    putBE16( b, vlanId );
    putBE16( b, innerEtherType );
    return b + payload;
}

struct Ipv4Options {
    int totalLength = -1;  ///< -1: header + payload; otherwise this value.
    uint16_t fragment = 0; ///< Flags and fragment offset (in 8-byte units).
    uint8_t ihlWords = 5;  ///< Header length in 32-bit words.
    uint8_t src[ 4 ] = { 192, 168, 1, 1 };
    uint8_t dst[ 4 ] = { 192, 168, 1, 2 };
};

/** IPv4 header around @p payload. */
inline Bytes ipv4( uint8_t protocol, const Bytes& payload, const Ipv4Options& o = {} )
{
    Bytes b;
    b.push_back( static_cast<uint8_t>( 0x40 | o.ihlWords ) );
    b.push_back( 0 );
    const auto headerLen = static_cast<size_t>( o.ihlWords ) * 4;
    putBE16( b, static_cast<uint16_t>( o.totalLength >= 0 ? o.totalLength
                                                          : headerLen + payload.size() ) );
    putBE16( b, 0x1234 ); // identification
    putBE16( b, o.fragment );
    b.push_back( 64 ); // TTL
    b.push_back( protocol );
    putBE16( b, 0 ); // checksum
    b.insert( b.end(), o.src, o.src + 4 );
    b.insert( b.end(), o.dst, o.dst + 4 );
    b.resize( headerLen < 20 ? 20 : headerLen, 0 ); // options
    return b + payload;
}

/** IPv6 header around @p payload; @p payloadLength -1 means its real size. */
inline Bytes ipv6( uint8_t nextHeader, const Bytes& payload, int payloadLength = -1 )
{
    Bytes b{ 0x60, 0, 0, 0 };
    putBE16( b, static_cast<uint16_t>( payloadLength >= 0 ? payloadLength : payload.size() ) );
    b.push_back( nextHeader );
    b.push_back( 64 ); // hop limit
    Bytes src( 16, 0 );
    src[ 0 ] = 0xfe;
    src[ 1 ] = 0x80;
    src[ 15 ] = 1;
    Bytes dst = src;
    dst[ 15 ] = 2;
    return b + src + dst + payload;
}

/** An IPv6 hop-by-hop, routing or destination options header of 8 bytes. */
inline Bytes ipv6Options( uint8_t nextHeader, const Bytes& payload )
{
    Bytes b{ nextHeader, 0, 1, 4, 0, 0, 0, 0 }; // PadN option fills it
    return b + payload;
}

/** An IPv6 fragment header; @p offset in 8-byte units. */
inline Bytes ipv6Fragment( uint8_t nextHeader, uint16_t offset, bool more, const Bytes& payload )
{
    Bytes b{ nextHeader, 0 };
    putBE16( b, static_cast<uint16_t>( ( offset << 3 ) | ( more ? 1 : 0 ) ) );
    putBE32( b, 0xCAFE );
    return b + payload;
}

/** TCP header (PSH, ACK) around @p payload. */
inline Bytes tcp( uint16_t srcPort, uint16_t dstPort, const Bytes& payload = {},
                  uint8_t dataOffsetWords = 5, uint8_t flags = 0x18 )
{
    Bytes b;
    putBE16( b, srcPort );
    putBE16( b, dstPort );
    putBE32( b, 1 ); // seq
    putBE32( b, 0 ); // ack
    b.push_back( static_cast<uint8_t>( dataOffsetWords << 4 ) );
    b.push_back( flags );
    putBE16( b, 0xFFFF ); // window
    putBE32( b, 0 );      // checksum, urgent pointer
    if ( dataOffsetWords > 5 ) {
        b.resize( static_cast<size_t>( dataOffsetWords ) * 4, 1 ); // NOP options
    }
    return b + payload;
}

/** UDP header around @p payload; @p length -1 means its real size. */
inline Bytes udp( uint16_t srcPort, uint16_t dstPort, const Bytes& payload = {}, int length = -1 )
{
    Bytes b;
    putBE16( b, srcPort );
    putBE16( b, dstPort );
    putBE16( b, static_cast<uint16_t>( length >= 0 ? length : 8 + payload.size() ) );
    putBE16( b, 0 );
    return b + payload;
}

/** A pcap record to put into a file. */
struct Record {
    Bytes data;
    uint32_t tsSec = 1000;
    uint32_t tsFrac = 0; ///< Microseconds, or nanoseconds in a nanosecond file.
    int inclLen = -1;    ///< -1: the size of data.
};

struct FileOptions {
    uint32_t linkType = tcpdump::DltEthernet;
    bool bigEndian = false;
    bool nanoseconds = false;
    uint16_t versionMajor = 2;
    uint16_t versionMinor = 4;
    uint32_t snaplen = 262144;
};

/** A pcap file with @p records, in the byte order and precision of @p o. */
inline Bytes pcapFile( const std::vector<Record>& records, const FileOptions& o = {} )
{
    auto put16
        = [ &o ]( Bytes& b, uint16_t v ) { o.bigEndian ? putBE16( b, v ) : putLE16( b, v ); };
    auto put32
        = [ &o ]( Bytes& b, uint32_t v ) { o.bigEndian ? putBE32( b, v ) : putLE32( b, v ); };

    Bytes b;
    put32( b, o.nanoseconds ? 0xA1B23C4D : 0xA1B2C3D4 );
    put16( b, o.versionMajor );
    put16( b, o.versionMinor );
    put32( b, 0 ); // thiszone
    put32( b, 0 ); // sigfigs
    put32( b, o.snaplen );
    put32( b, o.linkType );
    for ( const auto& r : records ) {
        put32( b, r.tsSec );
        put32( b, r.tsFrac );
        put32( b, r.inclLen >= 0 ? static_cast<uint32_t>( r.inclLen )
                                 : static_cast<uint32_t>( r.data.size() ) );
        put32( b, static_cast<uint32_t>( r.data.size() ) );
        b.insert( b.end(), r.data.begin(), r.data.end() );
    }
    return b;
}

/** A little-endian Ethernet pcap file with one record per packet. */
inline Bytes pcapOf( const std::vector<Bytes>& packets, uint32_t linkType = tcpdump::DltEthernet )
{
    std::vector<Record> records;
    uint32_t sec = 1000;
    for ( const auto& p : packets ) {
        records.push_back( { p, sec++, 0, -1 } );
    }
    FileOptions o;
    o.linkType = linkType;
    return pcapFile( records, o );
}

/** Parse @p file and return its only packet (asserting there is one is the caller's job). */
inline tcpdump::ParseResult parse( const Bytes& file )
{
    return tcpdump::parsePcap( file.data(), file.size() );
}

} // namespace tcpdump_test
