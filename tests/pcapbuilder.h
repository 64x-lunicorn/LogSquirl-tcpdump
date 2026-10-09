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
 * @brief Compact builders for synthetic packets, pcap and pcapng files, for tests.
 *
 * Each layer function wraps a payload in one protocol header, so a packet
 * reads inside out: eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 1, 2 ) ) ).
 * Pure C++, so that the fuzz harness can use it without Qt.
 */

#pragma once

#include "capture_reader.h"

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

/** A PPPoE header with @p code for session 0x1234 around @p payload. */
inline Bytes pppoe( uint8_t code, const Bytes& payload, int length = -1 )
{
    Bytes b{ 0x11, code };
    putBE16( b, code == 0 ? 0x1234 : 0 );
    putBE16( b, static_cast<uint16_t>( length >= 0 ? length : payload.size() ) );
    return b + payload;
}

/** A PPPoE session frame carrying PPP @p protocol, without address and control. */
inline Bytes pppoeSession( uint16_t protocol, const Bytes& payload )
{
    Bytes b;
    putBE16( b, protocol );
    return pppoe( 0x00, b + payload );
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

/** TCP header (PSH, ACK by default) around @p payload. */
inline Bytes tcp( uint16_t srcPort, uint16_t dstPort, const Bytes& payload = {},
                  uint8_t dataOffsetWords = 5, uint8_t flags = 0x18, uint32_t seq = 1,
                  uint32_t ack = 0, uint16_t window = 0xFFFF )
{
    Bytes b;
    putBE16( b, srcPort );
    putBE16( b, dstPort );
    putBE32( b, seq );
    putBE32( b, ack );
    b.push_back( static_cast<uint8_t>( dataOffsetWords << 4 ) );
    b.push_back( flags );
    putBE16( b, window );
    putBE32( b, 0 ); // checksum, urgent pointer
    if ( dataOffsetWords > 5 ) {
        b.resize( static_cast<size_t>( dataOffsetWords ) * 4, 1 ); // NOP options
    }
    return b + payload;
}

/**
 * TCP header with the options @p options, padded with end-of-options to a
 * whole number of words, around @p payload.
 */
inline Bytes tcpWithOptions( uint16_t srcPort, uint16_t dstPort, const Bytes& options,
                             uint8_t flags, uint32_t seq = 1, uint32_t ack = 0,
                             uint16_t window = 0xFFFF, const Bytes& payload = {} )
{
    const auto words = static_cast<uint8_t>( 5 + ( options.size() + 3 ) / 4 );
    auto header = tcp( srcPort, dstPort, {}, 5, flags, seq, ack, window ) + options;
    header.resize( static_cast<size_t>( words ) * 4, 0 );
    header[ 12 ] = static_cast<uint8_t>( words << 4 );
    return header + payload;
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

/** A VXLAN header with VNI @p vni (I flag set) around the Ethernet @p frame. */
inline Bytes vxlan( uint32_t vni, const Bytes& frame, uint8_t flags = 0x08 )
{
    Bytes b{ flags, 0, 0, 0 };
    putBE32( b, vni << 8 );
    return b + frame;
}

struct GreOptions {
    bool checksum = false; ///< C bit: checksum and reserved field.
    bool key = false;      ///< K bit: the key field, keyValue.
    bool sequence = false; ///< S bit: a sequence number.
    bool routing = false;  ///< R bit (RFC 1701 source routing).
    uint8_t version = 0;   ///< 1 for PPTP's enhanced GRE.
    uint32_t keyValue = 42;
};

/** A GRE header of @p protocolType (an EtherType) around @p payload. */
inline Bytes gre( uint16_t protocolType, const Bytes& payload, const GreOptions& o = {} )
{
    Bytes b;
    putBE16( b, static_cast<uint16_t>( ( o.checksum ? 0x8000 : 0 ) | ( o.routing ? 0x4000 : 0 )
                                       | ( o.key ? 0x2000 : 0 ) | ( o.sequence ? 0x1000 : 0 )
                                       | o.version ) );
    putBE16( b, protocolType );
    if ( o.checksum || o.routing ) {
        putBE32( b, 0 ); // checksum, offset
    }
    if ( o.key ) {
        putBE32( b, o.keyValue );
    }
    if ( o.sequence ) {
        putBE32( b, 7 );
    }
    return b + payload;
}

/** A pcap record to put into a file. */
struct Record {
    Bytes data;
    uint32_t tsSec = 1000;
    uint32_t tsFrac = 0;  ///< Microseconds, or nanoseconds in a nanosecond file.
    int64_t inclLen = -1; ///< -1: the size of data.
    int64_t origLen = -1; ///< The length on the wire; -1: the size of data.
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
        put32( b, r.origLen >= 0 ? static_cast<uint32_t>( r.origLen )
                                 : static_cast<uint32_t>( r.data.size() ) );
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

// ── pcapng ───────────────────────────────────────────────────────────────

/// pcapng block types.
constexpr uint32_t kShb = 0x0A0D0D0A; ///< Section Header Block
constexpr uint32_t kIdb = 1;          ///< Interface Description Block
constexpr uint32_t kSpb = 3;          ///< Simple Packet Block
constexpr uint32_t kNrb = 4;          ///< Name Resolution Block
constexpr uint32_t kIsb = 5;          ///< Interface Statistics Block
constexpr uint32_t kEpb = 6;          ///< Enhanced Packet Block

/**
 * Writes the blocks of a pcapng section in one byte order; a file is their
 * concatenation: Pcapng le; le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1, frame ).
 */
struct Pcapng {
    bool bigEndian = false;

    void put16( Bytes& b, uint16_t v ) const
    {
        bigEndian ? putBE16( b, v ) : putLE16( b, v );
    }

    void put32( Bytes& b, uint32_t v ) const
    {
        bigEndian ? putBE32( b, v ) : putLE32( b, v );
    }

    /// A block of @p type around @p body, padded to 32 bits; @p totalLength
    /// -1 means its real length, in both length fields.
    Bytes block( uint32_t type, Bytes body, int64_t totalLength = -1 ) const
    {
        body.resize( ( body.size() + 3 ) / 4 * 4, 0 );
        const auto length = totalLength >= 0 ? static_cast<uint32_t>( totalLength )
                                             : static_cast<uint32_t>( body.size() + 12 );
        Bytes b;
        put32( b, type );
        put32( b, length );
        b = b + body;
        put32( b, length );
        return b;
    }

    /// A Section Header Block of version @p major.1, with unknown section length.
    Bytes shb( uint16_t major = 1 ) const
    {
        Bytes body;
        put32( body, 0x1A2B3C4D );
        put16( body, major );
        put16( body, 0 );
        put32( body, 0xFFFFFFFF ); // section length -1: not given
        put32( body, 0xFFFFFFFF );
        return block( kShb, body );
    }

    /// An option: code, length, value padded to 32 bits.
    Bytes option( uint16_t code, const Bytes& value ) const
    {
        Bytes b;
        put16( b, code );
        put16( b, static_cast<uint16_t>( value.size() ) );
        b = b + value;
        b.resize( ( b.size() + 3 ) / 4 * 4, 0 );
        return b;
    }

    /// An Interface Description Block; @p tsresol is if_tsresol's byte,
    /// -1 for none (microseconds).  An if_name option comes first.
    Bytes idb( uint32_t linkType, int tsresol = -1, uint32_t snaplen = 262144 ) const
    {
        Bytes body;
        put16( body, static_cast<uint16_t>( linkType ) );
        put16( body, 0 );
        put32( body, snaplen );
        body = body + option( 2, text( "eth0" ) );
        if ( tsresol >= 0 ) {
            body = body + option( 9, { static_cast<uint8_t>( tsresol ) } );
        }
        return block( kIdb, body + option( 0, {} ) );
    }

    /// An Enhanced Packet Block; @p capturedLen -1 means the size of @p data.
    Bytes epb( uint32_t interfaceId, uint64_t timestamp, const Bytes& data,
               int64_t capturedLen = -1 ) const
    {
        Bytes body;
        put32( body, interfaceId );
        put32( body, static_cast<uint32_t>( timestamp >> 32 ) );
        put32( body, static_cast<uint32_t>( timestamp & 0xFFFFFFFF ) );
        put32( body, capturedLen >= 0 ? static_cast<uint32_t>( capturedLen )
                                      : static_cast<uint32_t>( data.size() ) );
        put32( body, static_cast<uint32_t>( data.size() ) );
        body = body + data;
        body.resize( ( body.size() + 3 ) / 4 * 4, 0 );
        return block( kEpb, body + option( 1, text( "comment" ) ) + option( 0, {} ) );
    }

    /// A Simple Packet Block of a packet @p originalLen long on the wire.
    Bytes spb( const Bytes& data, uint32_t originalLen ) const
    {
        Bytes body;
        put32( body, originalLen );
        return block( kSpb, body + data );
    }
};

/** Parse @p file and return its only packet (asserting there is one is the caller's job). */
inline tcpdump::ParseResult parse( const Bytes& file )
{
    return tcpdump::parsePcap( file.data(), file.size() );
}

} // namespace tcpdump_test
