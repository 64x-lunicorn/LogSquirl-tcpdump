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
 * @file wire_bytes.h
 * @brief Reading and formatting the fields of a packet, as they lie on the wire.
 *
 * Shared by the pcap Parser, its ICMP dissection and the Payload Describer.  The capture readers
 * also read the fields of their file with it, in the byte order the file was
 * written in.  Pure C++.
 */

#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace tcpdump {

/// Read a big-endian uint16 (network byte order).
inline uint16_t readBE16( const uint8_t* p )
{
    return static_cast<uint16_t>( ( p[ 0 ] << 8 ) | p[ 1 ] );
}

/// Read a big-endian uint32 (network byte order).
inline uint32_t readBE32( const uint8_t* p )
{
    return ( static_cast<uint32_t>( p[ 0 ] ) << 24 ) | ( static_cast<uint32_t>( p[ 1 ] ) << 16 )
           | ( static_cast<uint32_t>( p[ 2 ] ) << 8 ) | p[ 3 ];
}

/// Read a uint16 of a capture file; @p swap: it was written in the other
/// byte order than this host's.
inline uint16_t read16( const uint8_t* p, bool swap )
{
    uint16_t v;
    std::memcpy( &v, p, 2 );
    if ( swap ) {
        v = static_cast<uint16_t>( ( v >> 8 ) | ( v << 8 ) );
    }
    return v;
}

/// Read a uint32 of a capture file; @p swap: it was written in the other
/// byte order than this host's.
inline uint32_t read32( const uint8_t* p, bool swap )
{
    uint32_t v;
    std::memcpy( &v, p, 4 );
    if ( swap ) {
        v = ( ( v >> 24 ) & 0xFF ) | ( ( v >> 8 ) & 0xFF00 ) | ( ( v << 8 ) & 0xFF0000 )
            | ( ( v << 24 ) & 0xFF000000 );
    }
    return v;
}

/// An IPv4 address in dotted decimal.  Written out by hand: every packet
/// formats two, and snprintf() took a tenth of a conversion.
inline std::string formatIpv4( const uint8_t* p )
{
    char buf[ 15 ];
    size_t n = 0;
    for ( int i = 0; i < 4; ++i ) {
        if ( i > 0 ) {
            buf[ n++ ] = '.';
        }
        const unsigned v = p[ i ];
        if ( v >= 100 ) {
            buf[ n++ ] = static_cast<char>( '0' + v / 100 );
        }
        if ( v >= 10 ) {
            buf[ n++ ] = static_cast<char>( '0' + v / 10 % 10 );
        }
        buf[ n++ ] = static_cast<char>( '0' + v % 10 );
    }
    return std::string( buf, n );
}

/// A MAC address as six lowercase hexadecimal pairs, `00:11:22:33:44:55`.
inline std::string formatMac( const uint8_t* p )
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string mac( 17, ':' );
    for ( size_t i = 0; i < 6; ++i ) {
        mac[ 3 * i ] = kHex[ p[ i ] >> 4 ];
        mac[ 3 * i + 1 ] = kHex[ p[ i ] & 0x0F ];
    }
    return mac;
}

/// An IPv6 address in the RFC 5952 form: lowercase hexadecimal groups
/// without leading zeros, the longest run of two or more zero groups (the
/// leftmost on a tie) collapsed to `::`.  An IPv4-mapped address is shown in
/// hexadecimal too, as `::ffff:c000:201`.
inline std::string formatIpv6( const uint8_t* p )
{
    uint16_t groups[ 8 ];
    for ( int i = 0; i < 8; ++i ) {
        groups[ i ] = readBE16( p + 2 * i );
    }

    int runStart = -1;
    int runLength = 1; // a single zero group is never collapsed
    for ( int i = 0; i < 8; ) {
        int j = i;
        while ( j < 8 && groups[ j ] == 0 ) {
            ++j;
        }
        if ( j - i > runLength ) {
            runStart = i;
            runLength = j - i;
        }
        i = ( j > i ) ? j : i + 1;
    }

    std::string text;
    char group[ 5 ];
    for ( int i = 0; i < 8; ++i ) {
        if ( i == runStart ) {
            text += "::";
            i += runLength - 1;
            continue;
        }
        if ( !text.empty() && text.back() != ':' ) {
            text += ':';
        }
        std::snprintf( group, sizeof( group ), "%x", groups[ i ] );
        text += group;
    }
    return text;
}

} // namespace tcpdump
