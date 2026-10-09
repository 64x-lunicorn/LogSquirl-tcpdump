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
 * Shared by the pcap Parser and the Payload Describer.  Pure C++.
 */

#pragma once

#include <cstdint>
#include <cstdio>
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

/// An IPv4 address in dotted decimal.
inline std::string formatIpv4( const uint8_t* p )
{
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "%u.%u.%u.%u", p[ 0 ], p[ 1 ], p[ 2 ], p[ 3 ] );
    return buf;
}

/// An IPv6 address as eight hexadecimal groups.
inline std::string formatIpv6( const uint8_t* p )
{
    char buf[ 40 ];
    std::snprintf( buf, sizeof( buf ), "%x:%x:%x:%x:%x:%x:%x:%x", readBE16( p ), readBE16( p + 2 ),
                   readBE16( p + 4 ), readBE16( p + 6 ), readBE16( p + 8 ), readBE16( p + 10 ),
                   readBE16( p + 12 ), readBE16( p + 14 ) );
    return buf;
}

} // namespace tcpdump
