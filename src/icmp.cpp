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
 * @file icmp.cpp
 * @brief The Info of ICMP and ICMPv6 messages.
 *
 * Type and code names follow Wireshark's (RFC 792, RFC 4443, RFC 4861), in
 * the sentence case Info used before, so that `Destination unreachable` and
 * `Time exceeded` still begin an error message's Info.
 */

#include "icmp.h"

#include "pcap_parser.h"
#include "protocol_names.h"
#include "wire_bytes.h"

#include <cstdio>
#include <string>

namespace tcpdump {

namespace {

/// Bytes of the fixed ICMP and ICMPv6 header: type, code, checksum and 4
/// bytes that depend on the type.  An error message's quote follows them.
constexpr size_t kHeaderLen = 8;

/// A number and its name, for the type and code tables.
struct Name {
    uint8_t number;
    const char* name;
};

template <size_t N>
const char* nameOf( const Name ( &table )[ N ], uint8_t number )
{
    for ( const auto& entry : table ) {
        if ( entry.number == number ) {
            return entry.name;
        }
    }
    return nullptr;
}

// ── ICMP (RFC 792) ───────────────────────────────────────────────────────

constexpr uint8_t kEchoReply = 0;
constexpr uint8_t kUnreachable = 3;
constexpr uint8_t kSourceQuench = 4;
constexpr uint8_t kRedirect = 5;
constexpr uint8_t kEchoRequest = 8;
constexpr uint8_t kTimeExceeded = 11;
constexpr uint8_t kParameterProblem = 12;
constexpr uint8_t kFragmentationNeeded = 4; ///< Code of kUnreachable

constexpr Name kIcmpTypes[] = {
    { 0, "Echo (ping) reply" },    { 3, "Destination unreachable" },
    { 4, "Source quench" },        { 5, "Redirect" },
    { 8, "Echo (ping) request" },  { 9, "Router advertisement" },
    { 10, "Router solicitation" }, { 11, "Time exceeded" },
    { 12, "Parameter problem" },   { 13, "Timestamp request" },
    { 14, "Timestamp reply" },     { 15, "Information request" },
    { 16, "Information reply" },   { 17, "Address mask request" },
    { 18, "Address mask reply" },
};

constexpr Name kUnreachableCodes[] = {
    { 0, "Network unreachable" },
    { 1, "Host unreachable" },
    { 2, "Protocol unreachable" },
    { 3, "Port unreachable" },
    { 4, "Fragmentation needed" },
    { 5, "Source route failed" },
    { 6, "Destination network unknown" },
    { 7, "Destination host unknown" },
    { 8, "Source host isolated" },
    { 9, "Network administratively prohibited" },
    { 10, "Host administratively prohibited" },
    { 11, "Network unreachable for TOS" },
    { 12, "Host unreachable for TOS" },
    { 13, "Communication administratively filtered" },
    { 14, "Host precedence violation" },
    { 15, "Precedence cutoff in effect" },
};

constexpr Name kRedirectCodes[] = {
    { 0, "Redirect for network" },
    { 1, "Redirect for host" },
    { 2, "Redirect for TOS and network" },
    { 3, "Redirect for TOS and host" },
};

constexpr Name kTimeExceededCodes[] = {
    { 0, "TTL exceeded in transit" },
    { 1, "Fragment reassembly time exceeded" },
};

constexpr Name kParameterProblemCodes[] = {
    { 0, "Pointer indicates the error" },
    { 1, "Required option missing" },
    { 2, "Bad length" },
};

/// Whether ICMP @p type is a query that carries an identifier and sequence
/// number: echo, timestamp, information and address mask.
bool isIcmpQuery( uint8_t type )
{
    return type == kEchoReply || type == kEchoRequest || ( type >= 13 && type <= 18 );
}

// ── ICMPv6 (RFC 4443, RFC 4861, RFC 3810) ────────────────────────────────

constexpr uint8_t kV6Unreachable = 1;
constexpr uint8_t kV6PacketTooBig = 2;
constexpr uint8_t kV6TimeExceeded = 3;
constexpr uint8_t kV6ParameterProblem = 4;
constexpr uint8_t kV6EchoRequest = 128;
constexpr uint8_t kV6EchoReply = 129;
constexpr uint8_t kRouterSolicitation = 133;
constexpr uint8_t kRouterAdvertisement = 134;
constexpr uint8_t kNeighborSolicitation = 135;
constexpr uint8_t kNeighborAdvertisement = 136;

constexpr Name kIcmpv6Types[] = {
    { 1, "Destination unreachable" },
    { 2, "Packet too big" },
    { 3, "Time exceeded" },
    { 4, "Parameter problem" },
    { 128, "Echo (ping) request" },
    { 129, "Echo (ping) reply" },
    { 130, "Multicast listener query" },
    { 131, "Multicast listener report" },
    { 132, "Multicast listener done" },
    { 133, "Router solicitation" },
    { 134, "Router advertisement" },
    { 135, "Neighbor solicitation" },
    { 136, "Neighbor advertisement" },
    { 137, "Redirect" },
    { 143, "Multicast listener report v2" },
};

constexpr Name kV6UnreachableCodes[] = {
    { 0, "No route to destination" },
    { 1, "Administratively prohibited" },
    { 2, "Beyond scope of source address" },
    { 3, "Address unreachable" },
    { 4, "Port unreachable" },
    { 5, "Source address failed ingress/egress policy" },
    { 6, "Reject route to destination" },
};

constexpr Name kV6TimeExceededCodes[] = {
    { 0, "Hop limit exceeded in transit" },
    { 1, "Fragment reassembly time exceeded" },
};

constexpr Name kV6ParameterProblemCodes[] = {
    { 0, "Erroneous header field" },
    { 1, "Unrecognized Next Header type" },
    { 2, "Unrecognized IPv6 option" },
};

/// Neighbor discovery options holding a link-layer address (RFC 4861 4.6.1).
constexpr uint8_t kSourceLinkLayerAddress = 1;
constexpr uint8_t kTargetLinkLayerAddress = 2;

// ── Parts of Info ────────────────────────────────────────────────────────

/// The type's name, or `Type=42 Code=1` for a type without one.
template <size_t N>
std::string typeName( const Name ( &types )[ N ], uint8_t type, uint8_t code )
{
    if ( const auto* name = nameOf( types, type ) ) {
        return name;
    }
    return "Type=" + std::to_string( type ) + " Code=" + std::to_string( code );
}

/// The code's name, or `code=99` for a code without one.
template <size_t N>
std::string codeName( const Name ( &codes )[ N ], uint8_t code )
{
    if ( const auto* name = nameOf( codes, code ) ) {
        return name;
    }
    return "code=" + std::to_string( code );
}

/// ` id=0x1234, seq=7`, as Wireshark shows a query's fields.
std::string idAndSeq( const uint8_t* data )
{
    char buf[ 32 ];
    std::snprintf( buf, sizeof( buf ), " id=0x%04x, seq=%u", readBE16( data + 4 ),
                   static_cast<unsigned>( readBE16( data + 6 ) ) );
    return buf;
}

/// An address and port as `10.0.0.1:443` or `[2001:db8::1]:443`.
std::string endpoint( const std::string& address, uint16_t port )
{
    const bool v6 = address.find( ':' ) != std::string::npos;
    return ( v6 ? "[" + address + "]" : address ) + ":" + std::to_string( port );
}

/// ` for 10.0.0.1:443 → 192.168.1.5:51234 TCP`: the packet an error message
/// quotes behind its header, its ports only when the quote holds them.
/// Nothing when it does not hold a whole IP header.
std::string quotedPacket( const uint8_t* data, size_t len )
{
    if ( len <= kHeaderLen ) {
        return {};
    }
    PacketRecord quoted;
    dissectQuotedPacket( quoted, data + kHeaderLen, len - kHeaderLen );
    if ( quoted.srcIp.empty() ) {
        return {};
    }
    const auto* name = ipProtocolName( quoted.ipProtocol );
    const auto protocol = name ? name : "IP(" + std::to_string( quoted.ipProtocol ) + ")";
    if ( quoted.transport ) {
        return " for " + endpoint( quoted.srcIp, quoted.srcPort ) + " \xe2\x86\x92 "
               + endpoint( quoted.dstIp, quoted.dstPort ) + " " + protocol;
    }
    return " for " + quoted.srcIp + " \xe2\x86\x92 " + quoted.dstIp + " " + protocol;
}

/// The link-layer address of the first option of @p wanted type among the
/// neighbor discovery options at @p options, @p len bytes of them; empty
/// without one.  An option's length counts 8 bytes; one of 0 is invalid and
/// ends the walk, as one running past the captured bytes does.
std::string linkLayerAddress( const uint8_t* options, size_t len, uint8_t wanted )
{
    size_t at = 0;
    while ( len - at >= 2 && options[ at + 1 ] != 0 ) {
        const size_t optionLen = static_cast<size_t>( options[ at + 1 ] ) * 8;
        if ( optionLen > len - at ) {
            break;
        }
        if ( options[ at ] == wanted ) {
            return formatMac( options + at + 2 );
        }
        at += optionLen;
    }
    return {};
}

/// ` from 00:11:22:33:44:55` or ` is at …`: the link-layer address option
/// of @p type among the options from @p offset on; nothing without one.
std::string linkLayerPart( const uint8_t* data, size_t len, size_t offset, uint8_t type,
                           const char* lead )
{
    if ( len <= offset ) {
        return {};
    }
    const auto address = linkLayerAddress( data + offset, len - offset, type );
    return address.empty() ? std::string() : lead + address;
}

/// A router advertisement's flags and lifetime: ` (M, O, prf=high)
/// lifetime=1800s`.  M and O say where hosts get addresses and other
/// configuration from (RFC 4861), H marks a home agent (RFC 6275), P a proxy
/// (RFC 4389), and the router preference (RFC 4191) is named unless medium.
std::string routerAdvertisement( const uint8_t* data )
{
    const uint8_t flags = data[ 5 ];
    std::string list;
    auto add = [ &list ]( const char* flag ) {
        list += list.empty() ? flag : std::string( ", " ) + flag;
    };
    if ( flags & 0x80 ) {
        add( "M" );
    }
    if ( flags & 0x40 ) {
        add( "O" );
    }
    if ( flags & 0x20 ) {
        add( "H" );
    }
    if ( flags & 0x04 ) {
        add( "P" );
    }
    static const char* const kPreferences[] = { nullptr, "prf=high", "prf=reserved", "prf=low" };
    if ( const auto* preference = kPreferences[ ( flags >> 3 ) & 0x03 ] ) {
        add( preference );
    }
    return ( list.empty() ? std::string() : " (" + list + ")" )
           + " lifetime=" + std::to_string( readBE16( data + 6 ) ) + "s";
}

/// A neighbor advertisement's flags: ` (rtr, sol, ovr)`, as Wireshark
/// abbreviates router, solicited and override; nothing without flags.
std::string neighborFlags( uint8_t flags )
{
    std::string list;
    for ( const auto& [ bit, name ] :
          { std::pair{ 0x80, "rtr" }, std::pair{ 0x40, "sol" }, std::pair{ 0x20, "ovr" } } ) {
        if ( flags & bit ) {
            list += list.empty() ? name : std::string( ", " ) + name;
        }
    }
    return list.empty() ? list : " (" + list + ")";
}

} // anonymous namespace

std::string describeIcmp( const uint8_t* data, size_t len )
{
    const uint8_t type = data[ 0 ];
    const uint8_t code = data[ 1 ];
    auto info = typeName( kIcmpTypes, type, code );

    if ( isIcmpQuery( type ) ) {
        return info + idAndSeq( data );
    }
    switch ( type ) {
    case kUnreachable:
        info += " (" + codeName( kUnreachableCodes, code );
        if ( code == kFragmentationNeeded && readBE16( data + 6 ) != 0 ) {
            info += ", mtu=" + std::to_string( readBE16( data + 6 ) );
        }
        info += ")";
        break;
    case kRedirect:
        info += " (" + codeName( kRedirectCodes, code ) + ") gateway=" + formatIpv4( data + 4 );
        break;
    case kTimeExceeded:
        info += " (" + codeName( kTimeExceededCodes, code ) + ")";
        break;
    case kParameterProblem:
        info += " (" + codeName( kParameterProblemCodes, code ) + ")";
        break;
    case kSourceQuench:
        break;
    default:
        return info;
    }
    return info + quotedPacket( data, len );
}

std::string describeIcmpv6( const uint8_t* data, size_t len )
{
    const uint8_t type = data[ 0 ];
    const uint8_t code = data[ 1 ];
    auto info = typeName( kIcmpv6Types, type, code );

    // Neighbor solicitation and advertisement carry a 16-byte target behind
    // the header, their options follow it (RFC 4861 4.3, 4.4).
    constexpr size_t kTargetEnd = kHeaderLen + 16;

    switch ( type ) {
    case kV6EchoRequest:
    case kV6EchoReply:
        return info + idAndSeq( data );
    case kV6Unreachable:
        info += " (" + codeName( kV6UnreachableCodes, code ) + ")";
        break;
    case kV6PacketTooBig:
        info += " mtu=" + std::to_string( readBE32( data + 4 ) );
        break;
    case kV6TimeExceeded:
        info += " (" + codeName( kV6TimeExceededCodes, code ) + ")";
        break;
    case kV6ParameterProblem:
        info += " (" + codeName( kV6ParameterProblemCodes, code ) + ")";
        break;
    case kRouterSolicitation:
        return info + linkLayerPart( data, len, kHeaderLen, kSourceLinkLayerAddress, " from " );
    case kRouterAdvertisement:
        // Reachable time and retransmission timer take 8 bytes before the options.
        return info + routerAdvertisement( data )
               + linkLayerPart( data, len, kHeaderLen + 8, kSourceLinkLayerAddress, " from " );
    case kNeighborSolicitation:
        if ( len < kTargetEnd ) {
            return info;
        }
        return info + " for " + formatIpv6( data + kHeaderLen )
               + linkLayerPart( data, len, kTargetEnd, kSourceLinkLayerAddress, " from " );
    case kNeighborAdvertisement:
        if ( len < kTargetEnd ) {
            return info;
        }
        return info + " " + formatIpv6( data + kHeaderLen ) + neighborFlags( data[ 4 ] )
               + linkLayerPart( data, len, kTargetEnd, kTargetLinkLayerAddress, " is at " );
    default:
        return info;
    }
    return info + quotedPacket( data, len );
}

} // namespace tcpdump
