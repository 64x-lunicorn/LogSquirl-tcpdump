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
 * @file describe_dhcp_ntp.cpp
 * @brief The DHCP, DHCPv6 and NTP detectors of the Payload Describer.
 */

#include "describe_common.h"

#include <cstdio>
#include <string>

namespace tcpdump::describer {

// ── DHCP ─────────────────────────────────────────────────────────────────

namespace {

/// Where the BOOTP header (RFC 2131, 2) has the fields described: the
/// client's own address, the one the server assigns ("your" address), the
/// client hardware address, the server name and file fields, which an
/// overload option fills with options, and the options behind the magic
/// cookie.
constexpr size_t kDhcpCiaddrAt = 12;
constexpr size_t kDhcpYiaddrAt = 16;
constexpr size_t kDhcpChaddrAt = 28;
constexpr size_t kDhcpSnameAt = 44;
constexpr size_t kDhcpSnameBytes = 64;
constexpr size_t kDhcpFileAt = 108;
constexpr size_t kDhcpFileBytes = 128;
constexpr size_t kDhcpCookieAt = 236;
constexpr size_t kDhcpOptionsAt = 240;
constexpr uint32_t kDhcpMagicCookie = 0x63825363;

/// What the options of a DHCP message say that its description shows.
struct DhcpOptions {
    int messageType = -1;                      ///< Option 53; -1: none.
    const uint8_t* requestedAddress = nullptr; ///< Option 50.
    std::string hostName;                      ///< Option 12, as text.
    uint8_t overload = 0; ///< Option 52: 1 the file field, 2 sname, 3 both hold options.
};

/// Walk the options in @p field (RFC 2132, 2): pads skipped, up to the end
/// option or the end of the field.  An option whose length runs past the
/// field ends the walk; one of the wrong length is ignored.  Only the
/// options field itself may overload others (@p mayOverload).
void readDhcpOptions( FieldReader field, DhcpOptions& options, bool mayOverload )
{
    uint8_t code = 0;
    FieldReader value( nullptr, 0 );
    while ( field.u8( code ) && code != 255 ) {
        if ( code == 0 ) {
            continue;
        }
        if ( !field.takeVector8( value ) || !value.complete() ) {
            return;
        }
        const auto length = value.remaining();
        switch ( code ) {
        case 53:
            if ( length == 1 ) {
                options.messageType = value.here()[ 0 ];
            }
            break;
        case 50:
            if ( length == 4 ) {
                options.requestedAddress = value.here();
            }
            break;
        case 12:
            if ( length > 0 ) {
                options.hostName = fieldText( value.here(), length );
            }
            break;
        case 52:
            if ( mayOverload && length == 1 ) {
                options.overload = value.here()[ 0 ];
            }
            break;
        default:
            break;
        }
    }
}

/// A DHCP message type (option 53) as Wireshark names it, "DHCP Discover".
std::string dhcpMessageName( int type )
{
    static const char* const kNames[] = {
        nullptr,
        "Discover",
        "Offer",
        "Request",
        "Decline",
        "ACK",
        "NAK",
        "Release",
        "Inform",
        "Force Renew",
        "Lease query",
        "Lease Unassigned",
        "Lease Unknown",
        "Lease Active",
        "Bulk Lease Query",
        "Lease Query Done",
        "Active LeaseQuery",
        "Lease Query Status",
        "TLS",
    };
    if ( type > 0 && static_cast<size_t>( type ) < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return std::string( "DHCP " ) + kNames[ type ];
    }
    char buf[ 48 ];
    std::snprintf( buf, sizeof( buf ), "DHCP Unknown Message Type (0x%02x)", type );
    return buf;
}

/// A non-zero IPv4 address at @p at of the message, if it holds one there.
const uint8_t* dhcpAddress( const uint8_t* payload, size_t len, size_t at )
{
    if ( len < at + 4 || readBE32( payload + at ) == 0 ) {
        return nullptr;
    }
    return payload + at;
}

} // namespace

/// Describe a DHCP message like Wireshark, with the client and its address:
/// "DHCP Offer - Transaction ID 0x3903f326, 192.168.1.50 for
/// 00:11:22:33:44:55", "DHCP Discover - Transaction ID 0x3903f326 from
/// 00:11:22:33:44:55, Host Name: laptop".  The address is the one the
/// server assigns, else the one the client requests (option 50), else the
/// one it holds.  A message without a message type option (BOOTP) is a
/// "Boot Request" or "Boot Reply".  Options are read in the options field,
/// then in the file and sname fields if an overload option says they hold
/// options.  Empty if the payload is no BOOTP message, or shorter than its
/// transaction id.
std::string detectDhcp( const uint8_t* payload, size_t len )
{
    FieldReader header( payload, len );
    uint8_t op = 0;
    uint8_t htype = 0;
    uint8_t hlen = 0;
    uint32_t xid = 0;
    if ( !header.u8( op ) || ( op != 1 && op != 2 ) || !header.u8( htype ) || !header.u8( hlen )
         || !header.skip( 1 ) || !header.u32( xid ) ) {
        return {};
    }

    DhcpOptions options;
    if ( len >= kDhcpOptionsAt && readBE32( payload + kDhcpCookieAt ) == kDhcpMagicCookie ) {
        readDhcpOptions( { payload + kDhcpOptionsAt, len - kDhcpOptionsAt }, options, true );
        if ( options.overload & 1 ) {
            readDhcpOptions( { payload + kDhcpFileAt, kDhcpFileBytes }, options, false );
        }
        if ( options.overload & 2 ) {
            readDhcpOptions( { payload + kDhcpSnameAt, kDhcpSnameBytes }, options, false );
        }
    }

    char xidText[ 16 ];
    std::snprintf( xidText, sizeof( xidText ), "0x%08x", xid );
    std::string description = options.messageType >= 0
                                  ? dhcpMessageName( options.messageType )
                                  : ( op == 1 ? "Boot Request" : "Boot Reply" );
    description += std::string( " - Transaction ID " ) + xidText;

    const uint8_t* address = dhcpAddress( payload, len, kDhcpYiaddrAt );
    if ( !address ) {
        address = options.requestedAddress;
    }
    if ( !address ) {
        address = dhcpAddress( payload, len, kDhcpCiaddrAt );
    }
    const bool ethernet = htype == 1 && hlen == 6 && len >= kDhcpChaddrAt + 6;
    if ( address ) {
        description += ", " + formatIpv4( address );
    }
    if ( ethernet ) {
        description
            += ( address || op == 2 ? " for " : " from " ) + formatMac( payload + kDhcpChaddrAt );
    }
    if ( !options.hostName.empty() ) {
        description += ", Host Name: " + options.hostName;
    }
    return description;
}

// ── DHCPv6 ───────────────────────────────────────────────────────────────

namespace {

/// Most relays one message is looked into: RFC 8415, 7.6, lets a message
/// pass at most 8 of them.
constexpr int kMaxDhcpv6Relays = 8;

/// Most bytes of a DUID shown, as hexadecimal.
constexpr size_t kMaxDuidBytes = 32;

constexpr uint8_t kDhcpv6RelayForward = 12;
constexpr uint8_t kDhcpv6RelayReply = 13;

/// A DHCPv6 message type as Wireshark names it, "Solicit", or "Unknown (99)".
std::string dhcpv6MessageName( uint8_t type )
{
    static const char* const kNames[] = {
        nullptr,
        "Solicit",
        "Advertise",
        "Request",
        "Confirm",
        "Renew",
        "Rebind",
        "Reply",
        "Release",
        "Decline",
        "Reconfigure",
        "Information-request",
        "Relay-forw",
        "Relay-reply",
        "Leasequery",
        "Leasequery-reply",
        "Leasequery-done",
        "Leasequery-data",
        "Reconfigure-request",
        "Reconfigure-reply",
        "DHCPv4-query",
        "DHCPv4-response",
    };
    if ( type > 0 && type < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return kNames[ type ];
    }
    return "Unknown (" + std::to_string( type ) + ")";
}

/// Describe a DHCPv6 message like Wireshark: "Solicit XID: 0x1a2b3c CID:
/// 000100011c39cf88001122334455", the client's DUID (option 1) if it has
/// one; a relay message names its link address and the message it relays
/// (option 9), "Relay-forw L: 2001:db8::1, Solicit XID: …", up to
/// kMaxDhcpv6Relays deep.  Options are walked within the message; one whose
/// length runs past it ends the walk.  Empty if the message is shorter than
/// its header.
std::string describeDhcpv6( FieldReader message, int relays = 0 )
{
    uint8_t type = 0;
    if ( !message.u8( type ) ) {
        return {};
    }
    const bool relay = type == kDhcpv6RelayForward || type == kDhcpv6RelayReply;
    std::string description = dhcpv6MessageName( type );
    if ( relay ) {
        if ( message.remaining() < 1 + 16 + 16 ) {
            return {};
        }
        description += " L: " + formatIpv6( message.here() + 1 );
        message.skip( 1 + 16 + 16 );
    }
    else {
        uint32_t xid = 0;
        if ( !message.u24( xid ) ) {
            return {};
        }
        char xidText[ 16 ];
        std::snprintf( xidText, sizeof( xidText ), " XID: 0x%06x", xid );
        description += xidText;
    }

    uint16_t code = 0;
    FieldReader value( nullptr, 0 );
    while ( message.u16( code ) && message.takeVector16( value ) && value.complete() ) {
        if ( !relay && code == 1 && value.remaining() > 0 ) {
            description += " CID: " + hexBytes( value.here(), value.remaining(), kMaxDuidBytes );
            break;
        }
        if ( relay && code == 9 ) {
            const auto relayed
                = relays < kMaxDhcpv6Relays ? describeDhcpv6( value, relays + 1 ) : std::string();
            if ( !relayed.empty() ) {
                description += ", " + relayed;
            }
            break;
        }
    }
    return description;
}

} // namespace

std::string detectDhcpv6( const uint8_t* payload, size_t len )
{
    return describeDhcpv6( { payload, len } );
}

// ── NTP ──────────────────────────────────────────────────────────────────

namespace {

/// The NTP header of modes 0 to 5 (RFC 5905, 7.3), without extensions.
constexpr size_t kNtpHeaderBytes = 48;
constexpr uint8_t kNtpModeClient = 3;
constexpr uint8_t kNtpModeControl = 6;

/// An NTP mode as Wireshark's Info names it.
const char* ntpModeName( uint8_t mode )
{
    static const char* const kNames[] = {
        "reserved", "symmetric active", "symmetric passive", "client",
        "server",   "broadcast",        "control",           "private",
    };
    return kNames[ mode & 7 ];
}

/// The reference identifier of a stratum 0 or 1 packet as text: a
/// kiss-o'-death code ("RATE") or the primary source ("GPS"), padded with
/// NULs; empty unless it is printable ASCII.
std::string ntpReferenceText( const uint8_t* id )
{
    size_t length = 4;
    while ( length > 0 && id[ length - 1 ] == 0 ) {
        --length;
    }
    for ( size_t i = 0; i < length; ++i ) {
        if ( id[ i ] < 0x20 || id[ i ] >= 0x7F ) {
            return {};
        }
    }
    return std::string( reinterpret_cast<const char*>( id ), length );
}

} // namespace

/// Describe an NTP packet like Wireshark, "NTP Version 4, server", then its
/// stratum, "stratum 2", with the reference identifier of a primary server
/// or a kiss-o'-death, "stratum 1 (GPS)".  The stratum of a client request,
/// 0 as a rule, is left out unless it is set.  Control (mode 6) and private
/// (mode 7) messages have another header: only their version and mode are
/// shown.  Empty if the version is not 1 to 4, or the packet of mode 0 to 5
/// shorter than its header.
std::string detectNtp( const uint8_t* payload, size_t len )
{
    if ( len < 1 ) {
        return {};
    }
    const uint8_t version = ( payload[ 0 ] >> 3 ) & 7;
    const uint8_t mode = payload[ 0 ] & 7;
    if ( version < 1 || version > 4 || ( mode < kNtpModeControl && len < kNtpHeaderBytes ) ) {
        return {};
    }
    std::string description
        = "NTP Version " + std::to_string( version ) + ", " + ntpModeName( mode );
    if ( mode >= kNtpModeControl ) {
        return description;
    }
    const uint8_t stratum = payload[ 1 ];
    if ( mode == kNtpModeClient && stratum == 0 ) {
        return description;
    }
    description += ", stratum " + std::to_string( stratum );
    if ( stratum <= 1 ) {
        const auto reference = ntpReferenceText( payload + 12 );
        if ( !reference.empty() ) {
            description += " (" + reference + ")";
        }
    }
    return description;
}

} // namespace tcpdump::describer
