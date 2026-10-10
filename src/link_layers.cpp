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
 * @file link_layers.cpp
 * @brief IEEE 802.11 with and without Radiotap, PPP, Cisco HDLC and PPPoE.
 *
 * Frame names follow Wireshark's: `Beacon frame`, `QoS Data`, `Configuration
 * Request`, `Active Discovery Offer (PADO)`.  Every header is checked against
 * the captured bytes before it is read; a frame cut inside one is named as
 * such.
 */

#include "link_layers.h"

#include "describe_common.h"
#include "packet_layers.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstdio>
#include <iterator>
#include <string>

namespace tcpdump {

namespace {

uint16_t readLE16( const uint8_t* p )
{
    return static_cast<uint16_t>( p[ 0 ] | ( p[ 1 ] << 8 ) );
}

uint32_t readLE32( const uint8_t* p )
{
    return static_cast<uint32_t>( readLE16( p ) )
           | ( static_cast<uint32_t>( readLE16( p + 2 ) ) << 16 );
}

std::string hex16( uint16_t value )
{
    char hex[ 8 ];
    std::snprintf( hex, sizeof( hex ), "0x%04X", value );
    return hex;
}

/// A layer @p name of the @p len bytes at @p data, which are not read further.
void bodyLayer( PacketRecord& pkt, const char* name, const uint8_t* data, size_t len )
{
    if ( auto* layers = pkt.layers; layers && len > 0 ) {
        layers->layer( name, data, len );
        layers->field( "Length", std::to_string( len ) + " bytes", nullptr, 0 );
    }
}

// ── PPP ──────────────────────────────────────────────────────────────────

constexpr uint16_t kPppIpv4 = 0x0021;
constexpr uint16_t kPppIpv6 = 0x0057;

/// A PPP control protocol: its protocol number, label and code names.
struct ControlProtocol {
    uint16_t number;
    const char* label;
    const char* const* codes; ///< Names of codes 1, 2, …
    size_t codeCount;
};

/// The codes of LCP (RFC 1661, 1570), and the first seven of the network
/// control protocols built on it (IPCP, IPv6CP, CCP).
constexpr const char* kLcpCodes[] = {
    "Configuration Request", "Configuration Ack", "Configuration Nak", "Configuration Reject",
    "Termination Request",   "Termination Ack",   "Code Reject",       "Protocol Reject",
    "Echo Request",          "Echo Reply",        "Discard Request",   "Identification",
    "Time Remaining",
};
constexpr size_t kNcpCodeCount = 7;
constexpr const char* kPapCodes[]
    = { "Authenticate-Request", "Authenticate-Ack", "Authenticate-Nak" };
constexpr const char* kChapCodes[] = { "Challenge", "Response", "Success", "Failure" };

constexpr ControlProtocol kControlProtocols[] = {
    { 0xC021, "LCP", kLcpCodes, std::size( kLcpCodes ) },
    { 0x8021, "IPCP", kLcpCodes, kNcpCodeCount },
    { 0x8057, "IPv6CP", kLcpCodes, kNcpCodeCount },
    { 0x80FD, "CCP", kLcpCodes, kNcpCodeCount },
    { 0xC023, "PAP", kPapCodes, std::size( kPapCodes ) },
    { 0xC223, "CHAP", kChapCodes, std::size( kChapCodes ) },
};

/// Describe a packet of a PPP control protocol into @p pkt: its code's name.
/// What follows the code (options, names, passwords) is not shown.
void describeControl( PacketRecord& pkt, const ControlProtocol& cp, const uint8_t* data,
                      size_t len )
{
    pkt.protocol = cp.label;
    if ( len < 4 ) {
        pkt.info = std::string( "Truncated " ) + cp.label + " packet";
        bodyLayer( pkt, cp.label, data, len );
        return;
    }
    const uint8_t code = data[ 0 ];
    pkt.info = code >= 1 && code <= cp.codeCount ? cp.codes[ code - 1 ]
                                                 : "Code " + std::to_string( code );
    if ( auto* layers = pkt.layers ) {
        layers->layer( cp.label, data, len );
        layers->field( "Code", pkt.info + " (" + std::to_string( code ) + ")", data, 1 );
        layers->field( "Identifier", std::to_string( data[ 1 ] ), data + 1, 1 );
        layers->field( "Length", std::to_string( readBE16( data + 2 ) ), data + 2, 2 );
    }
}

/// Dissect a PPP frame from its protocol field on (RFC 1661): IP is handed
/// on, a control protocol described.  A protocol field of one byte (an odd
/// first byte) was compressed.  A frame cut inside the field is named as
/// one of @p carrier ("PPP", "PPPoES").
std::optional<NetworkLayer> dissectPppProtocol( PacketRecord& pkt, const uint8_t* data, size_t len,
                                                const char* carrier = "PPP" )
{
    const size_t fieldLen = len >= 1 && ( data[ 0 ] & 1 ) ? 1 : 2;
    if ( len < fieldLen ) {
        pkt.protocol = carrier;
        pkt.info = "Truncated PPP header";
        return std::nullopt;
    }
    const uint16_t protocol = fieldLen == 1 ? data[ 0 ] : readBE16( data );
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Point-to-Point Protocol", data, fieldLen );
        layers->field( "Protocol", hex16( protocol ), data, fieldLen );
    }
    data += fieldLen;
    len -= fieldLen;
    if ( protocol == kPppIpv4 ) {
        return NetworkLayer{ EthertypeIpv4, data, len };
    }
    if ( protocol == kPppIpv6 ) {
        return NetworkLayer{ EthertypeIpv6, data, len };
    }
    for ( const auto& cp : kControlProtocols ) {
        if ( cp.number == protocol ) {
            describeControl( pkt, cp, data, len );
            return std::nullopt;
        }
    }
    pkt.protocol = "PPP";
    pkt.info = "PPP protocol " + hex16( protocol );
    bodyLayer( pkt, "Data", data, len );
    return std::nullopt;
}

/// PPP with HDLC-like framing (RFC 1662): address 0xFF and control 0x03,
/// which a link may leave out (address and control field compression).
std::optional<NetworkLayer> dissectPpp( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    // No protocol starts with 0xFF, so it is the address.
    if ( len >= 1 && data[ 0 ] == 0xFF ) {
        const size_t framing = std::min<size_t>( len, 2 );
        return dissectPppProtocol( pkt, data + framing, len - framing );
    }
    return dissectPppProtocol( pkt, data, len );
}

/// Cisco HDLC: an address (0x0F unicast, 0x8F multicast), control 0x00 and
/// an EtherType.
std::optional<NetworkLayer> dissectCiscoHdlc( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    if ( len < 4 ) {
        pkt.protocol = "CHDLC";
        pkt.info = "Truncated Cisco HDLC header";
        bodyLayer( pkt, "Cisco HDLC (truncated)", data, len );
        return std::nullopt;
    }
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Cisco HDLC", data, 4 );
        layers->field( "Address", describer::hexCode( data[ 0 ] ), data, 1 );
        layers->field( "Control", describer::hexCode( data[ 1 ] ), data + 1, 1 );
        layers->field( "Protocol", etherTypeField( readBE16( data + 2 ) ), data + 2, 2 );
    }
    return NetworkLayer{ readBE16( data + 2 ), data + 4, len - 4 };
}

/// DLT_PPP_SERIAL holds PPP in HDLC-like framing, or Cisco HDLC frames,
/// told apart by their address byte.
std::optional<NetworkLayer> dissectPppSerial( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    if ( len >= 1 && ( data[ 0 ] == 0x0F || data[ 0 ] == 0x8F ) ) {
        return dissectCiscoHdlc( pkt, data, len );
    }
    return dissectPpp( pkt, data, len );
}

// ── PPPoE ────────────────────────────────────────────────────────────────

constexpr uint8_t kPppoeSession = 0x00;
constexpr uint16_t kTagEndOfList = 0x0000;
constexpr uint16_t kTagAcName = 0x0102;

/// The name of PPPoE discovery code @p code (RFC 2516), as Wireshark gives it.
const char* discoveryName( uint8_t code )
{
    switch ( code ) {
    case 0x09:
        return "Active Discovery Initiation (PADI)";
    case 0x07:
        return "Active Discovery Offer (PADO)";
    case 0x19:
        return "Active Discovery Request (PADR)";
    case 0x65:
        return "Active Discovery Session-confirmation (PADS)";
    case 0xA7:
        return "Active Discovery Terminate (PADT)";
    default:
        return nullptr;
    }
}

/// Describe a PPPoE discovery message, its @p len bytes of tags at @p tags,
/// into @p pkt: its name and the access concentrator's name.
void describeDiscovery( PacketRecord& pkt, uint8_t code, const uint8_t* tags, size_t len )
{
    pkt.protocol = "PPPoED";
    const auto* name = discoveryName( code );
    if ( !name ) {
        char hex[ 8 ];
        std::snprintf( hex, sizeof( hex ), "0x%02X", code );
        pkt.info = std::string( "Code " ) + hex;
        return;
    }
    pkt.info = name;
    for ( size_t at = 0; len - at >= 4; ) {
        const uint16_t type = readBE16( tags + at );
        const size_t valueLen = readBE16( tags + at + 2 );
        if ( type == kTagEndOfList || valueLen > len - at - 4 ) {
            break;
        }
        if ( type == kTagAcName ) {
            pkt.info += " AC-Name='" + describer::fieldText( tags + at + 4, valueLen ) + "'";
            break;
        }
        at += 4 + valueLen;
    }
}

// ── 802.11 ───────────────────────────────────────────────────────────────

constexpr uint8_t kTypeManagement = 0;
constexpr uint8_t kTypeControl = 1;
constexpr uint8_t kTypeData = 2;

/// Frame control flags, its second byte.
constexpr uint8_t kToDs = 0x01;
constexpr uint8_t kFromDs = 0x02;
constexpr uint8_t kMoreFragments = 0x04;
constexpr uint8_t kProtected = 0x40;
constexpr uint8_t kOrder = 0x80; ///< With QoS data or management: an HT control field

/// Duration, then the first address, of every frame.
constexpr size_t kAddress1 = 4;
constexpr size_t kAddress2 = 10;
constexpr size_t kAddress3 = 16;
constexpr size_t kSequenceControl = 22;
constexpr size_t kAddress4 = 24;
constexpr size_t kMacHeaderLen = 24; ///< Of a management or three-address data frame.

constexpr const char* kManagementNames[ 16 ] = {
    "Association Request",   "Association Response",
    "Reassociation Request", "Reassociation Response",
    "Probe Request",         "Probe Response",
    "Measurement Pilot",     nullptr,
    "Beacon frame",          "ATIM",
    "Disassociate",          "Authentication",
    "Deauthentication",      "Action",
    "Action No Ack",         nullptr,
};

constexpr const char* kControlNames[ 16 ] = {
    nullptr,
    nullptr,
    "Trigger",
    "TACK",
    "Beamforming Report Poll",
    "NDP Announcement",
    "Control Frame Extension",
    "Control Wrapper",
    "802.11 Block Ack Req",
    "802.11 Block Ack",
    "Power-Save poll",
    "Request-to-send",
    "Clear-to-send",
    "Acknowledgement",
    "CF-End",
    "CF-End + CF-Ack",
};

constexpr const char* kDataNames[ 16 ] = {
    "Data",
    "Data + CF-Ack",
    "Data + CF-Poll",
    "Data + CF-Ack + CF-Poll",
    "Null function (No data)",
    "Acknowledgement (No data)",
    "CF-poll (No data)",
    "CF-Ack/Poll (No data)",
    "QoS Data",
    "QoS Data + CF-Acknowledgment",
    "QoS Data + CF-Poll",
    "QoS Data + CF-Ack + CF-Poll",
    "QoS Null function (No data)",
    nullptr,
    "QoS CF-Poll (No Data)",
    "QoS CF-Ack + CF-Poll (No data)",
};

/// The name of a frame of @p type and @p subtype.
std::string frameName( uint8_t type, uint8_t subtype )
{
    const char* name = nullptr;
    switch ( type ) {
    case kTypeManagement:
        name = kManagementNames[ subtype ];
        break;
    case kTypeControl:
        name = kControlNames[ subtype ];
        break;
    case kTypeData:
        name = kDataNames[ subtype ];
        break;
    default:
        name = subtype == 0 ? "DMG Beacon" : subtype == 1 ? "S1G Beacon" : nullptr;
        break;
    }
    if ( name ) {
        return name;
    }
    return "Reserved frame (type " + std::to_string( type ) + ", subtype "
           + std::to_string( subtype ) + ")";
}

/// `, SSID="…"` for the SSID element among the information elements at
/// @p elements, @p len bytes of them; empty without a whole one.  An empty
/// SSID is the wildcard of a probe request.
std::string ssidOf( const uint8_t* elements, size_t len )
{
    constexpr uint8_t kSsid = 0;
    for ( size_t at = 0; len - at >= 2; at += 2 + elements[ at + 1 ] ) {
        const size_t valueLen = elements[ at + 1 ];
        if ( valueLen > len - at - 2 ) {
            break;
        }
        if ( elements[ at ] == kSsid ) {
            if ( valueLen == 0 ) {
                return ", SSID=Wildcard (Broadcast)";
            }
            const auto* ssid = elements + at + 2;
            const size_t shown = std::min( valueLen, describer::kMaxFieldBytes );
            return ", SSID=\"" + describer::escapeBytes( ssid, shown, true )
                   + ( shown < valueLen ? "\xe2\x80\xa6" : "" ) + "\"";
        }
    }
    return {};
}

/// What Info adds for a management frame's @p body: a beacon's interval
/// and the SSID of the frames that carry one.
std::string managementDetails( uint8_t subtype, const uint8_t* body, size_t len )
{
    // Fixed fields ahead of the information elements.
    size_t fixed = 0;
    switch ( subtype ) {
    case 0: // Association request: capabilities, listen interval
        fixed = 4;
        break;
    case 2: // Reassociation request: also the current AP's address
        fixed = 10;
        break;
    case 4: // Probe request: elements only
        break;
    case 5: // Probe response and beacon: timestamp, interval, capabilities
    case 8:
        if ( len < 12 ) {
            return {};
        }
        return ", BI=" + std::to_string( readLE16( body + 8 ) ) + ssidOf( body + 12, len - 12 );
    default:
        return {};
    }
    return len >= fixed ? ssidOf( body + fixed, len - fixed ) : std::string();
}

/// The data a data frame carries, LLC/SNAP first: the network layer by its
/// EtherType, or anything else as LLC.
std::optional<NetworkLayer> dissectLlc( PacketRecord& pkt, const std::string& summary,
                                        const uint8_t* data, size_t len )
{
    if ( len >= 8 && data[ 0 ] == 0xAA && data[ 1 ] == 0xAA && data[ 2 ] == 0x03
         && data[ 3 ] == 0x00 && data[ 4 ] == 0x00 && ( data[ 5 ] == 0x00 || data[ 5 ] == 0xF8 ) ) {
        if ( auto* layers = pkt.layers ) {
            layers->layer( "Logical-Link Control", data, 8 );
            layers->field( "DSAP", describer::hexCode( data[ 0 ] ), data, 1 );
            layers->field( "SSAP", describer::hexCode( data[ 1 ] ), data + 1, 1 );
            layers->field( "Type", etherTypeField( readBE16( data + 6 ) ), data + 6, 2 );
        }
        return NetworkLayer{ readBE16( data + 6 ), data + 8, len - 8 };
    }
    bodyLayer( pkt, "Logical-Link Control", data, len );
    if ( len < 2 ) {
        pkt.protocol = "802.11";
        pkt.info = summary;
        return std::nullopt;
    }
    pkt.protocol = "LLC";
    pkt.info = summary + ", DSAP " + describer::hexCode( data[ 0 ] ) + " SSAP "
               + describer::hexCode( data[ 1 ] );
    return std::nullopt;
}

/// Dissect an IEEE 802.11 frame.  @p padded: Radiotap says the MAC header
/// is padded to a multiple of 4 bytes.
std::optional<NetworkLayer> dissectIeee80211( PacketRecord& pkt, const uint8_t* data, size_t len,
                                              bool padded )
{
    pkt.protocol = "802.11";
    if ( len < 10 ) {
        pkt.info = "Truncated 802.11 header";
        return std::nullopt;
    }
    const uint8_t type = ( data[ 0 ] >> 2 ) & 0x03;
    const uint8_t subtype = data[ 0 ] >> 4;
    const uint8_t flags = data[ 1 ];
    if ( ( data[ 0 ] & 0x03 ) != 0 ) {
        pkt.info = "Unknown 802.11 protocol version " + std::to_string( data[ 0 ] & 0x03 );
        return std::nullopt;
    }
    const auto name = frameName( type, subtype );
    if ( auto* layers = pkt.layers ) {
        // The whole MAC header once its length is known, below; until then
        // the fields every frame has.
        layers->layer( "IEEE 802.11 " + name, data, 10 );
        layers->field( "Frame Control", hex16( readBE16( data ) ), data, 2 );
        layers->field( "Duration", std::to_string( readLE16( data + 2 ) ), data + 2, 2 );
        layers->field( "Receiver Address", formatMac( data + kAddress1 ), data + kAddress1, 6 );
    }

    if ( type == kTypeControl ) {
        // Every control frame names its receiver; most also the transmitter.
        pkt.dstMac = formatMac( data + kAddress1 );
        const bool receiverOnly = subtype == 6 || subtype == 7 || subtype == 12 || subtype == 13;
        if ( !receiverOnly && len >= kAddress2 + 6 ) {
            pkt.srcMac = formatMac( data + kAddress2 );
        }
        pkt.info = name;
        return std::nullopt;
    }
    if ( type != kTypeManagement && type != kTypeData ) {
        pkt.info = name;
        return std::nullopt;
    }

    const bool toDs = flags & kToDs;
    const bool fromDs = flags & kFromDs;
    const bool qos = type == kTypeData && ( subtype & 0x08 );
    size_t headerLen = kMacHeaderLen + ( toDs && fromDs && type == kTypeData ? 6 : 0 );
    const size_t qosAt = headerLen;
    headerLen += qos ? 2 : 0;
    if ( ( flags & kOrder ) && ( qos || type == kTypeManagement ) ) {
        headerLen += 4; // HT control
    }
    if ( len < headerLen ) {
        pkt.info = "Truncated 802.11 header";
        return std::nullopt;
    }

    // Source and destination: SA and DA, which of the addresses they are
    // depends on the direction (IEEE 802.11-2020, 9.3.2.1).
    size_t sa = kAddress2;
    size_t da = kAddress1;
    if ( type == kTypeData ) {
        if ( toDs && fromDs ) {
            sa = kAddress4;
            da = kAddress3;
        }
        else if ( toDs ) {
            da = kAddress3;
        }
        else if ( fromDs ) {
            sa = kAddress3;
        }
    }
    pkt.srcMac = formatMac( data + sa );
    pkt.dstMac = formatMac( data + da );

    const uint16_t sequence = readLE16( data + kSequenceControl );
    const uint16_t fragment = sequence & 0x0F;
    if ( auto* layers = pkt.layers ) {
        layers->setLength( headerLen );
        layers->field( "Transmitter Address", formatMac( data + kAddress2 ), data + kAddress2, 6 );
        layers->field( "Address 3", formatMac( data + kAddress3 ), data + kAddress3, 6 );
        if ( headerLen >= kAddress4 + 6 && type == kTypeData && toDs && fromDs ) {
            layers->field( "Address 4", formatMac( data + kAddress4 ), data + kAddress4, 6 );
        }
        layers->field( "Source Address", pkt.srcMac, data + sa, 6 );
        layers->field( "Destination Address", pkt.dstMac, data + da, 6 );
        layers->field( "Sequence Number", std::to_string( sequence >> 4 ), data + kSequenceControl,
                       2 );
        layers->field( "Fragment Number", std::to_string( fragment ), data + kSequenceControl, 1 );
    }
    const auto summary
        = name + ", SN=" + std::to_string( sequence >> 4 ) + ", FN=" + std::to_string( fragment );
    pkt.info = summary;
    if ( flags & kProtected ) {
        pkt.info += ", Protected";
        bodyLayer( pkt, "Data (protected)", data + headerLen, len - headerLen );
        return std::nullopt;
    }

    if ( padded ) {
        headerLen = ( headerLen + 3 ) / 4 * 4;
    }
    const uint8_t* body = data + std::min( headerLen, len );
    const size_t bodyLen = len - std::min( headerLen, len );

    if ( type == kTypeManagement ) {
        pkt.info += managementDetails( subtype, body, bodyLen );
        bodyLayer( pkt, "IEEE 802.11 Wireless Management", body, bodyLen );
        return std::nullopt;
    }
    if ( subtype & 0x04 ) {
        return std::nullopt; // no data
    }
    if ( fragment != 0 || ( flags & kMoreFragments ) ) {
        pkt.info += ", Fragmented";
        return std::nullopt;
    }
    if ( qos && ( data[ qosAt ] & 0x80 ) ) {
        pkt.info += ", A-MSDU";
        return std::nullopt;
    }
    return dissectLlc( pkt, summary, body, bodyLen );
}

/// Dissect a Radiotap header (radiotap.org), then the 802.11 frame behind
/// it.  Of its fields, only the flags are read, for a frame check sequence
/// at the end of the frame and padding behind the MAC header.
std::optional<NetworkLayer> dissectRadiotap( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    pkt.protocol = "Radiotap";
    if ( len < 8 ) {
        pkt.info = "Truncated Radiotap header";
        return std::nullopt;
    }
    if ( data[ 0 ] != 0 ) {
        pkt.info = "Radiotap version " + std::to_string( data[ 0 ] );
        return std::nullopt;
    }
    const size_t headerLen = readLE16( data + 2 );
    if ( headerLen < 8 || headerLen > len ) {
        pkt.info = "Invalid Radiotap header length " + std::to_string( headerLen );
        return std::nullopt;
    }
    if ( auto* layers = pkt.layers ) {
        layers->layer( "Radiotap Header", data, headerLen );
        layers->field( "Version", "0", data, 1 );
        layers->field( "Length", std::to_string( headerLen ), data + 2, 2 );
        layers->field( "Present Flags", hexField( readLE32( data + 4 ), 8 ), data + 4, 4 );
    }

    // The present bitmaps: bit 31 of each says another follows.  The fields
    // start behind the last one, each aligned to its size from the start of
    // the header.
    constexpr uint32_t kTsft = 0x01;
    constexpr uint32_t kFlags = 0x02;
    constexpr uint32_t kExtended = 0x80000000;
    const uint32_t present = readLE32( data + 4 );
    size_t at = 8;
    for ( uint32_t word = present; word & kExtended; at += 4 ) {
        if ( at + 4 > headerLen ) {
            pkt.info = "Invalid Radiotap header length " + std::to_string( headerLen );
            return std::nullopt;
        }
        word = readLE32( data + at );
    }
    uint8_t flags = 0;
    if ( present & kTsft ) {
        at = ( at + 7 ) / 8 * 8 + 8;
    }
    if ( ( present & kFlags ) && at < headerLen ) {
        flags = data[ at ];
    }

    constexpr uint8_t kFcsAtEnd = 0x10;
    constexpr uint8_t kDataPad = 0x20;
    size_t frameLen = len - headerLen;
    // The FCS is only in the captured bytes when the whole frame was captured.
    if ( ( flags & kFcsAtEnd ) && frameLen >= 4 && pkt.capturedLen >= pkt.originalLen ) {
        frameLen -= 4;
    }
    return dissectIeee80211( pkt, data + headerLen, frameLen, flags & kDataPad );
}

} // namespace

bool dissectsLinkLayer( uint32_t linkType )
{
    switch ( linkType ) {
    case DltPpp:
    case DltPppSerial:
    case DltPppEther:
    case DltCiscoHdlc:
    case DltIeee80211:
    case DltIeee80211Radio:
        return true;
    default:
        return false;
    }
}

std::optional<NetworkLayer> dissectLinkLayer( PacketRecord& pkt, uint32_t linkType,
                                              const uint8_t* data, size_t len )
{
    switch ( linkType ) {
    case DltPpp:
        return dissectPpp( pkt, data, len );
    case DltPppSerial:
        return dissectPppSerial( pkt, data, len );
    case DltPppEther:
        return dissectPppoe( pkt, data, len );
    case DltCiscoHdlc:
        return dissectCiscoHdlc( pkt, data, len );
    case DltIeee80211:
        return dissectIeee80211( pkt, data, len, false );
    case DltIeee80211Radio:
        return dissectRadiotap( pkt, data, len );
    default:
        return std::nullopt;
    }
}

std::optional<NetworkLayer> dissectPppoe( PacketRecord& pkt, const uint8_t* data, size_t len )
{
    // Version and type (1 and 1), code, session ID, length (RFC 2516).
    if ( len < 6 ) {
        pkt.protocol = len >= 2 && data[ 1 ] != kPppoeSession ? "PPPoED" : "PPPoES";
        pkt.info = "Truncated PPPoE header";
        return std::nullopt;
    }
    const uint8_t code = data[ 1 ];
    // The length bounds what follows, as Ethernet pads a short frame.
    const size_t payloadLen = std::min<size_t>( readBE16( data + 4 ), len - 6 );
    if ( auto* layers = pkt.layers ) {
        layers->layer( "PPP-over-Ethernet", data, 6 );
        layers->field( "Version", std::to_string( data[ 0 ] >> 4 ), data, 1 );
        layers->field( "Type", std::to_string( data[ 0 ] & 0x0F ), data, 1 );
        layers->field( "Code", describer::hexCode( code ), data + 1, 1 );
        layers->field( "Session ID", hex16( readBE16( data + 2 ) ), data + 2, 2 );
        layers->field( "Payload Length", std::to_string( readBE16( data + 4 ) ), data + 4, 2 );
    }
    if ( code != kPppoeSession ) {
        describeDiscovery( pkt, code, data + 6, payloadLen );
        bodyLayer( pkt, "PPPoE Tags", data + 6, payloadLen );
        return std::nullopt;
    }
    return dissectPppProtocol( pkt, data + 6, payloadLen, "PPPoES" );
}

} // namespace tcpdump
