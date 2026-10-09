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
 * @file describe_rtp.cpp
 * @brief RTP and RTCP packets of the Payload Describer, described where an
 *        SDP body announced them (media_expectations.h): RTP's header with
 *        its payload type named as RFC 3551 names it, the RTCP packets of a
 *        compound packet by their types.
 */

#include "describe_common.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── RTP and RTCP ─────────────────────────────────────────────────────────

namespace {

constexpr size_t kRtpHeaderBytes = 12;
constexpr size_t kRtcpHeaderBytes = 4;

/// Most RTCP packets of a compound packet named.
constexpr size_t kMaxRtcpPackets = 4;

/// RTCP's packet types (RFC 3550, 3611, 4585): the second byte of an RTCP
/// header, which an RTP header with the marker set and a payload type of
/// 72 to 79 would have, the reason RFC 3551 leaves those unassigned.
constexpr uint8_t kRtcpFirstType = 200;
constexpr uint8_t kRtcpLastType = 207;

/// The encoding name of an RTP payload type RFC 3551 assigns, or null.
const char* rtpPayloadTypeName( uint8_t type )
{
    switch ( type ) {
    case 0:
        return "PCMU";
    case 3:
        return "GSM";
    case 4:
        return "G723";
    case 5:
    case 6:
    case 16:
    case 17:
        return "DVI4";
    case 7:
        return "LPC";
    case 8:
        return "PCMA";
    case 9:
        return "G722";
    case 10:
    case 11:
        return "L16";
    case 12:
        return "QCELP";
    case 13:
        return "CN";
    case 14:
        return "MPA";
    case 15:
        return "G728";
    case 18:
        return "G729";
    case 25:
        return "CelB";
    case 26:
        return "JPEG";
    case 28:
        return "nv";
    case 31:
        return "H261";
    case 32:
        return "MPV";
    case 33:
        return "MP2T";
    case 34:
        return "H263";
    default:
        return nullptr;
    }
}

const char* rtcpTypeName( uint8_t type )
{
    switch ( type ) {
    case 200:
        return "Sender Report";
    case 201:
        return "Receiver Report";
    case 202:
        return "Source description";
    case 203:
        return "Goodbye";
    case 204:
        return "Application specific";
    case 205:
        return "Generic RTP Feedback";
    case 206:
        return "Payload-specific Feedback";
    case 207:
        return "Extended report";
    default:
        return nullptr;
    }
}

} // namespace

bool isRtcpHeader( const uint8_t* p, size_t len )
{
    return len >= 2 && ( p[ 0 ] >> 6 ) == 2 && p[ 1 ] >= kRtcpFirstType && p[ 1 ] <= kRtcpLastType;
}

std::string describeRtp( const uint8_t* p, size_t len, size_t wireLen )
{
    if ( len < kRtpHeaderBytes || ( p[ 0 ] >> 6 ) != 2 || isRtcpHeader( p, len ) ) {
        return {};
    }
    const uint8_t type = p[ 1 ] & 0x7F;
    const bool marker = ( p[ 1 ] & 0x80 ) != 0;
    const size_t csrcs = p[ 0 ] & 0x0F;
    std::string text = "PT=";
    if ( const char* name = rtpPayloadTypeName( type ) ) {
        text += name;
    }
    else if ( type >= 96 ) {
        text += "DynamicRTP-Type-" + std::to_string( type );
    }
    else {
        text += std::to_string( type );
    }
    text += ", SSRC=" + hexValue( readBE32( p + 8 ), 8 ) + ", Seq="
            + std::to_string( readBE16( p + 2 ) ) + ", Time=" + std::to_string( readBE32( p + 4 ) );
    if ( marker ) {
        text += ", Mark";
    }
    if ( kRtpHeaderBytes + 4 * csrcs > wireLen ) {
        text += " [Malformed Packet]";
    }
    return text;
}

std::string describeRtcp( const uint8_t* p, size_t len, size_t wireLen )
{
    if ( !isRtcpHeader( p, len ) ) {
        return {};
    }
    std::vector<std::string> names;
    bool more = false;
    size_t at = 0;
    while ( at < wireLen ) {
        if ( names.size() == kMaxRtcpPackets ) {
            more = true;
            break;
        }
        if ( at >= len || len - at < kRtcpHeaderBytes ) {
            more = true; // beyond the bytes kept
            break;
        }
        if ( !isRtcpHeader( p + at, len - at ) ) {
            names.emplace_back( "[Malformed Packet]" );
            break;
        }
        const size_t length = ( static_cast<size_t>( readBE16( p + at + 2 ) ) + 1 ) * 4;
        names.emplace_back( rtcpTypeName( p[ at + 1 ] ) );
        if ( length > wireLen - at ) {
            names.back() += " [Malformed Packet]";
            break;
        }
        at += length;
    }
    return joinNames( std::move( names ), kMaxRtcpPackets, more );
}

} // namespace tcpdump::describer
