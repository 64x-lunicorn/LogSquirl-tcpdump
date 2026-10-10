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
 * @file describe_quic.cpp
 * @brief The QUIC detector of the Payload Describer, and QUIC short headers
 *        in a stream that began with a long header.
 */

#include "describe_common.h"

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── QUIC ─────────────────────────────────────────────────────────────────

namespace {

constexpr uint8_t kQuicLongHeader = 0x80; ///< The header form bit: a long header.
constexpr uint8_t kQuicFixedBit = 0x40;   ///< Set in every QUIC v1 and v2 packet.

constexpr uint32_t kQuicV1 = 0x00000001;
constexpr uint32_t kQuicV2 = 0x6B3343CF;

/// Longest connection ID of QUIC v1 and v2; the version-independent
/// header (RFC 8999) allows 255 bytes, in a Version Negotiation packet.
constexpr size_t kMaxQuicCidBytes = 20;

/// Most packets of one datagram named, the same cap as TLS records'.
constexpr size_t kMaxQuicPackets = kMaxTlsMessages;

/// Most versions of a Version Negotiation packet named.
constexpr size_t kMaxQuicVersions = 8;

/// A draft version of the IETF drafts that already have the long header of
/// QUIC v1 (separate connection ID lengths): draft-22 to draft-34.
bool isQuicDraft( uint32_t version )
{
    return ( version >> 8 ) == 0xFF0000 && ( version & 0xFF ) >= 22 && ( version & 0xFF ) <= 34;
}

/// A version whose packets the describer can read: v1, v2 and the drafts.
bool isKnownQuicVersion( uint32_t version )
{
    return version == kQuicV1 || version == kQuicV2 || isQuicDraft( version );
}

/// A version as "1", "2", "draft-29", or "0x1A2A3A4A".
std::string quicVersionName( uint32_t version )
{
    if ( version == kQuicV1 ) {
        return "1";
    }
    if ( version == kQuicV2 ) {
        return "2";
    }
    if ( isQuicDraft( version ) ) {
        return "draft-" + std::to_string( version & 0xFF );
    }
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "0x%08X", version );
    return buf;
}

/// The packet types of a long header, numbered as in QUIC v1.
enum class QuicLongPacketType : uint8_t { Initial, ZeroRtt, Handshake, Retry };

/// The type of a long header packet; QUIC v2 (RFC 9369) numbers them
/// differently from v1 and the drafts.
QuicLongPacketType quicLongPacketType( uint32_t version, uint8_t firstByte )
{
    using Type = QuicLongPacketType;
    static const Type kV2[] = { Type::Retry, Type::Initial, Type::ZeroRtt, Type::Handshake };
    const auto type = static_cast<uint8_t>( ( firstByte >> 4 ) & 0x03 );
    return version == kQuicV2 ? kV2[ type ] : static_cast<Type>( type );
}

/// The name of a long header packet type.
const char* quicLongPacketName( uint32_t version, uint8_t firstByte )
{
    static const char* const kNames[] = { "Initial", "0-RTT", "Handshake", "Retry" };
    return kNames[ static_cast<size_t>( quicLongPacketType( version, firstByte ) ) ];
}

/// The fields every long header starts with (RFC 8999, 5.1).
struct QuicLongHeader {
    uint8_t firstByte = 0;
    uint32_t version = 0;
    FieldReader dcid{ nullptr, 0 };
    FieldReader scid{ nullptr, 0 };
};

/// Read a long header's version-independent fields: true if the packet
/// begins with a long header of a known version, or with a Version
/// Negotiation packet's, whose connection IDs are whole.
bool readQuicLongHeader( FieldReader& packet, QuicLongHeader& header )
{
    if ( !packet.u8( header.firstByte ) || !( header.firstByte & kQuicLongHeader )
         || !packet.u32( header.version ) ) {
        return false;
    }
    const bool negotiation = header.version == 0;
    if ( !negotiation
         && ( !( header.firstByte & kQuicFixedBit ) || !isKnownQuicVersion( header.version ) ) ) {
        return false;
    }
    if ( !packet.takeVector8( header.dcid ) || !header.dcid.complete()
         || !packet.takeVector8( header.scid ) || !header.scid.complete() ) {
        return false;
    }
    return negotiation
           || ( header.dcid.remaining() <= kMaxQuicCidBytes
                && header.scid.remaining() <= kMaxQuicCidBytes );
}

/// ", DCID=…, SCID=…", each left out if empty.
std::string quicCids( const QuicLongHeader& header )
{
    std::string out;
    if ( header.dcid.remaining() > 0 ) {
        out += ", DCID=" + hexBytes( header.dcid.here(), header.dcid.remaining() );
    }
    if ( header.scid.remaining() > 0 ) {
        out += ", SCID=" + hexBytes( header.scid.here(), header.scid.remaining() );
    }
    return out;
}

/// "Version Negotiation, DCID=…, SCID=…, Versions=1,draft-29": the versions
/// the server supports, if they are a whole list holding one this describer
/// knows; a client never sends such a packet, so anything less is no QUIC.
std::string quicVersionNegotiation( const QuicLongHeader& header, FieldReader versions )
{
    if ( versions.remaining() == 0 || versions.remaining() % 4 != 0 ) {
        return {};
    }
    std::string names;
    bool known = false;
    size_t named = 0;
    uint32_t version = 0;
    while ( versions.u32( version ) ) {
        known = known || isKnownQuicVersion( version );
        if ( named == kMaxQuicVersions ) {
            names += ",\xe2\x80\xa6";
        }
        if ( named++ < kMaxQuicVersions ) {
            names += ( names.empty() ? "" : "," ) + quicVersionName( version );
        }
    }
    if ( !known ) {
        return {};
    }
    return "Version Negotiation" + quicCids( header ) + ", Versions=" + names;
}

/// Skip the rest of a long header packet after its connection IDs: true if
/// another packet may follow it in the datagram (RFC 9000, 12.2).
bool skipQuicLongPacket( FieldReader& packet, uint32_t version, uint8_t firstByte )
{
    const auto type = quicLongPacketType( version, firstByte );
    if ( type == QuicLongPacketType::Retry ) {
        return false; // A Retry has no length: it fills the datagram.
    }
    uint64_t length = 0;
    if ( type == QuicLongPacketType::Initial ) {
        if ( !packet.varint( length ) || length > packet.remaining()
             || !packet.skip( static_cast<size_t>( length ) ) ) {
            return false;
        }
    }
    return packet.varint( length ) && length <= packet.remaining()
           && packet.skip( static_cast<size_t>( length ) );
}

} // namespace

/// Describe a QUIC datagram from the public header of its packets:
/// "Initial, Handshake, Version 1, DCID=…, SCID=…".  Only a datagram that
/// begins with a long header of a known version, or with a Version
/// Negotiation packet, is QUIC by its bytes alone; a short header's is told
/// by its stream (InStreamPass).  The packets are encrypted: their
/// type is all there is to name.  Packets coalesced behind the first are
/// named up to kMaxQuicPackets, a short header one as Protected Payload.
std::string detectQuic( const uint8_t* payload, size_t len )
{
    FieldReader datagram( payload, len );
    QuicLongHeader first;
    if ( !readQuicLongHeader( datagram, first ) ) {
        return {};
    }
    if ( first.version == 0 ) {
        return quicVersionNegotiation( first, datagram.take( datagram.remaining() ) );
    }

    std::vector<std::string> names{ quicLongPacketName( first.version, first.firstByte ) };
    bool more = skipQuicLongPacket( datagram, first.version, first.firstByte );
    while ( more && datagram.remaining() > 0 && names.size() <= kMaxQuicPackets ) {
        const uint8_t firstByte = *datagram.here();
        if ( ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) == kQuicFixedBit ) {
            names.emplace_back( "Protected Payload" ); // fills the datagram
            break;
        }
        QuicLongHeader next;
        if ( !readQuicLongHeader( datagram, next ) || next.version != first.version ) {
            break; // Padding, or bytes that are no packet
        }
        names.emplace_back( quicLongPacketName( next.version, next.firstByte ) );
        more = skipQuicLongPacket( datagram, next.version, next.firstByte );
    }

    return joinNames( std::move( names ), kMaxQuicPackets ) + ", Version "
           + quicVersionName( first.version ) + quicCids( first );
}

// ── QUIC in its stream ───────────────────────────────────────────────────

/// A UDP packet in its stream: QUIC short headers after a long header.
void describeQuicInStream( PacketRecord& pkt, const Stream& stream )
{
    auto& quic = stream.state->quic;
    FieldReader head( pkt.payloadHead.data(), pkt.payloadHeadLen );

    if ( pkt.streamCue == StreamCue::QuicLongHeader ) {
        // A long header the describer named: the connection ID its sender
        // chose is the one the other side sends short headers to.
        QuicLongHeader header;
        if ( readQuicLongHeader( head, header ) ) {
            quic.seen = true;
            if ( header.version != 0 ) {
                quic.dcidLength[ 1 - stream.direction ]
                    = static_cast<int8_t>( header.scid.remaining() );
            }
        }
        return;
    }

    // A short header: the fixed bit without the long header bit, and room
    // for a packet number and the 16 bytes header protection samples.
    const auto dcidLength = quic.dcidLength[ stream.direction ];
    const size_t minimumLength = 1 + std::max<int>( dcidLength, 0 ) + 4 + 16;
    uint8_t firstByte = 0;
    if ( !quic.seen || !head.u8( firstByte )
         || ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) != kQuicFixedBit
         || pkt.payloadLen < minimumLength ) {
        return;
    }
    std::string description = "Protected Payload";
    if ( dcidLength > 0 && head.remaining() >= static_cast<size_t>( dcidLength ) ) {
        description += ", DCID=" + hexBytes( head.here(), static_cast<size_t>( dcidLength ) );
    }
    redescribe( pkt, "QUIC", description );
}

} // namespace tcpdump::describer
