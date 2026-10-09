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
 * @file describe_websocket.cpp
 * @brief WebSocket frames (RFC 6455) on a TCP stream an HTTP 101 response
 *        upgraded, named as Wireshark names them, and their framing for
 *        the TCP Reassembly.
 *
 * Nothing in a frame's bytes tells WebSocket from any other protocol: only
 * the stream does, from the "101 Switching Protocols" response with
 * "Upgrade: websocket" on it (isWebSocketUpgrade(), describe_http.cpp).
 * So there is no detector, only the stream's pass and the framer, both of
 * which keep to streams so upgraded.
 */

#include "describe_common.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace tcpdump::describer {

namespace {

/// Most frames named in a segment, then "…".
constexpr size_t kMaxFrames = 8;
/// Most payload bytes of a text frame or a close reason shown.
constexpr size_t kMaxPreviewBytes = 40;
/// Longest payload of a control frame (RFC 6455, 5.5).
constexpr uint64_t kMaxControlPayload = 125;

constexpr uint8_t kOpContinuation = 0x0;
constexpr uint8_t kOpText = 0x1;
constexpr uint8_t kOpBinary = 0x2;
constexpr uint8_t kOpClose = 0x8;
constexpr uint8_t kOpPing = 0x9;
constexpr uint8_t kOpPong = 0xA;

/// The bits of a frame's first byte.
constexpr uint8_t kFin = 0x80;
constexpr uint8_t kRsv1 = 0x40; ///< A compressed message (permessage-deflate, RFC 7692).
constexpr uint8_t kOpcodeBits = 0x0F;
/// The bits of its second byte.
constexpr uint8_t kMaskBit = 0x80;
constexpr uint8_t kLengthBits = 0x7F;

/// What a frame's header says.
struct FrameHeader {
    uint8_t first = 0; ///< FIN, RSV1-3 and the opcode.
    bool masked = false;
    uint64_t payloadLength = 0;
    uint8_t mask[ 4 ] = {};
    size_t headerLength = 0; ///< 2 to 14 bytes.

    uint8_t opcode() const
    {
        return first & kOpcodeBits;
    }
    bool fin() const
    {
        return ( first & kFin ) != 0;
    }
    bool control() const
    {
        return ( first & 0x08 ) != 0;
    }
};

/// How long the header of a frame whose second byte is @p second is: 2
/// bytes, the 16- or 64-bit extended length, the masking key.
size_t headerLengthOf( uint8_t second )
{
    const auto length = second & kLengthBits;
    return 2 + ( length == 126 ? 2 : length == 127 ? 8 : 0 ) + ( ( second & kMaskBit ) ? 4 : 0 );
}

/// The header of the frame at @p p, of which @p len bytes are there: cut
/// if they do not hold it all, malformed if its 64-bit length has the most
/// significant bit set (RFC 6455, 5.2).
Read readHeader( const uint8_t* p, size_t len, FrameHeader& header )
{
    if ( len < 2 ) {
        return Read::Cut;
    }
    header.first = p[ 0 ];
    header.masked = ( p[ 1 ] & kMaskBit ) != 0;
    header.headerLength = headerLengthOf( p[ 1 ] );
    if ( len < header.headerLength ) {
        return Read::Cut;
    }
    const auto length = p[ 1 ] & kLengthBits;
    size_t at = 2;
    if ( length == 126 ) {
        header.payloadLength = readBE16( p + at );
        at += 2;
    }
    else if ( length == 127 ) {
        header.payloadLength
            = ( static_cast<uint64_t>( readBE32( p + at ) ) << 32 ) | readBE32( p + at + 4 );
        at += 8;
        if ( header.payloadLength >> 63 ) {
            return Read::Malformed;
        }
    }
    else {
        header.payloadLength = static_cast<uint64_t>( length );
    }
    if ( header.masked ) {
        std::memcpy( header.mask, p + at, 4 );
    }
    return Read::Ok;
}

/// Wireshark's name of an opcode.
std::string opcodeName( uint8_t opcode )
{
    switch ( opcode ) {
    case kOpContinuation:
        return "Continuation";
    case kOpText:
        return "Text";
    case kOpBinary:
        return "Binary";
    case kOpClose:
        return "Connection Close";
    case kOpPing:
        return "Ping";
    case kOpPong:
        return "Pong";
    default:
        return "Unknown " + hexCode( opcode );
    }
}

/// The name of a close frame's status code (RFC 6455, 7.4.1; IANA).
const char* closeCodeName( uint16_t code )
{
    switch ( code ) {
    case 1000:
        return "Normal Closure";
    case 1001:
        return "Going Away";
    case 1002:
        return "Protocol error";
    case 1003:
        return "Unsupported Data";
    case 1005:
        return "No Status Rcvd";
    case 1006:
        return "Abnormal Closure";
    case 1007:
        return "Invalid frame payload data";
    case 1008:
        return "Policy Violation";
    case 1009:
        return "Message Too Big";
    case 1010:
        return "Mandatory Ext.";
    case 1011:
        return "Internal Server";
    case 1012:
        return "Service Restart";
    case 1013:
        return "Try Again Later";
    case 1014:
        return "Bad Gateway";
    case 1015:
        return "TLS handshake";
    default:
        return nullptr;
    }
}

/// Up to @p n payload bytes of the frame, from @p offset into its payload,
/// unmasked.
std::vector<uint8_t> unmasked( const FrameHeader& header, const uint8_t* payload, size_t n,
                               size_t offset = 0 )
{
    std::vector<uint8_t> bytes( payload, payload + n );
    if ( header.masked ) {
        for ( size_t i = 0; i < n; ++i ) {
            bytes[ i ] ^= header.mask[ ( offset + i ) % 4 ];
        }
    }
    return bytes;
}

/// The @p available bytes of a payload in quotes, at most
/// kMaxPreviewBytes, an ellipsis after them if the payload has more.
std::string preview( const std::vector<uint8_t>& bytes, uint64_t payloadLength )
{
    const auto shown = std::min( bytes.size(), kMaxPreviewBytes );
    return quotedBytes( bytes.data(), shown ) + ( shown < payloadLength ? kEllipsis : "" );
}

/// One frame's description, from its header and the @p available payload
/// bytes at @p payload; @p malformed set if it breaks a rule of its opcode.
std::string describeFrame( const FrameHeader& header, const uint8_t* payload, size_t available,
                           bool& malformed )
{
    const auto opcode = header.opcode();
    std::string text = "WebSocket " + opcodeName( opcode );
    if ( header.fin() ) {
        text += " [FIN]";
    }
    if ( header.masked ) {
        text += " [MASKED]";
    }
    const bool compressed = ( header.first & kRsv1 ) != 0;
    if ( compressed ) {
        text += " [COMPRESSED]";
    }
    text += " len=" + std::to_string( header.payloadLength );

    const bool reserved = ( opcode > kOpBinary && opcode < kOpClose ) || opcode > kOpPong;
    if ( reserved
         || ( header.control()
              && ( !header.fin() || header.payloadLength > kMaxControlPayload || compressed ) )
         || ( opcode == kOpClose && header.payloadLength == 1 ) ) {
        malformed = true;
        return text + kMalformed;
    }

    if ( opcode == kOpClose && header.payloadLength >= 2 ) {
        if ( available < 2 ) {
            return text + " " + kEllipsis;
        }
        const auto bytes
            = unmasked( header, payload, std::min<size_t>( available, 2 + kMaxPreviewBytes ) );
        const uint16_t code = readBE16( bytes.data() );
        const char* name = closeCodeName( code );
        text += " "
                + ( name ? std::string( name ) + " (" + std::to_string( code ) + ")"
                         : "Status " + std::to_string( code ) );
        if ( header.payloadLength > 2 ) {
            const std::vector<uint8_t> reason( bytes.begin() + 2, bytes.end() );
            text += " " + preview( reason, header.payloadLength - 2 );
        }
    }
    else if ( opcode == kOpText && !compressed && header.payloadLength > 0 ) {
        const auto shown = std::min( available, kMaxPreviewBytes );
        text += " " + preview( unmasked( header, payload, shown ), header.payloadLength );
    }
    return text;
}

} // namespace

std::string describeWebSocketFrames( const uint8_t* p, size_t len, size_t wireLen )
{
    return nameMessages( wireLen, kMaxFrames, ", ", [ & ]( size_t offset ) {
        if ( offset >= len ) {
            return NamedMessage{ {}, 0, true, true }; // beyond the bytes kept
        }
        FrameHeader header;
        const auto read = readHeader( p + offset, len - offset, header );
        if ( read == Read::Cut ) {
            // The header goes on past the bytes there are, at least one of
            // which is: its opcode.
            return NamedMessage{
                "WebSocket " + opcodeName( p[ offset ] & kOpcodeBits ) + " " + kEllipsis, 0, true
            };
        }
        if ( read == Read::Malformed ) {
            return NamedMessage{ "WebSocket " + opcodeName( header.opcode() ) + kMalformed, 0,
                                 true };
        }
        const size_t payloadAt = offset + header.headerLength;
        const size_t there = len - payloadAt;
        const auto available
            = static_cast<size_t>( std::min<uint64_t>( header.payloadLength, there ) );
        bool malformed = false;
        auto text = describeFrame( header, p + payloadAt, available, malformed );
        // The rest is not to be read as frames, or the frame goes on in
        // later segments.
        const bool last = malformed || header.payloadLength > wireLen - payloadAt;
        return NamedMessage{
            std::move( text ),
            last ? 0 : header.headerLength + static_cast<size_t>( header.payloadLength ), last
        };
    } );
}

std::optional<size_t> frameWebSocketFrame( const uint8_t* payload, size_t len )
{
    if ( len < 2 ) {
        return 2;
    }
    FrameHeader header;
    const auto read = readHeader( payload, len, header );
    if ( read == Read::Cut ) {
        return header.headerLength;
    }
    if ( read == Read::Malformed
         || header.payloadLength > static_cast<uint64_t>( SIZE_MAX - header.headerLength ) ) {
        return std::nullopt; // no frame: described as it is
    }
    return header.headerLength + static_cast<size_t>( header.payloadLength );
}

// ── WebSocket in its stream ──────────────────────────────────────────────

void describeWebSocketInStream( PacketRecord& pkt, const Stream& stream )
{
    if ( !( stream.state->protocols & StreamState::kWebSocket ) || pkt.payloadLen == 0
         || pkt.payloadHeadLen == 0 ) {
        return;
    }
    // From the payload's first kPayloadHeadBytes; the TCP Reassembly
    // describes the frames from all of them.
    redescribe( pkt, "WebSocket",
                describeWebSocketFrames( pkt.payloadHead.data(), pkt.payloadHeadLen,
                                         std::max<size_t>( pkt.payloadLen, pkt.payloadHeadLen ) ) );
}

void rememberWebSocketInStream( const PacketRecord& pkt, const Stream& stream )
{
    if ( pkt.streamCue == StreamCue::WebSocketUpgrade ) {
        stream.state->protocols |= StreamState::kWebSocket;
    }
}

} // namespace tcpdump::describer
