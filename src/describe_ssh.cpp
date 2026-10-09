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
 * @file describe_ssh.cpp
 * @brief The SSH detector of the Payload Describer: the protocol banner
 *        and the binary packets of the key exchange (RFC 4253), named as
 *        Wireshark names them, their framing for the TCP Reassembly, and
 *        the phase of a stream: what a direction sends after its NEWKEYS
 *        is encrypted.
 */

#include "describe_common.h"

#include <cstring>
#include <iterator>

namespace tcpdump::describer {

namespace {

const std::string kEllipsis = "\xe2\x80\xa6";
const std::string kMalformed = " [Malformed Packet]";

constexpr uint16_t kSshPort = 22;

/// Longest identification string, CR LF included (RFC 4253, 4.2).
constexpr size_t kMaxBannerBytes = 255;

/// The packet_length field.
constexpr size_t kLengthBytes = 4;
/// packet_length, padding_length and the message number.
constexpr size_t kPacketHeaderBytes = 6;
/// Longest packet_length: a packet of 35,000 bytes at most (RFC 4253, 6.1).
constexpr uint32_t kMaxPacketLength = 35000 - kLengthBytes;
/// Shortest: padding_length, a message number and four bytes of padding,
/// to a multiple of the block.
constexpr uint32_t kMinPacketLength = 12;
/// Before NEWKEYS a packet is a multiple of 8 bytes long, the block of the
/// cipher "none".
constexpr uint32_t kBlockBytes = 8;
constexpr uint8_t kMinPadding = 4;

/// Most messages named in a segment, then "…".
constexpr size_t kMaxMessages = 8;
/// Most extensions of an SSH_MSG_EXT_INFO read.
constexpr uint32_t kMaxExtensions = 64;
/// The name-lists of SSH_MSG_KEXINIT: kex, host key, then encryption, MAC,
/// compression and language, client to server and server to client.
constexpr size_t kNameLists = 10;

constexpr uint8_t kMsgKexInit = 20;
constexpr uint8_t kMsgNewKeys = 21;

/// The side @p srcPort sends from: the server on port 22, else on the
/// lower port.
const char* sideOf( uint16_t srcPort, uint16_t dstPort )
{
    if ( srcPort == kSshPort || dstPort == kSshPort ) {
        return srcPort == kSshPort && dstPort != kSshPort ? "Server: " : "Client: ";
    }
    return srcPort < dstPort ? "Server: " : "Client: ";
}

std::string encryptedPacket( size_t len )
{
    return "Encrypted packet (len=" + std::to_string( len ) + ")";
}

// ── Messages ─────────────────────────────────────────────────────────────

enum class Read { Ok, Cut, Malformed };

/// A read of @p r that failed: the bytes were cut, or the message is
/// malformed if all of them are there.
Read failed( const FieldReader& r )
{
    return r.complete() ? Read::Malformed : Read::Cut;
}

/// A string (RFC 4251, 5): its 32-bit length and its bytes, in @p value.
Read readString( FieldReader& r, FieldReader* value = nullptr )
{
    uint32_t n = 0;
    if ( !r.u32( n ) ) {
        return failed( r );
    }
    if ( r.remaining() < n ) {
        return failed( r );
    }
    auto part = r.take( n );
    if ( value ) {
        *value = part;
    }
    return Read::Ok;
}

/// The fields of a message as @p layout lists them, 'u' a uint32, 's' a
/// string (or mpint), 'b' a boolean, and nothing after them.
Read readLayout( FieldReader r, const char* layout )
{
    for ( const char* field = layout; *field; ++field ) {
        bool ok = true;
        if ( *field == 'u' ) {
            uint32_t value = 0;
            ok = r.u32( value );
        }
        else if ( *field == 'b' ) {
            uint8_t value = 0;
            ok = r.u8( value );
        }
        else if ( const auto read = readString( r ); read != Read::Ok ) {
            return read;
        }
        if ( !ok ) {
            return failed( r );
        }
    }
    if ( !r.complete() ) {
        return Read::Cut;
    }
    return r.remaining() == 0 ? Read::Ok : Read::Malformed;
}

/// A name-list (RFC 4251, 5): names of printable US-ASCII, no spaces.
bool namesValid( const FieldReader& list )
{
    const auto* p = list.here();
    return std::all_of( p, p + list.remaining(), []( uint8_t c ) { return c > 0x20 && c < 0x7F; } );
}

/// A name-list shortened to its first name, then ",…" if more follow.
std::string firstName( const FieldReader& list )
{
    const auto* p = list.here();
    const auto* comma = std::find( p, p + list.remaining(), ',' );
    auto text = fieldText( p, static_cast<size_t>( comma - p ) );
    if ( comma != p + list.remaining() ) {
        text += "," + kEllipsis;
    }
    return text;
}

/// What a message was read as.
struct Message {
    std::string text;
    Read status = Read::Ok;
};

/// SSH_MSG_KEXINIT: the cookie, the ten name-lists, of which the key
/// exchange, host key and client-to-server encryption algorithms are
/// named, first_kex_packet_follows and the reserved field.
Message keyExchangeInit( FieldReader r )
{
    static const char* const kShown[] = { "kex", "hostkey", "cipher" };
    Message m{ "Key Exchange Init", Read::Ok };
    if ( !r.skip( 16 ) ) {
        m.status = failed( r );
        return m;
    }
    for ( size_t i = 0; i < kNameLists; ++i ) {
        FieldReader list( nullptr, 0 );
        m.status = readString( r, &list );
        if ( m.status == Read::Ok && !namesValid( list ) ) {
            m.status = Read::Malformed;
        }
        if ( m.status != Read::Ok ) {
            return m;
        }
        if ( i < std::size( kShown ) && list.remaining() > 0 ) {
            m.text += std::string( " " ) + kShown[ i ] + "=" + firstName( list );
        }
    }
    uint8_t follows = 0;
    uint32_t reserved = 0;
    if ( !r.u8( follows ) || !r.u32( reserved ) ) {
        m.status = failed( r );
        return m;
    }
    if ( follows != 0 ) {
        m.text += " first_kex_packet_follows";
    }
    m.status = !r.complete() ? Read::Cut : r.remaining() == 0 ? Read::Ok : Read::Malformed;
    return m;
}

/// SSH_MSG_EXT_INFO (RFC 8308): a count, then as many name and value strings.
Read extensionInfo( FieldReader r )
{
    uint32_t count = 0;
    if ( !r.u32( count ) ) {
        return failed( r );
    }
    if ( count > kMaxExtensions ) {
        return Read::Malformed;
    }
    for ( uint32_t i = 0; i < count; ++i ) {
        for ( int field = 0; field < 2; ++field ) {
            if ( const auto read = readString( r ); read != Read::Ok ) {
                return read;
            }
        }
    }
    if ( !r.complete() ) {
        return Read::Cut;
    }
    return r.remaining() == 0 ? Read::Ok : Read::Malformed;
}

/// The message numbered @p code, as Wireshark names it, its body in @p
/// body; empty text for a number not of the transport layer.  Numbers 30
/// to 34 depend on the key exchange method: Diffie-Hellman group exchange
/// (RFC 4419) is told by the layout of 30 and 31, the elliptic curve and
/// hybrid methods, which share theirs with plain Diffie-Hellman, are
/// named as ECDH (RFC 5656).
Message readMessage( uint8_t code, const FieldReader& body )
{
    auto named = [ &body ]( const char* name, const char* layout ) {
        return Message{ name, readLayout( body, layout ) };
    };
    switch ( code ) {
    case 1:
        return named( "Disconnect", "uss" );
    case 2:
        return named( "Ignore", "s" );
    case 3:
        return named( "Unimplemented", "u" );
    case 4:
        return named( "Debug", "bss" );
    case 5:
        return named( "Service Request", "s" );
    case 6:
        return named( "Service Accept", "s" );
    case 7:
        return Message{ "Extension Information", extensionInfo( body ) };
    case kMsgKexInit:
        return keyExchangeInit( body );
    case kMsgNewKeys:
        return named( "New Keys", "" );
    case 30:
        if ( readLayout( body, "u" ) == Read::Ok ) {
            return named( "Diffie-Hellman Group Exchange Request (Old)", "u" );
        }
        return named( "Elliptic Curve Diffie-Hellman Key Exchange Init", "s" );
    case 31:
        if ( readLayout( body, "ss" ) == Read::Ok ) {
            return named( "Diffie-Hellman Group Exchange Group", "ss" );
        }
        return named( "Elliptic Curve Diffie-Hellman Key Exchange Reply", "sss" );
    case 32:
        return named( "Diffie-Hellman Group Exchange Init", "s" );
    case 33:
        return named( "Diffie-Hellman Group Exchange Reply", "sss" );
    case 34:
        return named( "Diffie-Hellman Group Exchange Request", "uuu" );
    default:
        return {};
    }
}

// ── Binary packets ───────────────────────────────────────────────────────

/// packet_length as the unencrypted phase allows it.
bool lengthValid( uint32_t length )
{
    return length >= kMinPacketLength && length <= kMaxPacketLength
           && ( length + kLengthBytes ) % kBlockBytes == 0;
}

/// padding_length within a packet of @p length: four bytes at least, and
/// room for the message number.
bool paddingValid( uint8_t padding, uint32_t length )
{
    return padding >= kMinPadding && padding <= length - 2;
}

/// One binary packet (RFC 4253, 6), as far as it was read.
struct Packet {
    std::string text;
    Read status = Read::Ok;
    bool coded = false; ///< Its message number was captured
    bool known = false; ///< Its message number is of the transport layer
    uint8_t code = 0;
    size_t length = 0; ///< The bytes it takes, packet_length and all
};

/// The packet at @p p, of which @p len bytes were captured.
Packet readPacket( const uint8_t* p, size_t len )
{
    Packet packet;
    if ( len < kLengthBytes ) {
        packet.text = "Packet " + kEllipsis;
        packet.status = Read::Cut;
        return packet;
    }
    const uint32_t length = readBE32( p );
    if ( !lengthValid( length ) ) {
        packet.text = "Invalid packet length " + std::to_string( length ) + kMalformed;
        packet.status = Read::Malformed;
        return packet;
    }
    packet.length = kLengthBytes + length;
    if ( len >= 5 && !paddingValid( p[ 4 ], length ) ) {
        packet.text = "Invalid padding length " + std::to_string( p[ 4 ] ) + kMalformed;
        packet.status = Read::Malformed;
        return packet;
    }
    if ( len < kPacketHeaderBytes ) {
        packet.text = "Packet " + kEllipsis;
        packet.status = Read::Cut;
        return packet;
    }
    packet.coded = true;
    packet.code = p[ 5 ];
    const size_t bodyLength = length - p[ 4 ] - 2;
    const bool whole = len - kPacketHeaderBytes >= bodyLength;
    const FieldReader body( p + kPacketHeaderBytes, whole ? bodyLength : len - kPacketHeaderBytes,
                            whole );
    auto message = readMessage( packet.code, body );
    packet.known = !message.text.empty();
    if ( !packet.known ) {
        message = { "Unknown (" + std::to_string( packet.code ) + ")", Read::Ok };
    }
    packet.text = std::move( message.text );
    packet.status = message.status;
    if ( packet.status == Read::Ok && len < packet.length ) {
        packet.status = Read::Cut; // its padding is
    }
    if ( packet.status == Read::Cut ) {
        packet.text += " " + kEllipsis;
    }
    else if ( packet.status == Read::Malformed ) {
        packet.text += kMalformed;
    }
    return packet;
}

/// The packets of a segment, read one after the other.
struct Packets {
    std::string text;
    /// Every packet is of the transport layer and whole, but for the last,
    /// which may be cut if it is a KEXINIT or follows a whole one: what
    /// only SSH sends.
    bool plausible = true;
    bool newKeys = false; ///< A NEWKEYS came, and what followed it is encrypted
};

/// The packets of the @p len bytes at @p p, up to the first that is cut
/// or malformed, or a NEWKEYS, after which the rest is one encrypted packet.
Packets readPackets( const uint8_t* p, size_t len )
{
    Packets packets;
    std::vector<std::string> names;
    bool more = false;
    size_t at = 0;
    while ( at < len ) {
        if ( names.size() == kMaxMessages ) {
            more = true;
            break;
        }
        const auto packet = readPacket( p + at, len - at );
        names.push_back( packet.text );
        if ( packet.status == Read::Malformed || ( packet.coded && !packet.known ) ) {
            packets.plausible = false;
        }
        if ( packet.status == Read::Cut ) {
            if ( names.size() == 1 && packet.code != kMsgKexInit ) {
                packets.plausible = false;
            }
            break;
        }
        if ( packet.status != Read::Ok ) {
            break;
        }
        at += packet.length; // whole, so within len
        if ( packet.code == kMsgNewKeys ) {
            packets.newKeys = true;
            if ( at < len ) {
                names.push_back( encryptedPacket( len - at ) );
            }
            break;
        }
    }
    packets.text = joinNames( std::move( names ), kMaxMessages, more );
    return packets;
}

// ── The banner ───────────────────────────────────────────────────────────

/// The identification string a payload begins with (RFC 4253, 4.2):
/// "SSH-protoversion-softwareversion".
struct Banner {
    std::string text;
    size_t length = 0; ///< Its bytes, CR LF and all; 0 while cut
    /// The SSH version it announces: 2 for "2.0" and "1.99", 1 for another
    /// "1.x", 0 for another.
    int version = 0;
};

/// The banner at @p p, of which @p len bytes were captured; nothing if
/// the payload does not begin with "SSH-", digits, a dot, digits and a
/// dash, or has no line end where it must.
std::optional<Banner> readBanner( const uint8_t* p, size_t len )
{
    if ( len < 4 || std::memcmp( p, "SSH-", 4 ) != 0 ) {
        return std::nullopt;
    }
    const auto* end = p + std::min( len, kMaxBannerBytes );
    const auto* lf = std::find( p, end, '\n' );
    if ( lf == end && len >= kMaxBannerBytes ) {
        return std::nullopt;
    }
    const auto* dash = std::find( p + 4, lf, '-' );
    if ( dash == lf ) {
        return std::nullopt;
    }
    const std::string version( p + 4, dash );
    const auto dot = version.find( '.' );
    auto digits = []( const std::string& s ) {
        return !s.empty()
               && std::all_of( s.begin(), s.end(), []( char c ) { return c >= '0' && c <= '9'; } );
    };
    if ( dot == std::string::npos || !digits( version.substr( 0, dot ) )
         || !digits( version.substr( dot + 1 ) ) ) {
        return std::nullopt;
    }

    Banner banner;
    banner.version = version == "2.0" || version == "1.99" ? 2 : version[ 0 ] == '1' ? 1 : 0;
    const auto* lineEnd = lf != end && lf > p && lf[ -1 ] == '\r' ? lf - 1 : lf;
    banner.text = "Protocol (" + fieldText( p, static_cast<size_t>( lineEnd - p ) )
                  + ( lf == end ? kEllipsis : "" ) + ")";
    banner.length = lf == end ? 0 : static_cast<size_t>( lf - p ) + 1;
    return banner;
}

const char* labelOf( int version )
{
    return version == 2 ? "SSHv2" : version == 1 ? "SSHv1" : "SSH";
}

} // namespace

std::optional<PayloadDescription> detectSsh( const uint8_t* payload, size_t len, uint16_t srcPort,
                                             uint16_t dstPort )
{
    if ( len == 0 ) {
        return std::nullopt;
    }
    PayloadDescription result;
    result.description = sideOf( srcPort, dstPort );
    if ( const auto banner = readBanner( payload, len ) ) {
        result.label = labelOf( banner->version );
        result.description += banner->text;
        if ( banner->version == 2 ) {
            result.streamCue = StreamCue::SshBanner;
            if ( banner->length != 0 && banner->length < len ) {
                const auto packets = readPackets( payload + banner->length, len - banner->length );
                result.description += ", " + packets.text;
                if ( packets.newKeys ) {
                    result.streamCue = StreamCue::SshNewKeys;
                }
            }
        }
        return result;
    }

    const auto packets = readPackets( payload, len );
    if ( packets.plausible ) {
        result.label = "SSHv2";
        result.description += packets.text;
        result.streamCue = packets.newKeys ? StreamCue::SshNewKeys : StreamCue::None;
        return result;
    }
    if ( srcPort == kSshPort || dstPort == kSshPort ) {
        // No packet of the unencrypted phase: one of a connection whose
        // key exchange the capture did not see, as far as the port tells.
        result.label = "SSH";
        result.description += encryptedPacket( len );
        result.guessed = true;
        return result;
    }
    return std::nullopt;
}

std::optional<size_t> frameSshMessage( const uint8_t* payload, size_t len, SshPhase phase )
{
    if ( len == 0 ) {
        return std::nullopt;
    }
    if ( phase == SshPhase::Encrypted ) {
        return len; // no packet the framer can see into: the rest, whole
    }
    if ( len >= 4 && std::memcmp( payload, "SSH-", 4 ) == 0 ) {
        const auto* end = payload + std::min( len, kMaxBannerBytes );
        const auto* lf = std::find( payload, end, '\n' );
        if ( lf != end ) {
            return static_cast<size_t>( lf - payload ) + 1;
        }
        return len < kMaxBannerBytes ? std::optional<size_t>( len + 1 ) : std::nullopt;
    }
    if ( phase != SshPhase::Clear ) {
        return std::nullopt;
    }
    if ( len < kLengthBytes ) {
        return len + 1;
    }
    const uint32_t length = readBE32( payload );
    if ( !lengthValid( length ) || ( len >= 5 && !paddingValid( payload[ 4 ], length ) ) ) {
        return std::nullopt; // no packet: described as it is
    }
    const size_t packetLength = kLengthBytes + length;
    if ( len >= packetLength && payload[ 5 ] == kMsgNewKeys ) {
        return len; // NEWKEYS, and the encrypted packets after it
    }
    return packetLength;
}

// ── SSH in its stream ────────────────────────────────────────────────────

SshPhase sshPhaseOf( const StreamState& state, unsigned direction )
{
    if ( state.protocols & StreamState::sshEncrypted( direction ) ) {
        return SshPhase::Encrypted;
    }
    return ( state.protocols & StreamState::kSshBannerSeen ) ? SshPhase::Clear : SshPhase::Unknown;
}

void describeSshInStream( PacketRecord& pkt, const Stream& stream )
{
    const auto phase = sshPhaseOf( *stream.state, stream.direction );
    if ( phase == SshPhase::Unknown || pkt.payloadLen == 0 ) {
        return;
    }
    const std::string side = sideOf( pkt.srcPort, pkt.dstPort );
    if ( phase == SshPhase::Encrypted ) {
        redescribe( pkt, "SSHv2", side + encryptedPacket( pkt.payloadLen ) );
        return;
    }
    if ( pkt.protocolRecognised || pkt.payloadHeadLen == 0 ) {
        return;
    }
    // Packets of the key exchange that did not read as SSH on their own:
    // those in the payload's first kPayloadHeadBytes, what is cut or
    // malformed said so.
    const auto packets = readPackets( pkt.payloadHead.data(), pkt.payloadHeadLen );
    redescribe( pkt, "SSHv2", side + packets.text );
}

void rememberSshInStream( const PacketRecord& pkt, const Stream& stream )
{
    if ( pkt.streamCue == StreamCue::SshBanner ) {
        stream.state->protocols |= StreamState::kSshBannerSeen;
    }
    else if ( pkt.streamCue == StreamCue::SshNewKeys ) {
        stream.state->protocols |= static_cast<uint8_t>(
            StreamState::kSshBannerSeen | StreamState::sshEncrypted( stream.direction ) );
    }
}

} // namespace tcpdump::describer
