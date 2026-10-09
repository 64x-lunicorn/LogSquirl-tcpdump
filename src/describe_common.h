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
 * @file describe_common.h
 * @brief What the Payload Describer's protocol files share: payload text,
 *        the FieldReader, and the detectors and in-stream passes each of
 *        them defines for payload_describer.cpp's tables.
 *
 * Internal to the Payload Describer: payload_describer.h is its interface.
 * Every detector takes the captured payload bytes and returns a description,
 * empty if it does not recognise them.  Pure C++ — no Qt dependency.
 */

#pragma once

#include "payload_describer.h"
#include "pcap_parser.h"
#include "stream_tracker.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── Payload text (describe_text.cpp) ─────────────────────────────────────

/// The ellipsis that ends what is cut or left out, "…".
inline const std::string kEllipsis = "\xe2\x80\xa6";

/// What follows the name of a message that breaks its protocol's rules.
inline const std::string kMalformed = " [Malformed Packet]";

/// " …" after @p text, unless it ends in an ellipsis already: what is cut
/// is said once.
void markCut( std::string& text );

/// How far a field or a message could be read: all of it, not all as the
/// bytes are cut (the message goes on in a later segment, or was cut at
/// the snaplen), or not at all as it breaks the rules.
enum class Read { Ok, Cut, Malformed };

/// Format a protocol code as "0xNN".
std::string hexCode( uint8_t code );

/// @p value as "0x" and @p digits uppercase hexadecimal digits, "0x1234".
std::string hexValue( uint32_t value, int digits );

/// A 16-bit ID as "0x1234".
inline std::string id16( uint16_t value )
{
    return hexValue( value, 4 );
}

/// The value of the hex digit @p c, of either case, or -1.
int hexDigit( uint8_t c );

/// @p len bytes as lowercase hexadecimal, as Wireshark shows connection
/// IDs and DUIDs: at most @p maxBytes of them, then an ellipsis.
std::string hexBytes( const uint8_t* p, size_t len, size_t maxBytes = SIZE_MAX );

/// @p names joined with ", ": the first @p maxNames of them, then "…" if
/// there were more, or if @p more says that more were left unnamed.
std::string joinNames( std::vector<std::string> names, size_t maxNames, bool more = false );

/// Payload bytes as text: printable ASCII as is, anything else as \xNN, so
/// that a field can neither break the line nor hide what it contains.
/// Within quotes, '"' is escaped too.
std::string escapeBytes( const uint8_t* p, size_t len, bool quoted );

/// Payload bytes as text in double quotes, '"' escaped.
std::string quotedBytes( const uint8_t* p, size_t len );

/// Longest first line, in bytes, before it is cut.
constexpr size_t kMaxFirstLineBytes = 120;

/// Most bytes of a field (a server name, a domain name) shown, the same cap
/// as a first line's.
constexpr size_t kMaxFieldBytes = kMaxFirstLineBytes;

/// The first line of a payload, up to CR/LF and at most kMaxFirstLineBytes
/// bytes, escaped.
std::string firstLine( const uint8_t* payload, size_t len );

/// @p len bytes of a field as text, at most kMaxFieldBytes of them, then an
/// ellipsis.
std::string fieldText( const uint8_t* p, size_t len );

/// ASCII letter, independent of the C locale (unlike std::isalpha).
bool isAsciiAlpha( uint8_t c );

// ── Binary fields ────────────────────────────────────────────────────────

/// Reads the fields of a binary message (TLS, QUIC) from its bytes, never
/// beyond them.  A read that does not fit fails and leaves the reader as it
/// was.
class FieldReader {
public:
    FieldReader( const uint8_t* data, size_t len, bool complete = true )
        : data_( data )
        , len_( len )
        , complete_( complete )
    {
    }

    bool u8( uint8_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        value = data_[ pos_++ ];
        return true;
    }

    bool u16( uint16_t& value )
    {
        if ( len_ - pos_ < 2 ) {
            return false;
        }
        value = readBE16( data_ + pos_ );
        pos_ += 2;
        return true;
    }

    bool u24( uint32_t& value )
    {
        if ( len_ - pos_ < 3 ) {
            return false;
        }
        value = ( static_cast<uint32_t>( data_[ pos_ ] ) << 16 ) | readBE16( data_ + pos_ + 1 );
        pos_ += 3;
        return true;
    }

    bool u32( uint32_t& value )
    {
        if ( len_ - pos_ < 4 ) {
            return false;
        }
        value = readBE32( data_ + pos_ );
        pos_ += 4;
        return true;
    }

    /// A QUIC variable-length integer (RFC 9000, 16): its first two bits
    /// say whether it takes 1, 2, 4 or 8 bytes.
    bool varint( uint64_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        const size_t n = size_t{ 1 } << ( data_[ pos_ ] >> 6 );
        if ( len_ - pos_ < n ) {
            return false;
        }
        value = data_[ pos_ ] & 0x3F;
        for ( size_t i = 1; i < n; ++i ) {
            value = ( value << 8 ) | data_[ pos_ + i ];
        }
        pos_ += n;
        return true;
    }

    bool skip( size_t n )
    {
        if ( len_ - pos_ < n ) {
            return false;
        }
        pos_ += n;
        return true;
    }

    /// Skip a field behind its 8-bit length.
    bool skipVector8()
    {
        uint8_t n = 0;
        return u8( n ) && skip( n );
    }

    /// The next @p n bytes as a reader of their own: as many of them as
    /// there are, so a cut message is read as far as it goes.
    FieldReader take( size_t n )
    {
        const size_t available = std::min( n, len_ - pos_ );
        FieldReader part( data_ + pos_, available, available == n );
        pos_ += available;
        return part;
    }

    /// The next 8- or 16-bit length and the bytes it counts.
    bool takeVector8( FieldReader& part )
    {
        uint8_t n = 0;
        if ( !u8( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    bool takeVector16( FieldReader& part )
    {
        uint16_t n = 0;
        if ( !u16( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    /// All the bytes this reader was taken for are there.
    bool complete() const
    {
        return complete_;
    }

    /// All its bytes are there and read.
    bool readToEnd() const
    {
        return complete_ && pos_ == len_;
    }

    size_t remaining() const
    {
        return len_ - pos_;
    }
    const uint8_t* here() const
    {
        return data_ + pos_;
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
    bool complete_;
};

/// Most TLS records and handshake messages named in one segment, and QUIC
/// packets in one datagram.
constexpr size_t kMaxTlsMessages = 4;

// ── The detectors ────────────────────────────────────────────────────────

/// HTTP/1.x: a request or status line (describe_http.cpp).
std::string detectHttp( const uint8_t* payload, size_t len );
/// The HTTP/2 connection preface and the frames behind it (describe_http.cpp).
std::string detectHttp2Preface( const uint8_t* payload, size_t len );
/// An NMEA 0183 sentence (describe_nmea.cpp).
std::string detectNmea( const uint8_t* payload, size_t len );
/// A DNS message over UDP (describe_dns.cpp).
std::string detectDns( const uint8_t* payload, size_t len );
/// The DNS messages a TCP segment begins with (describe_dns.cpp).
std::string detectDnsOverTcp( const uint8_t* payload, size_t len );
/// A DHCP or BOOTP message (describe_dhcp_ntp.cpp).
std::string detectDhcp( const uint8_t* payload, size_t len );
/// A DHCPv6 message (describe_dhcp_ntp.cpp).
std::string detectDhcpv6( const uint8_t* payload, size_t len );
/// An NTP packet (describe_dhcp_ntp.cpp).
std::string detectNtp( const uint8_t* payload, size_t len );
/// TLS records (describe_tls.cpp).
std::string detectTls( const uint8_t* payload, size_t len );
/// A QUIC datagram that begins with a long header (describe_quic.cpp).
std::string detectQuic( const uint8_t* payload, size_t len );
/// A SOCKS message, told by its ports (describe_socks.cpp).
std::string detectSocks( const uint8_t* payload, size_t len, uint16_t srcPort, uint16_t dstPort );
/// The MQTT packets of a TCP segment: any on MQTT's port, else only behind
/// a CONNECT (describe_mqtt.cpp).
std::string detectMqtt( const uint8_t* payload, size_t len, bool onMqttPort );
/// The payload begins with an MQTT CONNECT (describe_mqtt.cpp).
bool isMqttConnect( const uint8_t* payload, size_t len );
/// A keep-alive of a SIP connection (RFC 5626, 3.5.1), the whole payload:
/// "Keep-alive (ping)" for a double CRLF, "Keep-alive (pong)" for one;
/// otherwise empty (describe_sip.cpp).
std::string detectSipKeepAlive( const uint8_t* payload, size_t len );
/// The SIP messages a payload begins with, line ends before them skipped,
/// every one of a TCP segment (describe_sip.cpp): what their SDP bodies
/// announce, and the calls a BYE ends, are added to @p calls.
std::string detectSip( const uint8_t* payload, size_t len, bool overTcp,
                       std::vector<SipCall>& calls );

/// SOME/IP messages (describe_someip.cpp): their description, and whether
/// the first is a SOME/IP-SD message.
struct SomeIpDescription {
    std::string text;
    bool sd = false;
};
/// The SOME/IP messages a payload begins with, every one of a datagram or
/// segment.  With @p heuristic, only if every message is whole and keeps
/// to the rules of the header, and they fill the payload; otherwise empty.
SomeIpDescription detectSomeIp( const uint8_t* payload, size_t len, bool heuristic );
/// The port SOME/IP-SD's (30490), or one configured for SOME/IP (someip.h).
bool onSomeIpPort( uint16_t srcPort, uint16_t dstPort );
/// SSH's port.
constexpr uint16_t kSshPort = 22;
/// The SSH banner a TCP payload begins with, on any port, and the binary
/// packets of the unencrypted phase behind it, labelled "SSHv2"
/// (describe_ssh.cpp).  Binary packets without a banner on port 22 only,
/// as any binary protocol may begin as they do, or with @p inSshStream,
/// on a stream that showed a banner, on any port, cut or malformed said
/// so; on port 22, any other payload as an encrypted packet, a guess.
std::optional<PayloadDescription> detectSsh( const uint8_t* payload, size_t len, uint16_t srcPort,
                                             uint16_t dstPort, bool inSshStream = false );
/// An HTTP "101 Switching Protocols" response with "Upgrade: websocket"
/// in its header section, which makes its stream WebSocket
/// (describe_http.cpp).
bool isWebSocketUpgrade( const uint8_t* payload, size_t len );
/// The DoIP messages (ISO 13400-2) a payload begins with, every one of a
/// datagram or segment, a diagnostic message with the UDS service it
/// carries (describe_doip.cpp).
std::string detectDoip( const uint8_t* payload, size_t len );

/// SMB messages (describe_smb.cpp): their description and their label,
/// "SMB2" (SMB2 and SMB 3), "SMB" (SMB1) or "NBSS", as the first names it.
struct SmbDescription {
    std::string text;
    const char* label = nullptr;
};
/// The NetBIOS Session Service messages a TCP payload begins with, every
/// one of a segment: the SMB2/3 commands in them as Wireshark names them,
/// "Create Request File: dir\file.txt", compounded ones too, up to 8 in
/// all, an encrypted or compressed SMB 3 message, an SMB1 command; empty
/// if the payload does not begin with an NBSS message.
SmbDescription detectSmb( const uint8_t* payload, size_t len );
/// The payload begins with an NBSS session message holding SMB: a protocol
/// ID of SMB1, SMB2 or an SMB 3 transform header (describe_smb.cpp).
bool beginsWithSmb( const uint8_t* payload, size_t len );

// ── Where an SDP body announced them (describe_rtp.cpp) ──────────────────

/// The payload begins with an RTCP header: version 2, an RTCP packet type.
bool isRtcpHeader( const uint8_t* payload, size_t len );
/// An RTP packet, "PT=PCMU, SSRC=0x…, Seq=…, Time=…", of @p wireLen bytes
/// of which @p len were kept; empty if it is no RTP version 2 (or RTCP).
std::string describeRtp( const uint8_t* payload, size_t len, size_t wireLen );
/// The packets of a compound RTCP packet, "Sender Report, Source
/// description"; empty if it does not begin with an RTCP header.
std::string describeRtcp( const uint8_t* payload, size_t len, size_t wireLen );

// ── Framing, for the TCP Reassembly ─────────────────────────────────────
//
// How many bytes the message a TCP payload begins with takes, header and
// all: more than len while it is not all there (one more than len when the
// header does not say how many), nothing if no message of the protocol
// begins there.

/// A TLS record (describe_tls.cpp).
std::optional<size_t> frameTlsRecord( const uint8_t* payload, size_t len );
/// A DNS message behind its 2-byte length (describe_dns.cpp).
std::optional<size_t> frameDnsOverTcp( const uint8_t* payload, size_t len );
/// An HTTP/1.x header section (describe_http.cpp).
std::optional<size_t> frameHttpHeader( const uint8_t* payload, size_t len );
/// A SIP message, its body as long as its Content-Length says, and the
/// line ends before it (describe_sip.cpp).
std::optional<size_t> frameSipMessage( const uint8_t* payload, size_t len );
/// An MQTT control packet, by its Remaining Length (describe_mqtt.cpp).
std::optional<size_t> frameMqttPacket( const uint8_t* payload, size_t len );
/// A SOME/IP message, by its Length: on SOME/IP's port whatever its header
/// says, elsewhere only if the header keeps to its rules (describe_someip.cpp).
std::optional<size_t> frameSomeIpMessage( const uint8_t* payload, size_t len, bool onSomeIpPort );
/// A DoIP message, by its payload length, if its header keeps to the
/// pattern of version and inverse version (describe_doip.cpp).
std::optional<size_t> frameDoipMessage( const uint8_t* payload, size_t len );
/// An NBSS message, by its length (describe_smb.cpp): on SMB's ports
/// (445, 139) any NBSS message, elsewhere a session message that holds SMB.
std::optional<size_t> frameSmbMessage( const uint8_t* payload, size_t len, bool onSmbPort );

/// A WebSocket frame, by its payload length (describe_websocket.cpp): on
/// an upgraded stream only, as nothing in its bytes tells it.
std::optional<size_t> frameWebSocketFrame( const uint8_t* payload, size_t len );

/// The WebSocket frames at @p p, the @p len captured bytes of a
/// @p wireLen-byte TCP payload of an upgraded stream, as Wireshark names
/// them, "WebSocket Text [FIN] [MASKED] len=5 \"hello\"": up to 8, then
/// "…"; a cut frame ends in "…", a malformed one says so
/// (describe_websocket.cpp).
std::string describeWebSocketFrames( const uint8_t* p, size_t len, size_t wireLen );

/// How far one direction of an SSH connection is, as its stream's state
/// says (StreamState::kSshBannerSeen, StreamState::sshEncrypted()).
enum class SshPhase {
    Unknown,   ///< No banner was seen: only a banner is framed.
    Clear,     ///< Before NEWKEYS: binary packets, by their packet_length.
    Encrypted, ///< After NEWKEYS: nothing to frame.
};
/// The phase of @p direction of the stream @p state is of.
SshPhase sshPhaseOf( const StreamState& state, unsigned direction );
/// An SSH banner, to its line end; in the clear phase a binary packet, by
/// its packet_length, and a NEWKEYS with all after it; in the encrypted
/// phase, all the bytes (describe_ssh.cpp).
std::optional<size_t> frameSshMessage( const uint8_t* payload, size_t len, SshPhase phase );

// ── In the stream ────────────────────────────────────────────────────────

/// A UDP packet in its stream: QUIC short headers after a long header
/// (describe_quic.cpp).
void describeQuicInStream( PacketRecord& pkt, const Stream& stream );

/// A TCP segment in its stream: HTTP/2 frames after the preface
/// (describe_http.cpp).
void describeHttp2InStream( PacketRecord& pkt, StreamState& state );

/// A TCP segment in its stream: MQTT packets after a CONNECT on another
/// port than MQTT's (describe_mqtt.cpp).
void describeMqttInStream( PacketRecord& pkt, StreamState& state );

/// A TCP segment in its stream: after NEWKEYS an encrypted packet, before
/// it the packets no detector recognised, as the stream's SSH phase says
/// (describe_ssh.cpp).
void describeSshInStream( PacketRecord& pkt, const Stream& stream );

/// A TCP segment in its stream: after the HTTP 101 response that upgraded
/// it, the WebSocket frames in the payload's first kPayloadHeadBytes
/// (describe_websocket.cpp).
void describeWebSocketInStream( PacketRecord& pkt, const Stream& stream );

/// After the TCP Reassembly: a 101 response upgrades its stream to
/// WebSocket (describe_websocket.cpp).
void rememberWebSocketInStream( const PacketRecord& pkt, const Stream& stream );

/// After the TCP Reassembly: what a segment's SSH banner or NEWKEYS tells
/// its stream's later segments (describe_ssh.cpp).
void rememberSshInStream( const PacketRecord& pkt, const Stream& stream );

} // namespace tcpdump::describer
