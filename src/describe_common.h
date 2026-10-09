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

#include "pcap_parser.h"
#include "stream_tracker.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── Payload text (describe_text.cpp) ─────────────────────────────────────

/// Format a protocol code as "0xNN".
std::string hexCode( uint8_t code );

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

/// Put @p description in place of the one in @p pkt's Info, and @p label
/// in place of its protocol: recognised from its content, so the label
/// sticks to the stream (StreamLabels).  In payload_describer.cpp.
void redescribe( PacketRecord& pkt, const char* label, const std::string& description );

} // namespace tcpdump::describer
