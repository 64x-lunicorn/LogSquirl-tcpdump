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
 * @file payload_describer.cpp
 * @brief The application-protocol detectors, and the order they are tried in.
 *
 * Every detector has the same shape: the payload and its ports in, a
 * description out if it recognises the payload.  Each transport has a table
 * of detectors; the first match wins, and the last entry of each table, the
 * port hint with the payload preview, always answers.  The detectors of
 * each protocol live in a file of their own, describe_*.cpp
 * (describe_common.h).
 */

#include "payload_describer.h"

#include "describe_common.h"
#include "protocol_names.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace tcpdump {

namespace {

using namespace describer;

// ── Payload preview ──────────────────────────────────────────────────────

/// Build an ASCII preview of a payload: printable bytes as themselves,
/// every other byte as a dot, at most kMaxPreviewChars characters followed
/// by an ellipsis.  Returns empty if the payload is predominantly binary
/// (less than 40% printable), where a preview would only be dots.
std::string payloadPreview( const uint8_t* payload, size_t len )
{
    auto isPrintable = []( uint8_t c ) { return c >= 0x20 && c < 0x7F; };

    const auto printable
        = static_cast<size_t>( std::count_if( payload, payload + len, isPrintable ) );
    if ( printable == 0 || printable * 10 < len * 4 ) {
        return {};
    }

    const size_t shown = std::min( len, kMaxPreviewChars );
    std::string preview;
    preview.reserve( shown + 3 );
    for ( size_t i = 0; i < shown; ++i ) {
        preview += isPrintable( payload[ i ] ) ? static_cast<char>( payload[ i ] ) : '.';
    }
    if ( len > shown ) {
        preview += "\xe2\x80\xa6"; // …
    }
    return preview;
}

// ── The detectors of a transport ─────────────────────────────────────────

/// What a detector looks at.
struct Payload {
    const uint8_t* data;
    size_t len;
    uint16_t srcPort;
    uint16_t dstPort;
    Transport transport;
};

/// A detector: the description of the payload if it recognises it.
using Detector = std::optional<PayloadDescription> ( * )( const Payload& );

/// A description with the given label and text.
std::optional<PayloadDescription> described( const char* label, std::string description )
{
    PayloadDescription result;
    result.label = label;
    result.description = std::move( description );
    return result;
}

/// A description with the given label, if the detector found anything.
std::optional<PayloadDescription> describedIfAny( const char* label, std::string description )
{
    if ( description.empty() ) {
        return std::nullopt;
    }
    return described( label, std::move( description ) );
}

/// A description with the label a port names: recognised if the payload
/// parsed (@p description is not empty), else only the port's guess, which
/// does not stick to the stream.
std::optional<PayloadDescription> describedOnPort( const char* label, std::string description )
{
    auto result = described( label, std::move( description ) );
    result->guessed = result->description.empty();
    return result;
}

bool onPort( const Payload& p, uint16_t port )
{
    return p.srcPort == port || p.dstPort == port;
}

/// DNS over TCP on port 53: described if the segment begins with a message.
std::optional<PayloadDescription> dnsOverTcpMessage( const Payload& p )
{
    if ( !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return describedIfAny( "DNS", detectDnsOverTcp( p.data, p.len ) );
}

std::optional<PayloadDescription> tlsRecord( const Payload& p )
{
    return describedIfAny( "TLS", detectTls( p.data, p.len ) );
}

std::optional<PayloadDescription> httpMessage( const Payload& p )
{
    return describedIfAny( "HTTP", detectHttp( p.data, p.len ) );
}

/// A description that begins what the rest of its stream builds on.
std::optional<PayloadDescription> withCue( std::optional<PayloadDescription> result, StreamCue cue )
{
    if ( result ) {
        result->streamCue = cue;
    }
    return result;
}

std::optional<PayloadDescription> http2Preface( const Payload& p )
{
    return withCue( describedIfAny( "HTTP2", detectHttp2Preface( p.data, p.len ) ),
                    StreamCue::Http2Preface );
}

std::optional<PayloadDescription> quicPacket( const Payload& p )
{
    return withCue( describedIfAny( "QUIC", detectQuic( p.data, p.len ) ),
                    StreamCue::QuicLongHeader );
}

/// MQTT on port 1883, and a connection that begins with a CONNECT on any
/// other: the CONNECT tells the rest of its stream to be read as MQTT.
std::optional<PayloadDescription> mqttPackets( const Payload& p )
{
    auto result = describedIfAny( "MQTT", detectMqtt( p.data, p.len, onPort( p, 1883 ) ) );
    return isMqttConnect( p.data, p.len ) ? withCue( std::move( result ), StreamCue::MqttConnect )
                                          : result;
}

/// SIP on any port, by its start line; the media its SDP bodies announce
/// goes with the description.  Before HTTP, whose OPTIONS a SIP request
/// shares.
std::optional<PayloadDescription> sipMessages( const Payload& p )
{
    std::vector<SipCall> calls;
    auto result
        = describedIfAny( "SIP", detectSip( p.data, p.len, p.transport == Transport::Tcp, calls ) );
    if ( result ) {
        result->sipCalls = std::move( calls );
    }
    return result;
}

std::optional<PayloadDescription> nmeaSentence( const Payload& p )
{
    return describedIfAny( "NMEA", detectNmea( p.data, p.len ) );
}

std::optional<PayloadDescription> socksMessage( const Payload& p )
{
    return describedIfAny( "SOCKS", detectSocks( p.data, p.len, p.srcPort, p.dstPort ) );
}

/// The last resort: the protocol the ports suggest, and a preview of the
/// payload's text.  Always answers, possibly with nothing.
std::optional<PayloadDescription> portHintAndPreview( const Payload& p )
{
    PayloadDescription result;
    auto proto = servicePortName( p.transport, p.srcPort );
    if ( !proto ) {
        proto = servicePortName( p.transport, p.dstPort );
    }
    if ( proto ) {
        result.label = proto;
        result.guessed = true;
    }
    result.description = payloadPreview( p.data, p.len );
    result.preview = !result.description.empty();
    return result;
}

/// The TCP detectors, in the order they are tried.
constexpr Detector kTcpDetectors[]
    = { dnsOverTcpMessage, tlsRecord,    sipMessages,  httpMessage,       http2Preface,
        mqttPackets,       nmeaSentence, socksMessage, portHintAndPreview };

/// DNS on port 53, mDNS on port 5353: named by the port, described if the
/// payload parses as a DNS message.
std::optional<PayloadDescription> dnsMessage( const Payload& p )
{
    const bool mdns = onPort( p, 5353 );
    if ( !mdns && !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return describedOnPort( mdns ? "mDNS" : "DNS", detectDns( p.data, p.len ) );
}

/// SSDP on port 1900: HTTP-shaped messages.
std::optional<PayloadDescription> ssdpMessage( const Payload& p )
{
    if ( !onPort( p, 1900 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "SSDP", detectHttp( p.data, p.len ) );
}

/// NTP on port 123: named by the port, described if it is an NTP packet.
std::optional<PayloadDescription> ntpPacket( const Payload& p )
{
    if ( !onPort( p, 123 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "NTP", detectNtp( p.data, p.len ) );
}

/// DHCP on ports 67 and 68: named by the port, described if it is a BOOTP
/// message.
std::optional<PayloadDescription> dhcpPacket( const Payload& p )
{
    if ( !onPort( p, 67 ) && !onPort( p, 68 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "DHCP", detectDhcp( p.data, p.len ) );
}

/// DHCPv6 on ports 546 and 547: named by the port, described if the
/// message has its header.
std::optional<PayloadDescription> dhcpv6Packet( const Payload& p )
{
    if ( !onPort( p, 546 ) && !onPort( p, 547 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "DHCPv6", detectDhcpv6( p.data, p.len ) );
}

/// The UDP detectors, in the order they are tried: ports first, then content.
constexpr Detector kUdpDetectors[]
    = { dnsMessage,  ssdpMessage, ntpPacket,    dhcpPacket,        dhcpv6Packet,
        sipMessages, quicPacket,  nmeaSentence, portHintAndPreview };

/// The detectors of a transport, as a range.
template <size_t N>
std::pair<const Detector*, const Detector*> detectorsOf( const Detector ( &table )[ N ] )
{
    return { table, table + N };
}

/// The description as one line: a control character a detector let
/// through, a newline above all, is escaped as \xNN.  The detectors escape
/// the payload text they quote, so this normally changes nothing; the
/// guarantee that one packet is one line rests here, not on each of them.
std::string oneLine( std::string description )
{
    auto isControl = []( char c ) {
        const auto byte = static_cast<uint8_t>( c );
        return byte < 0x20 || byte == 0x7F;
    };
    if ( std::none_of( description.begin(), description.end(), isControl ) ) {
        return description;
    }
    std::string escaped;
    escaped.reserve( description.size() + 8 );
    for ( const char c : description ) {
        if ( isControl( c ) ) {
            escaped += "\\x" + hexCode( static_cast<uint8_t>( c ) ).substr( 2 );
        }
        else {
            escaped += c;
        }
    }
    return escaped;
}

} // namespace

// ── The describer ────────────────────────────────────────────────────────

PayloadDescription describePayload( Transport transport, const uint8_t* payload, size_t len,
                                    uint16_t srcPort, uint16_t dstPort )
{
    const Payload p{ payload, len, srcPort, dstPort, transport };
    const auto [ first, last ]
        = transport == Transport::Tcp ? detectorsOf( kTcpDetectors ) : detectorsOf( kUdpDetectors );
    for ( auto detect = first; detect != last; ++detect ) {
        if ( auto result = ( *detect )( p ) ) {
            result->description = oneLine( std::move( result->description ) );
            return *result;
        }
    }
    return {};
}

namespace describer {

void redescribe( PacketRecord& pkt, const char* label, const std::string& description )
{
    pkt.previewBytes = 0;
    pkt.protocol = label;
    pkt.protocolRecognised = true;
    pkt.info = pkt.info.substr( 0, pkt.info.find( kDescriptionSeparator ) ) + kDescriptionSeparator
               + description;
}

} // namespace describer

void describeInStream( PacketRecord& pkt, const Stream& stream )
{
    if ( !stream.state || !pkt.transport ) {
        return;
    }
    if ( *pkt.transport == Transport::Udp ) {
        describer::describeQuicInStream( pkt, stream );
    }
    else {
        describer::describeHttp2InStream( pkt, *stream.state );
        describer::describeMqttInStream( pkt, *stream.state );
    }
}

void limitPreview( PacketRecord& pkt, size_t maxChars )
{
    static const std::string kEllipsis = "\xe2\x80\xa6";
    const std::string separator = kDescriptionSeparator;
    auto& info = pkt.info;
    // The preview and the separator before it end the Info, or there is none.
    if ( pkt.previewBytes == 0 || info.size() < pkt.previewBytes + separator.size()
         || info.compare( info.size() - pkt.previewBytes - separator.size(), separator.size(),
                          separator )
                != 0 ) {
        return;
    }
    const auto start = info.size() - pkt.previewBytes;
    if ( maxChars == 0 ) {
        info.erase( start - separator.size() );
        pkt.previewBytes = 0;
        return;
    }
    // One character per byte, but for the describer's ellipsis.
    const bool cut
        = info.size() - start >= kEllipsis.size()
          && info.compare( info.size() - kEllipsis.size(), kEllipsis.size(), kEllipsis ) == 0;
    const auto chars = pkt.previewBytes - ( cut ? kEllipsis.size() : 0 );
    if ( chars <= maxChars ) {
        return;
    }
    info.erase( start + maxChars );
    info += kEllipsis;
    pkt.previewBytes = maxChars + kEllipsis.size();
}

} // namespace tcpdump
