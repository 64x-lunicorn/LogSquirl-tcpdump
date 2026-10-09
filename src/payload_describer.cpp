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
#include <iterator>
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
    /// For a framer: the stream the payload is of, if known.
    const Stream* stream = nullptr;
    /// For a framer: a message of its protocol came before the payload in
    /// its direction of the stream.
    bool continuing = false;
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

/// SIP's port, UDP and TCP (5061 is SIP over TLS).
constexpr uint16_t kSipPort = 5060;

/// DoIP's port, UDP and TCP (ISO 13400-2); over TLS it is 3496.
constexpr uint16_t kDoipPort = 13400;

/// SMB directly over TCP, and NBSS, which carries it on port 139.
constexpr uint16_t kSmbPort = 445;
constexpr uint16_t kNbssPort = 139;

bool onSmbPort( const Payload& p )
{
    return onPort( p, kSmbPort ) || onPort( p, kNbssPort );
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

/// HTTP/1.x; a 101 response that upgrades its stream to WebSocket tells
/// the rest of the stream to be read as frames.
std::optional<PayloadDescription> httpMessage( const Payload& p );

/// A description that begins what the rest of its stream builds on.
std::optional<PayloadDescription> withCue( std::optional<PayloadDescription> result, StreamCue cue )
{
    if ( result ) {
        result->streamCue = cue;
    }
    return result;
}

std::optional<PayloadDescription> httpMessage( const Payload& p )
{
    auto result = describedIfAny( "HTTP", detectHttp( p.data, p.len ) );
    return isWebSocketUpgrade( p.data, p.len )
               ? withCue( std::move( result ), StreamCue::WebSocketUpgrade )
               : result;
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
/// shares.  A keep-alive, only line ends, on SIP's port only.
std::optional<PayloadDescription> sipMessages( const Payload& p )
{
    if ( onPort( p, kSipPort ) ) {
        if ( auto keepAlive = detectSipKeepAlive( p.data, p.len ); !keepAlive.empty() ) {
            return described( "SIP", std::move( keepAlive ) );
        }
    }
    std::vector<SipCall> calls;
    auto result
        = describedIfAny( "SIP", detectSip( p.data, p.len, p.transport == Transport::Tcp, calls ) );
    if ( result ) {
        result->sipCalls = std::move( calls );
    }
    return result;
}

/// SOME/IP on SOME/IP-SD's port or one configured for it, whatever the
/// header says; labelled by its first message.
std::optional<PayloadDescription> someIpOnPort( const Payload& p )
{
    if ( !onSomeIpPort( p.srcPort, p.dstPort ) ) {
        return std::nullopt;
    }
    const auto found = detectSomeIp( p.data, p.len, false );
    return describedOnPort( found.sd ? "SOME/IP-SD" : "SOME/IP", found.text );
}

/// SOME/IP on any other port, if every message's header keeps to the
/// rules and the messages fill the payload.
std::optional<PayloadDescription> someIpByHeader( const Payload& p )
{
    const auto found = detectSomeIp( p.data, p.len, true );
    return describedIfAny( found.sd ? "SOME/IP-SD" : "SOME/IP", found.text );
}

/// SSH, by its banner on any port, the binary packets of its key exchange
/// on port 22, where whatever else the payload holds is taken for an
/// encrypted packet, as a guess.  Before TLS, SIP and HTTP; the packets
/// of a stream that showed a banner on another port are the stream's to
/// tell (describeInStream(), sshFrame()).
std::optional<PayloadDescription> sshMessages( const Payload& p )
{
    return detectSsh( p.data, p.len, p.srcPort, p.dstPort );
}

/// DoIP on port 13400, over UDP and TCP: named by the port, described if
/// the payload begins with a DoIP header; a segment without payload (a
/// SYN) stays TCP.
std::optional<PayloadDescription> doipMessages( const Payload& p )
{
    if ( p.len == 0 || !onPort( p, kDoipPort ) ) {
        return std::nullopt;
    }
    return describedOnPort( "DoIP", detectDoip( p.data, p.len ) );
}

/// SMB on ports 445 and 139: named by the port, described if the payload
/// begins with an NBSS message; elsewhere a session message that holds
/// SMB, by its protocol ID.  A segment without payload (a SYN) stays TCP.
std::optional<PayloadDescription> smbMessages( const Payload& p )
{
    if ( p.len == 0 ) {
        return std::nullopt;
    }
    if ( !onSmbPort( p ) ) {
        if ( !beginsWithSmb( p.data, p.len ) ) {
            return std::nullopt;
        }
        const auto found = detectSmb( p.data, p.len );
        return describedIfAny( found.label, found.text );
    }
    const auto found = detectSmb( p.data, p.len );
    if ( !found.label ) {
        return describedOnPort( onPort( p, kSmbPort ) ? "SMB" : "NBSS", {} );
    }
    return describedOnPort( found.label, found.text );
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
    = { dnsOverTcpMessage, doipMessages, smbMessages,  someIpOnPort,      sshMessages,
        tlsRecord,         sipMessages,  httpMessage,  http2Preface,      mqttPackets,
        someIpByHeader,    nmeaSentence, socksMessage, portHintAndPreview };

// ── Framing a TCP stream's messages ──────────────────────────────────────

/// How many bytes the message at the start of a payload takes (see
/// describe_common.h), nothing if it is none of the protocol's.
using Frame = std::optional<size_t> ( * )( const Payload& );

/// Whether the message at the start of a payload is one only its stream
/// tells, which the detectors do not know (MessageExtent::describedInStream).
using ToldByStream = bool ( * )( const Payload& );

/// A protocol whose messages the TCP Reassembly puts together.
struct Framer {
    const char* label; ///< As its detector names it.
    Frame frame;
    /// Its messages are told by their stream, if so; never if null.
    ToldByStream inStream = nullptr;
    /// Describes whole messages of the protocol, as its stream tells them
    /// (describeTcpMessages()); describePayload() if null.
    Detector describe = nullptr;
    /// Tells a message after which the stream carries WebSocket frames
    /// (MessageExtent::upgradesTo); none if no message does.
    bool ( *upgrades )( const uint8_t*, size_t ) = nullptr;
};

/// WebSocket frames on a stream an HTTP 101 response upgraded, or after
/// such a response in the bytes walked, and nowhere else: nothing in their
/// bytes tells them.
bool always( const Payload& )
{
    return true;
}

std::optional<PayloadDescription> webSocketFrames( const Payload& p )
{
    return described( "WebSocket", describeWebSocketFrames( p.data, p.len, p.len ) );
}

std::optional<size_t> webSocketFrame( const Payload& p )
{
    if ( !p.continuing
         && ( !p.stream || !p.stream->state
              || !( p.stream->state->protocols & StreamState::kWebSocket ) ) ) {
        return std::nullopt;
    }
    return frameWebSocketFrame( p.data, p.len );
}

std::optional<size_t> dnsOverTcpFrame( const Payload& p )
{
    if ( !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return frameDnsOverTcp( p.data, p.len );
}

/// DoIP on its port only.
std::optional<size_t> doipFrame( const Payload& p )
{
    if ( !onPort( p, kDoipPort ) ) {
        return std::nullopt;
    }
    return frameDoipMessage( p.data, p.len );
}

/// SMB: any NBSS message on its ports, elsewhere one that holds SMB.
std::optional<size_t> smbFrame( const Payload& p )
{
    return frameSmbMessage( p.data, p.len, onSmbPort( p ) );
}

/// The phase of the SSH connection the payload is of, as far as its
/// stream knows: clear after a banner, or one came before in the direction.
SshPhase sshPhase( const Payload& p )
{
    auto phase = SshPhase::Unknown;
    if ( p.stream && p.stream->state ) {
        phase = sshPhaseOf( *p.stream->state, p.stream->direction );
    }
    if ( phase == SshPhase::Unknown && p.continuing ) {
        phase = SshPhase::Clear;
    }
    return phase;
}

/// SSH as far as its stream's phase lets it be framed: a banner always,
/// binary packets once a banner was seen, or one came before in the
/// direction, nothing after NEWKEYS.
std::optional<size_t> sshFrame( const Payload& p )
{
    return frameSshMessage( p.data, p.len, sshPhase( p ) );
}

/// The binary packets of the clear phase off port 22, which the detector
/// does not take for SSH without a banner before them.
bool sshToldByStream( const Payload& p )
{
    return !onPort( p, kSshPort ) && sshPhase( p ) == SshPhase::Clear
           && !( p.len >= 4 && std::memcmp( p.data, "SSH-", 4 ) == 0 );
}

/// SSH messages framed as such: binary packets on any port.
std::optional<PayloadDescription> sshInStream( const Payload& p )
{
    return detectSsh( p.data, p.len, p.srcPort, p.dstPort, true );
}

std::optional<size_t> tlsFrame( const Payload& p )
{
    return frameTlsRecord( p.data, p.len );
}

std::optional<size_t> sipFrame( const Payload& p )
{
    return frameSipMessage( p.data, p.len );
}

std::optional<size_t> httpFrame( const Payload& p )
{
    return frameHttpHeader( p.data, p.len );
}

std::optional<size_t> someIpFrame( const Payload& p )
{
    return frameSomeIpMessage( p.data, p.len, onSomeIpPort( p.srcPort, p.dstPort ) );
}

/// MQTT on port 1883 only: the framer cannot know of a CONNECT before.
std::optional<size_t> mqttFrame( const Payload& p )
{
    if ( !onPort( p, 1883 ) ) {
        return std::nullopt;
    }
    return frameMqttPacket( p.data, p.len );
}

/// The WebSocket framer's number in kTcpFramers.
constexpr uint8_t kWebSocketFramer = 1;

/// The TCP framers, in the order of their detectors in kTcpDetectors (SOME/IP
/// on its port aside, which frames by its header too), WebSocket, which has
/// none, before them all, as an upgraded stream carries nothing else; a
/// protocol is numbered by its place, from 1 (MessageExtent::framer).
constexpr Framer kTcpFramers[] = {
    { "WebSocket", webSocketFrame, always, webSocketFrames },
    { "DNS", dnsOverTcpFrame },
    { "DoIP", doipFrame },
    { "SMB2", smbFrame },
    { "SSHv2", sshFrame, sshToldByStream, sshInStream },
    { "TLS", tlsFrame },
    { "SIP", sipFrame },
    { "HTTP", httpFrame, nullptr, nullptr, isWebSocketUpgrade },
    { "MQTT", mqttFrame },
    { "SOME/IP", someIpFrame },
};

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
    = { dnsMessage,   ssdpMessage, ntpPacket,      dhcpPacket, dhcpv6Packet, doipMessages,
        someIpOnPort, sipMessages, someIpByHeader, quicPacket, nmeaSentence, portHintAndPreview };

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

void redescribe( PacketRecord& pkt, const char* label, const std::string& description )
{
    pkt.previewBytes = 0;
    pkt.protocol = label;
    pkt.protocolRecognised = true;
    pkt.info = pkt.info.substr( 0, pkt.info.find( kDescriptionSeparator ) ) + kDescriptionSeparator
               + description;
}

MessageExtent tcpMessageExtent( const uint8_t* data, size_t len, uint16_t srcPort, uint16_t dstPort,
                                uint8_t framer, const Stream* stream )
{
    Payload p{ data, len, srcPort, dstPort, Transport::Tcp, stream };
    for ( size_t i = 0; i < std::size( kTcpFramers ); ++i ) {
        const auto number = static_cast<uint8_t>( i + 1 );
        if ( framer != 0 && framer != number ) {
            continue;
        }
        p.continuing = framer == number;
        if ( const auto length = kTcpFramers[ i ].frame( p ) ) {
            MessageExtent extent;
            extent.framer = number;
            extent.label = kTcpFramers[ i ].label;
            extent.length = *length;
            extent.needsMore = *length > len;
            extent.describedInStream = kTcpFramers[ i ].inStream && kTcpFramers[ i ].inStream( p );
            if ( kTcpFramers[ i ].upgrades && !extent.needsMore
                 && kTcpFramers[ i ].upgrades( data, *length ) ) {
                extent.upgradesTo = kWebSocketFramer;
            }
            return extent;
        }
    }
    return {};
}

PayloadDescription describeTcpMessages( const uint8_t* data, size_t len, uint16_t srcPort,
                                        uint16_t dstPort, uint8_t framer )
{
    if ( framer != 0 && framer <= std::size( kTcpFramers ) && kTcpFramers[ framer - 1 ].describe ) {
        const Payload p{ data, len, srcPort, dstPort, Transport::Tcp };
        if ( auto result = kTcpFramers[ framer - 1 ].describe( p ) ) {
            result->description = oneLine( std::move( result->description ) );
            return *result;
        }
    }
    // The frames after a message that upgrades the stream are described
    // after the messages before them.
    size_t upgraded = 0;
    while ( framer != 0 && upgraded < len ) {
        const auto extent
            = tcpMessageExtent( data + upgraded, len - upgraded, srcPort, dstPort, framer );
        if ( !extent.complete() ) {
            upgraded = 0;
            break;
        }
        upgraded += extent.length;
        if ( extent.upgradesTo != 0 ) {
            break;
        }
    }
    if ( upgraded == 0 || upgraded >= len ) {
        return describePayload( Transport::Tcp, data, len, srcPort, dstPort );
    }
    auto result = describePayload( Transport::Tcp, data, upgraded, srcPort, dstPort );
    result.description += ( result.description.empty() ? "" : "; " )
                          + oneLine( describer::describeWebSocketFrames(
                              data + upgraded, len - upgraded, len - upgraded ) );
    result.streamCue = StreamCue::WebSocketUpgrade;
    return result;
}

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
        describer::describeSshInStream( pkt, stream );
        describer::describeWebSocketInStream( pkt, stream );
    }
}

void rememberInStream( const PacketRecord& pkt, const Stream& stream )
{
    if ( !stream.state || pkt.transport != Transport::Tcp ) {
        return;
    }
    describer::rememberSshInStream( pkt, stream );
    describer::rememberWebSocketInStream( pkt, stream );
}

void limitPreview( PacketRecord& pkt, size_t maxChars )
{
    const auto& kEllipsis = describer::kEllipsis;
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
