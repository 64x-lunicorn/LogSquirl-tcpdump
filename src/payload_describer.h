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
 * @file payload_describer.h
 * @brief Names the application protocol of a transport payload and describes it.
 *
 * The Payload Describer is the only place that knows which application
 * protocols exist on which transport and in which order they are tried.
 * It takes the captured payload bytes and the two ports, and returns a
 * protocol label and a one-line description, or no match.  A payload that
 * can only be told from what came before it in its stream (a QUIC short
 * header, an HTTP/2 frame) is looked at again once the Stream Tracker has found its stream.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "hpack.h"
#include "pcap_parser.h"
#include "stream_tracker.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump {

/// Longest payload preview, in characters, before it is cut with an
/// ellipsis; limitPreview() cuts it shorter.
constexpr size_t kMaxPreviewChars = 200;

/// What the describer knows about a payload.
struct PayloadDescription {
    std::string label;       ///< Protocol name ("TLS", "HTTP", …); empty: unknown.
    std::string description; ///< One line about the payload; empty: nothing to say.
    /// The label is only what the ports suggest, not what a detector
    /// recognised in the payload: a guess, which does not stick to the
    /// stream (StreamLabels).
    bool guessed = false;
    /// The description is a preview of the payload's text, no detector
    /// having recognised it: printable ASCII, a dot for every other byte.
    bool preview = false;
    /// What the payload begins for its stream, which describeInStream()
    /// builds on (PacketRecord::streamCue).
    StreamCue streamCue = StreamCue::None;
    /// The SIP messages of the payload that announce media or end a call
    /// (PacketRecord::sipCalls).
    std::vector<SipCall> sipCalls;
};

/**
 * Describe the @p len captured payload bytes at @p payload, sent from
 * @p srcPort to @p dstPort over @p transport.
 *
 * The detectors of the transport are tried in a fixed order; the first that
 * recognises the payload names it.  A payload none recognises gets the
 * protocol its port suggests, if any, and a preview of its text.
 */
PayloadDescription describePayload( Transport transport, const uint8_t* payload, size_t len,
                                    uint16_t srcPort, uint16_t dstPort );

/**
 * How far the application message at the start of some TCP payload
 * reaches, as the Payload Describer frames its protocol's messages for the
 * TCP Reassembly (tcp_reassembly.h).
 */
struct MessageExtent {
    /// The protocol that frames the message, a number for
    /// tcpMessageExtent() to keep to; 0: no message the describer can frame
    /// begins there.
    uint8_t framer = 0;
    /// The protocol's label ("TLS", …); null with framer 0.
    const char* label = nullptr;
    /// The bytes the message takes, header and all: at most those given when
    /// it is complete; otherwise at least this many are needed, one more
    /// than given when its header does not say how many.
    size_t length = 0;
    /// The message goes on past the bytes given.
    bool needsMore = false;
    /// Its protocol is told by the stream, not by the message's bytes
    /// (WebSocket): the parser could not describe it, so the TCP
    /// Reassembly describes whole messages too, by describeTcpMessages().
    bool describedInStream = false;

    /// A whole message is there.
    bool complete() const
    {
        return framer != 0 && !needsMore;
    }
};

/**
 * The extent of the message the @p len bytes at @p data begin with, sent
 * from @p srcPort to @p dstPort over TCP: a TLS record, a DNS message
 * behind its length (port 53), an SSH banner or binary packet, a SIP message
 * by its Content-Length, an HTTP/1.x header section, an MQTT control packet
 * (port 1883).  With @p framer other than 0, only that protocol is tried, as
 * a stream's later messages are of the protocol of its first.  With
 * @p stream, the payload's stream and direction, what its state knows
 * (SSH's phase, a WebSocket upgrade, after which only WebSocket frames
 * are framed) is kept to.
 */
MessageExtent tcpMessageExtent( const uint8_t* data, size_t len, uint16_t srcPort, uint16_t dstPort,
                                uint8_t framer = 0, const Stream* stream = nullptr );

/**
 * Describe the @p len bytes at @p data, whole messages of the protocol
 * tcpMessageExtent() numbered @p framer, sent from @p srcPort to
 * @p dstPort: WebSocket frames as such, any other protocol's messages as
 * describePayload() does.
 */
PayloadDescription describeTcpMessages( const uint8_t* data, size_t len, uint16_t srcPort,
                                        uint16_t dstPort, uint8_t framer );

/**
 * Put @p description in place of the one in @p pkt's Info (after
 * kDescriptionSeparator), and @p label in place of its protocol: recognised
 * from its content, so the label sticks to the stream (StreamLabels).
 */
void redescribe( PacketRecord& pkt, const char* label, const std::string& description );

/**
 * Describe @p pkt again with what its @p stream has shown so far, and
 * remember in the stream's state what later packets need: run on every
 * packet, in capture order, after the Stream Tracker and the TCP Analysis
 * (which forgets the state of a TCP stream's old connection), before the
 * Stream Labels.
 *
 * A UDP stream that carried a QUIC long header is a QUIC connection: its
 * short header packets, which carry no version, are labelled QUIC and
 * described as "Protected Payload, DCID=…", the connection ID as long as
 * the other side's last long header said.  A TCP stream that began with
 * the HTTP/2 connection preface is an HTTP/2 connection: its segments that
 * begin with frame headers are labelled HTTP2 and described as
 * "HEADERS[1], DATA[1]", each frame's type and stream.  A packet so
 * labelled counts as recognised (PacketRecord::protocolRecognised), so its
 * label sticks to the stream.  A TCP stream that began with an MQTT
 * CONNECT on a port other than MQTT's is an MQTT connection: its segments
 * no detector recognised that begin with MQTT packets are labelled MQTT
 * and described as on MQTT's port, as far as the first kPayloadHeadBytes
 * go.  A TCP stream that carried an SSH-2 banner is an SSH connection: a
 * direction's segments after its NEWKEYS are labelled SSHv2 and described
 * as "Client: Encrypted packet (len=N)", those before it no detector
 * recognised as the binary packets they begin with.  A TCP stream an HTTP
 * "101 Switching Protocols" response with "Upgrade: websocket" upgraded is
 * a WebSocket connection: its later segments are labelled WebSocket and
 * their frames described, as far as the first kPayloadHeadBytes go (the
 * TCP Reassembly describes them from all the bytes).  Packets of other
 * streams, and of streams past the stream cap, which have no state, are
 * left as they are.
 */
void describeInStream( PacketRecord& pkt, const Stream& stream );

/**
 * Remember in @p stream's state what @p pkt, as the TCP Reassembly left
 * its description (PacketRecord::streamCue), tells the stream's later
 * packets: run on every packet, in capture order, after the TCP
 * Reassembly (after describeInStream() where there is none).  An SSH-2
 * banner makes the stream an SSH connection, a NEWKEYS encrypts what its
 * direction sends after it, a 101 response with "Upgrade: websocket" makes
 * it a WebSocket connection.
 */
void rememberInStream( const PacketRecord& pkt, const Stream& stream );

/**
 * Cut the payload preview @p pkt's Info ends in (PacketRecord::previewBytes)
 * to its first @p maxChars characters, followed by an ellipsis, so that a
 * shorter preview can be chosen than the describer's kMaxPreviewChars; with
 * @p maxChars 0, leave it out, and the separator before it.  A preview no
 * longer than that, and a packet without one, are left as they are.  Run on
 * a packet as the reader hands it out, before anything else touches its
 * Info.
 */
void limitPreview( PacketRecord& pkt, size_t maxChars );

// ── Names from DNS answers (host_names.h) ────────────────────────────────

/// An address a DNS response resolved, and the name it resolved it from.
struct ResolvedName {
    std::string address; ///< As the Source and Destination columns write it.
    std::string name;    ///< "www.example.com"
};

/**
 * The names the DNS response of @p len bytes at @p message (a DNS or mDNS
 * message, without the length DNS over TCP puts before it) gives addresses,
 * in the order of its answers: an A or AAAA answer names its address with
 * the name the client asked for, its owner followed back through the
 * CNAME answers of the message ("www.example.com CNAME example.com,
 * example.com A 93.184.216.34" names 93.184.216.34 www.example.com); a
 * PTR answer for an in-addr.arpa or ip6.arpa name names the address that
 * name spells.  Only the answer section is read, at most kMaxResolvedNames
 * of its records, and only a standard query's response without an error;
 * an answer cut short ends the list.  A name that is not a host name
 * (isHostName()) names nothing.  Nothing is validated beyond that: a
 * response that claims a name gets it.
 */
std::vector<ResolvedName> dnsResolvedNames( const uint8_t* message, size_t len );

/// Answers of one DNS message dnsResolvedNames() reads at most.
constexpr size_t kMaxResolvedNames = 32;

/**
 * Whether @p name can stand in a column as a host name: 1 to kMaxHostName
 * letters, digits, '-', '_' and '.', not starting with '.', so that it
 * neither breaks a column into two nor reads as anything but a name.
 */
bool isHostName( const std::string& name );

/// The longest host name kept, in bytes (RFC 1035 allows 253 characters).
constexpr size_t kMaxHostName = 120;

// ── Decrypted TLS records (tls_decryption.h) ─────────────────────────────

/**
 * The handshake messages of a decrypted TLS record, @p len bytes at
 * @p data: "Encrypted Extensions, Certificate, Certificate Verify, Finished".
 */
std::string describeTlsHandshake( const uint8_t* data, size_t len );

/// A decrypted TLS alert, "Alert: close_notify".
std::string describeTlsAlert( const uint8_t* data, size_t len );

/**
 * One direction of an HTTP/2 connection whose bytes come whole and in
 * order, as decrypted TLS application data does, so that its header blocks
 * can be decoded (HPACK): the requests and responses are described, not
 * only the frames' types.
 *
 * Memory is bounded: besides the HPACK decoder's table, it holds the frame
 * header the bytes so far ended in, and of a frame that carries a header
 * block (HEADERS, PUSH_PROMISE, CONTINUATION) its payload, as long as
 * kMaxHeaderBlockBytes; a longer block is not decoded, nor any after it.
 * Other frames' payloads are passed over as they come.
 */
class Http2Direction {
public:
    /// The longest header block decoded, of all its frames together.
    static constexpr size_t kMaxHeaderBlockBytes = 64 * 1024;

    /**
     * Describe the next @p len bytes of the direction: the frames whose
     * header is among them, "HEADERS[1]: GET example.com/index.html,
     * DATA[1]", up to four, then "…"; the connection preface first, at the
     * start of the client's direction, as "Magic".  A header block's
     * request (:method, :authority, :path) or response (:status,
     * Content-Type, Content-Length) is told when the block is complete in
     * the same bytes.  Empty if no frame header is among them.
     */
    std::string describe( const uint8_t* data, size_t len );

    /// Bytes held now: the frame being read, the header block and the
    /// HPACK table.
    size_t memory() const;

    /// Let go of all that is held and decode no header block from now on,
    /// naming the frames only.
    void abandonHeaders();

private:
    /// A frame whose header is complete, held as far as needed.
    void frameDone( std::vector<std::string>& names, size_t nameIndex );

    HpackDecoder hpack_;
    bool started_ = false;        ///< Bytes came: the preface is behind.
    std::vector<uint8_t> frame_;  ///< The frame being read, its header first.
    uint32_t frameLength_ = 0;    ///< Its payload's length, once its header is there.
    size_t frameName_ = SIZE_MAX; ///< Its name's place in this call's names, if any.
    size_t skip_ = 0;             ///< Payload bytes of a frame still to pass over.
    std::vector<uint8_t> block_;  ///< Header block fragments before END_HEADERS.
    bool inBlock_ = false;        ///< A header block began and has not ended.
    size_t blockName_ = SIZE_MAX; ///< The name of the frame that began it, if in this call.
    bool headersAbandoned_ = false;
};

} // namespace tcpdump
