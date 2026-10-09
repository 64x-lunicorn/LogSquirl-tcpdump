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

#include "pcap_parser.h"
#include "stream_tracker.h"

#include <cstddef>
#include <cstdint>
#include <string>

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
 * go.  Packets of other
 * streams, and of streams past the stream cap, which have no state, are
 * left as they are.
 */
void describeInStream( PacketRecord& pkt, const Stream& stream );

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

} // namespace tcpdump
