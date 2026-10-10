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
 * @file stream_labels.h
 * @brief Keeps the protocol a detector recognised on a stream for the
 *        stream's later packets.
 *
 * The Payload Describer names one payload at a time, inside the parser,
 * before the packet's stream is known: a segment in the middle of an HTTP
 * body or a TLS record matches no detector and gets the port's guess
 * (HTTPS, HTTP-Alt) or none.  The Stream Labels, which the Packet Pipeline
 * runs on every packet, give such a packet the label its stream was
 * recognised by, so that the Protocol column names the whole conversation.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"

#include <string>
#include <vector>

namespace tcpdump {

/**
 * The protocols recognised on the streams of one capture, owned by the
 * Packet Pipeline next to the Stream Tracker.
 *
 * Each stream keeps the protocol in one byte of its state, a number into
 * the labels seen so far in the capture; at most kMaxLabels distinct labels
 * stick, those after them do not.
 */
class StreamLabels {
public:
    /// Distinct labels a capture can keep: a StreamState::label byte's worth.
    static constexpr size_t kMaxLabels = 255;

    /**
     * Run on every packet, in capture order, by the Packet Pipeline
     * (packet_pipeline.h).
     *
     * The first label a detector recognises on @p stream sticks to it.  A
     * later packet of it that no detector recognises
     * (PacketRecord::protocolRecognised) takes that label, and if it carries
     * payload, its description becomes "Continuation", followed by the
     * payload preview if there was one: "Continuation: {\"id\": 1}".  A
     * packet a detector recognises keeps its own label, also when it
     * differs from the stream's.  A port's guess never sticks.
     *
     * A new TCP connection on the same addresses and ports forgets the
     * label with the rest of the stream's state (analyseTcp()).  Packets
     * of no stream, or of one past the stream cap, are left as they are.
     */
    void apply( PacketRecord& pkt, const Stream& stream );

    /// The protocol a StreamState::label byte numbers; empty for 0, none.
    const std::string& name( uint8_t label ) const;

private:
    /// The labels by their number less one.
    std::vector<std::string> labels_;
};

} // namespace tcpdump
