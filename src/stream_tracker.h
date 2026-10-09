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
 * @file stream_tracker.h
 * @brief Numbers the TCP and UDP conversations of a capture.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>

namespace tcpdump {

constexpr int kNoStream = -1;   ///< Stream column "-": the packet has no TCP or UDP header.
constexpr int kUnnumbered = -2; ///< Stream column "?": past the stream cap.

/// What the Payload Describer knows about a QUIC connection on a UDP stream.
struct QuicConnection {
    bool seen = false; ///< A QUIC long header was seen on the stream.
    /// The length of the destination connection ID of short headers sent
    /// in each direction, indexed by Stream::direction; -1 while unknown.
    int8_t dcidLength[ 2 ] = { -1, -1 };
};

/**
 * What is known about one stream, kept for as long as the capture is read.
 *
 * Modules that follow a conversation over its packets (the Payload
 * Describer, …) keep their fields here, and read and update them through
 * the Stream the tracker hands out.  Every byte added here is paid once per
 * numbered stream, see kMaxStreams.
 */
struct StreamState {
    QuicConnection quic; ///< UDP only.
};

/// The stream a packet belongs to.
struct Stream {
    /// Its number, counted per transport from 0; kNoStream or kUnnumbered.
    int id = kNoStream;
    /// Its state, the same for every packet of the stream; null unless
    /// the stream is numbered.
    StreamState* state = nullptr;
    /// The packet's direction in the stream, 0 or 1: the same for every
    /// packet from the same address and port.
    unsigned direction = 0;
};

/**
 * Follows the conversations of one capture, packet by packet, as the
 * Converter reads them.
 *
 * Only TCP and UDP packets belong to a conversation: those sharing the same
 * addresses and ports, in either direction.  TCP and UDP are numbered on
 * their own, each from 0, as Wireshark's tcp.stream and udp.stream are; the
 * Protocol column says which one a number belongs to.  Every other packet
 * (ICMP, ARP, an IP fragment after the first, …) has no stream.
 *
 * At most maxStreams conversations, of both transports together, are
 * numbered, so that a port scan or a busy NAT cannot exhaust memory;
 * packets of later ones are unnumbered.
 */
class StreamTracker {
public:
    /// Conversations numbered by default: some 100 MB of memory at most.
    static constexpr size_t kMaxStreams = 1000000;

    explicit StreamTracker( size_t maxStreams = kMaxStreams )
        : maxStreams_( maxStreams )
    {
    }

    /// The stream of @p pkt, numbering its conversation if it is a new one.
    Stream track( const PacketRecord& pkt );

    /// Whether a conversation went unnumbered because of maxStreams.
    bool limitReached() const
    {
        return limitReached_;
    }

private:
    /// The conversations of one transport.
    struct Conversations {
        std::map<std::string, int> ids; ///< By their endpoints, in either order.
        std::deque<StreamState> states; ///< By stream id; a deque never moves them.
    };

    Conversations tcp_;
    Conversations udp_;
    size_t maxStreams_;
    bool limitReached_ = false;
};

} // namespace tcpdump
