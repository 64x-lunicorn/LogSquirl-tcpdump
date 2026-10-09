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
 * What is known about one direction of a TCP stream: what the TCP Analysis
 * needs to show relative numbers and to classify the next segment, the
 * fields of Wireshark's tcp_flow_t it uses, and no list of segments.
 * Sequence and acknowledgement numbers are relative, so that 0 means none
 * seen yet, as in Wireshark.  32 bytes.
 */
struct TcpDirection {
    /// The sequence number relative numbers count from: the initial one,
    /// or one less than the first seen when the SYN was not captured.
    uint32_t baseSeq = 0;
    /// One past the highest sequence number sent (a SYN and a FIN count
    /// one); 0 before the first segment.
    uint32_t nextSeq = 0;
    /// The acknowledgement number of the last segment; 0 without one.
    uint32_t lastAck = 0;
    /// The packet number of the last segment that changed lastAck, which
    /// the duplicate ACKs of it count from.
    uint32_t lastNonDupAck = 0;
    /// The time of the last segment, in nanoseconds since the epoch,
    /// modulo 2^64.
    uint64_t lastTime = 0;
    uint32_t dupAcks = 0; ///< Duplicate ACKs of lastAck so far.
    /// The window of the last segment, as sent; shifted by windowScale when
    /// kWindowScaled is set.
    uint16_t window = 0;
    /// The window scale option of this direction's SYN: its shift count,
    /// at most 14, plus one (4 bits); 0 while no SYN with the option was seen.
    uint8_t windowScale = 0;
    /// What is known and what the last segment was: TcpDirection::k… bits.
    uint8_t flags = 0;

    static constexpr uint8_t kBaseSeqSet = 0x01;      ///< A segment has told baseSeq.
    static constexpr uint8_t kWindowKnown = 0x02;     ///< window is set.
    static constexpr uint8_t kWindowScaled = 0x04;    ///< window is to be shifted.
    static constexpr uint8_t kKeepAlive = 0x08;       ///< The last segment was a keep-alive.
    static constexpr uint8_t kZeroWindowProbe = 0x10; ///< The last segment was a probe.
    /// The last segment that raised nextSeq carried data.
    static constexpr uint8_t kAdvancedWithData = 0x20;
    /// The bits each segment sets afresh; kBaseSeqSet stays.
    static constexpr uint8_t kSegmentFlags
        = kWindowKnown | kWindowScaled | kKeepAlive | kZeroWindowProbe | kAdvancedWithData;
};

/**
 * What is known about one stream, kept for as long as the capture is read.
 *
 * Modules that follow a conversation over its packets (the TCP Analysis,
 * the Payload Describer, the Stream Labels, …) keep their fields here, and
 * read and update them through the Stream the tracker hands out.  Every
 * byte added here is paid once per numbered stream, see kMaxStreams: 72
 * bytes today, the two TcpDirections taking most, and no byte is left
 * before the alignment adds 8.  A new
 * TCP connection on the same addresses and ports (see analyseTcp()) starts
 * from a fresh state, its HTTP/2, MQTT and SSH flags and label with it.
 */
struct StreamState {
    /// TCP only: each direction, indexed by Stream::direction.
    TcpDirection tcp[ 2 ];
    QuicConnection quic; ///< UDP only.
    /// TCP only: the stream began with the HTTP/2 connection preface.
    bool http2 = false;
    /// TCP only: the stream began with an MQTT CONNECT.
    bool mqtt = false;
    /// The protocol a detector recognised on the stream, as StreamLabels
    /// numbers it; 0 while none has.
    uint8_t label = 0;
    /// TCP only: what the TCP Reassembly knows of each direction d, whose
    /// bytes it keeps apart (tcp_reassembly.h): bit 1 << d, it holds some;
    /// bit 4 << d, it let them go for lack of memory, which the direction's
    /// next segment says.
    uint8_t reassembly = 0;
    /// TCP only: how far the stream's SSH connection is (describe_ssh.cpp):
    /// bit 1, an SSH-2 banner was seen; bit 2 << d, direction d sent its
    /// NEWKEYS, and what it sends after is encrypted.
    uint8_t ssh = 0;
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
    /// Conversations numbered by default: some 150 MB of memory at most.  The
    /// options may raise it tenfold (kMaxStreamCap, some 1.5 GB) or lower it.
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
