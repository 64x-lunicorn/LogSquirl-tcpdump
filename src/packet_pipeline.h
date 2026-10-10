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
 * @file packet_pipeline.h
 * @brief Takes each packet of a capture through the steps that follow its
 *        stream, in the one order they must run in.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "media_expectations.h"
#include "payload_describer.h"
#include "pcap_parser.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tcp_reassembly.h"
#include "tls_decryption.h"

#include <cstddef>
#include <optional>

namespace tcpdump {

/// How a PacketPipeline treats the packets of one capture.
struct PipelineOptions {
    /// Characters of a payload preview at most, kMaxPreviewChars at most;
    /// 0 leaves the preview out (limitPreview()).
    size_t previewChars = kMaxPreviewChars;
    /// Whether every TCP segment shows its timestamps option in Info, not
    /// only the SYNs (showTcpTimestamps()).
    bool tcpTimestamps = false;
    /// Conversations the Stream Tracker numbers at most.
    size_t maxStreams = StreamTracker::kMaxStreams;
    /// Bytes the TCP Reassembly holds at most, of all streams together, and
    /// of one direction.
    size_t reassemblyMemory = TcpReassembly::kDefaultMemoryLimit;
    size_t reassemblyStreamLimit = TcpReassembly::kStreamLimit;
    /// The secrets of a TLS session by its ClientHello's random, from a key
    /// log; empty: TLS is not decrypted.
    TlsDecryption::Lookup tlsKeys;
    /// How much of the key log has been read, so that a session it had no
    /// secrets for is looked for again once it grew; may be empty.
    TlsDecryption::KeyLogBytes tlsKeyLogBytes;
};

/// What a PacketPipeline found out about one packet, besides what it wrote
/// into the packet itself.
struct PacketOutcome {
    /// The stream the packet belongs to.
    Stream stream;
    /// What the TCP Analysis found in it.
    TcpAnalysis analysis;
    /// The messages it completed, as the TCP Reassembly put them together:
    /// valid until the next packet.
    ReassembledMessages messages;
};

/**
 * The Packet Pipeline: the steps every packet of a capture goes through
 * between the reader and its line, which follow its stream, and the state
 * they keep for the whole capture (the Stream Tracker, the TCP Reassembly,
 * the TLS Decryption, the MediaExpectations and the Stream Labels).
 *
 * run() takes a packet through them in this order, which each step relies
 * on:
 *
 * 1. limitPreview(), before anything else touches Info, whose end it cuts;
 * 2. with PipelineOptions::tcpTimestamps, showTcpTimestamps();
 * 3. the Stream Tracker gives the packet its stream;
 * 4. the TCP Analysis, which also forgets the state of a TCP stream's old
 *    connection, before any other step reads that state;
 * 5. describeInStream(), the Payload Describer with what the stream has
 *    shown so far;
 * 6. the TCP Reassembly, which describes a message where it completes;
 * 7. rememberInStream(), after the reassembly, which completes the
 *    messages it learns from (an SSH NEWKEYS, a WebSocket upgrade);
 * 8. with TLS keys, the TLS Decryption, of the records the reassembly
 *    returned whole;
 * 9. the MediaExpectations, after the reassembly, which completes SDP
 *    bodies, and before the Stream Labels, so that an RTP label sticks;
 * 10. the Stream Labels, last, from the label the packet ends with.
 *
 * What a caller does with the packet then (its line, the counts, the names
 * and the index of a conversion) is its own.
 */
class PacketPipeline {
public:
    explicit PacketPipeline( const PipelineOptions& options = {} );
    PacketPipeline( const PacketPipeline& ) = delete;
    PacketPipeline& operator=( const PacketPipeline& ) = delete;

    /**
     * Take @p pkt, the next packet of the capture as the reader hands it
     * out, with its captured transport payload (CaptureReader::payloadOf()),
     * through the steps, rewriting its protocol and Info as they describe
     * it.  Run on every packet, in capture order.
     */
    PacketOutcome run( PacketRecord& pkt, ByteView payload );

    /// The conversations so far.
    const StreamTracker& tracker() const
    {
        return tracker_;
    }

    /// The protocols recognised on them so far.
    const StreamLabels& labels() const
    {
        return labels_;
    }

    /// The TLS sessions with records decrypted so far; unset without TLS keys.
    std::optional<size_t> tlsSessionsDecrypted() const;

private:
    size_t previewChars_;
    bool tcpTimestamps_;
    StreamTracker tracker_;
    TcpReassembly reassembly_;
    std::optional<TlsDecryption> decryption_; ///< Only with TLS keys.
    MediaExpectations media_;
    StreamLabels labels_;
};

} // namespace tcpdump
