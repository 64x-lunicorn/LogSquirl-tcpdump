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
 * @file packet_recorder.h
 * @brief Records what the Packet Pipeline made of each packet of a capture,
 *        in the one order that needs, and makes the capture's summary.
 */

#pragma once

#include "capture_index.h"
#include "capture_stats.h"
#include "conversations.h"
#include "host_names.h"
#include "packet_formatter.h"
#include "packet_pipeline.h"
#include "pcap_parser.h"
#include "tls_key_log.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace tcpdump {

/**
 * What the Converter knows about a converted capture, in the shape the
 * sidebar shows it: the counts and breakdowns, and what was cut.
 *
 * "What was cut" is four facts, each standing on its own with the number
 * that applies, so that the sidebar prints what it is told.
 */
struct CaptureSummary {
    uint64_t packets = 0;
    uint64_t bytes = 0;           ///< Captured bytes of all packets.
    double durationSeconds = 0.0; ///< Between the earliest and the latest packet.
    /// The earliest and the latest packet time, as the UTC Time column
    /// writes them at the capture's precision; empty without packets.
    std::string firstTimeUtc;
    std::string lastTimeUtc;
    /// The capture's link-layer types by name, or number, in the order they
    /// were first seen: one for a pcap, one per kind of interface otherwise.
    std::vector<std::string> linkTypeNames;
    std::map<std::string, uint64_t> protocolPackets;
    std::map<std::string, uint64_t> protocolBytes;
    /// Packets per IP address in the Source or Destination column, for
    /// every address that was counted.
    std::map<std::string, uint64_t> endpointPackets;
    /// The names of those addresses at the end of the capture (or of what
    /// was converted so far), with host names shown (LineLayout::hostNames):
    /// the last a DNS answer gave each (HostNames); empty otherwise.
    std::map<std::string, std::string> endpointNames;
    /// Packets per address of a tunnel's endpoints, which no column shows
    /// (CaptureStats::tunnelEndpointPackets); empty without tunnels.
    std::map<std::string, uint64_t> tunnelEndpointPackets;
    /// TCP segments per analysis marker ("TCP Retransmission", …), for the
    /// kinds that occur, in the order of TcpMarker.
    std::vector<std::pair<std::string, uint64_t>> tcpMarkers;
    /// TCP handshakes captured whole, and the median of their initial
    /// round-trip times (iRTT) in nanoseconds; unset without any.
    uint64_t handshakes = 0;
    std::optional<uint64_t> medianInitialRttNs;
    /// The Conversations table: a row per numbered stream.  Shared, as it
    /// may hold a million rows: a summary taken anew (a live capture's
    /// next snapshot) holds a table of its own, never a changed one.
    std::shared_ptr<const ConversationRows> conversations;
    /// Packets of the streams past the stream cap (see streamCap), which
    /// the table counts together as "other streams", and their bytes on the
    /// wire.
    uint64_t otherStreamPackets = 0;
    uint64_t otherStreamBytes = 0;

    /// Packets captured shorter than on the wire, cut at the snaplen; their
    /// lines say "[cut to N bytes]".  0 when every packet was captured whole.
    uint64_t cutPackets = 0;
    /// The capture ends in the middle of a record, which is not shown; or
    /// its gzip stream ends early (compressionProblem).
    bool endsInsideRecord = false;
    /// Why a gzip-compressed capture's stream ended before its end, cut off
    /// or corrupt; empty otherwise.
    std::string compressionProblem;
    /// The conversion stopped with the packet of the last number
    /// (ConversionOptions::lastPacketNumber): a capture file had more
    /// packets, which were not converted, or a live capture got to it.
    bool packetNumbersUsedUp = false;
    /// Set when conversations past the stream cap went unnumbered and show
    /// stream "?" in the log: the cap, i.e. how many were numbered.
    std::optional<uint64_t> streamCap;
    /// Set when addresses past the endpoint cap went uncounted: the packets
    /// of all those addresses together.
    std::optional<uint64_t> otherEndpointPackets;

    /// Set when a TLS key log was given (ConversionOptions::keyLogPath):
    /// the TLS sessions with records decrypted.
    std::optional<uint64_t> tlsSessionsDecrypted;
    /// Why the key log could not be read, when it could not: never any of
    /// its contents.
    std::string keyLogError;

    bool operator==( const CaptureSummary& other ) const;
    bool operator!=( const CaptureSummary& other ) const
    {
        return !( *this == other );
    }
};

/// How a PacketRecorder records the packets of one capture.
struct RecorderOptions {
    /// The columns of a line, and whether host names are learned and shown.
    LineLayout layout;
    /// Addresses to count packets for at most (CaptureStats::maxEndpoints).
    size_t maxEndpoints = CaptureStats::kMaxEndpoints;
    /// Addresses whose names are kept at most, with host names shown.
    size_t maxHostNames = HostNames::kMaxNames;
    /// Packets between two checkpoints of the CaptureIndex.
    uint32_t checkpointInterval = CaptureIndex::kCheckpointInterval;
    /// The key log the Packet Pipeline's TLS keys come from, whose error
    /// the summary tells; null without one.  Must outlive the recorder.
    const tls::KeyLogFile* keyLog = nullptr;
};

/**
 * The Packet Recorder: what becomes of a packet of a capture once the Packet
 * Pipeline has run it, and the state that keeps for the whole capture (the
 * CaptureStats, the ConversationStats, the Packet Formatter, the HostNames
 * and the CaptureIndex).  A file conversion and a live capture both record
 * every packet with one.
 *
 * record() takes a packet and its PacketOutcome through these steps, in this
 * order:
 *
 * 1. the TCP Analysis's markers and iRTT into the CaptureStats;
 * 2. the packet into the ConversationStats, by its stream;
 * 3. the packet into the CaptureStats;
 * 4. its line, by the Packet Formatter, with the names known so far;
 * 5. with host names shown, the names its DNS answers give, after its line:
 *    a name labels the packets after its answer, not the answer's own line;
 * 6. its stream's extent, then its place, in the CaptureIndex.
 *
 * summary() and finalSummary() make the summary of what was recorded, with
 * what the Packet Pipeline's TLS Decryption, the key log and the HostNames
 * add to it.
 */
class PacketRecorder {
public:
    /// Records the packets @p reader, open, hands out, which @p pipeline
    /// runs; both must outlive the recorder.  Lines are written at the
    /// reader's precision.
    PacketRecorder( const CaptureReader& reader, const PacketPipeline& pipeline,
                    const RecorderOptions& options = {} );
    PacketRecorder( const PacketRecorder& ) = delete;
    PacketRecorder& operator=( const PacketRecorder& ) = delete;

    /// The column header line, which starts each text file.
    std::string header() const
    {
        return formatter_.header();
    }

    /**
     * Record @p pkt, the packet the reader handed out last, with its
     * captured transport payload, as @p outcome says the Packet Pipeline
     * left it.  Run on every packet, in capture order, right after the
     * pipeline.
     *
     * @return The packet's line, to be written to the text.
     */
    std::string record( const PacketRecord& pkt, ByteView payload, const PacketOutcome& outcome );

    /// The packets recorded so far.
    uint64_t packets() const
    {
        return stats_.packets;
    }

    /// Where each packet recorded so far is in the capture; the caller says
    /// which file or files that is.
    const std::shared_ptr<CaptureIndex>& index() const
    {
        return index_;
    }

    /// The summary of what was recorded so far, from a copy of the
    /// statistics: recording goes on as before.
    CaptureSummary summary() const;

    /// The summary of the whole capture, taking the statistics with it:
    /// once, after the last packet.
    CaptureSummary finalSummary();

private:
    CaptureSummary summarise( CaptureStats&& stats ) const;

    const CaptureReader& reader_;
    const PacketPipeline& pipeline_;
    const tls::KeyLogFile* keyLog_;
    CaptureStats stats_;
    ConversationStats conversations_;
    PacketFormatter formatter_;
    std::optional<HostNames> names_; ///< Only when they are shown.
    std::shared_ptr<CaptureIndex> index_;
};

/**
 * The lines a conversion writes for @p capture, a pcap or pcapng held in
 * memory: the column header, then a line per packet.
 *
 * Each packet is read as the Converter reads it (makeCaptureReader()), with
 * its captured payload, taken through a Packet Pipeline made with
 * @p options, so that it is reassembled, decrypted and labelled as in a
 * conversion, and recorded by a Packet Recorder with @p layout; with
 * PipelineOptions to match a conversion's ConversionOptions and the same
 * @p layout the lines are the ones the conversion writes.  A capture that
 * cannot be read gives no lines.
 */
std::vector<std::string> formatAllPackets( const std::vector<uint8_t>& capture,
                                           const PipelineOptions& options = {},
                                           const LineLayout& layout = {} );

} // namespace tcpdump
