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
 * @file pcap_converter.h
 * @brief Converts a pcap file into a text file with one line per packet.
 */

#pragma once

#include "capture_index.h"
#include "capture_stats.h"
#include "conversations.h"
#include "gzip_source.h"
#include "packet_formatter.h"
#include "payload_describer.h"
#include "pcap_parser.h"
#include "stream_tracker.h"
#include "tcp_reassembly.h"

#include <QString>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
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
    std::shared_ptr<const std::vector<Conversation>> conversations;
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
    /// Set when conversations past the stream cap went unnumbered and show
    /// stream "?" in the log: the cap, i.e. how many were numbered.
    std::optional<uint64_t> streamCap;
    /// Set when addresses past the endpoint cap went uncounted: the packets
    /// of all those addresses together.
    std::optional<uint64_t> otherEndpointPackets;

    bool operator==( const CaptureSummary& other ) const;
    bool operator!=( const CaptureSummary& other ) const
    {
        return !( *this == other );
    }
};

/**
 * Outcome of convertPcap().
 *
 * Failed is the Converter's only error mode: whatever keeps a conversion
 * from completing, an unreadable input, an output directory or file that
 * cannot be created or written, a memory allocation failure or any other
 * exception on the thread that runs it, ends as Failed with a message.
 * No exception leaves the Converter.
 */
struct ConversionResult {
    enum class Status {
        Converted, ///< outputPath holds the capture's text.
        /// See error.  Nothing is left behind, except for a live capture
        /// that broke off after its first packet: outputPath, rawPath and
        /// summary then hold what was captured (convertStream()).
        Failed,
        Cancelled, ///< Nothing is left behind.
        /// A stream stopped (Stop, or its capture program ended on purpose)
        /// before its capture header had come: nothing was captured, and
        /// nothing is left behind (convertStream()).  Not a failure.
        Stopped,
    };

    Status status = Status::Failed;
    QString error;      ///< Why it failed, when Failed.
    QString outputPath; ///< The text file, when Converted; see convertPcap().
    /// The capture's bytes as they were read, next to the text file, for a
    /// capture read from a stream (convertStream()); empty for a file.
    QString rawPath;
    CaptureSummary summary; ///< What was converted, when Converted.
    /// Where each packet of the text is in the capture file, when Converted
    /// (for a stream, in the raw capture), or when Failed keeping a capture.
    std::shared_ptr<CaptureIndex> index;
};

/// How often at least a live conversion makes its lines readable.
constexpr std::chrono::milliseconds kLiveFlushInterval{ 100 };
/// How often at most a live conversion hands out a LiveSnapshot.
constexpr std::chrono::milliseconds kLiveSnapshotInterval{ 1000 };

/// What a live conversion has converted so far, while it runs.
struct LiveSnapshot {
    CaptureSummary summary;              ///< As the final one, of the packets so far.
    std::chrono::milliseconds elapsed{}; ///< Since the conversion started.
    uint64_t rawBytes = 0;               ///< Bytes read from the stream so far.
    /// Where the packets so far are in the raw capture, which keeps growing
    /// (CaptureIndex::Growth::Growing), for the Packet Panel.
    std::shared_ptr<const CaptureIndex> index;
};

/**
 * What a live conversion tells while it runs (convertStream()).  Both are
 * called on the thread that converts; either may be empty.
 */
struct LiveObserver {
    /// The text file holds its header and the first packet line, so that a
    /// viewer that recognises its format at the first load sees a packet
    /// line: it can be opened now, following it.  Called once, with the
    /// paths of the text file and the raw capture; never for a capture
    /// without packets.
    std::function<void( const QString& logPath, const QString& rawPath )> firstPacket;
    /// A snapshot: with the first packet, then at most once every
    /// kLiveSnapshotInterval while packets come.  The final summary is the
    /// result's.
    std::function<void( const LiveSnapshot& )> snapshot;
};

/// Bytes in a mebibyte, the unit of ConversionOptions::reassemblyMegabytes.
constexpr size_t kMegabyte = 1024 * 1024;

/// Settings of a conversion, as the user chose them in the configuration
/// dialog (settings.h).  The defaults write the text the Log Format is made
/// for; a test lowers the caps to see them reached on a small capture.
struct ConversionOptions {
    /// The time columns and whether the MAC columns are shown.
    LineLayout layout;
    /// Whether a payload no detector recognises is previewed as text.
    bool preview = true;
    /// Characters of a payload preview at most, kMaxPreviewChars at most.
    size_t previewChars = kMaxPreviewChars;
    /// Conversations to number at most; later ones show stream "?".
    size_t maxStreams = StreamTracker::kMaxStreams;
    /// Addresses to count packets for at most; the rest are "other endpoints".
    size_t maxEndpoints = CaptureStats::kMaxEndpoints;
    /// Mebibytes the TCP Reassembly holds at most, of all streams together.
    size_t reassemblyMegabytes = TcpReassembly::kDefaultMemoryLimit / kMegabyte;
    /// Packets between two checkpoints of the CaptureIndex.
    uint32_t checkpointInterval = CaptureIndex::kCheckpointInterval;
    /// Decompressed bytes between two access points of a gzip-compressed
    /// capture (GzipSource::kAccessSpan).
    uint64_t gzipAccessSpan = GzipSource::kAccessSpan;
    /// Whether every TCP segment shows its timestamps option in Info, as
    /// Wireshark does, rather than the SYNs only (showTcpTimestamps()).
    bool tcpTimestamps = false;
    /// Ports SOME/IP is read on besides 30490, whatever its header says
    /// (someip.h); at most kMaxSomeIpPorts.
    std::vector<uint16_t> someIpPorts;
    /// A file naming SOME/IP services, methods and eventgroups
    /// (parseSomeIpNames()); empty: none.  One that cannot be read is
    /// ignored.
    QString someIpNamesFile;
};

/**
 * Convert the pcap file @p inputPath into a text file, one line per packet,
 * reading and writing packet by packet.  The file, named after the input
 * (<name>.log), is created readable by the user only, in a new directory
 * below @p outputRoot that only the user can enter (see tempdirs.h), so
 * that nobody else can read the text or plant a file in its place.  A
 * conversion that does not end Converted leaves nothing behind; the
 * directory of one that does is the caller's to remove.
 *
 * @param cancel    If set, checked between packets; stops the conversion.
 * @param progress  If set, called with the share of the input read so far,
 *                  in per mille, whenever that changes.
 * @param options   The columns, the preview and the memory caps.
 */
ConversionResult convertPcap( const QString& inputPath, const QString& outputRoot,
                              const std::atomic_bool* cancel = nullptr,
                              const std::function<void( int )>& progress = {},
                              const ConversionOptions& options = {} );

/**
 * Convert the capture read from @p source, a stream that is still being
 * written (capture_source.h), as convertPcap() converts a file: into
 * <@p name>.log ("capture.log" without a name), packet by packet as the
 * capture comes, until the stream ends.  A stream stopped or closed in the
 * middle of a record ends Converted, with the record reported cut off.
 *
 * The conversion is live: every byte read is also written, unchanged, to
 * the raw capture next to the text file, <name>.pcap or <name>.pcapng by
 * its format (ConversionResult::rawPath), so that it can be saved, converted
 * again or opened in Wireshark.  The lines written, and the raw bytes, are
 * flushed before every wait for more of the stream and at least every
 * kLiveFlushInterval.  @p live is told when the first packet line is there
 * and gets snapshots of the summary; there is no progress, as a stream's
 * size is unknown.
 *
 * A stream that breaks off with a read error (a capture program that
 * failed) ends Failed; once a packet was converted, what was captured is
 * kept: the text file, the raw capture and the summary of them.  A stream
 * stopped before its header had come (StreamSource::stopped()) ends
 * Stopped, not Failed: nothing went wrong, nothing was captured.
 *
 * @param cancel  If set, checked between packets; stops the conversion and
 *                removes what was written.  The source must be given it
 *                too, so that a wait for the next packet ends with it.
 */
ConversionResult convertStream( ByteSource& source, const QString& name, const QString& outputRoot,
                                const std::atomic_bool* cancel = nullptr,
                                const ConversionOptions& options = {},
                                const LiveObserver& live = {} );

/**
 * The rule that a cancel request wins, even over a conversion that had
 * just finished when the request came: if @p cancel is set, @p result
 * becomes Cancelled, whatever it was, and its output is removed.  Decided
 * here for the Converter, which applies it when its loop ends, and for the
 * caller, which applies it to the result it receives from the worker.
 */
ConversionResult applyCancelRequest( ConversionResult result, const std::atomic_bool* cancel );

} // namespace tcpdump
