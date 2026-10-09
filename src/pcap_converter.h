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

#include "capture_stats.h"
#include "pcap_parser.h"
#include "stream_tracker.h"

#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

/**
 * What the Converter knows about a converted capture, in the shape the
 * sidebar shows it: the counts and breakdowns, and what was cut.
 *
 * "What was cut" is three facts, each standing on its own with the number
 * that applies, so that the sidebar prints what it is told.
 */
struct CaptureSummary {
    uint64_t packets = 0;
    uint64_t bytes = 0;           ///< Captured bytes of all packets.
    double durationSeconds = 0.0; ///< Between the earliest and the latest packet.
    /// The capture's link-layer types by name, or number, in the order they
    /// were first seen: one for a pcap, one per kind of interface otherwise.
    std::vector<std::string> linkTypeNames;
    std::map<std::string, uint64_t> protocolPackets;
    std::map<std::string, uint64_t> protocolBytes;
    /// Packets per IP address, for every address that was counted.
    std::map<std::string, uint64_t> endpointPackets;

    /// The capture ends in the middle of a record, which is not shown.
    bool endsInsideRecord = false;
    /// Set when conversations past the stream cap went unnumbered and show
    /// stream "?" in the log: the cap, i.e. how many were numbered.
    std::optional<uint64_t> streamCap;
    /// Set when addresses past the endpoint cap went uncounted: the packets
    /// of all those addresses together.
    std::optional<uint64_t> otherEndpointPackets;
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
        Failed,    ///< See error; nothing is left behind.
        Cancelled, ///< Nothing is left behind.
    };

    Status status = Status::Failed;
    QString error;          ///< Why it failed, when Failed.
    QString outputPath;     ///< The text file, when Converted; see convertPcap().
    CaptureSummary summary; ///< What was converted, when Converted.
};

/// Settings of a conversion.  The defaults are the plugin's; a test lowers
/// the caps to see them reached on a small capture.
struct ConversionOptions {
    /// Conversations to number at most; later ones show stream "?".
    size_t maxStreams = StreamTracker::kMaxStreams;
    /// Addresses to count packets for at most; the rest are "other endpoints".
    size_t maxEndpoints = CaptureStats::kMaxEndpoints;
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
 * @param options   The memory caps; the defaults unless a test lowers them.
 */
ConversionResult convertPcap( const QString& inputPath, const QString& outputRoot,
                              const std::atomic_bool* cancel = nullptr,
                              const std::function<void( int )>& progress = {},
                              const ConversionOptions& options = {} );

/**
 * The rule that a cancel request wins, even over a conversion that had
 * just finished when the request came: if @p cancel is set, @p result
 * becomes Cancelled, whatever it was, and its output is removed.  Decided
 * here for the Converter, which applies it when its loop ends, and for the
 * caller, which applies it to the result it receives from the worker.
 */
ConversionResult applyCancelRequest( ConversionResult result, const std::atomic_bool* cancel );

} // namespace tcpdump
