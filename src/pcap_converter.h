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
#include "packet_formatter.h"
#include "pcap_parser.h"

#include <QString>

#include <atomic>
#include <functional>

namespace tcpdump {

/// Outcome of convertPcap().
struct ConversionResult {
    enum class Status {
        Converted, ///< The output file holds the capture.
        Failed,    ///< See error; no output file is left behind.
        Cancelled, ///< No output file is left behind.
    };

    Status status = Status::Failed;
    QString error;
    PcapGlobalHeader header;
    CaptureStats stats;
    bool truncated = false;          ///< The capture ends in the middle of a packet.
    bool streamLimitReached = false; ///< Some conversations have no stream number.
};

/// Settings of a conversion.  The defaults are the plugin's; a test lowers
/// the caps to see them reached on a small capture.
struct ConversionOptions {
    /// Conversations to number at most; later ones show stream "?".
    size_t maxStreams = PacketFormatter::kMaxStreams;
    /// Addresses to count packets for at most; the rest are "other endpoints".
    size_t maxEndpoints = CaptureStats::kMaxEndpoints;
};

/**
 * Convert the pcap file @p inputPath into a new text file at @p outputPath,
 * one line per packet, reading and writing packet by packet.  The output
 * file must not exist yet; it is created readable by the user only.
 *
 * @param cancel    If set, checked between packets; stops the conversion.
 * @param progress  If set, called with the share of the input read so far,
 *                  in per mille, whenever that changes.
 * @param options   The memory caps; the defaults unless a test lowers them.
 */
ConversionResult convertPcap( const QString& inputPath, const QString& outputPath,
                              const std::atomic_bool* cancel = nullptr,
                              const std::function<void( int )>& progress = {},
                              const ConversionOptions& options = {} );

} // namespace tcpdump
