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
 * @file packet_formatter.h
 * @brief Formats parsed PacketRecord structs into human-readable text lines.
 *
 * Each packet is rendered as a single-line summary suitable for display
 * in LogSquirl's log viewer.  The format mimics Wireshark's packet list:
 *
 *   No.  Time         Source          Destination     Protocol  Len  Info
 *   1    0.000000     192.168.1.1     10.0.0.1        TCP       60   443 → 54321 [SYN] Seq=0
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"

#include <string>
#include <vector>

namespace tcpdump {

/**
 * Format a single packet as a one-line summary string.
 *
 * @param pkt           Parsed packet record.
 * @param baseTimeSec   Seconds timestamp of the first packet.
 * @param baseTimeNsec  Nanoseconds fraction of the first packet's timestamp.
 * @param streamId      The packet's stream number from the Stream Tracker,
 *                      or kNoStream or kUnnumbered.
 * @param precision     The capture's finest precision: the time is shown to
 *                      the nanosecond or to the microsecond.
 * @return Formatted line.
 */
std::string formatPacketLine( const PacketRecord& pkt, uint32_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, TimePrecision precision = TimePrecision::Microseconds );

/**
 * Formats the packets of one capture, one at a time and in capture order,
 * so that a capture never needs to be held in memory as a whole.
 *
 * Remembers the first packet's time, which all times are relative to.  The
 * stream number is handed in: conversations are the Stream Tracker's.
 */
class PacketFormatter {
public:
    /// @param precision   The finest precision the capture announces: every
    ///                    time is shown with its decimals, so that the time
    ///                    column lines up and no packet's time is cut.
    explicit PacketFormatter( TimePrecision precision = TimePrecision::Microseconds )
        : precision_( precision )
    {
    }

    /// The column header line.
    std::string header() const;

    /// The line of the next packet of the capture, @p streamId its stream
    /// number from the Stream Tracker, or kNoStream or kUnnumbered.
    std::string format( const PacketRecord& pkt, int streamId );

private:
    TimePrecision precision_;
    bool haveBase_ = false;
    uint32_t baseTimeSec_ = 0;
    uint32_t baseTimeNsec_ = 0;
};

/**
 * Format all packets into a vector of lines.  Includes a column header
 * as the first line.
 *
 * Times are shown at the finest precision of the packets, streams numbered
 * by a Stream Tracker of their own.
 *
 * @param packets  Parsed packet records.
 * @return Vector of formatted text lines.
 */
std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets );

} // namespace tcpdump
