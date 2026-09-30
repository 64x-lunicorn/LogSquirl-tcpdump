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

#include <map>
#include <string>
#include <vector>

namespace tcpdump {

/**
 * Format a single packet as a one-line summary string.
 *
 * @param pkt           Parsed packet record.
 * @param baseTimeSec   Seconds timestamp of the first packet.
 * @param baseTimeNsec  Nanoseconds fraction of the first packet's timestamp.
 * @param streamId      Conversation/stream index (0-based, -1 if not applicable).
 * @param nanoseconds   Show the time to the nanosecond (a nanosecond capture)
 *                      rather than to the microsecond.
 * @return Formatted line.
 */
std::string formatPacketLine( const PacketRecord& pkt, uint32_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, bool nanoseconds = false );

/**
 * Formats the packets of one capture, one at a time and in capture order,
 * so that a capture never needs to be held in memory as a whole.
 *
 * Remembers the first packet's time, which all times are relative to, and
 * the conversations seen so far, to number the streams.
 */
class PacketFormatter {
public:
    /// @param nanoseconds  Show times to the nanosecond, for a nanosecond capture.
    explicit PacketFormatter( bool nanoseconds = false )
        : nanoseconds_( nanoseconds )
    {
    }

    /// The column header line.
    std::string header() const;

    /// The line of the next packet of the capture.
    std::string format( const PacketRecord& pkt );

private:
    /// Stream ID of the packet's conversation, -1 if it has none (no IP layer).
    int streamId( const PacketRecord& pkt );

    bool nanoseconds_;
    bool haveBase_ = false;
    uint32_t baseTimeSec_ = 0;
    uint32_t baseTimeNsec_ = 0;
    std::map<std::string, int> streams_;
};

/**
 * Format all packets into a vector of lines.  Includes a column header
 * as the first line.
 *
 * @param packets      Parsed packet records.
 * @param nanoseconds  Show times to the nanosecond, for a nanosecond capture.
 * @return Vector of formatted text lines.
 */
std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets,
                                           bool nanoseconds = false );

/**
 * Render TCP flags (SYN, ACK, FIN, RST, PSH, URG) as a bracket string.
 *
 * @param flags  TCP flags byte.
 * @return String like "[SYN, ACK]".
 */
std::string formatTcpFlags( uint8_t flags );

} // namespace tcpdump
