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
 * @file capture_stats.h
 * @brief Running statistics of a capture, for the sidebar summary.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace tcpdump {

/**
 * Statistics collected packet by packet, so that the capture itself need
 * not be kept in memory.
 */
struct CaptureStats {
    /// Addresses counted by default: some 10 MB of memory at most.
    static constexpr size_t kMaxEndpoints = 100000;

    uint64_t packets = 0;
    uint64_t bytes = 0; ///< Captured bytes of all packets.
    std::map<std::string, uint64_t> protocolPackets;
    std::map<std::string, uint64_t> protocolBytes;
    /// Packets per IP address, for at most maxEndpoints addresses, so that a
    /// scan of many addresses cannot exhaust memory.
    std::map<std::string, uint64_t> endpointPackets;
    /// Packets counted for addresses beyond maxEndpoints.
    uint64_t otherEndpointPackets = 0;
    size_t maxEndpoints = kMaxEndpoints;

    /// Earliest and latest packet time, in nanoseconds since the epoch.
    /// Packets need not be in time order, e.g. in a merged capture.
    int64_t firstTimeNs = 0;
    int64_t lastTimeNs = 0;

    /// Count @p pkt in.
    void add( const PacketRecord& pkt );

    /// Whether some addresses were counted as other endpoints.
    bool endpointLimitReached() const
    {
        return otherEndpointPackets > 0;
    }

    /// Time between the earliest and the latest packet, in seconds.
    double durationSeconds() const;

private:
    void countEndpoint( const std::string& address );
};

} // namespace tcpdump
