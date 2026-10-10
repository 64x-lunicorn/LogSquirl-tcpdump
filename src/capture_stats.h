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
#include "tcp_analysis.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

/**
 * The median of a stream of values in bounded memory: exact while it holds
 * at most kExactValues of them, then from a histogram of fixed size whose
 * buckets are a 64th of a power of two wide (an HDR histogram), so that the
 * median it gives lies within kRelativePrecision of the exact one.  Holds
 * kMaxMemoryBytes at most, however many values a long or live capture adds.
 */
class RunningMedian {
public:
    /// Values kept as they are before they are counted in the histogram.
    static constexpr size_t kExactValues = 4096;
    /// Buckets per power of two; values below it get a bucket each.
    static constexpr uint64_t kSubBuckets = 64;
    /// Relative error of the median from the histogram at most: half a
    /// bucket's width, i.e. 1/128 (0.8 %).
    static constexpr double kRelativePrecision = 1.0 / ( 2 * kSubBuckets );
    /// Memory held at most: the exact values or the histogram, 32 KiB.
    static constexpr size_t kMaxMemoryBytes = kExactValues * sizeof( uint64_t );

    void add( uint64_t value );

    /// Values added.
    uint64_t count() const
    {
        return count_;
    }

    /// Whether the median is still exact: the upper of the two middle values
    /// of an even count.  Otherwise it is the middle of its bucket.
    bool exact() const
    {
        return buckets_.empty();
    }

    /// The median, unset without any value.
    std::optional<uint64_t> median() const;

    /// Memory the values or the histogram hold.
    size_t memoryBytes() const
    {
        return ( exact_.capacity() + buckets_.capacity() ) * sizeof( uint64_t );
    }

private:
    void countInBucket( uint64_t value );

    uint64_t count_ = 0;
    std::vector<uint64_t> exact_;
    std::vector<uint64_t> buckets_;
};

/**
 * Statistics collected packet by packet, so that the capture itself need
 * not be kept in memory.
 */
struct CaptureStats {
    /// Addresses counted by default: some 10 MB of memory at most.  The
    /// options may raise it tenfold (kMaxEndpointCap, some 100 MB) or lower it.
    static constexpr size_t kMaxEndpoints = 100000;

    uint64_t packets = 0;
    uint64_t bytes = 0; ///< Captured bytes of all packets.
    /// Packets captured shorter than on the wire, i.e. cut at the snaplen.
    uint64_t cutPackets = 0;
    std::map<std::string, uint64_t> protocolPackets;
    std::map<std::string, uint64_t> protocolBytes;
    /// Packets per IP address in the Source or Destination column, i.e. of
    /// the packet a line shows, the innermost of a tunnelled one.  Together
    /// with tunnelEndpointPackets for at most maxEndpoints addresses, so
    /// that a scan of many addresses cannot exhaust memory.
    std::map<std::string, uint64_t> endpointPackets;
    /// Packets per address of a tunnel's endpoints, the outer packets a
    /// tunnelled one was carried in: each packet once per address, however
    /// many of its tunnels the address ends.  No column of the line shows
    /// them, so they are kept apart from endpointPackets.
    std::map<std::string, uint64_t> tunnelEndpointPackets;
    /// Packets counted for addresses beyond maxEndpoints.
    uint64_t otherEndpointPackets = 0;
    size_t maxEndpoints = kMaxEndpoints;

    /// TCP segments per kind of analysis marker, indexed by TcpMarker.
    std::array<uint64_t, kTcpMarkerKinds> tcpMarkers{};
    /// The initial round-trip times of the handshakes, in nanoseconds: their
    /// count and median, in bounded memory.
    RunningMedian initialRtts;

    /// Link-layer types (DLT_*) of the capture, each once, in the order they
    /// were first seen.  A capture holds few, so a list is searched.
    std::vector<uint32_t> linkTypes;

    /// Earliest and latest packet time, in seconds since the epoch and the
    /// nanoseconds of that second: kept apart, as a pcapng's times may lie
    /// further apart than an int64_t of nanoseconds reaches.  Packets need
    /// not be in time order, e.g. in a merged capture.
    int64_t firstTimeSec = 0;
    uint32_t firstTimeNsec = 0;
    int64_t lastTimeSec = 0;
    uint32_t lastTimeNsec = 0;

    /// Count @p pkt in, with the link-layer type it was dissected with.
    void add( const PacketRecord& pkt );

    /// Count the markers the TCP Analysis gave a segment, and the initial
    /// round-trip time of a handshake it completed.
    void addTcpAnalysis( const TcpAnalysis& analysis );

    /// The median of initialRtts; unset without any.
    std::optional<uint64_t> medianInitialRttNs() const
    {
        return initialRtts.median();
    }

    /// List @p linkType, unless it is listed already: also for a type the
    /// capture declares without a packet of it.
    void addLinkType( uint32_t linkType );

    /// Whether some addresses were counted as other endpoints.
    bool endpointLimitReached() const
    {
        return otherEndpointPackets > 0;
    }

    /// Time between the earliest and the latest packet, in seconds.
    double durationSeconds() const;

private:
    void countEndpoint( std::map<std::string, uint64_t>& counts, const std::string& address );
};

} // namespace tcpdump
