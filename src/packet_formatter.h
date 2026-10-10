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
 *   No. Stream UTC Time                    Time     Source      Destination Protocol Length Info
 *   1   0      2026-10-09 08:41:12.123456Z 0.000000 192.168.1.1 10.0.0.1    TCP      60     443 → …
 *
 * The UTC Time is the packet's wall-clock time, so that a capture can be
 * lined up with a log of the same incident; Time is relative to the first
 * packet, as Wireshark's.  The absolute time comes first: it is the line's
 * timestamp, which a Log Format reads, and LogSquirl's table view puts its
 * Δt column right after it.
 *
 * Every column but Info is followed by at least one space, also when its
 * value is as wide as the column or wider, and an empty value is shown as
 * "-": a line always splits into its columns at runs of spaces, which a Log
 * Format's regex relies on.
 *
 * Length is the length on the wire (PacketRecord::originalLen).  A packet
 * captured shorter than that, cut at the snaplen, ends its Info with
 * "[cut to N bytes]", N the bytes captured.
 *
 * That is the default Line Layout, the one the Log Format is made for.  A
 * Line Layout may leave out one of the time columns, or add Source MAC and
 * Destination MAC before Info.
 */

#pragma once

#include "host_names.h"
#include "pcap_parser.h"
#include "stream_tracker.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump {

/// Which of the two time columns a packet line has.
enum class TimeColumns {
    Both,         ///< UTC Time and Time, the default.
    AbsoluteOnly, ///< UTC Time only.
    RelativeOnly, ///< Time only: the line has no timestamp then.
};

/// The columns of a packet line that can be chosen.  The defaults are the
/// layout the Log Format, and every highlighter and filter made for it,
/// expects.
struct LineLayout {
    TimeColumns timeColumns = TimeColumns::Both;
    /// Source MAC and Destination MAC between Length and Info, "-" for a
    /// packet without them (one not on Ethernet or 802.11).  Info is the
    /// rest of the line to a Log Format, so they are read as its start.
    bool macColumns = false;
    /// Source and Destination show the name a DNS answer earlier in the
    /// capture gave their address (HostNames), behind it in parentheses
    /// and without a space, "93.184.216.34(example.com)", so that the
    /// column stays one word and still starts with its address.
    bool hostNames = false;
};

/**
 * A time as an ISO 8601 date and time in UTC, e.g.
 * "2026-10-09 08:41:12.123456Z": 6 decimals, or 9 at nanosecond precision
 * (cut, not rounded), and a Z for UTC.  Computed from the calendar alone, so
 * that neither the time zone nor the platform's time functions play a part.
 * A time before 1970 counts back from the epoch; a year outside 0000–9999 is
 * written with its sign, as ISO 8601's expanded years ("+10000", "-0001").
 *
 * @param seconds      Seconds since 1970-01-01 00:00:00 UTC.
 * @param nanoseconds  Fraction of the second, below 1,000,000,000.
 */
std::string formatUtcTime( int64_t seconds, uint32_t nanoseconds, TimePrecision precision );

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
 * @param layout        The columns to show.
 * @param names         The names of the addresses so far, shown with
 *                      LineLayout::hostNames; null for none.
 * @return Formatted line.
 */
std::string formatPacketLine( const PacketRecord& pkt, int64_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, TimePrecision precision = TimePrecision::Microseconds,
                              const LineLayout& layout = {}, const HostNames* names = nullptr );

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
    ///                    columns line up and no packet's time is cut.
    /// @param layout      The columns to show.
    explicit PacketFormatter( TimePrecision precision = TimePrecision::Microseconds,
                              const LineLayout& layout = {} )
        : precision_( precision )
        , layout_( layout )
    {
    }

    /// The column header line.
    std::string header() const;

    /// The line of the next packet of the capture, @p streamId its stream
    /// number from the Stream Tracker, or kNoStream or kUnnumbered, its
    /// addresses named by @p names when the layout shows host names.
    std::string format( const PacketRecord& pkt, int streamId, const HostNames* names = nullptr );

private:
    TimePrecision precision_;
    LineLayout layout_;
    bool haveBase_ = false;
    int64_t baseTimeSec_ = 0;
    uint32_t baseTimeNsec_ = 0;
};

/**
 * Format all packets into a vector of lines.  Includes a column header
 * as the first line.
 *
 * Times are shown at the finest precision of the packets, streams numbered
 * by a Stream Tracker of their own, TCP numbers shown relative by the TCP
 * Analysis, each packet described again in its stream by the Payload
 * Describer, and the protocol a stream was recognised by kept for its later
 * packets by Stream Labels of their own.
 *
 * @param packets  Parsed packet records.
 * @return Vector of formatted text lines.
 */
std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets );

} // namespace tcpdump
