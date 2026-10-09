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
 * @file display_filter.h
 * @brief Display filters: a Wireshark-style filter, translated into a Regex
 *        Lab pattern over the columns of the packet line.
 *
 * The user types `ip.addr == 10.0.0.1 && tcp.port == 443` as in Wireshark;
 * the plugin parses it and builds the pattern that selects the packet lines
 * it means, in any Line Layout, and opens it in the Regex Lab.  A filter
 * outside the supported subset is rejected with the position and the
 * reason, never approximated.
 *
 * Each field reads a column of the line (regex_lab.h): the addresses the
 * Source and Destination columns, the ports the two at the start of a TCP
 * or UDP packet's Info (after the MAC columns, the tunnels and the TCP
 * analysis markers), the streams the Stream column, frame.len the Length
 * column and a protocol name the Protocol column.  Each condition is a
 * lookahead from the start of the line, so that `&&`, `||` and `!` combine
 * conditions on different columns exactly; a number compared with `<` or
 * `>` becomes an exact numeric-range pattern.
 *
 * The pattern is for QRegularExpression (PCRE2), with which the Regex Lab
 * and LogSquirl's search run it: Vectorscan, LogSquirl's default engine,
 * has no lookaheads, and LogSquirl searches a pattern it rejects with Qt's
 * engine.  It is therefore not for the shipped presets, which Vectorscan
 * must read.
 */

#pragma once

#include <QString>

#include <cstdint>
#include <vector>

namespace tcpdump {

/// A field of the supported subset.
enum class FilterField {
    IpAddr,     ///< ip.addr: Source or Destination, an IPv4 packet's
    IpSrc,      ///< ip.src
    IpDst,      ///< ip.dst
    Ipv6Addr,   ///< ipv6.addr: Source or Destination, an IPv6 packet's
    Ipv6Src,    ///< ipv6.src
    Ipv6Dst,    ///< ipv6.dst
    TcpPort,    ///< tcp.port: either port of a TCP packet
    TcpSrcPort, ///< tcp.srcport
    TcpDstPort, ///< tcp.dstport
    UdpPort,    ///< udp.port: either port of a UDP packet
    UdpSrcPort, ///< udp.srcport
    UdpDstPort, ///< udp.dstport
    TcpStream,  ///< tcp.stream: the Stream column of a TCP packet
    UdpStream,  ///< udp.stream: the Stream column of a UDP packet
    FrameLen,   ///< frame.len: the Length column
};

/// How a field is compared; Present is a field alone, `tcp.port`.
enum class FilterOperator { Present, Equal, NotEqual, Less, Greater, LessEqual, GreaterEqual };

/// A parsed display filter, or one of its parts.
struct FilterExpression {
    enum class Kind {
        And,        ///< All operands
        Or,         ///< Any operand
        Not,        ///< Not its one operand
        Comparison, ///< field operator value
        Protocol,   ///< A protocol name: the Protocol column, case aside
    };
    Kind kind = Kind::Comparison;
    std::vector<FilterExpression> operands; ///< And, Or: two or more; Not: one.

    FilterField field = FilterField::FrameLen;
    FilterOperator op = FilterOperator::Present;
    uint64_t number = 0;   ///< The value of a port, stream or length field.
    QString address;       ///< The address, as the Source column shows it.
    int prefixLength = -1; ///< An IPv4 network's prefix length, or -1.
    QString protocol;      ///< Kind::Protocol: the name, as typed.
};

/// A display filter parsed, or why it could not be.
struct ParsedDisplayFilter {
    FilterExpression expression; ///< Valid when error is empty.
    QString error;               ///< Why the filter is rejected, for the user.
    int errorPosition = -1;      ///< Where, as an index into the filter.
};

/// A display filter as a Regex Lab pattern, or why there is none.
struct DisplayFilterPattern {
    QString pattern;        ///< Empty when the filter is rejected.
    QString error;          ///< Why the filter is rejected, for the user.
    int errorPosition = -1; ///< Where, as an index into the filter.
};

/// Parse @p filter, a filter of the supported subset: the fields above,
/// compared with ==, !=, <, >, <=, >= (or eq, ne, lt, gt, le, ge) or
/// alone, protocol names, and !/not, &&/and, ||/or and parentheses, not
/// binding tighter than and, and than or.  `tcp`, `udp`, `ip` and `ipv6`
/// stand for `tcp.port`, `udp.port`, `ip.addr` and `ipv6.addr` alone.
ParsedDisplayFilter parseDisplayFilter( const QString& filter );

/// The pattern that matches the packet lines @p expression selects, and no
/// other line.
QString filterPattern( const FilterExpression& expression );

/// parseDisplayFilter(), then filterPattern().
DisplayFilterPattern displayFilterPattern( const QString& filter );

/// The pattern of the decimal numbers from @p low to @p high, without
/// leading zeros, and of no other: empty when there are none.  A @p high of
/// UINT64_MAX is no bound: every longer number matches too.  It has no
/// anchors; the text around it delimits the number.
QString numberRangePattern( uint64_t low, uint64_t high );

} // namespace tcpdump
