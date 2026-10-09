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
 * @file tcp_analysis.h
 * @brief Follows each TCP stream's sequence numbers over its segments, and
 *        marks the segments Wireshark's TCP analysis would.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"

#include <cstddef>
#include <cstdint>

namespace tcpdump {

/**
 * The kinds of marker the TCP Analysis puts at the start of Info, as
 * Wireshark's "[TCP …]" expert markers.  In the order Wireshark adds them
 * to Info, each in front of the ones before.
 */
enum class TcpMarker : uint8_t {
    Retransmission,             ///< Data sent again, after a while.
    FastRetransmission,         ///< Data sent again on two duplicate ACKs for it.
    SpuriousRetransmission,     ///< Data sent again that was acknowledged already.
    OutOfOrder,                 ///< Data that arrives shortly after later data.
    PreviousSegmentNotCaptured, ///< Data beyond the next sequence number.
    WindowUpdate,               ///< An ACK that only changes the window.
    KeepAlive,                  ///< An empty or one-byte segment one byte behind.
    KeepAliveAck,               ///< The ACK repeated in answer to a keep-alive.
    DupAck,                     ///< An ACK that repeats the previous one.
    ZeroWindowProbe,            ///< One byte sent into a closed window.
    ZeroWindow,                 ///< A segment advertising a window of zero.
    ZeroWindowProbeAck,         ///< The ACK of a probe that keeps the window closed.
};

/// How many kinds of TcpMarker there are.
constexpr size_t kTcpMarkerKinds = 12;

/// The marker's text without its brackets, as Wireshark writes it in
/// Info: "TCP Retransmission", "TCP Dup ACK" (without its numbers), …
const char* tcpMarkerName( TcpMarker marker );

/// A set of TcpMarker, the markers of one segment.
class TcpMarkers {
public:
    TcpMarkers& set( TcpMarker marker )
    {
        bits_ |= bit( marker );
        return *this;
    }
    bool test( TcpMarker marker ) const
    {
        return ( bits_ & bit( marker ) ) != 0;
    }
    bool none() const
    {
        return bits_ == 0;
    }
    bool operator==( const TcpMarkers& other ) const
    {
        return bits_ == other.bits_;
    }

private:
    static uint16_t bit( TcpMarker marker )
    {
        return static_cast<uint16_t>( 1u << static_cast<unsigned>( marker ) );
    }
    uint16_t bits_ = 0;
};

/**
 * Show @p pkt's sequence and acknowledgement numbers in Info relative to
 * the first ones of each direction of its stream, as Wireshark does by
 * default, and remember what that takes in @p stream's state.
 *
 * A SYN's sequence number is its direction's base, so the SYN shows Seq=0
 * and the first byte of data Seq=1.  A direction whose SYN was not captured
 * counts from one less than the first number seen of it, the sequence
 * number of its first segment or the acknowledgement number of the other
 * direction's, whichever comes first, so that it too starts at 1.  A SYN
 * with a sequence number other than its direction's base starts a new
 * connection on the same addresses and ports, which counts afresh: the
 * stream's whole state is reset, its label (StreamLabels) too.  The
 * numbers wrap around at 2^32 with the sequence numbers.  Without the ACK
 * flag the acknowledgement field means nothing and Ack=0 is shown.
 *
 * The segment is then classified by Wireshark's TCP analysis heuristics
 * (packet-tcp.c, tcp_analyze_sequence_number()), as far as what each
 * direction keeps allows (TcpDirection): its markers are put at the start
 * of Info, "[TCP Retransmission] 80 → 54321 …", in Wireshark's wording and
 * order, and returned.  A segment that cannot be classified, such as the
 * first of a stream captured mid-way, gets none.  The Developer Guide
 * lists the rules and where they fall short of Wireshark's.
 *
 * Packets other than TCP ones and those of a stream past the stream cap,
 * which has no state, are left as they are.  A segment with a bogus TCP
 * header length gets relative numbers but no markers, as Wireshark does
 * not analyse it.
 */
TcpMarkers analyseTcp( PacketRecord& pkt, const Stream& stream );

} // namespace tcpdump
