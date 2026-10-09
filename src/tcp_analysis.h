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
 * @brief Follows each TCP stream's sequence numbers over its segments.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"

namespace tcpdump {

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
 * connection on the same addresses and ports, which counts afresh.  The
 * numbers wrap around at 2^32 with the sequence numbers.  Without the ACK
 * flag the acknowledgement field means nothing and Ack=0 is shown.
 *
 * Packets other than TCP ones, and those of a stream past the stream cap,
 * which has no state, are left as they are.
 */
void analyseTcp( PacketRecord& pkt, const Stream& stream );

} // namespace tcpdump
