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
 * @file tcp_analysis.cpp
 * @brief Implementation of the TCP Analysis.
 */

#include "tcp_analysis.h"

namespace tcpdump {

namespace {

constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpAck = 0x10;

/// Learn the bases of @p fwd, the packet's direction, and @p rev, the other
/// one, from a segment with sequence number @p seq and acknowledgement
/// number @p ack, if not known yet.  Unsigned arithmetic wraps at 2^32.
void learnBases( TcpDirection& fwd, TcpDirection& rev, uint8_t flags, uint32_t seq, uint32_t ack )
{
    const bool syn = ( flags & kTcpSyn ) != 0;
    if ( syn && !( flags & kTcpAck ) && fwd.baseSeqSet && fwd.baseSeq != seq ) {
        // A new connection on the same addresses and ports.
        fwd = {};
        rev = {};
    }
    if ( !fwd.baseSeqSet ) {
        fwd.baseSeq = syn ? seq : seq - 1;
        fwd.baseSeqSet = true;
    }
    // A SYN's acknowledgement field is not the other side's yet.
    if ( !rev.baseSeqSet && ( flags & kTcpAck ) ) {
        rev.baseSeq = ack - 1;
        rev.baseSeqSet = true;
    }
}

} // namespace

void analyseTcp( PacketRecord& pkt, const Stream& stream )
{
    if ( pkt.transport != Transport::Tcp || !stream.state ) {
        return;
    }
    auto& fwd = stream.state->tcp[ stream.direction ];
    auto& rev = stream.state->tcp[ 1 - stream.direction ];
    learnBases( fwd, rev, pkt.tcpFlags, pkt.tcpSeq, pkt.tcpAck );

    const auto seq = pkt.tcpSeq - fwd.baseSeq;
    const auto ack = ( pkt.tcpFlags & kTcpAck ) ? pkt.tcpAck - rev.baseSeq : 0;

    // The parser wrote the numbers as they are, right after the flags: the
    // first "Seq=" of Info, before any payload description.
    const auto raw = formatTcpNumbers( pkt.tcpSeq, pkt.tcpAck );
    const auto at = pkt.info.find( "Seq=" );
    if ( at != std::string::npos && pkt.info.compare( at, raw.size(), raw ) == 0 ) {
        pkt.info.replace( at, raw.size(), formatTcpNumbers( seq, ack ) );
    }
}

} // namespace tcpdump
