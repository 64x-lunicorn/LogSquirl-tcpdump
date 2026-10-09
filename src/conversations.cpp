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
 * @file conversations.cpp
 * @brief Implementation of the Conversations table's counts.
 */

#include "conversations.h"

#include <tuple>

namespace tcpdump {

namespace {

/// Seconds from @p fromSec.@p fromNsec to @p toSec.@p toNsec.
double secondsBetween( int64_t fromSec, uint32_t fromNsec, int64_t toSec, uint32_t toNsec )
{
    return static_cast<double>( toSec - fromSec )
           + ( static_cast<double>( toNsec ) - static_cast<double>( fromNsec ) ) / 1e9;
}

} // namespace

void ConversationStats::add( const PacketRecord& pkt, const Stream& stream )
{
    if ( stream.id == kNoStream || !pkt.transport ) {
        return;
    }
    if ( stream.id == kUnnumbered ) {
        ++otherPackets_;
        otherBytes_ += pkt.originalLen;
        return;
    }
    auto& streams = *pkt.transport == Transport::Tcp ? tcp_ : udp_;
    const auto id = static_cast<size_t>( stream.id );
    // The tracker numbers each transport's streams one after the other.
    while ( streams.size() <= id ) {
        streams.emplace_back();
    }
    auto& counts = streams[ id ];
    const auto direction = stream.direction & 1U;
    const auto time = std::tie( pkt.timestampSec, pkt.timestampNsec );
    if ( counts.packets[ 0 ] + counts.packets[ 1 ] == 0 ) {
        counts.directionA = static_cast<uint8_t>( direction );
        counts.firstSec = counts.lastSec = pkt.timestampSec;
        counts.firstNsec = counts.lastNsec = pkt.timestampNsec;
    }
    else if ( time < std::tie( counts.firstSec, counts.firstNsec ) ) {
        counts.firstSec = pkt.timestampSec;
        counts.firstNsec = pkt.timestampNsec;
    }
    else if ( time > std::tie( counts.lastSec, counts.lastNsec ) ) {
        counts.lastSec = pkt.timestampSec;
        counts.lastNsec = pkt.timestampNsec;
    }
    ++counts.packets[ direction ];
    counts.bytes[ direction ] += pkt.originalLen;
    if ( stream.state && stream.state->label != 0 ) {
        counts.label = stream.state->label;
    }
}

std::vector<Conversation> ConversationStats::conversations( const StreamTracker& tracker,
                                                            const StreamLabels& labels,
                                                            int64_t captureStartSec,
                                                            uint32_t captureStartNsec ) const
{
    std::vector<Conversation> rows;
    rows.reserve( tcp_.size() + udp_.size() );
    for ( const auto transport : { Transport::Tcp, Transport::Udp } ) {
        const auto& streams = transport == Transport::Tcp ? tcp_ : udp_;
        for ( size_t id = 0; id < streams.size(); ++id ) {
            const auto& counts = streams[ id ];
            const auto a = counts.directionA;
            const auto b = 1U - a;
            const auto ends = tracker.endpoints( transport, static_cast<int>( id ) );
            Conversation row;
            row.transport = transport;
            row.stream = static_cast<int>( id );
            row.protocol = labels.name( counts.label );
            if ( row.protocol.empty() ) {
                row.protocol = transport == Transport::Tcp ? "TCP" : "UDP";
            }
            row.addressA = ends.address[ a ];
            row.portA = ends.port[ a ];
            row.addressB = ends.address[ b ];
            row.portB = ends.port[ b ];
            row.packetsAToB = counts.packets[ a ];
            row.bytesAToB = counts.bytes[ a ];
            row.packetsBToA = counts.packets[ b ];
            row.bytesBToA = counts.bytes[ b ];
            row.startSeconds = secondsBetween( captureStartSec, captureStartNsec, counts.firstSec,
                                               counts.firstNsec );
            row.durationSeconds = secondsBetween( counts.firstSec, counts.firstNsec, counts.lastSec,
                                                  counts.lastNsec );
            rows.push_back( std::move( row ) );
        }
    }
    return rows;
}

} // namespace tcpdump
