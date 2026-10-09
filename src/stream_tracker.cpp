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
 * @file stream_tracker.cpp
 * @brief Implementation of the Stream Tracker.
 */

#include "stream_tracker.h"

#include <utility>

namespace tcpdump {

Stream StreamTracker::track( const PacketRecord& pkt )
{
    if ( !pkt.transport ) {
        return {}; // No TCP or UDP header: no conversation, no ports
    }
    auto& conversations = *pkt.transport == Transport::Tcp ? tcp_ : udp_;

    // Order the endpoints, so that both directions find the same key.
    auto epA = pkt.srcIp + ":" + std::to_string( pkt.srcPort );
    auto epB = pkt.dstIp + ":" + std::to_string( pkt.dstPort );
    const unsigned direction = ( epB < epA ) ? 1 : 0;
    auto key = direction == 0 ? ( epA + "|" + epB ) : ( epB + "|" + epA );

    const auto known = conversations.ids.find( key );
    if ( known != conversations.ids.end() ) {
        return { known->second, &conversations.states[ static_cast<size_t>( known->second ) ],
                 direction };
    }
    if ( tcp_.ids.size() + udp_.ids.size() >= maxStreams_ ) {
        limitReached_ = true;
        return { kUnnumbered, nullptr };
    }
    const auto next = static_cast<int>( conversations.states.size() );
    conversations.ids.emplace( std::move( key ), next );
    conversations.states.emplace_back();
    return { next, &conversations.states.back(), direction };
}

} // namespace tcpdump
