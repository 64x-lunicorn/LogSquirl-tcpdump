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
 * @file capture_stats.cpp
 * @brief Implementation of the running capture statistics.
 */

#include "capture_stats.h"

#include <algorithm>

namespace tcpdump {

void CaptureStats::add( const PacketRecord& pkt )
{
    const auto timeNs = static_cast<int64_t>( pkt.timestampSec ) * 1000000000
                        + static_cast<int64_t>( pkt.timestampNsec );
    if ( packets == 0 ) {
        firstTimeNs = lastTimeNs = timeNs;
    }
    else {
        firstTimeNs = std::min( firstTimeNs, timeNs );
        lastTimeNs = std::max( lastTimeNs, timeNs );
    }

    ++packets;
    bytes += pkt.capturedLen;
    addLinkType( pkt.linkType );
    ++protocolPackets[ pkt.protocol ];
    protocolBytes[ pkt.protocol ] += pkt.capturedLen;
    countEndpoint( pkt.srcIp );
    countEndpoint( pkt.dstIp );
}

void CaptureStats::addLinkType( uint32_t linkType )
{
    if ( std::find( linkTypes.begin(), linkTypes.end(), linkType ) == linkTypes.end() ) {
        linkTypes.push_back( linkType );
    }
}

void CaptureStats::countEndpoint( const std::string& address )
{
    if ( address.empty() ) {
        return;
    }
    const auto known = endpointPackets.find( address );
    if ( known != endpointPackets.end() ) {
        ++known->second;
    }
    else if ( endpointPackets.size() < maxEndpoints ) {
        endpointPackets.emplace( address, 1 );
    }
    else {
        ++otherEndpointPackets;
    }
}

double CaptureStats::durationSeconds() const
{
    return static_cast<double>( lastTimeNs - firstTimeNs ) / 1e9;
}

} // namespace tcpdump
