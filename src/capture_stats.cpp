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
#include <tuple>

namespace tcpdump {

void CaptureStats::add( const PacketRecord& pkt )
{
    const auto time = std::tie( pkt.timestampSec, pkt.timestampNsec );
    if ( packets == 0 || time < std::tie( firstTimeSec, firstTimeNsec ) ) {
        firstTimeSec = pkt.timestampSec;
        firstTimeNsec = pkt.timestampNsec;
    }
    if ( packets == 0 || time > std::tie( lastTimeSec, lastTimeNsec ) ) {
        lastTimeSec = pkt.timestampSec;
        lastTimeNsec = pkt.timestampNsec;
    }

    ++packets;
    bytes += pkt.capturedLen;
    if ( pkt.capturedLen < pkt.originalLen ) {
        ++cutPackets;
    }
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
    return static_cast<double>( lastTimeSec - firstTimeSec )
           + ( static_cast<double>( lastTimeNsec ) - static_cast<double>( firstTimeNsec ) ) / 1e9;
}

} // namespace tcpdump
