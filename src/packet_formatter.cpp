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
 * @file packet_formatter.cpp
 * @brief Formats parsed PacketRecord structs into Wireshark-style text lines.
 *
 * Output example:
 *   1    0.000000     192.168.1.100   10.0.0.1        TCP       60   443 → 54321 [SYN] Seq=0
 */

#include "packet_formatter.h"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <map>
#include <sstream>

namespace tcpdump {

namespace {

/// Width of the time column, with three more digits for nanoseconds.
int timeWidth( TimePrecision precision )
{
    return precision == TimePrecision::Nanoseconds ? 18 : 15;
}

/// @p deltaNs as seconds with 9 or 6 decimals, computed in integers so that
/// neither precision nor range is lost.
std::string formatRelativeTime( int64_t deltaNs, TimePrecision precision )
{
    const bool negative = deltaNs < 0;
    const auto magnitude
        = negative ? 0 - static_cast<uint64_t>( deltaNs ) : static_cast<uint64_t>( deltaNs );
    const auto seconds = static_cast<unsigned long long>( magnitude / 1000000000 );
    const auto fraction = magnitude % 1000000000;
    char buf[ 40 ];
    if ( precision == TimePrecision::Nanoseconds ) {
        std::snprintf( buf, sizeof( buf ), "%s%llu.%09llu", negative ? "-" : "", seconds,
                       static_cast<unsigned long long>( fraction ) );
    }
    else {
        std::snprintf( buf, sizeof( buf ), "%s%llu.%06llu", negative ? "-" : "", seconds,
                       static_cast<unsigned long long>( fraction / 1000 ) );
    }
    return buf;
}

} // namespace

std::string formatPacketLine( const PacketRecord& pkt, uint32_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, TimePrecision precision )
{
    // Time relative to the first packet; negative for an earlier packet
    const int64_t deltaNs = ( static_cast<int64_t>( pkt.timestampSec ) - baseTimeSec ) * 1000000000
                            + ( static_cast<int64_t>( pkt.timestampNsec ) - baseTimeNsec );

    const std::string streamStr = streamId >= 0             ? std::to_string( streamId )
                                  : streamId == kUnnumbered ? "?"
                                                            : "-";

    // Use fixed-width columns like Wireshark's packet list
    std::ostringstream oss;
    oss << std::left;
    oss << std::setw( 7 ) << pkt.number;
    oss << std::setw( 8 ) << streamStr;
    oss << std::setw( timeWidth( precision ) ) << formatRelativeTime( deltaNs, precision );
    oss << std::setw( 40 ) << ( pkt.srcIp.empty() ? pkt.srcMac : pkt.srcIp );
    oss << std::setw( 40 ) << ( pkt.dstIp.empty() ? pkt.dstMac : pkt.dstIp );
    oss << std::setw( 10 ) << pkt.protocol;
    oss << std::setw( 7 ) << pkt.capturedLen;
    oss << pkt.info;

    return oss.str();
}

std::string PacketFormatter::header() const
{
    std::ostringstream hdr;
    hdr << std::left;
    hdr << std::setw( 7 ) << "No.";
    hdr << std::setw( 8 ) << "Stream";
    hdr << std::setw( timeWidth( precision_ ) ) << "Time";
    hdr << std::setw( 40 ) << "Source";
    hdr << std::setw( 40 ) << "Destination";
    hdr << std::setw( 10 ) << "Protocol";
    hdr << std::setw( 7 ) << "Len";
    hdr << "Info";
    return hdr.str();
}

std::string PacketFormatter::format( const PacketRecord& pkt )
{
    if ( !haveBase_ ) {
        haveBase_ = true;
        baseTimeSec_ = pkt.timestampSec;
        baseTimeNsec_ = pkt.timestampNsec;
    }
    return formatPacketLine( pkt, baseTimeSec_, baseTimeNsec_, streamId( pkt ), precision_ );
}

int PacketFormatter::streamId( const PacketRecord& pkt )
{
    // Packets sharing the same IP+port 4-tuple (in either direction) belong
    // to the same conversation.
    if ( pkt.srcIp.empty() && pkt.dstIp.empty() ) {
        return kNoStream; // No IP layer (e.g. ARP) — no stream
    }

    // Build canonical key: sort endpoints so both directions match
    auto epA = pkt.srcIp + ":" + std::to_string( pkt.srcPort );
    auto epB = pkt.dstIp + ":" + std::to_string( pkt.dstPort );
    std::string key = ( epA < epB ) ? ( epA + "|" + epB ) : ( epB + "|" + epA );

    const auto known = streams_.find( key );
    if ( known != streams_.end() ) {
        return known->second;
    }
    if ( streams_.size() >= maxStreams_ ) {
        streamLimitReached_ = true;
        return kUnnumbered;
    }
    const auto next = static_cast<int>( streams_.size() );
    streams_.emplace( std::move( key ), next );
    return next;
}

std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets )
{
    auto finest = TimePrecision::Microseconds;
    for ( const auto& pkt : packets ) {
        finest = std::max( finest, pkt.precision );
    }
    PacketFormatter formatter( finest );
    std::vector<std::string> lines;
    lines.reserve( packets.size() + 1 );
    lines.push_back( formatter.header() );

    for ( const auto& pkt : packets ) {
        lines.push_back( formatter.format( pkt ) );
    }
    return lines;
}

} // namespace tcpdump
