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

#include <cstdio>
#include <iomanip>
#include <map>
#include <sstream>

namespace tcpdump {

std::string formatTcpFlags( uint8_t flags )
{
    std::string result = "[";
    bool first = true;
    auto add = [ & ]( const char* name ) {
        if ( !first )
            result += ", ";
        result += name;
        first = false;
    };
    if ( flags & 0x02 )
        add( "SYN" );
    if ( flags & 0x10 )
        add( "ACK" );
    if ( flags & 0x01 )
        add( "FIN" );
    if ( flags & 0x04 )
        add( "RST" );
    if ( flags & 0x08 )
        add( "PSH" );
    if ( flags & 0x20 )
        add( "URG" );
    if ( first )
        result += "none";
    result += "]";
    return result;
}

std::string formatPacketLine( const PacketRecord& pkt, uint32_t baseTimeSec, uint32_t baseTimeUsec,
                              int streamId )
{
    // Calculate relative time from the first packet
    double relTime = 0.0;
    if ( pkt.timestampSec >= baseTimeSec ) {
        relTime
            = static_cast<double>( pkt.timestampSec - baseTimeSec )
              + ( static_cast<double>( pkt.timestampUsec ) - static_cast<double>( baseTimeUsec ) )
                    / 1000000.0;
    }

    // Use fixed-width columns like Wireshark's packet list
    char timeBuf[ 16 ];
    std::snprintf( timeBuf, sizeof( timeBuf ), "%.6f", relTime );

    std::string streamStr = ( streamId >= 0 ) ? std::to_string( streamId ) : "-";

    std::ostringstream oss;
    oss << std::left;
    oss << std::setw( 7 ) << pkt.number;
    oss << std::setw( 8 ) << streamStr;
    oss << std::setw( 15 ) << timeBuf;
    oss << std::setw( 40 ) << ( pkt.srcIp.empty() ? pkt.srcMac : pkt.srcIp );
    oss << std::setw( 40 ) << ( pkt.dstIp.empty() ? pkt.dstMac : pkt.dstIp );
    oss << std::setw( 10 ) << pkt.protocol;
    oss << std::setw( 7 ) << pkt.capturedLen;
    oss << pkt.info;

    return oss.str();
}

std::string PacketFormatter::header()
{
    std::ostringstream hdr;
    hdr << std::left;
    hdr << std::setw( 7 ) << "No.";
    hdr << std::setw( 8 ) << "Stream";
    hdr << std::setw( 15 ) << "Time";
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
        baseTimeUsec_ = pkt.timestampUsec;
    }
    return formatPacketLine( pkt, baseTimeSec_, baseTimeUsec_, streamId( pkt ) );
}

int PacketFormatter::streamId( const PacketRecord& pkt )
{
    // Packets sharing the same IP+port 4-tuple (in either direction) belong
    // to the same conversation.
    if ( pkt.srcIp.empty() && pkt.dstIp.empty() ) {
        return -1; // No IP layer (e.g. ARP) — no stream
    }

    // Build canonical key: sort endpoints so both directions match
    auto epA = pkt.srcIp + ":" + std::to_string( pkt.srcPort );
    auto epB = pkt.dstIp + ":" + std::to_string( pkt.dstPort );
    std::string key = ( epA < epB ) ? ( epA + "|" + epB ) : ( epB + "|" + epA );

    const auto next = static_cast<int>( streams_.size() );
    return streams_.emplace( std::move( key ), next ).first->second;
}

std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets )
{
    std::vector<std::string> lines;
    lines.reserve( packets.size() + 1 );
    lines.push_back( PacketFormatter::header() );

    PacketFormatter formatter;
    for ( const auto& pkt : packets ) {
        lines.push_back( formatter.format( pkt ) );
    }
    return lines;
}

} // namespace tcpdump
