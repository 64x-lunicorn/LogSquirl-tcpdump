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
 * @file packet_layers.cpp
 * @brief Collecting a packet's layers, and dissecting a packet into them.
 */

#include "packet_layers.h"

#include "packet_formatter.h"
#include "protocol_names.h"

#include <algorithm>
#include <cstdio>

namespace tcpdump {

std::pair<size_t, size_t> PacketLayers::span( const uint8_t* at, size_t length ) const
{
    if ( !at ) {
        return { 0, 0 }; // a field without bytes of its own
    }
    if ( at < packet_ || at > packet_ + len_ ) {
        return { len_, 0 };
    }
    const auto offset = static_cast<size_t>( at - packet_ );
    return { offset, std::min( length, len_ - offset ) };
}

void PacketLayers::layer( std::string name, const uint8_t* at, size_t length )
{
    const auto [ offset, cut ] = span( at, length );
    layers_.push_back( { std::move( name ), offset, cut, {} } );
}

void PacketLayers::setLength( size_t length )
{
    if ( !layers_.empty() ) {
        auto& last = layers_.back();
        last.length = std::min( length, len_ - std::min( last.offset, len_ ) );
    }
}

void PacketLayers::field( std::string name, std::string value, const uint8_t* at, size_t length )
{
    if ( layers_.empty() ) {
        return;
    }
    const auto [ offset, cut ] = span( at, length );
    layers_.back().fields.push_back( { std::move( name ), std::move( value ), offset, cut } );
}

std::string hexField( uint64_t value, int digits )
{
    char hex[ 24 ];
    std::snprintf( hex, sizeof( hex ), "0x%0*llX", digits,
                   static_cast<unsigned long long>( value ) );
    return hex;
}

std::string etherTypeField( uint16_t etherType )
{
    const auto* name = etherTypeName( etherType );
    return name ? std::string( name ) + " (" + hexField( etherType, 4 ) + ")"
                : hexField( etherType, 4 );
}

std::string ipProtocolField( uint8_t protocol )
{
    const auto* name = ipProtocolName( protocol );
    return name ? std::string( name ) + " (" + std::to_string( protocol ) + ")"
                : std::to_string( protocol );
}

std::vector<PacketLayer> dissectLayers( const PacketRecord& record, const uint8_t* data, size_t len,
                                        bool swap )
{
    PacketLayers layers( data, len );

    // The record itself, as Wireshark's Frame: it spans every captured byte.
    layers.layer( "Frame " + std::to_string( record.number ) + ": "
                      + std::to_string( record.originalLen ) + " bytes on wire, "
                      + std::to_string( record.capturedLen ) + " bytes captured",
                  data, len );
    layers.field( "Arrival Time",
                  formatUtcTime( record.timestampSec, record.timestampNsec, record.precision ),
                  nullptr, 0 );
    layers.field( "Frame Number", std::to_string( record.number ), nullptr, 0 );
    layers.field( "Frame Length", std::to_string( record.originalLen ) + " bytes", nullptr, 0 );
    layers.field( "Capture Length", std::to_string( record.capturedLen ) + " bytes", nullptr, 0 );
    layers.field( "Link Type",
                  linkTypeName( record.linkType ) + " (" + std::to_string( record.linkType ) + ")",
                  nullptr, 0 );

    PacketRecord pkt;
    pkt.number = record.number;
    pkt.timestampSec = record.timestampSec;
    pkt.timestampNsec = record.timestampNsec;
    pkt.capturedLen = record.capturedLen;
    pkt.originalLen = record.originalLen;
    pkt.linkType = record.linkType;
    pkt.precision = record.precision;
    pkt.layers = &layers;
    dissectPacket( pkt, pkt.linkType, swap, data, len );
    return layers.take();
}

} // namespace tcpdump
