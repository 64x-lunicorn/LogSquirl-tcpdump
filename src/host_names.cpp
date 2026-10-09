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
 * @file host_names.cpp
 * @brief Implementation of the Host Names.
 */

#include "host_names.h"

#include "payload_describer.h"
#include "wire_bytes.h"

#include <algorithm>

namespace tcpdump {

namespace {

constexpr uint16_t kDnsPort = 53;
constexpr uint16_t kMdnsPort = 5353;

} // namespace

HostNames::HostNames( size_t maxNames )
    : maxNames_( std::max<size_t>( maxNames, 1 ) )
{
}

void HostNames::learn( const PacketRecord& pkt, ByteView payload, ByteView tcpMessages )
{
    if ( pkt.transport == Transport::Udp
         && ( pkt.srcPort == kDnsPort || pkt.srcPort == kMdnsPort ) ) {
        if ( payload.data && payload.size > 0 ) {
            learnMessage( payload.data, payload.size );
        }
        return;
    }
    if ( pkt.transport != Transport::Tcp || pkt.srcPort != kDnsPort || !tcpMessages.data ) {
        return;
    }
    // Each message behind its length; the bytes behind the last whole one
    // are none of DNS's.
    size_t at = 0;
    while ( tcpMessages.size - at >= 2 ) {
        const size_t length = readBE16( tcpMessages.data + at );
        if ( tcpMessages.size - at - 2 < length ) {
            break;
        }
        learnMessage( tcpMessages.data + at + 2, length );
        at += 2 + length;
    }
}

void HostNames::learnMessage( const uint8_t* message, size_t len )
{
    for ( const auto& [ address, name ] : dnsResolvedNames( message, len ) ) {
        add( address, name );
    }
}

void HostNames::add( const std::string& address, const std::string& name )
{
    const auto it = names_.find( address );
    if ( it != names_.end() ) {
        it->second.name = name;
        order_.splice( order_.end(), order_, it->second.age );
        return;
    }
    if ( names_.size() >= maxNames_ ) {
        names_.erase( order_.front() );
        order_.pop_front();
    }
    order_.push_back( address );
    names_.emplace( address, Entry{ name, std::prev( order_.end() ) } );
}

const std::string* HostNames::find( const std::string& address ) const
{
    const auto it = names_.find( address );
    return it == names_.end() ? nullptr : &it->second.name;
}

} // namespace tcpdump
