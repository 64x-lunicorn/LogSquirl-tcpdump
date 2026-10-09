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
 * @file media_expectations.cpp
 * @brief Implementation of the media endpoints SDP announced.
 */

#include "media_expectations.h"

#include "describe_common.h"

#include <algorithm>
#include <string>

namespace tcpdump {

namespace {

std::string endpointKey( const std::string& ip, uint16_t port )
{
    return ip + ' ' + std::to_string( port );
}

} // namespace

void MediaExpectations::expect( const std::string& ip, uint16_t port, bool rtcp,
                                const std::string& callId, int64_t now )
{
    if ( max_ == 0 ) {
        return;
    }
    auto key = endpointKey( ip, port );
    if ( expected_.find( key ) == expected_.end() && expected_.size() >= max_ ) {
        const auto oldest = std::min_element(
            expected_.begin(), expected_.end(),
            []( const auto& a, const auto& b ) { return a.second.lastSeen < b.second.lastSeen; } );
        expected_.erase( oldest );
    }
    expected_[ std::move( key ) ] = { ip, callId, rtcp, now };
}

void MediaExpectations::announce( const SipCall& call, int64_t now )
{
    // A BYE ends the call; a new SDP body replaces what its call expected
    // at the addresses it names.
    for ( auto it = expected_.begin(); it != expected_.end(); ) {
        const bool replaced
            = std::any_of( call.media.begin(), call.media.end(),
                           [ & ]( const auto& m ) { return m.ip == it->second.ip; } );
        if ( it->second.callId == call.callId && ( call.ends || replaced ) ) {
            it = expected_.erase( it );
        }
        else {
            ++it;
        }
    }
    if ( call.ends ) {
        return;
    }
    for ( const auto& m : call.media ) {
        expect( m.ip, m.rtpPort, false, call.callId, now );
        if ( m.rtcpPort != 0 && m.rtcpPort != m.rtpPort ) {
            expect( m.ip, m.rtcpPort, true, call.callId, now );
        }
    }
}

MediaExpectations::Expectation* MediaExpectations::find( const std::string& ip, uint16_t port,
                                                         int64_t now )
{
    const auto it = expected_.find( endpointKey( ip, port ) );
    if ( it == expected_.end() ) {
        return nullptr;
    }
    if ( now - it->second.lastSeen > kIdleSeconds ) {
        expected_.erase( it );
        return nullptr;
    }
    return &it->second;
}

void MediaExpectations::apply( PacketRecord& pkt )
{
    for ( const auto& call : pkt.sipCalls ) {
        announce( call, pkt.timestampSec );
    }
    if ( expected_.empty() || pkt.transport != Transport::Udp || pkt.payloadHeadLen == 0 ) {
        return;
    }
    auto* expectation = find( pkt.dstIp, pkt.dstPort, pkt.timestampSec );
    if ( !expectation ) {
        expectation = find( pkt.srcIp, pkt.srcPort, pkt.timestampSec );
    }
    if ( !expectation ) {
        return;
    }
    const auto* head = pkt.payloadHead.data();
    const auto wireLen = std::max<size_t>( pkt.payloadLen, pkt.payloadHeadLen );
    const bool rtcp = expectation->rtcp || describer::isRtcpHeader( head, pkt.payloadHeadLen );
    const auto text = rtcp ? describer::describeRtcp( head, pkt.payloadHeadLen, wireLen )
                           : describer::describeRtp( head, pkt.payloadHeadLen, wireLen );
    if ( text.empty() ) {
        return;
    }
    expectation->lastSeen = pkt.timestampSec;
    describer::redescribe( pkt, rtcp ? "RTCP" : "RTP", text );
}

} // namespace tcpdump
