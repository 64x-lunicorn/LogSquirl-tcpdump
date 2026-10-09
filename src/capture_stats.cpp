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
    countEndpoint( endpointPackets, pkt.srcIp );
    countEndpoint( endpointPackets, pkt.dstIp );
    // Nested tunnels often share their endpoints: each counts the packet
    // once.  A packet has at most kMaxTunnels, so a list is searched.
    std::vector<const std::string*> tunnelEnds;
    for ( const auto& tunnel : pkt.tunnels ) {
        for ( const auto* address : { &tunnel.srcIp, &tunnel.dstIp } ) {
            const auto seen = std::find_if(
                tunnelEnds.begin(), tunnelEnds.end(),
                [ address ]( const std::string* other ) { return *other == *address; } );
            if ( seen == tunnelEnds.end() ) {
                tunnelEnds.push_back( address );
                countEndpoint( tunnelEndpointPackets, *address );
            }
        }
    }
}

void CaptureStats::addTcpAnalysis( const TcpAnalysis& analysis )
{
    for ( size_t i = 0; i < kTcpMarkerKinds; ++i ) {
        if ( analysis.markers.test( static_cast<TcpMarker>( i ) ) ) {
            ++tcpMarkers[ i ];
        }
    }
    if ( analysis.initialRttNs ) {
        initialRtts.add( *analysis.initialRttNs );
    }
}

namespace {

/// Bits of a value below its highest set one that pick its sub-bucket.
constexpr int kSubBucketBits = 6;
static_assert( RunningMedian::kSubBuckets == uint64_t{ 1 } << kSubBucketBits );
/// Buckets of the histogram: kSubBuckets for the values below it, and as
/// many for each power of two from it up to 2^63.
constexpr size_t kBuckets = RunningMedian::kSubBuckets * ( 64 - kSubBucketBits + 1 );
static_assert( kBuckets * sizeof( uint64_t ) <= RunningMedian::kMaxMemoryBytes );

int highestBit( uint64_t value )
{
    int bit = 0;
    while ( value >>= 1 ) {
        ++bit;
    }
    return bit;
}

size_t bucketOf( uint64_t value )
{
    if ( value < RunningMedian::kSubBuckets ) {
        return static_cast<size_t>( value );
    }
    const int shift = highestBit( value ) - kSubBucketBits;
    return static_cast<size_t>( RunningMedian::kSubBuckets * static_cast<uint64_t>( shift + 1 )
                                + ( ( value >> shift ) - RunningMedian::kSubBuckets ) );
}

/// The middle of bucket @p bucket: the value itself below kSubBuckets.
uint64_t bucketMiddle( size_t bucket )
{
    if ( bucket < RunningMedian::kSubBuckets ) {
        return bucket;
    }
    const int shift = static_cast<int>( bucket / RunningMedian::kSubBuckets ) - 1;
    const uint64_t lower = ( RunningMedian::kSubBuckets + bucket % RunningMedian::kSubBuckets )
                           << shift;
    return lower + ( ( uint64_t{ 1 } << shift ) >> 1 );
}

} // namespace

void RunningMedian::add( uint64_t value )
{
    ++count_;
    if ( !exact() ) {
        countInBucket( value );
        return;
    }
    if ( exact_.size() < kExactValues ) {
        exact_.reserve( kExactValues );
        exact_.push_back( value );
        return;
    }
    buckets_.assign( kBuckets, 0 );
    for ( const uint64_t kept : exact_ ) {
        countInBucket( kept );
    }
    std::vector<uint64_t>().swap( exact_ );
    countInBucket( value );
}

void RunningMedian::countInBucket( uint64_t value )
{
    ++buckets_[ bucketOf( value ) ];
}

std::optional<uint64_t> RunningMedian::median() const
{
    if ( count_ == 0 ) {
        return std::nullopt;
    }
    // The upper of the two middle ones of an even count, as an integer.
    const uint64_t rank = count_ / 2;
    if ( exact() ) {
        auto values = exact_;
        const auto middle = values.begin() + static_cast<std::ptrdiff_t>( rank );
        std::nth_element( values.begin(), middle, values.end() );
        return *middle;
    }
    uint64_t below = 0;
    for ( size_t bucket = 0; bucket < buckets_.size(); ++bucket ) {
        below += buckets_[ bucket ];
        if ( below > rank ) {
            return bucketMiddle( bucket );
        }
    }
    return std::nullopt; // Not reached: the buckets hold count_ values.
}

void CaptureStats::addLinkType( uint32_t linkType )
{
    if ( std::find( linkTypes.begin(), linkTypes.end(), linkType ) == linkTypes.end() ) {
        linkTypes.push_back( linkType );
    }
}

void CaptureStats::countEndpoint( std::map<std::string, uint64_t>& counts,
                                  const std::string& address )
{
    if ( address.empty() ) {
        return;
    }
    const auto known = counts.find( address );
    if ( known != counts.end() ) {
        ++known->second;
    }
    else if ( endpointPackets.size() + tunnelEndpointPackets.size() < maxEndpoints ) {
        counts.emplace( address, 1 );
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
