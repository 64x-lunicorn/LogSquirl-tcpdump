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

#include <algorithm>
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
    auto& made = *pkt.transport == Transport::Tcp ? tcpMade_ : udpMade_;
    const auto chunk = id / ConversationRows::kChunkRows;
    if ( chunk < made.changed.size() ) {
        made.changed[ chunk ] = true;
    }
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

bool Conversation::operator==( const Conversation& other ) const
{
    return std::tie( transport, stream, portA, portB, protocol, addressA, addressB, packetsAToB,
                     bytesAToB, packetsBToA, bytesBToA, startSeconds, durationSeconds )
           == std::tie( other.transport, other.stream, other.portA, other.portB, other.protocol,
                        other.addressA, other.addressB, other.packetsAToB, other.bytesAToB,
                        other.packetsBToA, other.bytesBToA, other.startSeconds,
                        other.durationSeconds );
}

// ── ConversationRows ─────────────────────────────────────────────────────

ConversationRows::ConversationRows( std::vector<Conversation> rows )
    : ConversationRows( std::vector<std::shared_ptr<const Chunk>>{
          std::make_shared<const Chunk>( std::move( rows ) ) } )
{
}

ConversationRows::ConversationRows( std::vector<std::shared_ptr<const Chunk>> chunks )
    : chunks_( std::move( chunks ) )
{
    starts_.reserve( chunks_.size() );
    for ( const auto& chunk : chunks_ ) {
        starts_.push_back( size_ );
        size_ += chunk->size();
    }
}

const Conversation& ConversationRows::operator[]( size_t i ) const
{
    // The chunk is the last one that starts at or before the row.
    const auto at = std::upper_bound( starts_.begin(), starts_.end(), i ) - starts_.begin() - 1;
    const auto chunk = static_cast<size_t>( at );
    return ( *chunks_[ chunk ] )[ i - starts_[ chunk ] ];
}

std::vector<Conversation> ConversationRows::list() const
{
    std::vector<Conversation> rows;
    rows.reserve( size_ );
    for ( const auto& chunk : chunks_ ) {
        rows.insert( rows.end(), chunk->begin(), chunk->end() );
    }
    return rows;
}

// ── ConversationStats ────────────────────────────────────────────────────

Conversation ConversationStats::row( Transport transport, size_t id, const StreamTracker& tracker,
                                     const StreamLabels& labels, int64_t captureStartSec,
                                     uint32_t captureStartNsec ) const
{
    const auto& counts = ( transport == Transport::Tcp ? tcp_ : udp_ )[ id ];
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
    row.startSeconds
        = secondsBetween( captureStartSec, captureStartNsec, counts.firstSec, counts.firstNsec );
    row.durationSeconds
        = secondsBetween( counts.firstSec, counts.firstNsec, counts.lastSec, counts.lastNsec );
    return row;
}

std::vector<Conversation> ConversationStats::conversations( const StreamTracker& tracker,
                                                            const StreamLabels& labels,
                                                            int64_t captureStartSec,
                                                            uint32_t captureStartNsec ) const
{
    std::vector<Conversation> rows;
    rows.reserve( tcp_.size() + udp_.size() );
    for ( const auto transport : { Transport::Tcp, Transport::Udp } ) {
        const auto count = ( transport == Transport::Tcp ? tcp_ : udp_ ).size();
        for ( size_t id = 0; id < count; ++id ) {
            rows.push_back(
                row( transport, id, tracker, labels, captureStartSec, captureStartNsec ) );
        }
    }
    return rows;
}

std::shared_ptr<const ConversationRows> ConversationStats::rows( const StreamTracker& tracker,
                                                                 const StreamLabels& labels,
                                                                 int64_t captureStartSec,
                                                                 uint32_t captureStartNsec ) const
{
    constexpr auto kRows = ConversationRows::kChunkRows;
    // Every row's start counts from the capture's.
    const bool startMoved = captureStartSec != madeStartSec_ || captureStartNsec != madeStartNsec_;
    madeStartSec_ = captureStartSec;
    madeStartNsec_ = captureStartNsec;
    std::vector<std::shared_ptr<const ConversationRows::Chunk>> all;
    for ( const auto transport : { Transport::Tcp, Transport::Udp } ) {
        auto& made = transport == Transport::Tcp ? tcpMade_ : udpMade_;
        const auto count = ( transport == Transport::Tcp ? tcp_ : udp_ ).size();
        const auto chunks = ( count + kRows - 1 ) / kRows;
        made.chunks.resize( chunks );
        made.changed.resize( chunks, true );
        for ( size_t c = 0; c < chunks; ++c ) {
            const auto end = std::min( count, ( c + 1 ) * kRows );
            auto& chunk = made.chunks[ c ];
            if ( startMoved || made.changed[ c ] || !chunk || chunk->size() != end - c * kRows ) {
                auto fresh = std::make_shared<ConversationRows::Chunk>();
                fresh->reserve( end - c * kRows );
                for ( auto id = c * kRows; id < end; ++id ) {
                    fresh->push_back(
                        row( transport, id, tracker, labels, captureStartSec, captureStartNsec ) );
                }
                chunk = std::move( fresh );
                made.changed[ c ] = false;
            }
            all.push_back( chunk );
        }
    }
    return std::make_shared<const ConversationRows>( std::move( all ) );
}

} // namespace tcpdump
