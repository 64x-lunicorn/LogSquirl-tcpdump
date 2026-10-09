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
 * @file tcp_reassembly.cpp
 * @brief Implementation of the TCP Reassembly.
 */

#include "tcp_reassembly.h"

#include "payload_describer.h"

#include <algorithm>
#include <string>
#include <utility>

namespace tcpdump {

namespace {

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;

/// StreamState::reassembly: the direction has an entry: holds bytes, or skips a message.
constexpr uint8_t heldBit( unsigned direction )
{
    return static_cast<uint8_t>( 1u << direction );
}

/// StreamState::reassembly: the direction's bytes were let go for lack of memory.
constexpr uint8_t letGoBit( unsigned direction )
{
    return static_cast<uint8_t>( 4u << direction );
}

/// Where a run of bytes stops being whole messages.
struct Walk {
    /// The end of the last whole message, or of the bytes if those after
    /// it are none the protocol frames.
    size_t end = 0;
    /// The message that begins at end and goes on past the bytes; framer 0
    /// if there is none.
    MessageExtent incomplete;
};

/// Walk the messages of protocol @p framer in the @p len bytes at @p data,
/// one after the other from the first.
Walk walkMessages( const uint8_t* data, size_t len, const PacketRecord& pkt, const Stream& stream,
                   uint8_t framer )
{
    Walk walk;
    while ( walk.end < len ) {
        const auto extent = tcpMessageExtent( data + walk.end, len - walk.end, pkt.srcPort,
                                              pkt.dstPort, framer, &stream );
        if ( extent.framer == 0 ) {
            walk.end = len; // the rest is none of the protocol's: described as it is
            break;
        }
        if ( extent.needsMore ) {
            walk.incomplete = extent;
            break;
        }
        walk.end += extent.length;
    }
    return walk;
}

/// Append @p marker to the end of @p pkt's Info.
void mark( PacketRecord& pkt, const char* marker )
{
    pkt.info += ' ';
    pkt.info += marker;
    pkt.previewBytes = 0; // Info no longer ends in the preview
}

/// Describe @p pkt from the @p len bytes at @p data, whole messages of
/// protocol @p framer, @p label, put together from @p segments segments.
void describeMessages( PacketRecord& pkt, const uint8_t* data, size_t len, uint8_t framer,
                       const char* label, uint32_t segments )
{
    const auto described = describeTcpMessages( data, len, pkt.srcPort, pkt.dstPort, framer );
    auto description = described.description;
    if ( segments > 1 ) {
        description += ( description.empty() ? "" : " " ) + std::string( "[reassembled from " )
                       + std::to_string( segments ) + " segments]";
    }
    redescribe( pkt, described.label.empty() ? label : described.label.c_str(), description );
    pkt.sipCalls = described.sipCalls;   // what the messages' SDP bodies announce
    pkt.streamCue = described.streamCue; // what they tell the stream's later packets
}

/// Describe @p pkt as a segment of a message of protocol @p label that
/// completes later, or, @p what, one past the limit: what its first bytes
/// seemed to announce is not so.
void describeSegment( PacketRecord& pkt, const char* label, const char* what = kSegmentOfMessage )
{
    redescribe( pkt, label, what );
    pkt.sipCalls.clear();
    pkt.streamCue = StreamCue::None;
}

/// The incomplete message @p extent, @p rest of whose bytes are there, is
/// longer than @p limit and its header says by how much: the bytes left
/// are worth skipping.
bool announcedPast( const MessageExtent& extent, size_t rest, size_t limit )
{
    // A framer that cannot tell the length yet answers one more than given.
    return extent.framer != 0 && extent.length > limit && extent.length > rest + 1;
}

} // namespace

TcpReassembly::TcpReassembly( size_t memoryLimit, size_t streamLimit )
    : memoryLimit_( memoryLimit )
    , streamLimit_( streamLimit )
{
}

TcpReassembly::Key TcpReassembly::keyOf( const Stream& stream, unsigned direction )
{
    return ( static_cast<Key>( stream.id ) << 1 ) | direction;
}

TcpReassembly::Entry* TcpReassembly::find( const Stream& stream, unsigned direction )
{
    const auto it = entries_.find( keyOf( stream, direction ) );
    return it == entries_.end() ? nullptr : &it->second;
}

void TcpReassembly::release( Key key )
{
    const auto it = entries_.find( key );
    if ( it == entries_.end() ) {
        return;
    }
    it->second.state->reassembly &= static_cast<uint8_t>( ~heldBit( it->second.direction ) );
    used_ -= it->second.cost;
    lru_.erase( it->second.lru );
    entries_.erase( it );
}

void TcpReassembly::release( const Stream& stream, unsigned direction )
{
    release( keyOf( stream, direction ) );
}

void TcpReassembly::recharge( Entry& entry )
{
    size_t cost = kEntryOverhead + entry.held.capacity();
    for ( const auto& segment : entry.order.early() ) {
        cost += kEarlySegmentOverhead + segment.bytes.capacity();
    }
    used_ = used_ - entry.cost + cost;
    entry.cost = cost;
}

bool TcpReassembly::makeRoom( size_t bytes, Key keep )
{
    while ( used_ + bytes > memoryLimit_ ) {
        auto oldest = lru_.begin();
        if ( oldest != lru_.end() && *oldest == keep ) {
            ++oldest;
        }
        if ( oldest == lru_.end() ) {
            return false;
        }
        const auto& entry = entries_.at( *oldest );
        entry.state->reassembly |= letGoBit( entry.direction );
        release( *oldest );
    }
    return true;
}

bool TcpReassembly::reserve( Entry& entry, Key key, size_t extra )
{
    const auto early = entry.order.earlyBytes();
    const auto needed = entry.held.size() + extra;
    if ( needed + early > streamLimit_ ) {
        return false;
    }
    const auto capacity = entry.held.capacity();
    if ( needed <= capacity ) {
        return true;
    }
    // Grow by half at least, within the limit, so that a header section that
    // comes in many small segments is not copied once per segment.
    const auto grown
        = std::max( needed, std::min( capacity + capacity / 2, streamLimit_ - early ) );
    if ( !makeRoom( grown - capacity, key ) ) {
        return false;
    }
    entry.held.reserve( grown );
    recharge( entry );
    return true;
}

bool TcpReassembly::append( Entry& entry, Key key, const uint8_t* data, size_t len )
{
    if ( !reserve( entry, key, len ) ) {
        return false;
    }
    entry.held.insert( entry.held.end(), data, data + len );
    entry.order.advance( len );
    ++entry.segments;
    return true;
}

bool TcpReassembly::holdEarly( Entry& entry, Key key, uint32_t seq, ByteView payload )
{
    if ( entry.order.holds( seq, payload.size ) ) {
        return true; // the same bytes again
    }
    if ( entry.order.early().size() >= kMaxEarlySegments
         || entry.held.capacity() + entry.order.earlyBytes() + payload.size > streamLimit_
         || !makeRoom( kEarlySegmentOverhead + payload.size, key ) ) {
        return false;
    }
    entry.order.holdEarly( seq, payload );
    recharge( entry );
    return true;
}

bool TcpReassembly::appendEarly( Entry& entry, Key key )
{
    std::vector<uint8_t> next;
    while ( entry.order.popNext( next ) ) {
        if ( !append( entry, key, next.data(), next.size() ) ) {
            return false;
        }
    }
    recharge( entry );
    return true;
}

void TcpReassembly::skip( const Stream& stream, const char* label, uint32_t from, size_t bytes )
{
    const auto key = keyOf( stream, stream.direction );
    release( key );
    if ( bytes > kMaxSkip || !makeRoom( kEntryOverhead, key ) ) {
        return;
    }
    auto& entry = entries_[ key ];
    entry.state = stream.state;
    entry.direction = stream.direction;
    entry.label = label;
    entry.skipping = true;
    entry.skipFrom = from;
    entry.skipEnd = from + static_cast<uint32_t>( bytes );
    entry.lru = lru_.insert( lru_.end(), key );
    recharge( entry );
    stream.state->reassembly |= heldBit( stream.direction );
}

std::optional<ReassembledMessages> TcpReassembly::skipSegment( PacketRecord& pkt,
                                                               const Stream& stream,
                                                               ByteView payload, Entry& entry )
{
    lru_.splice( lru_.end(), lru_, entry.lru );
    if ( seqAfter( entry.skipFrom, pkt.tcpSeq ) > 0 ) {
        return ReassembledMessages{}; // bytes from before the rest: a retransmission
    }
    const uint32_t end = pkt.tcpSeq + pkt.payloadLen;
    const auto* label = entry.label;
    if ( seqAfter( end, entry.skipEnd ) <= 0 ) {
        describeSegment( pkt, label, kContinuationOfMessage );
        if ( end == entry.skipEnd ) {
            release( keyOf( stream, stream.direction ) ); // the message is over
        }
        return ReassembledMessages{};
    }
    const auto offset = static_cast<size_t>( entry.skipEnd - pkt.tcpSeq );
    const bool inside = seqAfter( entry.skipEnd, pkt.tcpSeq ) > 0;
    release( keyOf( stream, stream.direction ) );
    if ( !inside ) {
        return std::nullopt; // past the message, perhaps after a gap: a segment as any
    }
    if ( payload.data == nullptr || payload.size != pkt.payloadLen ) {
        describeSegment( pkt, label, kContinuationOfMessage ); // what comes after it was cut
        return ReassembledMessages{};
    }
    return startMessage( pkt, stream, { payload.data + offset, payload.size - offset }, label );
}

ReassembledMessages TcpReassembly::continueMessage( PacketRecord& pkt, const Stream& stream,
                                                    Entry& entry )
{
    const auto walk
        = walkMessages( entry.held.data(), entry.held.size(), pkt, stream, entry.framer );
    const auto rest = entry.held.size() - walk.end;
    if ( announcedPast( walk.incomplete, rest, streamLimit_ ) ) {
        // The message being held turns out longer than the limit: its rest
        // is skipped, whole messages before it described.
        completed_ = std::move( entry.held );
        entry.held = std::vector<uint8_t>();
        const auto segments = walk.end == 0 ? 1 : entry.segments;
        const auto framer = entry.framer;
        const auto* label = entry.label;
        skip( stream, label, entry.order.nextSeq(), walk.incomplete.length - rest );
        if ( walk.end > 0 ) {
            completed_.resize( walk.end );
        }
        describeMessages( pkt, completed_.data(), completed_.size(), framer, label, segments );
        mark( pkt, kReassemblyLimit );
        if ( walk.end == 0 ) {
            return {};
        }
        return { { completed_.data(), completed_.size() }, segments };
    }
    if ( walk.end == 0 ) {
        describeSegment( pkt, entry.label );
        return {};
    }

    // The bytes after the whole messages begin the next one, which is held.
    completed_ = std::move( entry.held );
    entry.held = std::vector<uint8_t>();
    const auto segments = entry.segments;
    const auto framer = entry.framer;
    const auto* label = entry.label;
    const auto key = keyOf( stream, stream.direction );
    if ( walk.incomplete.framer == 0 ) {
        release( key );
    }
    else {
        entry.held.reserve( std::max( rest, std::min( walk.incomplete.length, streamLimit_ ) ) );
        entry.held.assign( completed_.begin() + static_cast<std::ptrdiff_t>( walk.end ),
                           completed_.end() );
        entry.segments = 1;
        recharge( entry );
    }
    completed_.resize( walk.end );
    describeMessages( pkt, completed_.data(), completed_.size(), framer, label, segments );
    return { { completed_.data(), completed_.size() }, segments };
}

ReassembledMessages TcpReassembly::startMessage( PacketRecord& pkt, const Stream& stream,
                                                 ByteView payload, const char* after )
{
    const auto first
        = tcpMessageExtent( payload.data, payload.size, pkt.srcPort, pkt.dstPort, 0, &stream );
    if ( first.framer == 0 ) {
        if ( after ) {
            describeMessages( pkt, payload.data, payload.size, 0, after, 1 );
        }
        return {}; // no message the describer frames: described as it is
    }
    const auto walk = walkMessages( payload.data, payload.size, pkt, stream, first.framer );
    if ( walk.incomplete.framer == 0 ) {
        if ( ( first.describedInStream || after ) && walk.end > 0 ) {
            // Whole messages the parser could not tell: described from all
            // the bytes, not only the first ones describeInStream() had.
            describeMessages( pkt, payload.data, walk.end, first.framer, first.label, 1 );
        }
        return {}; // whole messages: the parser described them
    }

    const auto key = keyOf( stream, stream.direction );
    release( key ); // what an old connection on the ports may have left
    const auto rest = payload.size - walk.end;
    const auto expected = std::min( walk.incomplete.length, streamLimit_ );
    if ( walk.incomplete.length > streamLimit_
         || !makeRoom( kEntryOverhead + std::max( rest, expected ), key ) ) {
        if ( after ) {
            describeMessages( pkt, payload.data, payload.size, first.framer, first.label, 1 );
        }
        if ( announcedPast( walk.incomplete, rest, streamLimit_ ) ) {
            skip( stream, first.label, pkt.tcpSeq + pkt.payloadLen, walk.incomplete.length - rest );
        }
        mark( pkt, kReassemblyLimit );
        return {};
    }
    auto& entry = entries_[ key ];
    entry.state = stream.state;
    entry.direction = stream.direction;
    entry.framer = first.framer;
    entry.label = first.label;
    entry.order.reset( pkt.tcpSeq + pkt.payloadLen );
    entry.segments = 1;
    entry.held.reserve( std::max( rest, expected ) );
    entry.held.assign( payload.data + walk.end, payload.data + payload.size );
    entry.lru = lru_.insert( lru_.end(), key );
    recharge( entry );
    stream.state->reassembly |= heldBit( stream.direction );

    if ( walk.end == 0 ) {
        describeSegment( pkt, first.label );
        return {};
    }
    describeMessages( pkt, payload.data, walk.end, first.framer, first.label, 1 );
    return { { payload.data, walk.end }, 1 };
}

ReassembledMessages TcpReassembly::segment( PacketRecord& pkt, const Stream& stream,
                                            ByteView payload )
{
    const auto key = keyOf( stream, stream.direction );
    auto* entry = ( stream.state->reassembly & heldBit( stream.direction ) )
                      ? find( stream, stream.direction )
                      : nullptr;
    if ( entry && entry->skipping ) {
        if ( auto taken = skipSegment( pkt, stream, payload, *entry ) ) {
            return *taken;
        }
        entry = nullptr;
    }
    if ( payload.data == nullptr || payload.size != pkt.payloadLen ) {
        // Bytes the capture lacks, cut at the snaplen: a gap.
        if ( entry ) {
            release( key );
        }
        return {};
    }

    if ( entry ) {
        lru_.splice( lru_.end(), lru_, entry->lru );
        const auto place = entry->order.place( pkt.tcpSeq, payload.size );
        if ( place.fit == ByteStreamOrderer::Fit::Early ) {
            if ( holdEarly( *entry, key, pkt.tcpSeq, payload ) ) {
                describeSegment( pkt, entry->label );
                return {};
            }
            release( key ); // too much came early: a gap, which this segment is after
        }
        else if ( place.fit == ByteStreamOrderer::Fit::Taken ) {
            return {}; // bytes taken already: a retransmission
        }
        else {
            if ( !append( *entry, key, payload.data + place.overlap, payload.size - place.overlap )
                 || !appendEarly( *entry, key ) ) {
                release( key );
                mark( pkt, kReassemblyLimit );
                return {};
            }
            return continueMessage( pkt, stream, *entry );
        }
    }

    // A segment of bytes sent before, retransmitted or late, begins no
    // message: those after it have been seen.
    const auto& tcp = stream.state->tcp[ stream.direction ];
    if ( tcp.flags & TcpDirection::kBaseSeqSet ) {
        const uint32_t end = pkt.tcpSeq - tcp.baseSeq + ( ( pkt.tcpFlags & kTcpSyn ) ? 1 : 0 )
                             + pkt.payloadLen + ( ( pkt.tcpFlags & kTcpFin ) ? 1 : 0 );
        if ( seqAfter( tcp.nextSeq, end ) > 0 ) {
            return {};
        }
    }
    return startMessage( pkt, stream, payload );
}

ReassembledMessages TcpReassembly::apply( PacketRecord& pkt, const Stream& stream,
                                          ByteView payload )
{
    if ( pkt.transport != Transport::Tcp || !stream.state || stream.id < 0
         || pkt.tcpHeaderLen < 20 ) {
        return {};
    }
    auto& state = *stream.state;
    const auto direction = stream.direction;
    const auto flags = pkt.tcpFlags;

    if ( flags & kTcpSyn ) {
        // A handshake, perhaps of a new connection on the same ports: what
        // an old one left is of no use.
        release( stream, 0 );
        release( stream, 1 );
    }
    if ( ( flags & kTcpAck ) && ( state.reassembly & heldBit( 1 - direction ) ) ) {
        // The other side has bytes the capture lacks: a gap there.
        const auto* other = find( stream, 1 - direction );
        if ( other && !other->skipping && seqAfter( pkt.tcpAck, other->order.nextSeq() ) > 0 ) {
            release( stream, 1 - direction );
        }
    }

    ReassembledMessages result;
    if ( pkt.payloadLen > 0 && !( state.protocols & StreamState::kHttp2 ) ) {
        const bool letGo = ( state.reassembly & letGoBit( direction ) ) != 0;
        state.reassembly &= static_cast<uint8_t>( ~letGoBit( direction ) );
        result = segment( pkt, stream, payload );
        if ( letGo ) {
            mark( pkt, kReassemblyLimit );
        }
    }

    if ( flags & kTcpRst ) {
        release( stream, 0 );
        release( stream, 1 );
    }
    else if ( flags & kTcpFin ) {
        release( stream, direction ); // nothing completes a message after it
    }
    return result;
}

} // namespace tcpdump
