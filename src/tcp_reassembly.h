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
 * @file tcp_reassembly.h
 * @brief Puts together the application messages a TCP stream carries over
 *        several segments, so that each is described once, where it completes.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <unordered_map>
#include <vector>

namespace tcpdump {

/// Info of a segment that carries part of a message completed by a later one.
constexpr const char* kSegmentOfMessage = "[TCP segment of a reassembled PDU]";
/// Ends the Info of a segment whose message could not be held.
constexpr const char* kReassemblyLimit = "[reassembly limit]";

/// The messages a segment completed, as the TCP Reassembly put them together.
struct ReassembledMessages {
    /// The messages, from the start of the first to the end of the last; empty
    /// when the segment completed none that began in an earlier one, or
    /// left part of its last one to a later one.  Valid until the next call
    /// of TcpReassembly::apply().
    ByteView bytes;
    /// Segments the first message was put together from; 1 when it lies in
    /// the segment.
    uint32_t segments = 0;
};

/**
 * The TCP Reassembly: follows, per TCP stream and direction, the bytes after
 * the last complete application message, in sequence order, and describes
 * a message that spans segments once, on the segment that completes it.
 *
 * Which bytes make a message is the Payload Describer's to say
 * (tcpMessageExtent()): a TLS record, a DNS-over-TCP message, an HTTP/1.x
 * header section.  A segment that ends in the first part of one is
 * described as kSegmentOfMessage and its bytes are held; the segment that
 * completes it is described from all of them, "[reassembled from k
 * segments]" after the description.  A segment that begins and ends with
 * whole messages, or none the describer frames, keeps its own description,
 * and costs no memory.
 *
 * Segments are taken in sequence order: one that comes early is held until
 * the bytes before it come; a retransmission, and the part of a segment
 * that overlaps bytes already taken, is dropped.  A gap, bytes the capture
 * lacks (the other side acknowledges them, a segment was cut at the snaplen,
 * or too many came after it), ends the message: its bytes are dropped, and
 * reassembly starts again at the next segment that begins a message.
 *
 * Memory is bounded.  A direction holds at most streamLimit bytes, its
 * buffer's capacity and the segments that came early together; all
 * directions together at most memoryLimit, with kEntryOverhead counted for
 * each.  A message that does not fit in a direction's limit is not held:
 * its segment keeps its own description, "[reassembly limit]" after it.
 * When all directions together would pass memoryLimit, those that waited
 * longest are let go, their next segment marked so.  A direction is let go
 * on its FIN, both on a SYN (a new connection) or an RST; a stream past the
 * stream cap has no state and is never held.  The state a stream keeps is
 * one byte of StreamState (StreamState::reassembly); the bytes live here.
 */
class TcpReassembly {
public:
    /// Bytes a direction holds at most: a TLS record, the longest message
    /// framed, takes 18,437.
    static constexpr size_t kStreamLimit = 64 * 1024;
    /// Bytes all directions hold at most by default.
    static constexpr size_t kDefaultMemoryLimit = 64 * 1024 * 1024;
    /// Segments that came early a direction holds at most.
    static constexpr size_t kMaxEarlySegments = 32;
    /// Bytes counted for a held direction besides its buffer: its entry in
    /// the table and in the order they were used in.
    static constexpr size_t kEntryOverhead = 128;
    /// Bytes counted for a segment that came early besides its bytes.
    static constexpr size_t kEarlySegmentOverhead = 32;

    explicit TcpReassembly( size_t memoryLimit = kDefaultMemoryLimit,
                            size_t streamLimit = kStreamLimit );

    /**
     * Run on every packet, in capture order, after describeInStream() and
     * before the Stream Labels, with the packet's captured TCP payload
     * (CaptureReader::payloadOf()).  Rewrites the Info and protocol of a
     * segment as the class describes, and returns the messages it completed.
     * Packets of other transports, of no stream or one past the stream
     * cap, and of an HTTP/2 stream are left as they are.
     */
    ReassembledMessages apply( PacketRecord& pkt, const Stream& stream, ByteView payload );

    /// Bytes counted as held now, by the rules above.
    size_t memoryUsed() const
    {
        return used_;
    }

    /// Directions that hold bytes now.
    size_t directionsHeld() const
    {
        return entries_.size();
    }

private:
    /// A segment that came before the bytes ahead of it.
    struct EarlySegment {
        uint32_t seq = 0;
        std::vector<uint8_t> bytes;
    };

    /// What a direction holds while a message in it is incomplete.
    struct Entry {
        StreamState* state = nullptr; ///< Its stream's, to mark when let go.
        unsigned direction = 0;
        /// The bytes from the start of the incomplete message, in order.
        std::vector<uint8_t> held;
        /// The sequence number after the held bytes.
        uint32_t nextSeq = 0;
        /// Segments the held bytes came from.
        uint32_t segments = 0;
        /// The protocol that frames the messages (MessageExtent::framer).
        uint8_t framer = 0;
        const char* label = nullptr;
        std::vector<EarlySegment> early;
        size_t cost = 0;                   ///< Counted in used_.
        std::list<uint64_t>::iterator lru; ///< Its place in lru_.
    };

    using Key = uint64_t;
    static Key keyOf( const Stream& stream, unsigned direction );

    Entry* find( const Stream& stream, unsigned direction );
    void release( Key key );
    void release( const Stream& stream, unsigned direction );
    /// Count @p entry's memory afresh.
    void recharge( Entry& entry );
    /// Make room for @p bytes more, letting go of the directions that
    /// waited longest, never @p keep; false if there is none to let go.
    bool makeRoom( size_t bytes, Key keep );
    /// Room in @p entry's buffer for @p extra more bytes, within the limits.
    bool reserve( Entry& entry, Key key, size_t extra );
    /// Append @p len bytes at @p data to @p entry, at its next sequence number.
    bool append( Entry& entry, Key key, const uint8_t* data, size_t len );
    /// Hold a segment that came early; false if it cannot be.
    bool holdEarly( Entry& entry, Key key, uint32_t seq, ByteView payload );
    /// Append the segments that came early and are next now.
    bool appendEarly( Entry& entry, Key key );

    /// Take a segment's payload, in sequence order.
    ReassembledMessages segment( PacketRecord& pkt, const Stream& stream, ByteView payload );
    /// Describe what the held bytes of @p entry hold now.
    ReassembledMessages continueMessage( PacketRecord& pkt, const Stream& stream, Entry& entry );
    /// Hold the message a segment ends in, if it does, when nothing is held.
    ReassembledMessages startMessage( PacketRecord& pkt, const Stream& stream, ByteView payload );

    size_t memoryLimit_;
    size_t streamLimit_;
    size_t used_ = 0;
    std::unordered_map<Key, Entry> entries_;
    std::list<Key> lru_; ///< The held directions, the one used longest ago first.
    /// The messages the last segment completed, when they began earlier.
    std::vector<uint8_t> completed_;
};

} // namespace tcpdump
