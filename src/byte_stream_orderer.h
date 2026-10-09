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
 * @file byte_stream_orderer.h
 * @brief Puts the segments of one direction of a TCP stream in sequence
 *        order, for the TCP Reassembly and Follow stream content.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace tcpdump {

/// How far sequence number @p a is after @p b, modulo 2^32: negative if before.
inline int64_t seqAfter( uint32_t a, uint32_t b )
{
    return static_cast<int32_t>( a - b );
}

/**
 * The Byte Stream Orderer: where each segment of one direction of a TCP
 * stream lies against the bytes taken so far, which end at nextSeq().
 *
 * A segment at nextSeq() (or one that begins before it and goes on past it)
 * is next: its bytes from nextSeq() on are taken, and the caller advances
 * past them.  One that begins after nextSeq() came early, before the bytes
 * ahead of it; the caller may hold a copy of it here, and pops it once the
 * bytes before it were taken.  One whose bytes were all taken is a
 * retransmission, and dropped.  Bytes that never come (a gap) are the
 * caller's to notice, by an acknowledgement past them or too much held
 * early: it skips them, to the first segment held or further.
 *
 * It holds no limit of its own: the caller says how many segments and
 * bytes may come early (earlyBytes(), early()), as its memory allows.
 */
class ByteStreamOrderer {
public:
    /// A segment that came before the bytes ahead of it.
    struct EarlySegment {
        uint32_t seq = 0;
        std::vector<uint8_t> bytes;
    };

    /// Where a segment lies against the bytes taken.
    enum class Fit {
        Next,  ///< Its bytes after overlap are the next ones.
        Early, ///< It begins after nextSeq().
        Taken, ///< All its bytes were taken: a retransmission.
    };

    struct Place {
        Fit fit = Fit::Next;
        /// Next: bytes at its start that were taken already.
        size_t overlap = 0;
    };

    ByteStreamOrderer() = default;
    explicit ByteStreamOrderer( uint32_t nextSeq )
        : nextSeq_( nextSeq )
    {
    }

    /// Start afresh at @p nextSeq, holding nothing.
    void reset( uint32_t nextSeq );

    /// The sequence number after the bytes taken.
    uint32_t nextSeq() const
    {
        return nextSeq_;
    }

    /// Where a segment of @p len bytes at @p seq lies.
    Place place( uint32_t seq, size_t len ) const;

    /// The caller took @p len bytes at nextSeq().
    void advance( size_t len )
    {
        nextSeq_ += static_cast<uint32_t>( len );
    }

    /// Whether a segment at @p seq of @p len bytes or more is held already.
    bool holds( uint32_t seq, size_t len ) const;

    /// Hold a copy of a segment that came early (place() said Early).
    void holdEarly( uint32_t seq, ByteView bytes );

    /**
     * Pop a held segment that is next now into @p bytes: its bytes not taken
     * yet, at nextSeq(), which the caller then takes and advance()s past.
     * Held segments whose bytes were all taken are dropped.  False when no
     * held one is next.
     */
    bool popNext( std::vector<uint8_t>& bytes );

    /// The sequence number of the held segment that comes first; unset
    /// when none is held.
    std::optional<uint32_t> firstEarlySeq() const;

    /// Skip the bytes up to @p seq, which never came: how many those are;
    /// 0, and nothing skipped, when @p seq is not after nextSeq().
    uint32_t skipTo( uint32_t seq );

    /// The segments held, in the order they came.
    const std::vector<EarlySegment>& early() const
    {
        return early_;
    }

    /// The bytes of the segments held.
    size_t earlyBytes() const;

private:
    uint32_t nextSeq_ = 0;
    std::vector<EarlySegment> early_;
};

} // namespace tcpdump
