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
 * @file conversations.h
 * @brief The Conversations table: packets and bytes of each stream, each
 *        way, as Wireshark's Statistics > Conversations counts them.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_labels.h"
#include "stream_tracker.h"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <vector>

namespace tcpdump {

/// One row of the Conversations table: a numbered TCP or UDP stream.
struct Conversation {
    Transport transport = Transport::Tcp;
    int stream = 0; ///< Its number in the Stream column, counted per transport.
    /// End A sent the stream's first packet, end B received it.
    uint16_t portA = 0;
    uint16_t portB = 0;
    /// The protocol its Stream Label names ("TLS", "DNS", …), or the
    /// transport's ("TCP", "UDP") when no detector recognised it.
    std::string protocol;
    std::string addressA;
    std::string addressB;
    /// Packets and their bytes on the wire (the Length column), each way.
    uint64_t packetsAToB = 0;
    uint64_t bytesAToB = 0;
    uint64_t packetsBToA = 0;
    uint64_t bytesBToA = 0;
    /// Its earliest packet, in seconds after the capture's earliest one.
    double startSeconds = 0.0;
    /// Between its earliest and its latest packet, in seconds.
    double durationSeconds = 0.0;

    bool operator==( const Conversation& other ) const;
};

/**
 * The rows of the Conversations table, TCP's first, each by its number, in
 * chunks of kChunkRows: immutable, so that a summary and the next one of a
 * live capture share the chunks whose streams had no packet in between.
 */
class ConversationRows {
public:
    static constexpr size_t kChunkRows = 4096;
    using Chunk = std::vector<Conversation>;

    ConversationRows() = default;
    /// @p rows, as one chunk.
    explicit ConversationRows( std::vector<Conversation> rows );
    explicit ConversationRows( std::vector<std::shared_ptr<const Chunk>> chunks );

    size_t size() const
    {
        return size_;
    }
    bool empty() const
    {
        return size_ == 0;
    }
    const Conversation& operator[]( size_t i ) const;

    const std::vector<std::shared_ptr<const Chunk>>& chunks() const
    {
        return chunks_;
    }

    /// Every row, copied.
    std::vector<Conversation> list() const;

private:
    std::vector<std::shared_ptr<const Chunk>> chunks_;
    std::vector<size_t> starts_; ///< The first row of each chunk.
    size_t size_ = 0;
};

/**
 * Counts the packets of each numbered stream, packet by packet, as the
 * Converter reads them; owned by the Converter.
 *
 * A stream's counts take 64 bytes (and the tracker 8 more to find its
 * endpoints), kept only for the streams the Stream Tracker numbers, so that
 * the stream cap bounds them too; the endpoints
 * and the protocol are the tracker's and the Stream Labels', looked up when
 * the table is taken.  Packets of streams past the cap are counted
 * together, as the table's "other streams".
 */
class ConversationStats {
public:
    /// Count @p pkt in, of @p stream, as the Packet Pipeline left it.
    /// Packets of no stream are not counted.
    void add( const PacketRecord& pkt, const Stream& stream );

    /// The table as it stands: a row per stream, TCP's first, each by its
    /// number, with the endpoints @p tracker numbered it by and the label
    /// @p labels gave it.  Start times count from @p captureStartSec and
    /// @p captureStartNsec, the capture's earliest packet.  May be taken
    /// again while packets are still being added (a live capture).
    std::vector<Conversation> conversations( const StreamTracker& tracker,
                                             const StreamLabels& labels, int64_t captureStartSec,
                                             uint32_t captureStartNsec ) const;

    /// The same table as rows in chunks: those of the chunks whose streams
    /// had no packet since the last call are the same as then, shared; the
    /// others are made anew.  All are when the capture's start changed.
    std::shared_ptr<const ConversationRows> rows( const StreamTracker& tracker,
                                                  const StreamLabels& labels,
                                                  int64_t captureStartSec,
                                                  uint32_t captureStartNsec ) const;

    /// Packets of streams past the stream cap, all together.
    uint64_t otherPackets() const
    {
        return otherPackets_;
    }

    /// Their bytes on the wire.
    uint64_t otherBytes() const
    {
        return otherBytes_;
    }

private:
    /// What is counted of one stream.
    struct Counts {
        uint64_t packets[ 2 ] = { 0, 0 }; ///< By Stream::direction.
        uint64_t bytes[ 2 ] = { 0, 0 };
        int64_t firstSec = 0;
        int64_t lastSec = 0;
        uint32_t firstNsec = 0;
        uint32_t lastNsec = 0;
        /// The StreamState::label last seen on it; 0 while none was.
        uint8_t label = 0;
        /// The direction of its first packet, whose source is end A.
        uint8_t directionA = 0;
    };

    /// The row of stream @p id of @p transport.
    Conversation row( Transport transport, size_t id, const StreamTracker& tracker,
                      const StreamLabels& labels, int64_t captureStartSec,
                      uint32_t captureStartNsec ) const;

    /// The chunks of rows() made last, of one transport, and which ones had
    /// a packet since.
    struct Made {
        std::vector<std::shared_ptr<const ConversationRows::Chunk>> chunks;
        std::vector<bool> changed;
    };

    std::deque<Counts> tcp_; ///< By stream number.
    std::deque<Counts> udp_;
    mutable Made tcpMade_;
    mutable Made udpMade_;
    mutable int64_t madeStartSec_ = 0;
    mutable uint32_t madeStartNsec_ = 0;
    uint64_t otherPackets_ = 0;
    uint64_t otherBytes_ = 0;
};

} // namespace tcpdump
