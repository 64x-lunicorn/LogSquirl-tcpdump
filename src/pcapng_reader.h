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
 * @file pcapng_reader.h
 * @brief Reads pcapng captures, as Wireshark and macOS's `tcpdump -P` write them.
 *
 * A pcapng file is a sequence of blocks, each with its type and its length
 * before and after it.  A section header block starts a section and gives
 * its byte order; interface description blocks declare the section's
 * interfaces, each with its link-layer type, snaplen and timestamp unit;
 * enhanced and simple packet blocks hold the packets.  Every other block is
 * skipped by its length.  Pure C++.
 */

#pragma once

#include "pcap_parser.h"

#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump {

/**
 * Reads a pcapng capture one block at a time, so that only one packet is
 * held in memory.
 *
 * The finest precision is announced at open() for the time column, before
 * any packet is read.  open() therefore reads the blocks up to the first
 * packet block, where Wireshark's dumpcap declares all its interfaces, and
 * announces the finest precision of the interfaces declared so far.  An
 * interface declared later, after a packet or in a later section, has its
 * packets marked and shown at most at that precision, since the reader
 * promises that no packet is finer; writers that declare interfaces as they
 * see them, such as macOS's tcpdump, in practice give them all the same
 * resolution.  Reading the whole file twice to know better would double
 * the time a large capture takes to open.  On a stream that is still being
 * written (ByteSource::ready()), open() reads on past the first interface
 * only as far as blocks have come, so that a capture with no traffic yet
 * opens; dumpcap and tcpdump write all their interfaces at once.
 *
 * linkTypes() lists the link-layer types of all interfaces declared so far,
 * each once, also those of interfaces without a packet; a capture without
 * packets thus still names its interfaces' types, as a pcap without packets
 * names its header's.
 *
 * A block the reader cannot read on from, because its length lies beyond
 * the end of the file or contradicts its fields, ends the capture like a
 * pcap that is cut off inside a record (truncated()).
 */
class PcapngReader : public CaptureReader {
public:
    /// Interfaces a section may declare at most; a further one ends the
    /// capture as unreadable, so that the interface table stays small.
    static constexpr size_t kMaxInterfaces = 65536;

    /// @param start  Where the first section header starts, as
    ///               findCaptureStart() found it for a pcapng.
    explicit PcapngReader( ByteSource& source, uint64_t start = 0 )
        : CaptureReader( source, start )
    {
    }

    /// Read the first section header and the blocks up to the first packet
    /// block, on a stream up to the first that has not come yet.
    bool open() override;

    bool next( PacketRecord& pkt ) override;

    TimePrecision precision() const override
    {
        return precision_;
    }

    std::vector<uint32_t> linkTypes() const override
    {
        return linkTypes_;
    }

    /// Also keeps the section's byte order and interfaces, shared with the
    /// checkpoint before as long as no interface was declared between them.
    ReaderCheckpoint checkpoint() const override;

    bool resume( const ReaderCheckpoint& checkpoint ) override;

    /// The section header block of the last packet's section and the
    /// interface description blocks declared in it so far.
    CaptureHeaders headers() const override;

private:
    /// A timestamp unit: 10^-exponent or, if binary, 2^-exponent seconds.
    struct TimeUnit {
        bool binary = false;
        uint8_t exponent = 6; ///< pcapng's default: microseconds
    };

    struct Interface {
        uint32_t linkType = 0;
        uint32_t snaplen = 0; ///< 0: no limit
        TimeUnit unit;
        TimePrecision precision = TimePrecision::Microseconds;
        RecordSpan block; ///< Its interface description block.
    };

    struct BlockHeader {
        uint32_t type = 0;
        uint32_t length = 0;   ///< The block's total length.
        uint32_t consumed = 0; ///< Bytes of the block read so far.
        uint64_t start = 0;    ///< Where the block starts in the source.
    };

    /// What a checkpoint keeps of the section it lies in.
    struct SectionState : ReaderState {
        bool swap = false;
        RecordSpan sectionHeader;
        std::vector<Interface> interfaces;
    };

    bool fail( const char* problem );
    void endBroken();

    bool readBlockHeader( BlockHeader& block );
    bool finishBlock( BlockHeader& block );
    bool readSectionHeader( BlockHeader& block );
    bool readInterface( BlockHeader& block );
    bool readPacket( BlockHeader& block, PacketRecord& pkt );
    bool readBlocksUpToPacket( bool untilWaiting = false );

    RecordSpan sectionHeader_;          ///< The current section's header block.
    std::vector<Interface> interfaces_; ///< The current section's.
    /// The section state the last checkpoint kept, while it is still current.
    mutable std::shared_ptr<const SectionState> sectionState_;
    std::vector<uint32_t> linkTypes_;
    TimePrecision precision_ = TimePrecision::Microseconds;
    bool precisionAnnounced_ = false;
    bool havePacketBlock_ = false; ///< pendingBlock_ is a packet block read up to its body.
    BlockHeader pendingBlock_;
    std::string problem_; ///< Why the last block could not be read; empty at the end.
    bool open_ = false;
};

} // namespace tcpdump
