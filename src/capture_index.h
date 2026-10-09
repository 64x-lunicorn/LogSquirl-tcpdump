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
 * @file capture_index.h
 * @brief Finding the packets of a converted capture again: the line →
 *        record index, and the cursor that reads packets back from it.
 *
 * The text a capture converts to holds a line per packet, numbered in the
 * No. column; the packet itself stays in the capture file.  While it
 * converts, the Converter keeps a checkpoint every kCheckpointInterval
 * packets (CaptureIndex): where the next record starts and what the reader
 * needs to go on reading there, a few bytes each, so that the index of even
 * a huge capture takes a few KB and no packet is kept in memory.  A
 * CaptureCursor reads packet N from the nearest checkpoint before it, at
 * most kCheckpointInterval - 1 packets more, and on from there in order.
 *
 * It also keeps where each numbered stream begins and ends, the numbers of
 * its first and last packet, 8 bytes a stream, so that Follow stream
 * content reads only the packets between the two.
 *
 * The capture file is told by its path, size and modification time when it
 * was converted: a file changed since is reported, not misread.
 */

#pragma once

#include "pcap_parser.h"

#include <QDateTime>
#include <QFile>
#include <QString>

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace tcpdump {

class FileSource;
class HeadSource;

/**
 * The checkpoints of a converted capture, kept with its summary.  Filled by
 * the Converter, packet by packet; a capture that grows (a live capture)
 * keeps adding to it.
 */
class CaptureIndex {
public:
    /// Packets between two checkpoints.
    static constexpr uint32_t kCheckpointInterval = 10000;

    /// An index with a checkpoint every @p interval packets (at least 1).
    explicit CaptureIndex( uint32_t interval = kCheckpointInterval );

    /// Note @p reader's place after it returned a packet: every interval-th
    /// packet, the place after it is kept as a checkpoint, and the packets
    /// counted either way.
    void note( const CaptureReader& reader );

    /// The first and the last packet of a stream, by their numbers.
    struct StreamExtent {
        uint32_t first = 0;
        uint32_t last = 0;
    };

    /// Note that packet @p number belongs to stream @p id of @p transport,
    /// as the StreamTracker numbered it; packets of no stream or of one
    /// past the stream cap (a negative id) are not noted.
    void noteStream( Transport transport, int id, uint32_t number );

    /// The first and last packet of stream @p id of @p transport; unset for
    /// a stream not noted.
    std::optional<StreamExtent> streamExtent( Transport transport, int id ) const;

    /// Remember the capture file at @p path as it is now, the file the
    /// checkpoints point into.
    void setCaptureFile( const QString& path );

    /// The checkpoint to read packet @p number from: the last one before
    /// it, or null to read from the start of the capture.
    const ReaderCheckpoint* nearest( uint32_t number ) const;

    /// Why the capture file can no longer be read as it was converted (gone
    /// or changed since), or empty when it can.
    QString fileProblem() const;

    const std::vector<ReaderCheckpoint>& checkpoints() const
    {
        return checkpoints_;
    }

    uint32_t interval() const
    {
        return interval_;
    }

    /// Packets of the capture, i.e. the number of the last one.
    uint32_t packets() const
    {
        return packets_;
    }

    /// The capture file, as its canonical path; empty before setCaptureFile().
    const QString& capturePath() const
    {
        return path_;
    }

private:
    uint32_t interval_;
    uint32_t packets_ = 0;
    std::vector<ReaderCheckpoint> checkpoints_;
    /// By stream id, per transport: the StreamTracker numbers them from 0.
    std::vector<StreamExtent> tcpStreams_;
    std::vector<StreamExtent> udpStreams_;
    QString path_;
    qint64 size_ = -1;
    QDateTime modified_;
};

/// A packet read back from its capture.
struct CapturedPacket {
    /// Dissected as the Converter dissected it, without what its stream
    /// adds (Stream column, stream labels, TCP analysis).
    PacketRecord record;
    /// Its captured bytes, as dissected: at most kMaxDissectedBytes.
    std::vector<uint8_t> bytes;
    bool byteSwapped = false;  ///< As CaptureReader::byteSwapped() said.
    uint64_t recordOffset = 0; ///< Where its record starts in the capture file.
    uint64_t recordLength = 0; ///< Its record's length in the file, header and all.
};

/**
 * Reads packets of a converted capture back from its file, by their number,
 * from the nearest checkpoint of its CaptureIndex.  Reading packets in
 * ascending order goes on from where the last one ended, so that a sorted
 * set is read in one pass from front to back.  Holds the file open between
 * reads; one cursor serves one thread.
 */
class CaptureCursor {
public:
    explicit CaptureCursor( std::shared_ptr<const CaptureIndex> index );
    ~CaptureCursor();
    CaptureCursor( const CaptureCursor& ) = delete;
    CaptureCursor& operator=( const CaptureCursor& ) = delete;

    /// Read packet @p number (1-based, as the No. column numbers it) into
    /// @p packet.  On failure error() says why, for the user.
    bool read( uint32_t number, CapturedPacket& packet );

    /// Why the last read() failed.
    const QString& error() const
    {
        return error_;
    }

private:
    /// Open the capture again, at @p checkpoint if there is one.
    bool reopen( const ReaderCheckpoint* checkpoint );
    void close();

    std::shared_ptr<const CaptureIndex> index_;
    QFile file_;
    std::unique_ptr<FileSource> fileSource_;
    std::unique_ptr<HeadSource> headSource_;
    std::unique_ptr<CaptureReader> reader_;
    QString error_;
};

} // namespace tcpdump
