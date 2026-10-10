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
 * content reads only the packets between the two; in chunks a copy of the
 * index shares (SharedChunks), so that a live capture's snapshot of it
 * costs a pointer per 4,096 streams, not 8 bytes per stream.
 *
 * The capture file is told by its path, size and modification time when it
 * was converted: a file changed since is reported, not misread.
 *
 * Offsets are those in the capture as its reader reads it: for a
 * gzip-compressed file, in the decompressed capture.  Such a file's index
 * keeps the access points its GzipSource kept, so that a packet is reached
 * by decompressing at most GzipSource::kAccessSpan bytes, not the whole
 * file before it.
 *
 * A live capture with a ring buffer (raw_capture.h) splits its raw capture
 * into files, CaptureParts, and deletes the oldest: the packets keep their
 * numbers across the files, the checkpoints point into the capture as it was
 * read, and the cursor reads a packet from the file it is in.  A packet of a
 * file deleted since is reported rotated away, not misread.
 */

#pragma once

#include "pcap_parser.h"
#include "shared_chunks.h"

#include <QDateTime>
#include <QFile>
#include <QString>

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace tcpdump {

class CaptureFile;
class GzipAccessPoints;
class HeadSource;

/**
 * One file of a capture split into several (a live capture's ring buffer):
 * the headers the capture needs ahead of its records, copied, then the
 * capture as it was read from streamOffset on.  The first file of a capture
 * is the capture from its start, with nothing copied ahead.
 */
struct CapturePart {
    QString path;
    uint32_t packetsBefore = 0; ///< Packets in the files before it: its first is packetsBefore + 1.
    uint64_t streamOffset = 0;  ///< Where its records start in the capture as it was read.
    uint64_t headerLength = 0;  ///< Bytes of headers copied ahead of them.
    /// Where each header record copied ahead lies in the capture as it was
    /// read, and where in this file: offset there → offset here.
    std::vector<std::pair<uint64_t, uint64_t>> headerOffsets;

    /// Where the byte at @p offset of the capture as it was read lies in this
    /// file; unset for one that is in neither its records nor its headers.
    std::optional<uint64_t> fileOffset( uint64_t offset ) const;
};

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

    /// Whether the capture file may still grow behind the packets noted.
    enum class Growth {
        Fixed,   ///< A file converted whole: any change is a change.
        Growing, ///< A live capture's raw file, still written: it may grow.
    };

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

    /// Chunks of stream extents this index and @p other share, for the
    /// tests: a copy shares them all, until either notes a stream of one.
    size_t streamChunksSharedWith( const CaptureIndex& other ) const
    {
        return tcpStreams_.chunksSharedWith( other.tcpStreams_ )
               + udpStreams_.chunksSharedWith( other.udpStreams_ );
    }

    /// Remember the capture file at @p path as it is now, the file the
    /// checkpoints point into.  A Growing file is read as it was converted
    /// as long as it is not shorter than now.
    void setCaptureFile( const QString& path, Growth growth = Growth::Fixed );

    /// The access points of a gzip-compressed capture file, which offsets in
    /// it are read with; null for an uncompressed one.
    void setGzipAccessPoints( std::shared_ptr<const GzipAccessPoints> points )
    {
        gzipPoints_ = std::move( points );
    }

    const std::shared_ptr<const GzipAccessPoints>& gzipAccessPoints() const
    {
        return gzipPoints_;
    }

    /// Remember the files of a capture split into @p parts, in order, as
    /// they are now; only the last one may be Growing.  The packets before
    /// the first one's are rotated away, and their checkpoints dropped.
    void setCaptureParts( const std::vector<CapturePart>& parts, Growth growth = Growth::Fixed );

    /// The capture's files, with their canonical paths: one for a capture
    /// that is not split; none before setCaptureFile().
    std::vector<CapturePart> parts() const;

    /// The file packet @p number is in; null for one rotated away or past
    /// the files.
    const CapturePart* partOf( uint32_t number ) const;

    /// Packets in files deleted since (a ring buffer's): numbers 1 to this.
    uint32_t rotatedAway() const
    {
        return files_.empty() ? 0 : files_.front().part.packetsBefore;
    }

    /// The checkpoint to read packet @p number from: the last one before
    /// it, or null to read from the start of the capture.
    const ReaderCheckpoint* nearest( uint32_t number ) const;

    /// Why the capture file can no longer be read as it was converted (gone
    /// or changed since), or empty when it can; of every file of a capture
    /// split into several.
    QString fileProblem() const;

    /// Why the file packet @p number is in can no longer be read as it was
    /// converted, or empty when it can.
    QString fileProblem( uint32_t number ) const;

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

    /// The capture file, as its canonical path (the last one of a capture
    /// split into several); empty before setCaptureFile().
    QString capturePath() const
    {
        return files_.empty() ? QString() : files_.back().part.path;
    }

private:
    uint32_t interval_;
    uint32_t packets_ = 0;
    std::vector<ReaderCheckpoint> checkpoints_;
    /// By stream id, per transport: the StreamTracker numbers them from 0.
    /// A copy of the index (a live capture's snapshot) shares them.
    static constexpr size_t kStreamChunk = 4096;
    SharedChunks<StreamExtent, kStreamChunk> tcpStreams_;
    SharedChunks<StreamExtent, kStreamChunk> udpStreams_;
    /// A capture file as it was when it was remembered.
    struct File {
        CapturePart part; ///< Its path canonical.
        qint64 size = -1;
        Growth growth = Growth::Fixed;
        QDateTime modified;
    };
    /// Why @p file can no longer be read as it was converted, or empty.
    static QString problemOf( const File& file );
    /// The file packet @p number is in, or null.
    const File* fileOf( uint32_t number ) const;

    std::vector<File> files_;
    std::shared_ptr<const GzipAccessPoints> gzipPoints_;
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
    /// The records a file of it needs ahead of it, where they lie in the
    /// capture file: its format's header, a pcapng section's interfaces.
    CaptureHeaders headers;
    /// The capture file it was read from, which the offsets are in: one of
    /// the files of a capture split into several.
    QString file;
};

/**
 * Reads packets of a converted capture back from its file, by their number,
 * from the nearest checkpoint of its CaptureIndex.  Reading packets in
 * ascending order goes on from where the last one ended, so that a sorted
 * set is read in one pass from front to back.  Holds the file open between
 * reads; one cursor serves one thread.  A gzip-compressed file is read
 * decompressed, from the access point before the checkpoint.
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

    /// Keep the record of each packet read, as it lies in the file, so that
    /// it can be copied without reading the file again (Export packets):
    /// of a gzip-compressed capture, decompressing it again.
    void keepRecords( bool keep )
    {
        keepRecords_ = keep;
    }

    /// The record of the packet read last, header and all; empty when it
    /// was not kept: keepRecords() is off, it is longer than
    /// kMaxKeptRecord, or the reader had read part of it before.
    ByteView recordBytes() const;

    /// The longest record kept.
    static constexpr size_t kMaxKeptRecord = 16 * 1024 * 1024;

private:
    class RecordingSource;
    /// Open the file @p part again, at @p checkpoint (in it) if there is one.
    bool reopen( const CapturePart& part, const ReaderCheckpoint* checkpoint );
    void close();

    std::shared_ptr<const CaptureIndex> index_;
    std::unique_ptr<CaptureFile> file_;
    /// Between the file and the reader: keeps what the reader reads.
    std::unique_ptr<RecordingSource> recording_;
    std::unique_ptr<HeadSource> headSource_;
    std::unique_ptr<CaptureReader> reader_;
    /// The file reader_ reads, and the packets of the capture before it.
    QString readerPath_;
    uint32_t readerPacketsBefore_ = 0;
    QString error_;
    bool keepRecords_ = false;
    /// Where the record of the packet read last lies, if it was kept.
    uint64_t recordOffset_ = 0;
    uint64_t recordLength_ = 0;
};

} // namespace tcpdump
