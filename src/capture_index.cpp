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
 * @file capture_index.cpp
 * @brief Checkpoints of a converted capture, and reading packets back.
 */

#include "capture_index.h"

#include "capture_file.h"
#include "capture_reader.h"

#include <QFileInfo>

#include <algorithm>

namespace tcpdump {

namespace {

/// Why a packet of a ring buffer's file deleted since cannot be read.
QString rotatedAwayText()
{
    return QStringLiteral( "Rotated away: the ring buffer has deleted the capture file it was "
                           "in." );
}

} // namespace

// ── CaptureIndex ─────────────────────────────────────────────────────────

CaptureIndex::CaptureIndex( uint32_t interval )
    : interval_( std::max<uint32_t>( interval, 1 ) )
{
}

void CaptureIndex::note( const CaptureReader& reader )
{
    packets_ = reader.packetsRead();
    if ( packets_ % interval_ == 0 ) {
        checkpoints_.push_back( reader.checkpoint() );
    }
}

void CaptureIndex::noteStream( Transport transport, int id, uint32_t number )
{
    if ( id < 0 ) {
        return;
    }
    auto& streams = transport == Transport::Tcp ? tcpStreams_ : udpStreams_;
    const auto at = static_cast<size_t>( id );
    if ( at >= streams.size() ) {
        // Numbered in order: a new stream is the next one.
        streams.resize( at + 1 );
        streams[ at ].first = number;
    }
    streams[ at ].last = number;
}

std::optional<CaptureIndex::StreamExtent> CaptureIndex::streamExtent( Transport transport,
                                                                      int id ) const
{
    const auto& streams = transport == Transport::Tcp ? tcpStreams_ : udpStreams_;
    if ( id < 0 || static_cast<size_t>( id ) >= streams.size()
         || streams[ static_cast<size_t>( id ) ].first == 0 ) {
        return std::nullopt;
    }
    return streams[ static_cast<size_t>( id ) ];
}

std::optional<uint64_t> CapturePart::fileOffset( uint64_t offset ) const
{
    if ( offset >= streamOffset ) {
        return offset - streamOffset + headerLength;
    }
    for ( const auto& [ there, here ] : headerOffsets ) {
        if ( there == offset ) {
            return here;
        }
    }
    return std::nullopt;
}

void CaptureIndex::setCaptureFile( const QString& path, Growth growth )
{
    CapturePart part;
    part.path = path;
    setCaptureParts( { part }, growth );
}

void CaptureIndex::setCaptureParts( const std::vector<CapturePart>& parts, Growth growth )
{
    files_.clear();
    for ( size_t i = 0; i < parts.size(); ++i ) {
        const QFileInfo info( parts[ i ].path );
        File file;
        file.part = parts[ i ];
        file.part.path = info.canonicalFilePath();
        file.size = info.size();
        file.growth = i + 1 == parts.size() ? growth : Growth::Fixed;
        file.modified = info.lastModified();
        files_.push_back( std::move( file ) );
    }
}

std::vector<CapturePart> CaptureIndex::parts() const
{
    std::vector<CapturePart> parts;
    for ( const auto& file : files_ ) {
        parts.push_back( file.part );
    }
    return parts;
}

const CaptureIndex::File* CaptureIndex::fileOf( uint32_t number ) const
{
    if ( number <= rotatedAway() || number > packets_ ) {
        return nullptr;
    }
    // The last file whose packets start before it.
    const auto after = std::upper_bound(
        files_.begin(), files_.end(), number,
        []( uint32_t n, const File& file ) { return n <= file.part.packetsBefore; } );
    return after == files_.begin() ? nullptr : &*std::prev( after );
}

const CapturePart* CaptureIndex::partOf( uint32_t number ) const
{
    const auto* file = fileOf( number );
    return file ? &file->part : nullptr;
}

const ReaderCheckpoint* CaptureIndex::nearest( uint32_t number ) const
{
    // The checkpoints are in ascending order: the last one before number.
    const auto after = std::lower_bound(
        checkpoints_.begin(), checkpoints_.end(), number,
        []( const ReaderCheckpoint& c, uint32_t n ) { return c.packetsBefore < n; } );
    return after == checkpoints_.begin() ? nullptr : &*std::prev( after );
}

QString CaptureIndex::problemOf( const File& file )
{
    const QFileInfo info( file.part.path );
    if ( file.part.path.isEmpty() || !info.exists() ) {
        return QStringLiteral( "The capture file %1 is gone." ).arg( file.part.path );
    }
    const bool changed = file.growth == Growth::Growing
                             ? info.size() < file.size
                             : info.size() != file.size || info.lastModified() != file.modified;
    if ( changed ) {
        return QStringLiteral( "The capture file %1 has changed since it was converted: "
                               "open it again to see its packets." )
            .arg( info.fileName() );
    }
    return {};
}

QString CaptureIndex::fileProblem() const
{
    if ( files_.empty() ) {
        return QStringLiteral( "The capture file is gone." );
    }
    for ( const auto& file : files_ ) {
        if ( auto problem = problemOf( file ); !problem.isEmpty() ) {
            return problem;
        }
    }
    return {};
}

QString CaptureIndex::fileProblem( uint32_t number ) const
{
    const auto* file = fileOf( number );
    if ( !file ) {
        return number <= rotatedAway() ? rotatedAwayText() : fileProblem();
    }
    // A ring buffer deletes its files but the one it writes: the packets of
    // a file gone since the index was taken were rotated away.
    if ( file != &files_.back() && !QFileInfo::exists( file->part.path ) ) {
        return rotatedAwayText();
    }
    return problemOf( *file );
}

// ── CaptureCursor ────────────────────────────────────────────────────────

CaptureCursor::CaptureCursor( std::shared_ptr<const CaptureIndex> index )
    : index_( std::move( index ) )
{
}

CaptureCursor::~CaptureCursor()
{
    close();
}

void CaptureCursor::close()
{
    // The reader reads through the sources, the sources from the file.
    reader_.reset();
    readerPath_.clear();
    headSource_.reset();
    fileSource_.reset();
    file_.close();
}

bool CaptureCursor::reopen( const CapturePart& part, const ReaderCheckpoint* checkpoint )
{
    close();
    QString problem;
    if ( !openRegularFile( part.path, file_, problem ) ) {
        error_ = problem;
        return false;
    }
    fileSource_ = std::make_unique<FileSource>( file_ );
    headSource_ = std::make_unique<HeadSource>( *fileSource_ );
    reader_ = makeCaptureReader( *headSource_ );
    if ( !reader_->open() || ( checkpoint && !reader_->resume( *checkpoint ) ) ) {
        close();
        error_ = QStringLiteral( "The capture file can no longer be read as it was converted." );
        return false;
    }
    if ( checkpoint ) {
        // The checkpoint was taken as the capture was read: the headers it
        // names lie elsewhere in a later file of it, copied ahead of its records.
        reader_->relocateHeaders(
            [ &part ]( uint64_t offset ) { return part.fileOffset( offset ).value_or( offset ); } );
    }
    readerPath_ = part.path;
    readerPacketsBefore_ = part.packetsBefore;
    return true;
}

bool CaptureCursor::read( uint32_t number, CapturedPacket& packet )
{
    error_.clear();
    if ( !index_ ) {
        error_ = QStringLiteral( "No capture." );
        return false;
    }
    if ( number == 0 || number > index_->packets() ) {
        error_ = QStringLiteral( "The capture has no packet %1." ).arg( number );
        return false;
    }
    // Checked before every read: a file changed between two is not misread;
    // one a ring buffer deleted is said to be.
    if ( const auto problem = index_->fileProblem( number ); !problem.isEmpty() ) {
        close();
        error_ = problem;
        return false;
    }
    const auto* part = index_->partOf( number );
    if ( !part ) {
        error_ = QStringLiteral( "The capture has no packet %1." ).arg( number );
        return false;
    }

    // The nearest checkpoint, if it lies after a packet of the packet's file
    // (open() reads up to its first): there, the packets are counted from
    // the file's first and the offsets are its own.
    std::optional<ReaderCheckpoint> checkpoint;
    if ( const auto* nearest = index_->nearest( number );
         nearest && nearest->packetsBefore > part->packetsBefore
         && nearest->offset >= part->streamOffset ) {
        checkpoint = *nearest;
        checkpoint->packetsBefore -= part->packetsBefore;
        checkpoint->offset = *part->fileOffset( nearest->offset );
    }

    // Go on from where the cursor is, unless it reads another file, or the
    // packet lies behind it or a checkpoint lies between the two.
    const uint32_t local = number - part->packetsBefore;
    const uint32_t from = checkpoint ? checkpoint->packetsBefore : 0;
    if ( !reader_ || readerPath_ != part->path || readerPacketsBefore_ != part->packetsBefore
         || reader_->packetsRead() >= local || reader_->packetsRead() < from ) {
        if ( !reopen( *part, checkpoint ? &*checkpoint : nullptr ) ) {
            return false;
        }
    }

    PacketRecord record;
    while ( reader_->packetsRead() < local ) {
        if ( !reader_->next( record ) ) {
            close();
            error_ = QStringLiteral( "The capture ends before packet %1: it has changed since "
                                     "it was converted." )
                         .arg( number );
            return false;
        }
    }
    record.number = number;
    packet.record = std::move( record );
    packet.bytes = reader_->packetBytes();
    packet.byteSwapped = reader_->byteSwapped();
    packet.recordOffset = reader_->recordOffset();
    packet.recordLength = reader_->recordLength();
    packet.headers = reader_->headers();
    packet.file = part->path;
    return true;
}

} // namespace tcpdump
