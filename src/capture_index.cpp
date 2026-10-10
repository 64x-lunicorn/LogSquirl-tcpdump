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
        streams.growTo( at + 1 );
        streams.writable( at ).first = number;
    }
    if ( streams[ at ].last != number ) {
        streams.writable( at ).last = number;
    }
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
    // The checkpoints in the files rotated away are never read again (a
    // packet is read from a checkpoint in its own file): dropped, so that
    // a ring buffer that runs for days keeps those of its files only.
    if ( !files_.empty() && files_.front().part.packetsBefore > 0 ) {
        const auto rotatedAway = files_.front().part.packetsBefore;
        checkpoints_.erase( checkpoints_.begin(),
                            std::find_if( checkpoints_.begin(), checkpoints_.end(),
                                          [ rotatedAway ]( const ReaderCheckpoint& c ) {
                                              return c.packetsBefore > rotatedAway;
                                          } ) );
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

/// Passes a file's bytes on to the reader and, when it keeps them, a copy
/// of those from the reader's place on (trimTo()), up to kMaxKeptRecord:
/// the record the reader reads next, and what it read ahead of it.
class CaptureCursor::RecordingSource : public ByteSource {
public:
    RecordingSource( ByteSource& inner, bool keep )
        : inner_( inner )
        , keeping_( keep )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        const auto got = inner_.read( dst, n );
        if ( keeping_ ) {
            if ( kept_.size() + got > kMaxKeptRecord ) {
                kept_.clear(); // too long to keep: copied from the file
                start_ = position_ + got;
            }
            else {
                kept_.insert( kept_.end(), dst, dst + got );
            }
        }
        position_ += got;
        return got;
    }

    bool skip( uint64_t n ) override
    {
        if ( keeping_ && n <= kMaxKeptRecord ) {
            return ByteSource::skip( n ); // read, so that they are kept
        }
        if ( !inner_.skip( n ) ) {
            return false;
        }
        kept_.clear();
        position_ += n;
        start_ = position_;
        return true;
    }

    bool seek( uint64_t offset ) override
    {
        if ( !inner_.seek( offset ) ) {
            return false;
        }
        kept_.clear();
        position_ = offset;
        start_ = offset;
        return true;
    }

    bool ready() override
    {
        return inner_.ready();
    }

    /// Let go of what was kept before @p offset, where the reader is.
    void trimTo( uint64_t offset )
    {
        if ( offset <= start_ ) {
            return;
        }
        const auto drop = std::min<uint64_t>( offset - start_, kept_.size() );
        kept_.erase( kept_.begin(), kept_.begin() + static_cast<std::ptrdiff_t>( drop ) );
        start_ = offset;
    }

    /// The bytes kept from @p offset on, @p length of them; empty if not all
    /// of them were kept.
    ByteView bytes( uint64_t offset, uint64_t length ) const
    {
        if ( offset < start_ || offset - start_ + length > kept_.size() ) {
            return {};
        }
        return { kept_.data() + ( offset - start_ ), static_cast<size_t>( length ) };
    }

private:
    ByteSource& inner_;
    bool keeping_;
    uint64_t position_ = 0; ///< Bytes passed on so far: the reader's offsets.
    uint64_t start_ = 0;    ///< Where the bytes kept start.
    std::vector<uint8_t> kept_;
};

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
    recording_.reset();
    file_.reset();
    recordLength_ = 0;
}

bool CaptureCursor::reopen( const CapturePart& part, const ReaderCheckpoint* checkpoint )
{
    close();
    QString problem;
    file_ = std::make_unique<CaptureFile>();
    if ( !file_->open( part.path, problem, index_->gzipAccessPoints() ) ) {
        file_.reset();
        error_ = problem;
        return false;
    }
    recording_ = std::make_unique<RecordingSource>( file_->source(), keepRecords_ );
    headSource_ = std::make_unique<HeadSource>( *recording_ );
    reader_ = makeCaptureReader( *headSource_ );
    if ( !reader_->open() || ( checkpoint && !reader_->resume( *checkpoint ) ) ) {
        close();
        error_ = QStringLiteral( "The capture file can no longer be read as it was converted." );
        return false;
    }
    if ( checkpoint ) {
        // The checkpoint was taken as the capture was read: the headers it
        // names lie elsewhere in a later file of it, copied ahead of its records.
        if ( !reader_->relocateHeaders(
                 [ &part ]( uint64_t offset ) { return part.fileOffset( offset ); } ) ) {
            // Bytes at the offset the capture had them would be another
            // record's: an export would copy them as the headers.
            close();
            error_ = QStringLiteral( "%1 lacks the headers its packets need: it has changed "
                                     "since it was written." )
                         .arg( QFileInfo( part.path ).fileName() );
            return false;
        }
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
    recordLength_ = 0;
    while ( reader_->packetsRead() < local ) {
        // Only what comes after the record read last is kept: the reader may
        // have read ahead of where it is.
        recording_->trimTo( reader_->recordOffset() + reader_->recordLength() );
        if ( !reader_->next( record ) ) {
            close();
            error_ = QStringLiteral( "The capture ends before packet %1: it has changed since "
                                     "it was converted." )
                         .arg( number );
            return false;
        }
    }
    if ( keepRecords_ ) {
        recordOffset_ = reader_->recordOffset();
        recordLength_ = reader_->recordLength();
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

ByteView CaptureCursor::recordBytes() const
{
    if ( !recording_ || recordLength_ == 0 ) {
        return {};
    }
    return recording_->bytes( recordOffset_, recordLength_ );
}

} // namespace tcpdump
