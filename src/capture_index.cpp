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

void CaptureIndex::setCaptureFile( const QString& path, Growth growth )
{
    const QFileInfo info( path );
    path_ = info.canonicalFilePath();
    size_ = info.size();
    growth_ = growth;
    modified_ = info.lastModified();
}

const ReaderCheckpoint* CaptureIndex::nearest( uint32_t number ) const
{
    // The checkpoints are in ascending order: the last one before number.
    const auto after = std::lower_bound(
        checkpoints_.begin(), checkpoints_.end(), number,
        []( const ReaderCheckpoint& c, uint32_t n ) { return c.packetsBefore < n; } );
    return after == checkpoints_.begin() ? nullptr : &*std::prev( after );
}

QString CaptureIndex::fileProblem() const
{
    const QFileInfo info( path_ );
    if ( path_.isEmpty() || !info.exists() ) {
        return QStringLiteral( "The capture file %1 is gone." ).arg( path_ );
    }
    const bool changed = growth_ == Growth::Growing
                             ? info.size() < size_
                             : info.size() != size_ || info.lastModified() != modified_;
    if ( changed ) {
        return QStringLiteral( "The capture file %1 has changed since it was converted: "
                               "open it again to see its packets." )
            .arg( info.fileName() );
    }
    return {};
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
    headSource_.reset();
    file_.reset();
}

bool CaptureCursor::reopen( const ReaderCheckpoint* checkpoint )
{
    close();
    QString problem;
    file_ = std::make_unique<CaptureFile>();
    if ( !file_->open( index_->capturePath(), problem, index_->gzipAccessPoints() ) ) {
        file_.reset();
        error_ = problem;
        return false;
    }
    headSource_ = std::make_unique<HeadSource>( file_->source() );
    reader_ = makeCaptureReader( *headSource_ );
    if ( !reader_->open() || ( checkpoint && !reader_->resume( *checkpoint ) ) ) {
        close();
        error_ = QStringLiteral( "The capture file can no longer be read as it was converted." );
        return false;
    }
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
    // Checked before every read: a file changed between two is not misread.
    if ( const auto problem = index_->fileProblem(); !problem.isEmpty() ) {
        close();
        error_ = problem;
        return false;
    }

    // Go on from where the cursor is, unless the packet lies behind it or a
    // checkpoint lies between the two.
    const auto* checkpoint = index_->nearest( number );
    const uint32_t from = checkpoint ? checkpoint->packetsBefore : 0;
    if ( !reader_ || reader_->packetsRead() >= number || reader_->packetsRead() < from ) {
        if ( !reopen( checkpoint ) ) {
            return false;
        }
    }

    PacketRecord record;
    while ( reader_->packetsRead() < number ) {
        if ( !reader_->next( record ) ) {
            close();
            error_ = QStringLiteral( "The capture ends before packet %1: it has changed since "
                                     "it was converted." )
                         .arg( number );
            return false;
        }
    }
    packet.record = std::move( record );
    packet.bytes = reader_->packetBytes();
    packet.byteSwapped = reader_->byteSwapped();
    packet.recordOffset = reader_->recordOffset();
    packet.recordLength = reader_->recordLength();
    packet.headers = reader_->headers();
    return true;
}

} // namespace tcpdump
