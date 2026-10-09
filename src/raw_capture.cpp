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
 * @file raw_capture.cpp
 * @brief Writing a live capture's raw capture, rotating a ring buffer's files.
 */

#include "raw_capture.h"

#include "capture_file.h"

#include <QDateTime>
#include <QFileInfo>
#include <QSaveFile>

#include <algorithm>
#include <cstring>

namespace tcpdump {

namespace {

/// Bytes copied at a time.
constexpr qint64 kCopyChunk = 64 * 1024;

/// Where a pcapng section header block holds its section's length, which a
/// copy of it cannot know: -1, "not given", as a stream's writer puts it.
constexpr int kSectionLengthAt = 16;
constexpr int kSectionLengthSize = 8;

} // namespace

RawCapture::RawCapture( const QDir& dir, const QString& baseName, CaptureFormat format,
                        uint32_t ringFiles )
    : dir_( dir )
    , baseName_( baseName )
    , suffix_( format == CaptureFormat::Pcapng ? QStringLiteral( "pcapng" )
                                               : QStringLiteral( "pcap" ) )
    , format_( format )
    , ringFiles_( ringFiles )
{
}

bool RawCapture::fail( const QString& what )
{
    error_ = what;
    return false;
}

QString RawCapture::pathOf( uint32_t number ) const
{
    if ( ringFiles_ == 0 ) {
        return dir_.filePath( baseName_ + QLatin1Char( '.' ) + suffix_ );
    }
    return dir_.filePath(
        QStringLiteral( "%1_%2_%3.%4" )
            .arg( baseName_ )
            .arg( number, 5, 10, QLatin1Char( '0' ) )
            .arg( QDateTime::currentDateTime().toString( QStringLiteral( "yyyyMMddHHmmss" ) ),
                  suffix_ ) );
}

bool RawCapture::create( const QString& path )
{
    file_.setFileName( path );
    // Never into an existing file or through a link planted in its place;
    // read back when a ring buffer's file is rotated.
    if ( !file_.open( QIODevice::ReadWrite | QIODevice::NewOnly ) ) {
        return fail( file_.errorString() );
    }
    file_.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
    return true;
}

bool RawCapture::open()
{
    fileNumber_ = 1;
    if ( !create( pathOf( fileNumber_ ) ) ) {
        return false;
    }
    CapturePart part;
    part.path = QFileInfo( file_.fileName() ).absoluteFilePath();
    parts_.push_back( part );
    return true;
}

bool RawCapture::write( const uint8_t* data, size_t n )
{
    if ( n == 0 ) {
        return true;
    }
    if ( file_.write( reinterpret_cast<const char*>( data ), static_cast<qint64>( n ) )
         != static_cast<qint64>( n ) ) {
        return fail( file_.errorString() );
    }
    written_ += n;
    return true;
}

bool RawCapture::flush()
{
    return file_.flush() || fail( file_.errorString() );
}

bool RawCapture::close()
{
    if ( !file_.isOpen() ) {
        return true;
    }
    const bool flushed = flush();
    file_.close();
    return flushed;
}

uint64_t RawCapture::fileSize() const
{
    const auto& part = parts_.back();
    return part.headerLength + ( written_ - part.streamOffset );
}

bool RawCapture::readBack( uint64_t offset, uint64_t length, QByteArray& into )
{
    // seek() writes what is buffered first.
    if ( !file_.seek( static_cast<qint64>( offset ) ) ) {
        return fail( file_.errorString() );
    }
    const auto at = into.size();
    into.resize( at + static_cast<qsizetype>( length ) );
    if ( file_.read( into.data() + at, static_cast<qint64>( length ) )
         != static_cast<qint64>( length ) ) {
        return fail( QStringLiteral( "The raw capture cannot be read back" ) );
    }
    return true;
}

bool RawCapture::rotate( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers )
{
    const auto current = parts_.back();
    if ( ringFiles_ == 0 || cut < current.streamOffset || cut > written_ ) {
        return fail( QStringLiteral( "The raw capture cannot be split there" ) );
    }

    // The headers the new file needs, from where they lie in this one: its
    // records, or the headers copied ahead of them.
    CapturePart next;
    next.packetsBefore = packetsBefore;
    next.streamOffset = cut;
    QByteArray head;
    for ( size_t i = 0; i < headers.records.size(); ++i ) {
        const auto& record = headers.records[ i ];
        const auto here = current.fileOffset( record.offset );
        if ( !here || record.offset + record.length > cut ) {
            return fail( QStringLiteral( "The raw capture's headers are not where they were "
                                         "read" ) );
        }
        next.headerOffsets.emplace_back( record.offset, static_cast<uint64_t>( head.size() ) );
        const auto at = head.size();
        if ( !readBack( *here, record.length, head ) ) {
            return false;
        }
        if ( headers.format == CaptureFormat::Pcapng && i == 0
             && record.length >= kSectionLengthAt + kSectionLengthSize ) {
            std::memset( head.data() + at + kSectionLengthAt, 0xFF, kSectionLengthSize );
        }
    }
    next.headerLength = static_cast<uint64_t>( head.size() );

    // What was read past the cut belongs to the new file.
    const auto end = *current.fileOffset( cut );
    QByteArray tail;
    if ( !readBack( end, written_ - cut, tail ) ) {
        return false;
    }
    if ( !file_.resize( static_cast<qint64>( end ) ) || !close() ) {
        return fail( file_.errorString() );
    }

    ++fileNumber_;
    if ( !create( pathOf( fileNumber_ ) ) ) {
        return false;
    }
    next.path = QFileInfo( file_.fileName() ).absoluteFilePath();
    if ( file_.write( head ) != head.size() || file_.write( tail ) != tail.size() ) {
        return fail( file_.errorString() );
    }
    parts_.push_back( std::move( next ) );

    while ( parts_.size() > ringFiles_ ) {
        QFile::remove( parts_.front().path );
        parts_.erase( parts_.begin() );
    }
    return true;
}

bool saveCaptureParts( const std::vector<CapturePart>& parts, const QString& target,
                       QString& error )
{
    if ( parts.empty() ) {
        error = QStringLiteral( "There is no capture file to save." );
        return false;
    }
    QSaveFile output( target );
    if ( !output.open( QIODevice::WriteOnly ) ) {
        error = QStringLiteral( "%1 cannot be written: %2" ).arg( target, output.errorString() );
        return false;
    }
    QByteArray buffer;
    for ( size_t i = 0; i < parts.size(); ++i ) {
        QFile input;
        if ( !openRegularFile( parts[ i ].path, input, error ) ) {
            output.cancelWriting();
            return false;
        }
        // The first file as it is; the headers of the others are in it.
        if ( i > 0 && !input.seek( static_cast<qint64>( parts[ i ].headerLength ) ) ) {
            output.cancelWriting();
            error = QStringLiteral( "%1 cannot be read: %2" )
                        .arg( parts[ i ].path, input.errorString() );
            return false;
        }
        while ( !input.atEnd() ) {
            buffer = input.read( kCopyChunk );
            if ( buffer.isEmpty() && !input.atEnd() ) {
                output.cancelWriting();
                error = QStringLiteral( "%1 cannot be read: %2" )
                            .arg( parts[ i ].path, input.errorString() );
                return false;
            }
            if ( output.write( buffer ) != buffer.size() ) {
                output.cancelWriting();
                error = QStringLiteral( "%1 cannot be written: %2" )
                            .arg( target, output.errorString() );
                return false;
            }
        }
    }
    if ( !output.commit() ) {
        error = QStringLiteral( "%1 cannot be written: %2" ).arg( target, output.errorString() );
        return false;
    }
    QFile( target ).setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
    return true;
}

} // namespace tcpdump
