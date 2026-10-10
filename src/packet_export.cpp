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
 * @file packet_export.cpp
 * @brief Writing chosen packets of a capture to a new capture file.
 */

#include "packet_export.h"

#include "capture_file.h"
#include "regex_lab.h"

#include <QFileInfo>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStringList>

#include <algorithm>
#include <cstring>
#include <memory>

namespace tcpdump {

namespace {

/// Bytes copied at a time.
constexpr qint64 kCopyChunk = 64 * 1024;

/// Where a pcapng section header holds its section length, which is -1
/// ("not given") in either byte order.
constexpr size_t kSectionLengthAt = 16;
constexpr size_t kSectionLengthSize = 8;

/// A number or a range of them: "7", "12-40".
const QRegularExpression& rangeRegex()
{
    static const QRegularExpression regex( QStringLiteral( "^(\\d+)(?:-(\\d+))?$" ) );
    return regex;
}

/// Copies records from the capture to the export.
class RecordCopier {
public:
    explicit RecordCopier( QSaveFile& to )
        : to_( to )
    {
    }

    /// Copy from @p from from now on: the capture file the next records are
    /// in, decompressed if need be (CaptureFile).
    void setSource( ByteSource& from )
    {
        from_ = &from;
    }

    /// Copy @p span; a pcapng section header with its section length unknown.
    bool copy( const RecordSpan& span, bool sectionHeader = false )
    {
        // The spans come in ascending order: in a gzip-compressed capture
        // a seek decompresses on from the last one.
        if ( !from_ || !from_->seek( span.offset ) ) {
            return fail( QStringLiteral( "The capture file ends before a record: it has "
                                         "changed since it was converted." ) );
        }
        uint64_t left = span.length;
        bool first = true;
        while ( left > 0 ) {
            const auto chunk = static_cast<qint64>( std::min<uint64_t>( left, kCopyChunk ) );
            buffer_.resize( chunk );
            if ( !readFully( chunk ) ) {
                return fail( QStringLiteral( "The capture file ends inside a record: it has "
                                             "changed since it was converted." ) );
            }
            if ( first && sectionHeader
                 && chunk >= qint64( kSectionLengthAt + kSectionLengthSize ) ) {
                std::memset( buffer_.data() + kSectionLengthAt, 0xFF, kSectionLengthSize );
            }
            first = false;
            if ( to_.write( buffer_.constData(), chunk ) != chunk ) {
                return fail(
                    QStringLiteral( "The export cannot be written: %1" ).arg( to_.errorString() ) );
            }
            left -= static_cast<uint64_t>( chunk );
        }
        return true;
    }

    const QString& error() const
    {
        return error_;
    }

private:
    /// Read @p n bytes into the buffer; false if the capture ends first.
    bool readFully( qint64 n )
    {
        auto* data = reinterpret_cast<uint8_t*>( buffer_.data() );
        qint64 got = 0;
        while ( got < n ) {
            const auto more = from_->read( data + got, static_cast<size_t>( n - got ) );
            if ( more == 0 ) {
                return false;
            }
            got += static_cast<qint64>( more );
        }
        return true;
    }

    bool fail( const QString& error )
    {
        error_ = error;
        return false;
    }

    ByteSource* from_ = nullptr;
    QSaveFile& to_;
    QByteArray buffer_;
    QString error_;
};

ExportResult failed( const QString& error )
{
    ExportResult result;
    result.status = ExportResult::Status::Failed;
    result.error = error;
    return result;
}

} // namespace

// ── Choosing the packets ─────────────────────────────────────────────────

PacketNumbers::PacketNumbers( std::initializer_list<uint32_t> numbers )
    : PacketNumbers( std::vector<uint32_t>( numbers ) )
{
}

PacketNumbers::PacketNumbers( const std::vector<uint32_t>& numbers )
{
    std::vector<Range> ranges;
    ranges.reserve( numbers.size() );
    for ( const auto number : numbers ) {
        ranges.push_back( { number, number } );
    }
    *this = ofRanges( std::move( ranges ) );
}

PacketNumbers PacketNumbers::ofRanges( std::vector<Range> ranges )
{
    std::sort( ranges.begin(), ranges.end(),
               []( const Range& a, const Range& b ) { return a.first < b.first; } );
    PacketNumbers numbers;
    for ( const auto& range : ranges ) {
        if ( range.first > range.last ) {
            continue;
        }
        auto& merged = numbers.ranges_;
        // Overlapping or next to the last one: one range.
        if ( !merged.empty() && uint64_t{ range.first } <= uint64_t{ merged.back().last } + 1 ) {
            merged.back().last = std::max( merged.back().last, range.last );
        }
        else {
            merged.push_back( range );
        }
    }
    return numbers;
}

uint64_t PacketNumbers::count() const
{
    uint64_t count = 0;
    for ( const auto& range : ranges_ ) {
        count += uint64_t{ range.last } - range.first + 1;
    }
    return count;
}

std::vector<uint32_t> PacketNumbers::list() const
{
    std::vector<uint32_t> numbers;
    for ( const auto& range : ranges_ ) {
        for ( uint64_t number = range.first; number <= range.last; ++number ) {
            numbers.push_back( static_cast<uint32_t>( number ) );
        }
    }
    return numbers;
}

namespace {

/// The packets of the packet lines in @p text and, if @p numbersToo, of the
/// numbers and ranges in its other lines.
PacketSet parse( const QString& text, uint32_t packets, bool numbersToo )
{
    PacketSet set;
    std::vector<PacketNumbers::Range> ranges;
    const auto add = [ & ]( uint64_t first, uint64_t last ) {
        if ( first == 0 || first > last || last > packets ) {
            ++set.skipped;
            return;
        }
        ranges.push_back( { static_cast<uint32_t>( first ), static_cast<uint32_t>( last ) } );
    };
    // "12 - 40" is one range; commas and spaces separate the others.
    static const QRegularExpression dash( QStringLiteral( "\\s*[-\\x{2013}]\\s*" ) );
    static const QRegularExpression separators( QStringLiteral( "[,\\s]+" ) );
    for ( const auto& line : text.split( QLatin1Char( '\n' ) ) ) {
        const auto trimmed = line.trimmed();
        if ( trimmed.isEmpty() ) {
            continue;
        }
        const auto packetLine = packetLineRegex().match( line );
        if ( packetLine.hasMatch() ) {
            bool ok = false;
            const auto number
                = packetLine.captured( QStringLiteral( "number" ) ).toULongLong( &ok );
            ok ? add( number, number ) : void( ++set.skipped );
            continue;
        }
        if ( !numbersToo ) {
            ++set.skipped;
            continue;
        }
        auto pieces = trimmed;
        pieces.replace( dash, QStringLiteral( "-" ) );
        for ( const auto& piece : pieces.split( separators, Qt::SkipEmptyParts ) ) {
            const auto range = rangeRegex().match( piece );
            if ( !range.hasMatch() ) {
                ++set.skipped;
                continue;
            }
            bool firstOk = false;
            bool lastOk = true;
            const auto first = range.captured( 1 ).toULongLong( &firstOk );
            const auto last
                = range.hasCaptured( 2 ) ? range.captured( 2 ).toULongLong( &lastOk ) : first;
            firstOk&& lastOk ? add( first, last ) : void( ++set.skipped );
        }
    }
    set.numbers = PacketNumbers::ofRanges( std::move( ranges ) );
    return set;
}

} // namespace

PacketSet parsePacketSet( const QString& text, uint32_t packets )
{
    return parse( text, packets, true );
}

PacketSet packetLinesOf( const QString& text, uint32_t packets )
{
    return parse( text, packets, false );
}

QString formatPacketRanges( const PacketNumbers& numbers )
{
    QStringList ranges;
    for ( const auto& range : numbers.ranges() ) {
        ranges << ( range.first == range.last
                        ? QString::number( range.first )
                        : QStringLiteral( "%1-%2" ).arg( range.first ).arg( range.last ) );
    }
    return ranges.join( QStringLiteral( ", " ) );
}

CaptureFormat captureFormatOf( const QString& path )
{
    CaptureFile file;
    QString problem;
    CaptureFormat format = CaptureFormat::Pcap;
    if ( !file.open( path, problem ) ) {
        return format;
    }
    HeadSource head( file.source() );
    const auto& bytes = head.peek( kMaxPreamble + 24 );
    std::string error;
    size_t offset = 0;
    findCaptureStart( bytes.data(), bytes.size(), offset, format, error );
    return format;
}

// ── Writing them ─────────────────────────────────────────────────────────

ExportResult exportPackets( std::shared_ptr<const CaptureIndex> index, const PacketNumbers& numbers,
                            const QString& outputPath, const std::atomic_bool* cancel,
                            const std::function<void( int permille )>& progress )
{
    if ( !index ) {
        return failed( QStringLiteral( "No capture." ) );
    }
    if ( numbers.empty() ) {
        return failed( QStringLiteral( "No packet to export." ) );
    }

    // Replacing the capture with some of its packets would lose the others.
    const auto target = QFileInfo( outputPath ).canonicalFilePath();
    for ( const auto& part : index->parts() ) {
        if ( !target.isEmpty() && target == part.path ) {
            return failed( QStringLiteral( "The packets cannot replace the capture they are "
                                           "from: choose another file." ) );
        }
    }

    // The file the packets are copied from, decompressed if need be; one of
    // several, by packet, for a capture split by a ring buffer.
    std::unique_ptr<CaptureFile> capture;
    QString capturePath;
    QString problem;
    // Written aside and renamed when complete: a failed or cancelled export
    // leaves nothing behind.
    QSaveFile output( outputPath );
    if ( !output.open( QIODevice::WriteOnly ) ) {
        return failed(
            QStringLiteral( "%1 cannot be written: %2" ).arg( outputPath, output.errorString() ) );
    }

    ExportResult result;
    CaptureCursor cursor( index );
    // The cursor keeps each record it reads, which is copied from there:
    // the capture is read (and decompressed) once.  The file is opened
    // again only for the headers, and a record the cursor could not keep.
    cursor.keepRecords( true );
    RecordCopier copier( output );
    CapturedPacket packet;
    bool headerWritten = false;
    uint64_t section = 0;   ///< The pcapng section written last, by where it starts.
    size_t headersOfIt = 0; ///< Its header records written so far.
    int lastPermille = -1;
    const auto total = numbers.count();
    uint64_t done = 0;
    for ( const auto& range : numbers.ranges() ) {
        for ( uint64_t at = range.first; at <= range.last; ++at ) {
            const auto number = static_cast<uint32_t>( at );
            if ( cancel && cancel->load() ) {
                output.cancelWriting();
                result.status = ExportResult::Status::Cancelled;
                return result;
            }
            if ( !cursor.read( number, packet ) ) {
                output.cancelWriting();
                return failed(
                    QStringLiteral( "Packet %1: %2" ).arg( number ).arg( cursor.error() ) );
            }
            // The capture file, opened when a record is to be copied from it.
            const auto source = [ & ] {
                if ( capture && capturePath == packet.file ) {
                    return true;
                }
                capture = std::make_unique<CaptureFile>();
                if ( !capture->open( packet.file, problem, index->gzipAccessPoints() ) ) {
                    return false;
                }
                capturePath = packet.file;
                copier.setSource( capture->source() );
                return true;
            };
            const auto& headers = packet.headers;
            if ( headers.records.empty() ) {
                output.cancelWriting();
                return failed(
                    QStringLiteral( "Packet %1 has no header to write before it." ).arg( number ) );
            }
            result.format = headers.format;

            // The headers it needs that were not written yet: a pcap's once, a
            // pcapng section's header when the section changes, and the section's
            // interfaces as they are declared.
            if ( headers.format == CaptureFormat::Pcapng ) {
                if ( !headerWritten || headers.records.front().offset != section ) {
                    section = headers.records.front().offset;
                    headersOfIt = 0;
                }
            }
            for ( ; headersOfIt < headers.records.size(); ++headersOfIt ) {
                const bool sectionHeader
                    = headers.format == CaptureFormat::Pcapng && headersOfIt == 0;
                if ( !source() ) {
                    output.cancelWriting();
                    return failed( problem );
                }
                if ( !copier.copy( headers.records[ headersOfIt ], sectionHeader ) ) {
                    output.cancelWriting();
                    return failed( copier.error() );
                }
            }
            headerWritten = true;

            const auto record = cursor.recordBytes();
            if ( record.data && record.size == packet.recordLength ) {
                const auto length = static_cast<qint64>( record.size );
                if ( output.write( reinterpret_cast<const char*>( record.data ), length )
                     != length ) {
                    output.cancelWriting();
                    return failed( QStringLiteral( "The export cannot be written: %1" )
                                       .arg( output.errorString() ) );
                }
            }
            else {
                ++result.recordsReadAgain;
                if ( !source() ) {
                    output.cancelWriting();
                    return failed( problem );
                }
                if ( !copier.copy( { packet.recordOffset, packet.recordLength } ) ) {
                    output.cancelWriting();
                    return failed( copier.error() );
                }
            }
            ++result.packets;

            if ( progress ) {
                const auto permille = static_cast<int>( ++done * 1000 / total );
                if ( permille != lastPermille ) {
                    lastPermille = permille;
                    progress( permille );
                }
            }
        }
    }

    // A cancel that came with the last packet still wins.
    if ( cancel && cancel->load() ) {
        output.cancelWriting();
        result.status = ExportResult::Status::Cancelled;
        result.packets = 0;
        return result;
    }
    if ( !output.commit() ) {
        return failed(
            QStringLiteral( "%1 cannot be written: %2" ).arg( outputPath, output.errorString() ) );
    }
    result.status = ExportResult::Status::Exported;
    return result;
}

} // namespace tcpdump
