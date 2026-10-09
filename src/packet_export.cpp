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

/// Copies records from the capture file to the export.
class RecordCopier {
public:
    RecordCopier( QFile& from, QSaveFile& to )
        : from_( from )
        , to_( to )
    {
    }

    /// Copy @p span; a pcapng section header with its section length unknown.
    bool copy( const RecordSpan& span, bool sectionHeader = false )
    {
        if ( !from_.seek( static_cast<qint64>( span.offset ) ) ) {
            return fail( QStringLiteral( "The capture file cannot be read: %1" )
                             .arg( from_.errorString() ) );
        }
        uint64_t left = span.length;
        bool first = true;
        while ( left > 0 ) {
            const auto chunk = static_cast<qint64>( std::min<uint64_t>( left, kCopyChunk ) );
            buffer_.resize( chunk );
            if ( from_.read( buffer_.data(), chunk ) != chunk ) {
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
    bool fail( const QString& error )
    {
        error_ = error;
        return false;
    }

    QFile& from_;
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

namespace {

/// The packets of the packet lines in @p text and, if @p numbersToo, of the
/// numbers and ranges in its other lines.
PacketSet parse( const QString& text, uint32_t packets, bool numbersToo )
{
    PacketSet set;
    const auto add = [ & ]( uint64_t first, uint64_t last ) {
        if ( first == 0 || first > last || last > packets ) {
            ++set.skipped;
            return;
        }
        for ( auto number = first; number <= last; ++number ) {
            set.numbers.push_back( static_cast<uint32_t>( number ) );
        }
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
    std::sort( set.numbers.begin(), set.numbers.end() );
    set.numbers.erase( std::unique( set.numbers.begin(), set.numbers.end() ), set.numbers.end() );
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

QString formatPacketRanges( const std::vector<uint32_t>& numbers )
{
    QStringList ranges;
    for ( size_t i = 0; i < numbers.size(); ) {
        size_t j = i;
        while ( j + 1 < numbers.size() && numbers[ j + 1 ] == numbers[ j ] + 1 ) {
            ++j;
        }
        ranges << ( j == i ? QString::number( numbers[ i ] )
                           : QStringLiteral( "%1-%2" ).arg( numbers[ i ] ).arg( numbers[ j ] ) );
        i = j + 1;
    }
    return ranges.join( QStringLiteral( ", " ) );
}

CaptureFormat captureFormatOf( const QString& path )
{
    QFile file;
    QString problem;
    CaptureFormat format = CaptureFormat::Pcap;
    if ( !openRegularFile( path, file, problem ) ) {
        return format;
    }
    const auto head = file.read( static_cast<qint64>( kMaxPreamble + 24 ) );
    std::string error;
    findCaptureStart( reinterpret_cast<const uint8_t*>( head.constData() ),
                      static_cast<size_t>( head.size() ), format, error );
    return format;
}

// ── Writing them ─────────────────────────────────────────────────────────

ExportResult exportPackets( std::shared_ptr<const CaptureIndex> index,
                            std::vector<uint32_t> numbers, const QString& outputPath,
                            const std::atomic_bool* cancel,
                            const std::function<void( int permille )>& progress )
{
    if ( !index ) {
        return failed( QStringLiteral( "No capture." ) );
    }
    std::sort( numbers.begin(), numbers.end() );
    numbers.erase( std::unique( numbers.begin(), numbers.end() ), numbers.end() );
    if ( numbers.empty() ) {
        return failed( QStringLiteral( "No packet to export." ) );
    }

    // Replacing the capture with some of its packets would lose the others.
    if ( QFileInfo( outputPath ).canonicalFilePath() == index->capturePath() ) {
        return failed( QStringLiteral( "The packets cannot replace the capture they are "
                                       "from: choose another file." ) );
    }

    QFile capture;
    QString problem;
    if ( !openRegularFile( index->capturePath(), capture, problem ) ) {
        return failed( problem );
    }
    // Written aside and renamed when complete: a failed or cancelled export
    // leaves nothing behind.
    QSaveFile output( outputPath );
    if ( !output.open( QIODevice::WriteOnly ) ) {
        return failed(
            QStringLiteral( "%1 cannot be written: %2" ).arg( outputPath, output.errorString() ) );
    }

    ExportResult result;
    CaptureCursor cursor( index );
    RecordCopier copier( capture, output );
    CapturedPacket packet;
    bool headerWritten = false;
    uint64_t section = 0;   ///< The pcapng section written last, by where it starts.
    size_t headersOfIt = 0; ///< Its header records written so far.
    int lastPermille = -1;
    for ( size_t i = 0; i < numbers.size(); ++i ) {
        if ( cancel && cancel->load() ) {
            output.cancelWriting();
            result.status = ExportResult::Status::Cancelled;
            return result;
        }
        if ( !cursor.read( numbers[ i ], packet ) ) {
            output.cancelWriting();
            return failed(
                QStringLiteral( "Packet %1: %2" ).arg( numbers[ i ] ).arg( cursor.error() ) );
        }
        const auto& headers = packet.headers;
        if ( headers.records.empty() ) {
            output.cancelWriting();
            return failed( QStringLiteral( "Packet %1 has no header to write before it." )
                               .arg( numbers[ i ] ) );
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
            const bool sectionHeader = headers.format == CaptureFormat::Pcapng && headersOfIt == 0;
            if ( !copier.copy( headers.records[ headersOfIt ], sectionHeader ) ) {
                output.cancelWriting();
                return failed( copier.error() );
            }
        }
        headerWritten = true;

        if ( !copier.copy( { packet.recordOffset, packet.recordLength } ) ) {
            output.cancelWriting();
            return failed( copier.error() );
        }
        ++result.packets;

        if ( progress ) {
            const auto permille = static_cast<int>( ( i + 1 ) * 1000 / numbers.size() );
            if ( permille != lastPermille ) {
                lastPermille = permille;
                progress( permille );
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
