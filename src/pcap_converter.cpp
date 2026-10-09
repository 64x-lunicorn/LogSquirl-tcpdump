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
 * @file pcap_converter.cpp
 * @brief Implementation of the streaming pcap-to-text conversion.
 */

#include "pcap_converter.h"

#include "capture_reader.h"
#include "media_expectations.h"
#include "packet_formatter.h"
#include "payload_describer.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tempdirs.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <exception>
#include <new>

#ifdef Q_OS_UNIX
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tcpdump {

namespace {

/// A ByteSource reading a QFile.
class FileSource : public ByteSource {
public:
    explicit FileSource( QFile& file )
        : file_( file )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        const auto got = file_.read( reinterpret_cast<char*>( dst ), static_cast<qint64>( n ) );
        return got > 0 ? static_cast<size_t>( got ) : 0;
    }

    bool skip( uint64_t n ) override
    {
        const auto target = static_cast<uint64_t>( file_.pos() ) + n;
        if ( target > static_cast<uint64_t>( file_.size() ) ) {
            file_.seek( file_.size() );
            return false;
        }
        return file_.seek( static_cast<qint64>( target ) );
    }

private:
    QFile& file_;
};

/// The summary of a converted capture, from what was collected on the way.
CaptureSummary summarise( CaptureStats&& stats, const StreamTracker& tracker,
                          const CaptureReader& reader, size_t maxStreams )
{
    // The packets' link-layer types first, then any the capture declares
    // without a packet of it, such as a pcap's when it holds none.
    for ( const auto linkType : reader.linkTypes() ) {
        stats.addLinkType( linkType );
    }

    CaptureSummary summary;
    summary.packets = stats.packets;
    summary.bytes = stats.bytes;
    summary.cutPackets = stats.cutPackets;
    summary.durationSeconds = stats.durationSeconds();
    if ( stats.packets > 0 ) {
        summary.firstTimeUtc
            = formatUtcTime( stats.firstTimeSec, stats.firstTimeNsec, reader.precision() );
        summary.lastTimeUtc
            = formatUtcTime( stats.lastTimeSec, stats.lastTimeNsec, reader.precision() );
    }
    for ( const auto linkType : stats.linkTypes ) {
        summary.linkTypeNames.push_back( linkTypeName( linkType ) );
    }
    summary.protocolPackets = std::move( stats.protocolPackets );
    summary.protocolBytes = std::move( stats.protocolBytes );
    summary.endpointPackets = std::move( stats.endpointPackets );
    summary.tunnelEndpointPackets = std::move( stats.tunnelEndpointPackets );
    for ( size_t i = 0; i < kTcpMarkerKinds; ++i ) {
        if ( stats.tcpMarkers[ i ] > 0 ) {
            summary.tcpMarkers.emplace_back( tcpMarkerName( static_cast<TcpMarker>( i ) ),
                                             stats.tcpMarkers[ i ] );
        }
    }
    summary.endsInsideRecord = reader.truncated();
    if ( tracker.limitReached() ) {
        summary.streamCap = maxStreams;
    }
    if ( stats.endpointLimitReached() ) {
        summary.otherEndpointPackets = stats.otherEndpointPackets;
    }
    return summary;
}

/// The message for a path that is not a regular file.
QString notRegular( const QString& path )
{
    return QStringLiteral( "%1 is not a regular file" ).arg( path );
}

/**
 * Open @p path for reading if it is, or links to, a regular file.
 *
 * Reading a FIFO or a device can block for good, and a blocked worker would
 * block the plugin's shutdown, which waits for it.  On Unix the file is
 * opened without blocking and checked with fstat(), so that it cannot be
 * swapped for a FIFO between the check and the opening.  Reading a regular
 * file on a network share that stalls can still block; that is left to the
 * operating system's timeouts.
 */
bool openRegularFile( const QString& path, QFile& file, QString& error )
{
    const QFileInfo info( path );
    const auto target = info.canonicalFilePath(); // follows symbolic links
    if ( target.isEmpty() ) {
        error = QStringLiteral( "Cannot open file: %1 does not exist" ).arg( path );
        return false;
    }
    if ( !QFileInfo( target ).isFile() ) {
        error = notRegular( path );
        return false;
    }

#ifdef Q_OS_UNIX
    const int fd
        = ::open( QFile::encodeName( target ).constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC );
    if ( fd < 0 ) {
        error = QStringLiteral( "Cannot open file: %1" )
                    .arg( QString::fromLocal8Bit( std::strerror( errno ) ) );
        return false;
    }
    struct stat st;
    if ( ::fstat( fd, &st ) != 0 || !S_ISREG( st.st_mode ) ) {
        ::close( fd );
        error = notRegular( path );
        return false;
    }
    const int flags = ::fcntl( fd, F_GETFL );
    if ( flags != -1 ) {
        ::fcntl( fd, F_SETFL, flags & ~O_NONBLOCK );
    }
    if ( !file.open( fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle ) ) {
        ::close( fd );
        error = QStringLiteral( "Cannot open file: %1" ).arg( file.errorString() );
        return false;
    }
#else
    file.setFileName( target );
    if ( !file.open( QIODevice::ReadOnly ) ) {
        error = QStringLiteral( "Cannot open file: %1" ).arg( file.errorString() );
        return false;
    }
#endif
    return true;
}

/// A Failed result with @p error.
ConversionResult failed( const QString& error )
{
    ConversionResult result;
    result.status = ConversionResult::Status::Failed;
    result.error = error;
    return result;
}

/// The conversion itself; whatever it throws, convertPcap() turns into Failed.
ConversionResult convertOrThrow( const QString& inputPath, const QString& outputRoot,
                                 const std::atomic_bool* cancel,
                                 const std::function<void( int )>& progress,
                                 const ConversionOptions& options )
{
    QFile input;
    QString inputError;
    if ( !openRegularFile( inputPath, input, inputError ) ) {
        return failed( inputError );
    }
    FileSource file( input );
    HeadSource source( file );
    const auto capture = makeCaptureReader( source ); // pcap or pcapng, by the first block
    CaptureReader& reader = *capture;                 // the rest sees the capture through the seam
    if ( !reader.open() ) {
        return failed( QString::fromStdString( reader.error() ) );
    }

    // The directory is removed with this object unless the conversion ends
    // Converted: on every other return, and when an exception unwinds.
    QTemporaryDir outputDir( tempDirTemplate( outputRoot ) );
    if ( !outputDir.isValid() ) {
        return failed( QStringLiteral( "Cannot create a temporary directory: %1" )
                           .arg( outputDir.errorString() ) );
    }
    auto baseName = QFileInfo( inputPath ).completeBaseName();
    if ( baseName.isEmpty() ) {
        baseName = QStringLiteral( "capture" );
    }
    QFile output( outputDir.filePath( baseName + QStringLiteral( ".log" ) ) );
    // Never write into an existing file or through a link planted in its place.
    if ( !output.open( QIODevice::WriteOnly | QIODevice::NewOnly | QIODevice::Text ) ) {
        return failed(
            QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
    }
    output.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
    auto writeFailed = [ &output ] {
        return failed(
            QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
    };
    auto writeLine = [ &output ]( const std::string& line ) {
        return output.write( line.data(), static_cast<qint64>( line.size() ) )
                   == static_cast<qint64>( line.size() )
               && output.write( "\n", 1 ) == 1;
    };

    CaptureStats stats;
    stats.maxEndpoints = options.maxEndpoints;
    StreamTracker tracker( options.maxStreams );
    StreamLabels labels;
    MediaExpectations media;
    PacketFormatter formatter( reader.precision(), options.layout );
    if ( !writeLine( formatter.header() ) ) {
        return writeFailed();
    }

    const auto inputSize = std::max<qint64>( input.size(), 1 );
    int lastPermille = -1;
    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        if ( cancel && cancel->load() ) {
            ConversionResult result;
            result.status = ConversionResult::Status::Cancelled;
            return result;
        }
        limitPreview( pkt, options.preview ? options.previewChars : 0 );
        const auto stream = tracker.track( pkt );
        stats.addTcpMarkers( analyseTcp( pkt, stream ) );
        describeInStream( pkt, stream );
        media.apply( pkt );
        labels.apply( pkt, stream );
        stats.add( pkt );
        if ( !writeLine( formatter.format( pkt, stream.id ) ) ) {
            return writeFailed();
        }
        if ( progress ) {
            const auto permille = static_cast<int>( std::min<uint64_t>(
                reader.bytesRead() * 1000 / static_cast<uint64_t>( inputSize ), 1000 ) );
            if ( permille != lastPermille ) {
                lastPermille = permille;
                progress( permille );
            }
        }
    }
    if ( !output.flush() ) {
        return writeFailed();
    }
    output.close();

    ConversionResult result;
    result.status = ConversionResult::Status::Converted;
    result.outputPath = QFileInfo( output.fileName() ).absoluteFilePath();
    result.summary = summarise( std::move( stats ), tracker, reader, options.maxStreams );
    outputDir.setAutoRemove( false );
    return applyCancelRequest( std::move( result ), cancel );
}

} // namespace

ConversionResult convertPcap( const QString& inputPath, const QString& outputRoot,
                              const std::atomic_bool* cancel,
                              const std::function<void( int )>& progress,
                              const ConversionOptions& options )
{
    try {
        return convertOrThrow( inputPath, outputRoot, cancel, progress, options );
    } catch ( const std::bad_alloc& ) {
        return failed( QStringLiteral( "Not enough memory to read the capture" ) );
    } catch ( const std::exception& e ) {
        return failed( QString::fromUtf8( e.what() ) );
    } catch ( ... ) {
        return failed( QStringLiteral( "Unknown error" ) );
    }
}

ConversionResult applyCancelRequest( ConversionResult result, const std::atomic_bool* cancel )
{
    if ( !cancel || !cancel->load() ) {
        return result;
    }
    if ( !result.outputPath.isEmpty() ) {
        QDir( QFileInfo( result.outputPath ).absolutePath() ).removeRecursively();
    }
    ConversionResult cancelled;
    cancelled.status = ConversionResult::Status::Cancelled;
    return cancelled;
}

} // namespace tcpdump
