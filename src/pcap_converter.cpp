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

#include "capture_file.h"
#include "capture_reader.h"
#include "capture_source.h"
#include "packet_formatter.h"
#include "payload_describer.h"
#include "pcapng_reader.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tcp_reassembly.h"
#include "tempdirs.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <exception>
#include <new>
#include <thread>
#include <tuple>

namespace tcpdump {

namespace {

/**
 * The input of a live conversion: reads the stream, and writes every byte
 * read, unchanged, to the raw capture.  The bytes read before the raw file
 * exists (the header the format is told by) are kept until it is attached.
 * Before every read that would wait for the stream, it calls beforeWait, so
 * that the Converter makes what it wrote readable first.
 */
class LiveInput : public ByteSource {
public:
    LiveInput( ByteSource& stream, std::function<void()> beforeWait )
        : stream_( stream )
        , beforeWait_( std::move( beforeWait ) )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        if ( n > 0 && !stream_.ready() ) {
            beforeWait_();
        }
        const auto got = stream_.read( dst, n );
        bytesRead_ += got;
        keep( dst, got );
        return got;
    }

    // skip() reads, so what is skipped is kept too.

    bool ready() override
    {
        return stream_.ready();
    }

    /// Write the bytes read so far, and from now on every byte read, to
    /// @p raw.  False if they cannot be written.
    bool attach( QFile& raw )
    {
        raw_ = &raw;
        keep( pending_.data(), pending_.size() );
        pending_.clear();
        pending_.shrink_to_fit();
        return !failed_;
    }

    /// Whether every byte read could be written to the raw file.
    bool failed() const
    {
        return failed_;
    }

    /// Bytes read from the stream so far.
    uint64_t bytesRead() const
    {
        return bytesRead_;
    }

private:
    void keep( const uint8_t* data, size_t n )
    {
        if ( n == 0 ) {
            return;
        }
        if ( !raw_ ) {
            pending_.insert( pending_.end(), data, data + n );
        }
        else if ( raw_->write( reinterpret_cast<const char*>( data ), static_cast<qint64>( n ) )
                  != static_cast<qint64>( n ) ) {
            failed_ = true;
        }
    }

    ByteSource& stream_;
    std::function<void()> beforeWait_;
    std::vector<uint8_t> pending_;
    QFile* raw_ = nullptr;
    bool failed_ = false;
    uint64_t bytesRead_ = 0;
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
    summary.handshakes = stats.initialRtts.count();
    summary.medianInitialRttNs = stats.medianInitialRttNs();
    summary.endsInsideRecord = reader.truncated();
    if ( tracker.limitReached() ) {
        summary.streamCap = maxStreams;
    }
    if ( stats.endpointLimitReached() ) {
        summary.otherEndpointPackets = stats.otherEndpointPackets;
    }
    return summary;
}

/// The summary of a capture still being converted, from a copy of what was
/// collected so far: the conversion goes on with @p stats as they are.
CaptureSummary summariseSoFar( const CaptureStats& stats, const StreamTracker& tracker,
                               const CaptureReader& reader, size_t maxStreams )
{
    return summarise( CaptureStats( stats ), tracker, reader, maxStreams );
}

/// A Failed result with @p error.
ConversionResult failed( const QString& error )
{
    ConversionResult result;
    result.status = ConversionResult::Status::Failed;
    result.error = error;
    return result;
}

/// Why the stream @p input broke off, or nothing for a file or a stream
/// that ended normally.
std::optional<ConversionResult> streamFailure( const ByteSource& input )
{
    const auto* stream = dynamic_cast<const StreamSource*>( &input );
    if ( !stream || stream->error().empty() ) {
        return std::nullopt;
    }
    return failed( QStringLiteral( "Cannot read the capture: %1" )
                       .arg( QString::fromStdString( stream->error() ) ) );
}

/// Stopped, if @p input is a stream that was stopped (rather than closed or
/// broken off), for a stream whose header has not come.
std::optional<ConversionResult> stoppedBeforeHeader( const ByteSource& input )
{
    const auto* stream = dynamic_cast<const StreamSource*>( &input );
    if ( !stream || !stream->stopped() || !stream->error().empty() ) {
        return std::nullopt;
    }
    ConversionResult result;
    result.status = ConversionResult::Status::Stopped;
    return result;
}

using Clock = std::chrono::steady_clock;

/**
 * The conversion of the capture in @p input, named @p name; whatever it
 * throws, the caller turns into Failed.  @p inputPath is the capture file
 * @p input reads, which the CaptureIndex points into, and @p inputSize its
 * size for progress; both empty for a stream, whose size is unknown and
 * which reports none.  With @p live, the input is a stream converted live
 * (convertStream()), and the index points into its raw capture.
 *
 * Every packet goes through the same steps for a file and a stream: the
 * Parser's record, the stream it belongs to, its TCP analysis, its payload
 * described in the stream and reassembled, its stream labels, the summary's
 * counts, its line, and its place in the CaptureIndex.
 */
ConversionResult convertOrThrow( ByteSource& input, const QString& inputPath, const QString& name,
                                 uint64_t inputSize, const QString& outputRoot,
                                 const std::atomic_bool* cancel,
                                 const std::function<void( int )>& progress,
                                 const ConversionOptions& options, const LiveObserver* live )
{
    const auto started = Clock::now();
    // What to do before a wait for the stream, once there is output.
    std::function<void()> beforeWait;
    std::optional<LiveInput> liveInput;
    if ( live ) {
        liveInput.emplace( input, [ &beforeWait ] {
            if ( beforeWait ) {
                beforeWait();
            }
        } );
    }

    HeadSource source( liveInput ? static_cast<ByteSource&>( *liveInput ) : input );
    const auto capture = makeCaptureReader( source ); // pcap or pcapng, by the first block
    CaptureReader& reader = *capture;                 // the rest sees the capture through the seam
    if ( !reader.open() ) {
        // A stream stopped before its header came was not read: it did not
        // fail, and a cancel request still wins.
        auto result = stoppedBeforeHeader( input ).value_or(
            streamFailure( input ).value_or( failed( QString::fromStdString( reader.error() ) ) ) );
        return applyCancelRequest( std::move( result ), cancel );
    }

    // The directory is removed with this object unless the conversion ends
    // Converted: on every other return, and when an exception unwinds.
    QTemporaryDir outputDir( tempDirTemplate( outputRoot ) );
    if ( !outputDir.isValid() ) {
        return failed( QStringLiteral( "Cannot create a temporary directory: %1" )
                           .arg( outputDir.errorString() ) );
    }
    auto baseName = name;
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

    // A live capture's bytes, as they were read, next to its text.
    QFile raw;
    auto rawFailed = [ &raw ] {
        return failed(
            QStringLiteral( "Cannot write the raw capture: %1" ).arg( raw.errorString() ) );
    };
    if ( live ) {
        const bool pcapng = dynamic_cast<const PcapngReader*>( &reader ) != nullptr;
        raw.setFileName( outputDir.filePath(
            baseName + ( pcapng ? QStringLiteral( ".pcapng" ) : QStringLiteral( ".pcap" ) ) ) );
        if ( !raw.open( QIODevice::WriteOnly | QIODevice::NewOnly ) ) {
            return rawFailed();
        }
        raw.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
        if ( !liveInput->attach( raw ) ) {
            return rawFailed();
        }
    }

    CaptureStats stats;
    stats.maxEndpoints = options.maxEndpoints;
    StreamTracker tracker( options.maxStreams );
    StreamLabels labels;
    TcpReassembly reassembly( options.reassemblyMegabytes * kMegabyte );
    PacketFormatter formatter( reader.precision(), options.layout );
    if ( !writeLine( formatter.header() ) ) {
        return writeFailed();
    }

    auto index = std::make_shared<CaptureIndex>( options.checkpointInterval );
    // Live: what was written is made readable before every wait and at
    // least every kLiveFlushInterval; snapshots go out with the first packet
    // and then at most every kLiveSnapshotInterval.
    auto lastFlush = started;
    auto lastSnapshot = started;
    bool flushFailed = false;
    bool snapshotDue = false; ///< Packets came since the last snapshot.
    auto flush = [ & ] {
        lastFlush = Clock::now();
        if ( !output.flush() || ( live && !raw.flush() ) ) {
            flushFailed = true;
        }
    };
    auto sendSnapshot = [ & ] {
        lastSnapshot = Clock::now();
        snapshotDue = false;
        if ( !live->snapshot ) {
            return;
        }
        LiveSnapshot snapshot;
        snapshot.summary = summariseSoFar( stats, tracker, reader, options.maxStreams );
        snapshot.elapsed
            = std::chrono::duration_cast<std::chrono::milliseconds>( lastSnapshot - started );
        snapshot.rawBytes = liveInput->bytesRead();
        // The packets so far, for the Packet Panel: their bytes are in the
        // raw file once it is flushed, which goes on growing behind them.
        flush();
        auto soFar = std::make_shared<CaptureIndex>( *index );
        soFar->setCaptureFile( raw.fileName(), CaptureIndex::Growth::Growing );
        snapshot.index = std::move( soFar );
        live->snapshot( snapshot );
    };
    if ( live ) {
        beforeWait = [ & ] {
            flush();
            if ( !snapshotDue || !live->snapshot ) {
                return;
            }
            // The packets of a burst would wait for the next packet to be
            // in a snapshot: while the stream has nothing new, wait for the
            // snapshot's turn instead.  ready() also turns on a stop.
            while ( !liveInput->ready() && Clock::now() - lastSnapshot < kLiveSnapshotInterval ) {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
            if ( Clock::now() - lastSnapshot >= kLiveSnapshotInterval ) {
                sendSnapshot();
            }
        };
    }

    int lastPermille = -1;
    bool firstPacket = true;
    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        if ( cancel && cancel->load() ) {
            ConversionResult result;
            result.status = ConversionResult::Status::Cancelled;
            return result;
        }
        limitPreview( pkt, options.preview ? options.previewChars : 0 );
        if ( options.tcpTimestamps ) {
            showTcpTimestamps( pkt );
        }
        const auto stream = tracker.track( pkt );
        if ( pkt.transport ) {
            index->noteStream( *pkt.transport, stream.id, reader.packetsRead() );
        }
        stats.addTcpAnalysis( analyseTcp( pkt, stream ) );
        describeInStream( pkt, stream );
        reassembly.apply( pkt, stream, reader.payloadOf( pkt ) );
        labels.apply( pkt, stream );
        stats.add( pkt );
        if ( !writeLine( formatter.format( pkt, stream.id ) ) ) {
            return writeFailed();
        }
        index->note( reader );
        if ( live ) {
            snapshotDue = true;
            const auto now = Clock::now();
            if ( firstPacket ) {
                // The header and this line are in the file before it is opened.
                flush();
                if ( !flushFailed && live->firstPacket ) {
                    live->firstPacket( QFileInfo( output.fileName() ).absoluteFilePath(),
                                       QFileInfo( raw.fileName() ).absoluteFilePath() );
                }
                sendSnapshot();
            }
            else {
                if ( now - lastFlush >= kLiveFlushInterval ) {
                    flush();
                }
                if ( now - lastSnapshot >= kLiveSnapshotInterval ) {
                    sendSnapshot();
                }
            }
            if ( flushFailed ) {
                return writeFailed();
            }
            if ( liveInput->failed() ) {
                return rawFailed();
            }
        }
        firstPacket = false;
        if ( progress && inputSize > 0 ) {
            const auto permille = static_cast<int>(
                std::min<uint64_t>( reader.bytesRead() * 1000 / inputSize, 1000 ) );
            if ( permille != lastPermille ) {
                lastPermille = permille;
                progress( permille );
            }
        }
    }
    beforeWait = nullptr;

    auto broken = streamFailure( input );
    // A live capture that broke off keeps what was captured, once there is
    // a packet to show.
    if ( broken && ( !live || stats.packets == 0 ) ) {
        return std::move( *broken );
    }
    if ( !output.flush() ) {
        return writeFailed();
    }
    output.close();
    if ( live ) {
        if ( liveInput->failed() || !raw.flush() ) {
            return rawFailed();
        }
        raw.close();
    }

    ConversionResult result;
    if ( broken ) {
        result = std::move( *broken );
    }
    else {
        result.status = ConversionResult::Status::Converted;
    }
    result.outputPath = QFileInfo( output.fileName() ).absoluteFilePath();
    if ( live ) {
        result.rawPath = QFileInfo( raw.fileName() ).absoluteFilePath();
    }
    result.summary = summarise( std::move( stats ), tracker, reader, options.maxStreams );
    index->setCaptureFile( live ? result.rawPath : inputPath );
    result.index = std::move( index );
    outputDir.setAutoRemove( false );
    return applyCancelRequest( std::move( result ), cancel );
}

/// @p convert's result, or Failed for whatever it throws.
template <typename Convert>
ConversionResult failedOnException( Convert&& convert )
{
    try {
        return convert();
    } catch ( const std::bad_alloc& ) {
        return failed( QStringLiteral( "Not enough memory to read the capture" ) );
    } catch ( const std::exception& e ) {
        return failed( QString::fromUtf8( e.what() ) );
    } catch ( ... ) {
        return failed( QStringLiteral( "Unknown error" ) );
    }
}

} // namespace

ConversionResult convertPcap( const QString& inputPath, const QString& outputRoot,
                              const std::atomic_bool* cancel,
                              const std::function<void( int )>& progress,
                              const ConversionOptions& options )
{
    return failedOnException( [ & ] {
        QFile input;
        QString inputError;
        if ( !openRegularFile( inputPath, input, inputError ) ) {
            return failed( inputError );
        }
        FileSource file( input );
        const auto size = static_cast<uint64_t>( std::max<qint64>( input.size(), 1 ) );
        return convertOrThrow( file, inputPath, QFileInfo( inputPath ).completeBaseName(), size,
                               outputRoot, cancel, progress, options, nullptr );
    } );
}

ConversionResult convertStream( ByteSource& source, const QString& name, const QString& outputRoot,
                                const std::atomic_bool* cancel, const ConversionOptions& options,
                                const LiveObserver& live )
{
    return failedOnException( [ & ] {
        return convertOrThrow( source, {}, name, 0, outputRoot, cancel, {}, options, &live );
    } );
}

bool CaptureSummary::operator==( const CaptureSummary& other ) const
{
    auto fields = []( const CaptureSummary& s ) {
        return std::tie( s.packets, s.bytes, s.durationSeconds, s.firstTimeUtc, s.lastTimeUtc,
                         s.linkTypeNames, s.protocolPackets, s.protocolBytes, s.endpointPackets,
                         s.tunnelEndpointPackets, s.tcpMarkers, s.cutPackets, s.endsInsideRecord,
                         s.streamCap, s.otherEndpointPackets );
    };
    return fields( *this ) == fields( other );
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
