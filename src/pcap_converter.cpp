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
#include "gzip_source.h"
#include "host_names.h"
#include "media_expectations.h"
#include "packet_formatter.h"
#include "payload_describer.h"
#include "pcapng_reader.h"
#include "raw_capture.h"
#include "someip.h"
#include "stream_labels.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"
#include "tcp_reassembly.h"
#include "tempdirs.h"
#include "tls_decryption.h"
#include "tls_key_log.h"

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
 *
 * With a deadline (expired), a wait for the stream is a wait in slices that
 * ends at the deadline though nothing comes: the input then reads as ended,
 * as a stopped stream does.  Only a wait: the rest of a record that has come
 * is read.
 */
class LiveInput : public ByteSource {
public:
    LiveInput( ByteSource& stream, std::function<void()> beforeWait, std::function<bool()> expired )
        : stream_( stream )
        , beforeWait_( std::move( beforeWait ) )
        , expired_( std::move( expired ) )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        if ( n > 0 && !ready() ) {
            beforeWait_();
            while ( expired_ && !ready() ) {
                std::this_thread::sleep_for( kDeadlineSlice );
            }
        }
        if ( timedOut_ ) {
            return 0;
        }
        const auto got = stream_.read( dst, n );
        bytesRead_ += got;
        keep( dst, got );
        return got;
    }

    // skip() reads, so what is skipped is kept too.

    bool ready() override
    {
        if ( timedOut_ || stream_.ready() ) {
            return true;
        }
        timedOut_ = expired_ && expired_();
        return timedOut_;
    }

    /// Write the bytes read so far, and from now on every byte read, to
    /// @p raw.  False if they cannot be written.
    bool attach( RawCapture& raw )
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

    /// Whether the input ended at its deadline.
    bool timedOut() const
    {
        return timedOut_;
    }

private:
    /// How often a wait with a deadline looks at the clock.
    static constexpr std::chrono::milliseconds kDeadlineSlice{ 10 };

    void keep( const uint8_t* data, size_t n )
    {
        if ( n == 0 ) {
            return;
        }
        if ( !raw_ ) {
            pending_.insert( pending_.end(), data, data + n );
        }
        else if ( !raw_->write( data, n ) ) {
            failed_ = true;
        }
    }

    ByteSource& stream_;
    std::function<void()> beforeWait_;
    std::function<bool()> expired_;
    std::vector<uint8_t> pending_;
    RawCapture* raw_ = nullptr;
    bool failed_ = false;
    bool timedOut_ = false;
    uint64_t bytesRead_ = 0;
};

/// The summary of a converted capture, from what was collected on the way.
CaptureSummary summarise( CaptureStats&& stats, const StreamTracker& tracker,
                          const StreamLabels& labels, const ConversationStats& conversations,
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
    // Rows of streams without a packet since the last summary are shared with it.
    summary.conversations
        = conversations.rows( tracker, labels, stats.firstTimeSec, stats.firstTimeNsec );
    summary.otherStreamPackets = conversations.otherPackets();
    summary.otherStreamBytes = conversations.otherBytes();
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
/// collected so far: the conversion goes on with @p stats and
/// @p conversations as they are.
CaptureSummary summariseSoFar( const CaptureStats& stats, const StreamTracker& tracker,
                               const StreamLabels& labels, const ConversationStats& conversations,
                               const CaptureReader& reader, size_t maxStreams )
{
    return summarise( CaptureStats( stats ), tracker, labels, conversations, reader, maxStreams );
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

/// Failed with @p error, the reader's: for a stream "Not a capture: …" with
/// what its writer said (a capture program's stderr), which is where a
/// program that writes text instead of a capture says why.
ConversionResult notACapture( ByteSource& input, const std::string& error )
{
    auto* stream = dynamic_cast<StreamSource*>( &input );
    if ( !stream ) {
        return failed( QString::fromStdString( error ) );
    }
    auto message = QStringLiteral( "Not a capture: %1" ).arg( QString::fromStdString( error ) );
    if ( const auto said = stream->writerSaid(); !said.empty() ) {
        message += QLatin1Char( '\n' ) + QString::fromStdString( said );
    }
    return failed( message );
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
 * throws, the caller turns into Failed.  @p file is the capture file
 * @p input reads, which the CaptureIndex points into and whose size and
 * consumed bytes give the progress; null for a stream, whose size is
 * unknown and which reports none.  With @p live, the input is a stream
 * converted live (convertStream()), and the index points into its raw
 * capture, stopped by @p limits as measured by @p clock.
 *
 * Every packet goes through the same steps for a file and a stream: the
 * Parser's record (its preview limited), the stream it belongs to, its TCP
 * analysis, its payload described in the stream, reassembled and, with a key
 * log, decrypted, the media an SDP announced, its stream labels, the
 * conversations' and the summary's counts, its line, the names its DNS
 * answers give (with host names shown), and its place in the CaptureIndex.
 */
ConversionResult convertOrThrow( ByteSource& input, CaptureFile* file, const QString& inputPath,
                                 const QString& name, const QString& outputRoot,
                                 const std::atomic_bool* cancel,
                                 const std::function<void( int )>& progress,
                                 const ConversionOptions& options, const LiveObserver* live,
                                 const LiveLimits& limits = {}, const LiveClock& clock = {} )
{
    // How SOME/IP is read, for the Payload Describer on this thread.
    SomeIpConfig someIp;
    someIp.ports = options.someIpPorts;
    if ( !options.someIpNamesFile.isEmpty() ) {
        someIp.names = loadSomeIpNames( QFile::encodeName( options.someIpNamesFile ).toStdString() )
                           .value_or( SomeIpNames{} );
    }
    const SomeIpScope someIpScope( someIp );

    const auto started = Clock::now();
    // The limits' durations, by the clock they are measured with.
    auto clockNow = [ &clock ] { return clock ? clock() : Clock::now(); };
    const auto limitsStarted = clockNow();
    auto fileStarted = limitsStarted; ///< When the ring buffer's file was started.
    StopCondition stoppedBy = StopCondition::None;

    // What to do before a wait for the stream, once there is output.
    std::function<void()> beforeWait;
    std::optional<LiveInput> liveInput;
    if ( live ) {
        std::function<bool()> expired;
        if ( limits.duration.count() > 0 ) {
            expired = [ & ] { return clockNow() - limitsStarted >= limits.duration; };
        }
        liveInput.emplace(
            input,
            [ &beforeWait ] {
                if ( beforeWait ) {
                    beforeWait();
                }
            },
            std::move( expired ) );
    }

    HeadSource source( liveInput ? static_cast<ByteSource&>( *liveInput ) : input );
    const auto capture = makeCaptureReader( source ); // pcap or pcapng, by the first block
    CaptureReader& reader = *capture;                 // the rest sees the capture through the seam
    GzipSource* gzip = file ? file->gzip() : nullptr;
    if ( !reader.open() ) {
        // A stream stopped before its header came was not read: it did not
        // fail, and a cancel request still wins.  Nor did one that came to
        // its duration.
        auto result = stoppedBeforeHeader( input );
        if ( !result && liveInput && liveInput->timedOut() ) {
            result.emplace();
            result->status = ConversionResult::Status::Stopped;
            result->stoppedBy = StopCondition::Duration;
        }
        if ( !result ) {
            result = streamFailure( input );
        }
        if ( !result ) {
            result = notACapture( input, reader.error() );
        }
        if ( gzip && gzip->cutOff() ) {
            result = failed( QStringLiteral( "Cannot read the gzip-compressed capture: %1" )
                                 .arg( QString::fromStdString( gzip->error() ) ) );
        }
        return applyCancelRequest( std::move( *result ), cancel );
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
    // A live capture's bytes, as they were read, next to its text: one
    // file, or a ring buffer's.
    std::optional<RawCapture> raw;
    auto rawFailed = [ &raw ] {
        return failed( QStringLiteral( "Cannot write the raw capture: %1" ).arg( raw->error() ) );
    };
    if ( live ) {
        const bool pcapng = dynamic_cast<const PcapngReader*>( &reader ) != nullptr;
        raw.emplace( QDir( outputDir.path() ), baseName,
                     pcapng ? CaptureFormat::Pcapng : CaptureFormat::Pcap,
                     limits.ringBuffer() ? limits.ringFiles : 0 );
        if ( !raw->open() || !liveInput->attach( *raw ) ) {
            return rawFailed();
        }
    }
    // The text of a raw file is named after it: <name>.log, or a ring
    // buffer's <name>_00001_<time>.log, one per file.
    auto textPath = [ & ] {
        return outputDir.filePath( ( raw ? QFileInfo( raw->path() ).completeBaseName() : baseName )
                                   + QStringLiteral( ".log" ) );
    };

    QFile output( textPath() );
    auto writeFailed = [ &output ] {
        return failed(
            QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
    };
    // Never write into an existing file or through a link planted in its place.
    auto openText = [ &output ] {
        if ( !output.open( QIODevice::WriteOnly | QIODevice::NewOnly | QIODevice::Text ) ) {
            return false;
        }
        output.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
        return true;
    };
    if ( !openText() ) {
        return writeFailed();
    }
    auto writeLine = [ &output ]( const std::string& line ) {
        return output.write( line.data(), static_cast<qint64>( line.size() ) )
                   == static_cast<qint64>( line.size() )
               && output.write( "\n", 1 ) == 1;
    };

    CaptureStats stats;
    stats.maxEndpoints = options.maxEndpoints;
    StreamTracker tracker( options.maxStreams );
    StreamLabels labels;
    ConversationStats conversations;
    MediaExpectations media;
    TcpReassembly reassembly( options.reassemblyMegabytes * kMegabyte );
    // TLS sessions are decrypted only with a key log, read now and as it
    // grows; its secrets go with it when the conversion ends.
    std::optional<tls::KeyLogFile> keyLog;
    std::optional<TlsDecryption> decryption;
    if ( !options.keyLogPath.isEmpty() ) {
        keyLog.emplace( options.keyLogPath );
        decryption.emplace(
            [ &keyLog ]( const uint8_t* clientRandom ) { return keyLog->find( clientRandom ); },
            [ &keyLog ] { return keyLog->bytesRead(); } );
    }
    // The names DNS answers gave addresses, only when they are shown.
    std::optional<HostNames> names;
    if ( options.layout.hostNames ) {
        names.emplace( options.maxHostNames );
    }
    // The summary with what the decryption did and the endpoints' names.
    auto withDecryption = [ & ]( CaptureSummary summary ) {
        if ( decryption ) {
            summary.tlsSessionsDecrypted = decryption->sessionsDecrypted();
            summary.keyLogError = keyLog->error().toStdString();
        }
        if ( names ) {
            for ( const auto& [ address, packets ] : summary.endpointPackets ) {
                if ( const auto* name = names->find( address ) ) {
                    summary.endpointNames.emplace( address, *name );
                }
            }
        }
        return summary;
    };
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
        if ( !output.flush() || ( live && !raw->flush() ) ) {
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
        snapshot.summary = withDecryption(
            summariseSoFar( stats, tracker, labels, conversations, reader, options.maxStreams ) );
        snapshot.elapsed
            = std::chrono::duration_cast<std::chrono::milliseconds>( lastSnapshot - started );
        snapshot.rawBytes = liveInput->bytesRead();
        snapshot.rawFile = raw->fileNumber();
        // The packets so far, for the Packet Panel: their bytes are in the
        // raw file once it is flushed, which goes on growing behind them.
        flush();
        auto soFar = std::make_shared<CaptureIndex>( *index );
        soFar->setCaptureParts( raw->parts(), CaptureIndex::Growth::Growing );
        snapshot.index = std::move( soFar );
        live->snapshot( std::move( snapshot ) );
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
    auto reportProgress = [ & ] {
        if ( !progress || !file ) {
            return;
        }
        // A gzip-compressed file's progress is in compressed bytes.
        const auto size = std::max<uint64_t>( file->size(), 1 );
        const auto permille
            = static_cast<int>( std::min<uint64_t>( file->consumed() * 1000 / size, 1000 ) );
        if ( permille != lastPermille ) {
            lastPermille = permille;
            progress( permille );
        }
    };
    bool firstPacket = true;
    // The text file written has no packet line yet: the next one opens it.
    bool firstOfText = true;
    // A ring buffer's file ends after the packet that filled it, or the last
    // one before its duration was over, when the next packet comes: where
    // that packet's record ends, and the headers a file needs there.
    bool fileFull = false;
    uint64_t fileEnd = 0;
    CaptureHeaders fileHeaders;
    // Start the next file, and the text of it; why not, if they cannot be.
    // The text of a file is never rewritten: it stays as it is, also once
    // its raw file is deleted, for its tab.
    auto rotate = [ & ]() -> std::optional<ConversionResult> {
        if ( !output.flush() ) {
            return writeFailed();
        }
        output.close();
        if ( !raw->rotate( fileEnd, reader.packetsRead() - 1, fileHeaders ) ) {
            return rawFailed();
        }
        fileFull = false;
        fileStarted = clockNow();
        output.setFileName( textPath() );
        if ( !openText() || !writeLine( formatter.header() ) ) {
            return writeFailed();
        }
        firstOfText = true;
        // Not the checkpoints of the files deleted: a capture that runs for
        // days keeps those of its files only.
        index->setCaptureParts( raw->parts(), CaptureIndex::Growth::Growing );
        // The Packet Panel's index follows the files at once.
        sendSnapshot();
        if ( flushFailed ) {
            return writeFailed();
        }
        return std::nullopt;
    };

    bool numbersUsedUp = false;
    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        if ( cancel && cancel->load() ) {
            ConversionResult result;
            result.status = ConversionResult::Status::Cancelled;
            return result;
        }
        if ( limits.ringBuffer() && !firstPacket
             && ( fileFull
                  || ( limits.fileDuration.count() > 0
                       && clockNow() - fileStarted >= limits.fileDuration ) ) ) {
            if ( auto failure = rotate() ) {
                return std::move( *failure );
            }
        }
        limitPreview( pkt, options.preview ? options.previewChars : 0 );
        if ( options.tcpTimestamps ) {
            showTcpTimestamps( pkt );
        }
        const auto stream = tracker.track( pkt );
        stats.addTcpAnalysis( analyseTcp( pkt, stream ) );
        describeInStream( pkt, stream );
        const auto payload = reader.payloadOf( pkt );
        const auto messages = reassembly.apply( pkt, stream, payload );
        rememberInStream( pkt, stream ); // after the reassembly, which completes NEWKEYS
        if ( decryption ) {
            decryption->apply( pkt, stream, messages );
        }
        media.apply( pkt ); // after the reassembly, which completes SDP bodies
        labels.apply( pkt, stream );
        conversations.add( pkt, stream );
        stats.add( pkt );
        if ( !writeLine( formatter.format( pkt, stream.id, names ? &*names : nullptr ) ) ) {
            return writeFailed();
        }
        // Behind its own line: a name labels the packets after its answer.
        if ( names ) {
            names->learn( pkt, payload, messages.bytes );
        }
        if ( pkt.transport ) {
            index->noteStream( *pkt.transport, stream.id, reader.packetsRead() );
        }
        index->note( reader );
        if ( live ) {
            snapshotDue = true;
            const auto now = Clock::now();
            if ( firstOfText ) {
                // The header and this line are in the file before it is opened.
                firstOfText = false;
                flush();
                if ( !flushFailed && live->firstPacket ) {
                    live->firstPacket( QFileInfo( output.fileName() ).absoluteFilePath(),
                                       QFileInfo( raw->path() ).absoluteFilePath() );
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

            // The first stop condition reached ends the capture with this packet.
            if ( limits.packets > 0 && stats.packets >= limits.packets ) {
                stoppedBy = StopCondition::Packets;
            }
            else if ( limits.bytes > 0 && liveInput->bytesRead() >= limits.bytes ) {
                stoppedBy = StopCondition::Bytes;
            }
            else if ( limits.duration.count() > 0
                      && clockNow() - limitsStarted >= limits.duration ) {
                stoppedBy = StopCondition::Duration;
            }
            if ( stoppedBy != StopCondition::None ) {
                break;
            }

            // A ring buffer's file that this packet filled ends with it.
            if ( limits.ringBuffer() ) {
                fileFull = limits.fileBytes > 0 && raw->fileSize() >= limits.fileBytes;
                fileEnd = reader.recordOffset() + reader.recordLength();
                fileHeaders = reader.headers();
            }
        }
        firstPacket = false;
        reportProgress();

        // No packet is numbered past the last number, where a 32-bit count
        // would wrap: a live capture stops with it, as at a stop condition;
        // a file is converted that far, its summary saying it had more.
        if ( reader.packetsRead() >= options.lastPacketNumber ) {
            if ( live ) {
                numbersUsedUp = true;
                stoppedBy = StopCondition::PacketNumbers;
            }
            else {
                PacketRecord rest;
                numbersUsedUp = reader.next( rest );
            }
            break;
        }
    }
    beforeWait = nullptr;
    reportProgress(); // a gzip stream's end lies behind its last packet
    if ( liveInput && liveInput->timedOut() ) {
        stoppedBy = StopCondition::Duration;
    }

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
    if ( live && ( liveInput->failed() || !raw->close() ) ) {
        return rawFailed();
    }

    ConversionResult result;
    if ( broken ) {
        result = std::move( *broken );
    }
    else {
        result.status = ConversionResult::Status::Converted;
    }
    result.outputPath = QFileInfo( output.fileName() ).absoluteFilePath();
    result.summary = withDecryption( summarise( std::move( stats ), tracker, labels, conversations,
                                                reader, options.maxStreams ) );
    result.summary.packetNumbersUsedUp = numbersUsedUp;
    if ( gzip && gzip->cutOff() ) {
        // The capture ends where its gzip stream does: as one cut off.
        result.summary.endsInsideRecord = true;
        result.summary.compressionProblem = gzip->error();
    }
    if ( live ) {
        result.rawPath = QFileInfo( raw->path() ).absoluteFilePath();
        result.stoppedBy = stoppedBy;
        index->setCaptureParts( raw->parts() );
    }
    else {
        index->setCaptureFile( inputPath );
    }
    if ( gzip ) {
        index->setGzipAccessPoints( gzip->accessPoints() );
    }
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
        CaptureFile file;
        QString inputError;
        if ( !file.open( inputPath, inputError ) ) {
            return failed( inputError );
        }
        if ( auto* gzip = file.gzip() ) {
            // For the Packet Panel and Export Packets to reach any packet.
            gzip->keepAccessPoints( options.gzipAccessSpan );
        }
        return convertOrThrow( file.source(), &file, inputPath, captureBaseName( inputPath ),
                               outputRoot, cancel, progress, options, nullptr );
    } );
}

ConversionResult convertStream( ByteSource& source, const QString& name, const QString& outputRoot,
                                const std::atomic_bool* cancel, const ConversionOptions& options,
                                const LiveObserver& live, const LiveLimits& limits,
                                const LiveClock& clock )
{
    return failedOnException( [ & ] {
        return convertOrThrow( source, nullptr, {}, name, outputRoot, cancel, {}, options, &live,
                               limits, clock );
    } );
}

bool CaptureSummary::operator==( const CaptureSummary& other ) const
{
    auto fields = []( const CaptureSummary& s ) {
        return std::tie( s.packets, s.bytes, s.durationSeconds, s.firstTimeUtc, s.lastTimeUtc,
                         s.linkTypeNames, s.protocolPackets, s.protocolBytes, s.endpointPackets,
                         s.tunnelEndpointPackets, s.tcpMarkers, s.cutPackets, s.endsInsideRecord,
                         s.compressionProblem, s.packetNumbersUsedUp, s.streamCap,
                         s.otherEndpointPackets, s.tlsSessionsDecrypted, s.keyLogError,
                         s.endpointNames );
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
