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
#include "packet_pipeline.h"
#include "packet_recorder.h"
#include "pcapng_reader.h"
#include "raw_capture.h"
#include "someip.h"
#include "tempdirs.h"
#include "tls_key_log.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <exception>
#include <new>
#include <thread>

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
 * Parser's record through the Packet Pipeline, then the Packet Recorder,
 * which counts it, makes its line, learns its names and notes its place,
 * and the line into the text; live, the Live Output then says whether to
 * flush, open the text or send a snapshot, and whether the capture stops.
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

    // Live: when the capture stops, and when what was written is flushed
    // and a snapshot goes out, by the one clock.
    std::optional<LiveOutput> liveOutput;
    std::chrono::steady_clock::time_point fileStarted; ///< When the ring buffer's file was started.
    StopCondition stoppedBy = StopCondition::None;

    // What to do before a wait for the stream, once there is output.
    std::function<void()> beforeWait;
    std::optional<LiveInput> liveInput;
    if ( live ) {
        liveOutput.emplace( limits, clock, options.lastPacketNumber );
        fileStarted = liveOutput->now();
        std::function<bool()> expired;
        if ( limits.duration.count() > 0 ) {
            expired = [ &liveOutput ] { return liveOutput->durationOver(); };
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

    // TLS sessions are decrypted only with a key log, read now and as it
    // grows; its secrets go with it when the conversion ends.
    std::optional<tls::KeyLogFile> keyLog;
    PipelineOptions pipelineOptions;
    pipelineOptions.previewChars = options.preview ? options.previewChars : 0;
    pipelineOptions.tcpTimestamps = options.tcpTimestamps;
    pipelineOptions.maxStreams = options.maxStreams;
    pipelineOptions.reassemblyMemory = options.reassemblyMegabytes * kMegabyte;
    if ( !options.keyLogPath.isEmpty() ) {
        keyLog.emplace( options.keyLogPath );
        pipelineOptions.tlsKeys
            = [ &keyLog ]( const uint8_t* clientRandom ) { return keyLog->find( clientRandom ); };
        pipelineOptions.tlsKeyLogBytes = [ &keyLog ] { return keyLog->bytesRead(); };
    }
    PacketPipeline pipeline( pipelineOptions );
    RecorderOptions recorderOptions;
    recorderOptions.layout = options.layout;
    recorderOptions.maxEndpoints = options.maxEndpoints;
    recorderOptions.maxHostNames = options.maxHostNames;
    recorderOptions.checkpointInterval = options.checkpointInterval;
    recorderOptions.keyLog = keyLog ? &*keyLog : nullptr;
    PacketRecorder recorder( reader, pipeline, recorderOptions );
    if ( !writeLine( recorder.header() ) ) {
        return writeFailed();
    }

    const auto& index = recorder.index();
    // Live: what was written is made readable, a text opened and snapshots
    // sent when the Live Output says so (act()).
    bool flushFailed = false;
    auto flush = [ & ] {
        if ( !output.flush() || ( live && !raw->flush() ) ) {
            flushFailed = true;
        }
    };
    auto sendSnapshot = [ & ] {
        if ( !live->snapshot ) {
            return;
        }
        LiveSnapshot snapshot;
        snapshot.summary = recorder.summary();
        snapshot.elapsed = liveOutput->elapsed();
        snapshot.rawBytes = liveInput->bytesRead();
        snapshot.rawFile = raw->fileNumber();
        // The packets so far, for the Packet Panel: their bytes are in the
        // raw file, flushed first, which goes on growing behind them.
        auto soFar = std::make_shared<CaptureIndex>( *index );
        soFar->setCaptureParts( raw->parts(), CaptureIndex::Growth::Growing );
        snapshot.index = std::move( soFar );
        live->snapshot( std::move( snapshot ) );
    };
    auto act = [ & ]( const LiveStep& step ) {
        if ( step.flush ) {
            flush();
        }
        if ( step.firstOfText && !flushFailed && live->firstPacket ) {
            live->firstPacket( QFileInfo( output.fileName() ).absoluteFilePath(),
                               QFileInfo( raw->path() ).absoluteFilePath() );
        }
        if ( step.snapshot ) {
            sendSnapshot();
        }
    };
    if ( live ) {
        beforeWait = [ & ] {
            act( liveOutput->beforeWait() );
            if ( !live->snapshot || !liveOutput->snapshotWaits() ) {
                return;
            }
            // The packets of a burst would wait for the next packet to be
            // in a snapshot: while the stream has nothing new, wait for the
            // snapshot's turn instead.  ready() also turns on a stop.
            while ( !liveInput->ready() && liveOutput->snapshotWaits() ) {
                std::this_thread::sleep_for( std::chrono::milliseconds( 10 ) );
            }
            act( liveOutput->beforeWait() );
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
        fileStarted = liveOutput->now();
        output.setFileName( textPath() );
        if ( !openText() || !writeLine( recorder.header() ) ) {
            return writeFailed();
        }
        // Not the checkpoints of the files deleted: a capture that runs for
        // days keeps those of its files only.
        index->setCaptureParts( raw->parts(), CaptureIndex::Growth::Growing );
        // The Packet Panel's index follows the files at once, and the next
        // packet opens the new text.
        act( liveOutput->textStarted() );
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
                       && liveOutput->now() - fileStarted >= limits.fileDuration ) ) ) {
            if ( auto failure = rotate() ) {
                return std::move( *failure );
            }
        }
        const auto payload = reader.payloadOf( pkt );
        const auto outcome = pipeline.run( pkt, payload );
        if ( !writeLine( recorder.record( pkt, payload, outcome ) ) ) {
            return writeFailed();
        }
        if ( live ) {
            const auto step = liveOutput->packet( recorder.packets(), liveInput->bytesRead() );
            act( step );
            if ( flushFailed ) {
                return writeFailed();
            }
            if ( liveInput->failed() ) {
                return rawFailed();
            }

            // The first stop condition reached ends the capture with this
            // packet, as does the last packet number.
            if ( step.stop != StopCondition::None ) {
                stoppedBy = step.stop;
                numbersUsedUp = step.stop == StopCondition::PacketNumbers;
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
        // would wrap: a file is converted that far, its summary saying it
        // had more (a live capture's Live Output stops it there).
        if ( !live && reader.packetsRead() >= options.lastPacketNumber ) {
            PacketRecord rest;
            numbersUsedUp = reader.next( rest );
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
    if ( broken && ( !live || recorder.packets() == 0 ) ) {
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
    result.summary = recorder.finalSummary();
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
    result.index = index;
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
