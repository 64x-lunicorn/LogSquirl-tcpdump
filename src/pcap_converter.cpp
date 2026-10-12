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
#include "someip.h"
#include "tempdirs.h"
#include "tls_key_log.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <exception>
#include <memory>
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

    /// Write the bytes read so far, and from now on every byte read, to the
    /// raw file of @p files.  False if they cannot be written.
    bool attach( LiveFiles& files )
    {
        files_ = &files;
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
        if ( !files_ ) {
            pending_.insert( pending_.end(), data, data + n );
        }
        else if ( !files_->writeRaw( data, n ) ) {
            failed_ = true;
        }
    }

    ByteSource& stream_;
    std::function<void()> beforeWait_;
    std::function<bool()> expired_;
    std::vector<uint8_t> pending_;
    LiveFiles* files_ = nullptr;
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
 * and the line into the text.  Live, the Live Output, which owns the text
 * and the raw capture, first starts a ring buffer's next file if one is
 * due, then says whether to flush, open the text or send a snapshot, and
 * whether the capture stops.
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

    // The output directory outlives the files in it, a Live Output's too.
    std::optional<QTemporaryDir> outputDir;
    // Live: when the capture stops, when what was written is flushed and a
    // snapshot goes out, and when a ring buffer's next file starts, by the
    // one clock; it owns the files once the capture's format is known.
    std::optional<LiveOutput> liveOutput;
    StopCondition stoppedBy = StopCondition::None;

    // What to do before a wait for the stream, once there is output.
    std::function<void()> beforeWait;
    std::optional<LiveInput> liveInput;
    if ( live ) {
        liveOutput.emplace( limits, clock, options.lastPacketNumber );
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
    outputDir.emplace( tempDirTemplate( outputRoot ) );
    if ( !outputDir->isValid() ) {
        return failed( QStringLiteral( "Cannot create a temporary directory: %1" )
                           .arg( outputDir->errorString() ) );
    }
    auto baseName = name;
    if ( baseName.isEmpty() ) {
        baseName = QStringLiteral( "capture" );
    }

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

    // The text the lines go to: a file's <name>.log, or a live capture's,
    // which its Live Output owns with the raw capture next to it, each text
    // starting with the column header.
    QFile output;
    QIODevice* text = &output;
    LiveFiles* files = nullptr;
    auto writeFailed = [ &text ] {
        return failed(
            QStringLiteral( "Cannot write the output file: %1" ).arg( text->errorString() ) );
    };
    auto liveFailed = [ &files ] { return failed( files->error() ); };
    auto writeLine = [ &text ]( const std::string& line ) {
        return text->write( line.data(), static_cast<qint64>( line.size() ) )
                   == static_cast<qint64>( line.size() )
               && text->write( "\n", 1 ) == 1;
    };
    if ( live ) {
        const bool pcapng = dynamic_cast<const PcapngReader*>( &reader ) != nullptr;
        auto disk = std::make_unique<DiskLiveFiles>(
            QDir( outputDir->path() ), baseName,
            pcapng ? CaptureFormat::Pcapng : CaptureFormat::Pcap,
            limits.ringBuffer() ? limits.ringFiles : 0, recorder.header() );
        const bool opened = disk->open();
        liveOutput->open( std::move( disk ), reader );
        files = &liveOutput->files();
        if ( !opened || !liveInput->attach( *files ) ) {
            return liveFailed();
        }
        text = &files->text();
    }
    else {
        output.setFileName( outputDir->filePath( baseName + QStringLiteral( ".log" ) ) );
        // Never write into an existing file or through a link planted in its place.
        if ( !output.open( QIODevice::WriteOnly | QIODevice::NewOnly | QIODevice::Text ) ) {
            return writeFailed();
        }
        output.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
        if ( !writeLine( recorder.header() ) ) {
            return writeFailed();
        }
    }

    const auto& index = recorder.index();
    // Live: what was written is made readable, a text opened and snapshots
    // sent when the Live Output says so (act()).
    bool flushFailed = false;
    auto sendSnapshot = [ & ] {
        // The index follows the raw files: not the checkpoints of the files
        // a ring buffer deleted, so that a capture that runs for days keeps
        // those of its files only.
        index->setCaptureParts( files->parts(), CaptureIndex::Growth::Growing );
        if ( !live->snapshot ) {
            return;
        }
        LiveSnapshot snapshot;
        snapshot.summary = recorder.summary();
        snapshot.elapsed = liveOutput->elapsed();
        snapshot.rawBytes = liveInput->bytesRead();
        snapshot.rawFile = files->fileNumber();
        // The packets so far, for the Packet Panel: their bytes are in the
        // raw files, flushed first, the last of which goes on growing
        // behind them.
        snapshot.index = std::make_shared<CaptureIndex>( *index );
        live->snapshot( std::move( snapshot ) );
    };
    auto act = [ & ]( const LiveStep& step ) {
        if ( step.flush && !files->flush() ) {
            flushFailed = true;
        }
        if ( step.firstOfText && !flushFailed && live->firstPacket ) {
            live->firstPacket( QFileInfo( files->textPath() ).absoluteFilePath(),
                               QFileInfo( files->rawPath() ).absoluteFilePath() );
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
    bool numbersUsedUp = false;
    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        if ( cancel && cancel->load() ) {
            ConversionResult result;
            result.status = ConversionResult::Status::Cancelled;
            return result;
        }
        if ( live ) {
            // A ring buffer's file that is full or old ends before this
            // packet, which then opens the next text.
            const auto started = liveOutput->beforePacket();
            if ( !started ) {
                return liveFailed();
            }
            act( *started );
            if ( flushFailed ) {
                return liveFailed();
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
            if ( flushFailed || liveInput->failed() ) {
                return liveFailed();
            }

            // The first stop condition reached ends the capture with this
            // packet, as does the last packet number.
            if ( step.stop != StopCondition::None ) {
                stoppedBy = step.stop;
                numbersUsedUp = step.stop == StopCondition::PacketNumbers;
                break;
            }
        }
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
    if ( live ) {
        if ( liveInput->failed() || !files->close() ) {
            return liveFailed();
        }
    }
    else {
        if ( !output.flush() ) {
            return writeFailed();
        }
        output.close();
    }

    ConversionResult result;
    if ( broken ) {
        result = std::move( *broken );
    }
    else {
        result.status = ConversionResult::Status::Converted;
    }
    result.outputPath
        = QFileInfo( live ? files->textPath() : output.fileName() ).absoluteFilePath();
    result.summary = recorder.finalSummary();
    result.summary.packetNumbersUsedUp = numbersUsedUp;
    if ( gzip && gzip->cutOff() ) {
        // The capture ends where its gzip stream does: as one cut off.
        result.summary.endsInsideRecord = true;
        result.summary.compressionProblem = gzip->error();
    }
    if ( live ) {
        result.rawPath = QFileInfo( files->rawPath() ).absoluteFilePath();
        result.stoppedBy = stoppedBy;
        index->setCaptureParts( files->parts() );
    }
    else {
        index->setCaptureFile( inputPath );
    }
    if ( gzip ) {
        index->setGzipAccessPoints( gzip->accessPoints() );
    }
    result.index = index;
    outputDir->setAutoRemove( false );
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
    removeOutput( result );
    ConversionResult cancelled;
    cancelled.status = ConversionResult::Status::Cancelled;
    return cancelled;
}

void removeOutput( const ConversionResult& result )
{
    if ( !result.outputPath.isEmpty() ) {
        QDir( QFileInfo( result.outputPath ).absolutePath() ).removeRecursively();
    }
}

} // namespace tcpdump
