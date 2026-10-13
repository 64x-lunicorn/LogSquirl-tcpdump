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
 * @file live_output.cpp
 * @brief Implementation of the Live Output's stop, cadence and ring buffer
 *        decisions, and of a live capture's files on disk.
 */

#include "live_output.h"

#include <QFileInfo>

#include <utility>

namespace tcpdump {

DiskLiveFiles::DiskLiveFiles( const QDir& dir, const QString& baseName, CaptureFormat format,
                              uint32_t ringFiles, std::string header )
    : dir_( dir )
    , raw_( dir, baseName, format, ringFiles )
    , header_( std::move( header ) )
{
}

bool DiskLiveFiles::open()
{
    if ( !raw_.open() ) {
        return rawFailed();
    }
    return openText();
}

bool DiskLiveFiles::openText()
{
    // The text of a raw file is named after it: <name>.log, or a ring
    // buffer's <name>_00001_<time>.log.
    text_.setFileName(
        dir_.filePath( QFileInfo( raw_.path() ).completeBaseName() + QStringLiteral( ".log" ) ) );
    // Never write into an existing file or through a link planted in its place.
    if ( !text_.open( QIODevice::WriteOnly | QIODevice::NewOnly | QIODevice::Text ) ) {
        return textFailed();
    }
    text_.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner );
    const auto size = static_cast<qint64>( header_.size() );
    if ( text_.write( header_.data(), size ) != size || text_.write( "\n", 1 ) != 1 ) {
        return textFailed();
    }
    return true;
}

bool DiskLiveFiles::writeRaw( const uint8_t* data, size_t n )
{
    return raw_.write( data, n ) || rawFailed();
}

bool DiskLiveFiles::flush()
{
    if ( !text_.flush() ) {
        return textFailed();
    }
    return raw_.flush() || rawFailed();
}

bool DiskLiveFiles::startNext( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers )
{
    if ( !text_.flush() ) {
        return textFailed();
    }
    text_.close();
    if ( !raw_.rotate( cut, packetsBefore, headers ) ) {
        return rawFailed();
    }
    return openText();
}

bool DiskLiveFiles::close()
{
    if ( !text_.flush() ) {
        return textFailed();
    }
    text_.close();
    return raw_.close() || rawFailed();
}

bool DiskLiveFiles::textFailed()
{
    error_ = textWriteError( text_ );
    return false;
}

bool DiskLiveFiles::rawFailed()
{
    error_ = QStringLiteral( "Cannot write the raw capture: %1" ).arg( raw_.error() );
    return false;
}

LiveOutput::LiveOutput( const LiveLimits& limits, LiveClock clock, uint32_t lastPacketNumber )
    : limits_( limits )
    , clock_( std::move( clock ) )
    , lastPacketNumber_( lastPacketNumber )
    , started_( now() )
    , lastFlush_( started_ )
    , lastSnapshot_( started_ )
    , fileStarted_( started_ )
{
}

void LiveOutput::open( std::unique_ptr<LiveFiles> files, const CaptureReader& reader )
{
    files_ = std::move( files );
    reader_ = &reader;
}

std::optional<LiveStep> LiveOutput::beforePacket()
{
    if ( !fileHasPacket_ || !limits_.ringBuffer() ) {
        return LiveStep{};
    }
    const auto at = now();
    if ( !fileOver( at ) ) {
        return LiveStep{};
    }
    if ( !files_->startNext( fileEnd_, packetsInFiles_, fileHeaders_ ) ) {
        return std::nullopt;
    }
    fileStarted_ = at;
    fileHasPacket_ = false;
    fileFull_ = false;
    // The Packet Panel's index follows the files at once, and the next
    // packet opens the new text.
    firstOfText_ = true;
    LiveStep step;
    snapshotAt( step, at );
    lastFlush_ = at;
    return step;
}

bool LiveOutput::fileOver( std::chrono::steady_clock::time_point now ) const
{
    return fileFull_
           || ( limits_.fileDuration.count() > 0 && now - fileStarted_ >= limits_.fileDuration );
}

LiveStep LiveOutput::packet( uint64_t packets, uint64_t bytesRead )
{
    if ( reader_ && limits_.ringBuffer() ) {
        // The file ends after this packet if it filled it, or later at the
        // next packet once it is old: where its record ends, and the
        // headers a file starting there needs, as they are now.
        fileHasPacket_ = true;
        fileFull_ = limits_.fileBytes > 0 && files_->rawFileSize() >= limits_.fileBytes;
        fileEnd_ = reader_->recordOffset() + reader_->recordLength();
        packetsInFiles_ = reader_->packetsRead();
        fileHeaders_ = reader_->headers();
    }

    const auto at = now();
    snapshotPending_ = true;
    LiveStep step;
    if ( firstOfText_ ) {
        // The header and this line are in the file before it is opened.
        firstOfText_ = false;
        step.flush = true;
        step.firstOfText = true;
        snapshotAt( step, at );
    }
    else {
        step.flush = at - lastFlush_ >= kLiveFlushInterval;
        if ( at - lastSnapshot_ >= kLiveSnapshotInterval ) {
            snapshotAt( step, at );
        }
    }
    if ( step.flush ) {
        lastFlush_ = at;
    }
    step.stop = stopAt( packets, bytesRead, at );
    return step;
}

LiveStep LiveOutput::beforeWait()
{
    const auto at = now();
    LiveStep step;
    step.flush = true;
    lastFlush_ = at;
    if ( snapshotPending_ && at - lastSnapshot_ >= kLiveSnapshotInterval ) {
        snapshotAt( step, at );
    }
    return step;
}

bool LiveOutput::snapshotWaits() const
{
    return snapshotPending_ && now() - lastSnapshot_ < kLiveSnapshotInterval;
}

bool LiveOutput::durationOver() const
{
    return durationOverAt( now() );
}

bool LiveOutput::durationOverAt( std::chrono::steady_clock::time_point now ) const
{
    return limits_.duration.count() > 0 && now - started_ >= limits_.duration;
}

std::chrono::steady_clock::time_point LiveOutput::now() const
{
    return clock_ ? clock_() : std::chrono::steady_clock::now();
}

std::chrono::milliseconds LiveOutput::elapsed() const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>( lastSnapshot_ - started_ );
}

StopCondition LiveOutput::stopAt( uint64_t packets, uint64_t bytesRead,
                                  std::chrono::steady_clock::time_point now ) const
{
    if ( limits_.packets > 0 && packets >= limits_.packets ) {
        return StopCondition::Packets;
    }
    if ( limits_.bytes > 0 && bytesRead >= limits_.bytes ) {
        return StopCondition::Bytes;
    }
    if ( durationOverAt( now ) ) {
        return StopCondition::Duration;
    }
    // No packet is numbered past the last number, where a 32-bit count
    // would wrap: the capture stops with it, as at a stop condition.
    if ( packets >= lastPacketNumber_ ) {
        return StopCondition::PacketNumbers;
    }
    return StopCondition::None;
}

void LiveOutput::snapshotAt( LiveStep& step, std::chrono::steady_clock::time_point now )
{
    // A snapshot's index points into the raw file, flushed first.
    step.flush = true;
    step.snapshot = true;
    lastSnapshot_ = now;
    snapshotPending_ = false;
}

} // namespace tcpdump
