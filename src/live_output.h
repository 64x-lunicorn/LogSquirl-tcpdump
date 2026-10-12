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
 * @file live_output.h
 * @brief Decides, packet by packet, when a live capture stops, when its
 *        output is flushed and its snapshots go out, and when a ring
 *        buffer's next file starts, on one clock; and owns its files.
 */

#pragma once

#include "capture_index.h"
#include "pcap_parser.h"
#include "raw_capture.h"

#include <QDir>
#include <QFile>
#include <QIODevice>
#include <QString>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

/// Which stop condition of a live capture (LiveLimits) ended it.
enum class StopCondition : uint8_t {
    None,     ///< None: Stop, or the stream ended.
    Duration, ///< It ran for LiveLimits::duration.
    Packets,  ///< It converted LiveLimits::packets packets.
    Bytes,    ///< It read LiveLimits::bytes bytes.
    /// It converted the packet of the last number the No. column has
    /// (kMaxPacketNumber); not a LiveLimits setting.
    PacketNumbers,
};

/// How often at least a live conversion makes its lines readable.
constexpr std::chrono::milliseconds kLiveFlushInterval{ 100 };
/// How often at most a live conversion hands out a LiveSnapshot.
constexpr std::chrono::milliseconds kLiveSnapshotInterval{ 1000 };

/**
 * When a live capture stops by itself, and whether its raw capture is a ring
 * buffer, as dumpcap's -a and -b say it (raw_capture.h).  0 is "none"
 * throughout: the defaults capture until Stop, into one file.
 *
 * The stop conditions are checked after each packet, so the packet that
 * reaches a count or a size is the last one; the duration is also checked
 * while the stream has nothing to read.  The first one reached ends the
 * capture as Stop does: Converted, with what was captured.
 *
 * A ring buffer starts a new file after the packet that filled the current
 * one, by size or duration, and keeps the newest ringFiles files.  Each file
 * has a text file of its own, named after it, which LiveObserver::firstPacket
 * hands out to be opened; a text is never rewritten, also once its raw file
 * is deleted.
 */
struct LiveLimits {
    std::chrono::seconds duration{ 0 };     ///< Stop after this long.
    uint64_t packets = 0;                   ///< Stop after this many packets.
    uint64_t bytes = 0;                     ///< Stop once this many bytes were read.
    uint32_t ringFiles = 0;                 ///< The ring buffer's files; 0: no ring buffer.
    uint64_t fileBytes = 0;                 ///< A new file once one is this big.
    std::chrono::seconds fileDuration{ 0 }; ///< A new file once one is this old.

    /// Whether the raw capture is a ring buffer: files kept, and a size or
    /// duration to start a new one at.
    bool ringBuffer() const
    {
        return ringFiles > 0 && ( fileBytes > 0 || fileDuration.count() > 0 );
    }

    bool operator==( const LiveLimits& other ) const
    {
        return duration == other.duration && packets == other.packets && bytes == other.bytes
               && ringFiles == other.ringFiles && fileBytes == other.fileBytes
               && fileDuration == other.fileDuration;
    }
    bool operator!=( const LiveLimits& other ) const
    {
        return !( *this == other );
    }
};

/// The clock a live conversion measures LiveLimits' durations and its flush
/// and snapshot cadence with; a test hands it a fake one.  Empty: the
/// steady clock.
using LiveClock = std::function<std::chrono::steady_clock::time_point()>;

/**
 * The files a live capture writes, which its Live Output owns: a text, and
 * the raw capture it was read from (raw_capture.h), one file each, or with
 * a ring buffer the newest raw files and a text per raw file, named after
 * it.  DiskLiveFiles writes them; a test hands the Live Output a fake.
 * Error messages are the user's: a call that fails leaves error() saying
 * which file and why.
 */
class LiveFiles {
public:
    virtual ~LiveFiles() = default;

    /// The text written, which the Converter appends the lines to.
    virtual QIODevice& text() = 0;

    /// Append @p n bytes of the capture, as they were read, to the raw file.
    virtual bool writeRaw( const uint8_t* data, size_t n ) = 0;

    /// Make the text and the raw file readable up to here.
    virtual bool flush() = 0;

    /// Bytes of the raw file written, the headers copied ahead included.
    virtual uint64_t rawFileSize() const = 0;

    /**
     * A ring buffer's: end the raw file at @p cut, where the record of the
     * capture's packet @p packetsBefore ends, and the text with it; start
     * the next raw file, what was read past the cut behind a copy of
     * @p headers (RawCapture::rotate()), and its text with the column
     * header.  The oldest raw files beyond the ring buffer's are deleted;
     * a text is never rewritten.
     */
    virtual bool startNext( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers )
        = 0;

    /// Flush and close the text and the raw file.
    virtual bool close() = 0;

    /// The raw files kept, oldest first; the last is the one written.
    virtual const std::vector<CapturePart>& parts() const = 0;

    /// The number of the raw file written, from 1.
    virtual uint32_t fileNumber() const = 0;

    /// The path of the text written.
    virtual QString textPath() const = 0;

    /// The path of the raw file written.
    virtual QString rawPath() const = 0;

    /// Why the last call failed, as the user is told.
    virtual QString error() const = 0;
};

/**
 * A live capture's files on disk, next to each other in one directory:
 * <name>.pcap (or .pcapng) and <name>.log, or a ring buffer's
 * <name>_00001_<time>.pcap and <name>_00001_<time>.log and on.  Each text
 * starts with the column header; never written into an existing file or
 * through a link planted in its place, and readable by the user only.
 */
class DiskLiveFiles : public LiveFiles {
public:
    /// The files of the capture @p baseName in @p dir, its raw capture in
    /// @p format, a ring buffer's of @p ringFiles files (0: one file); each
    /// text starts with @p header.
    DiskLiveFiles( const QDir& dir, const QString& baseName, CaptureFormat format,
                   uint32_t ringFiles, std::string header );

    /// Create the first raw file and its text.
    bool open();

    QIODevice& text() override
    {
        return text_;
    }
    bool writeRaw( const uint8_t* data, size_t n ) override;
    bool flush() override;
    uint64_t rawFileSize() const override
    {
        return raw_.fileSize();
    }
    bool startNext( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers ) override;
    bool close() override;
    const std::vector<CapturePart>& parts() const override
    {
        return raw_.parts();
    }
    uint32_t fileNumber() const override
    {
        return raw_.fileNumber();
    }
    QString textPath() const override
    {
        return text_.fileName();
    }
    QString rawPath() const override
    {
        return raw_.path();
    }
    QString error() const override
    {
        return error_;
    }

private:
    /// Create the text of the raw file written, and write its header.
    bool openText();
    /// Keep the text file's error for error(); false.
    bool textFailed();
    /// Keep the raw capture's error for error(); false.
    bool rawFailed();

    QDir dir_;
    RawCapture raw_;
    QFile text_;
    std::string header_;
    QString error_;
};

/// What the Converter does for a live capture now: each is done in this
/// order, a snapshot flushing first.
struct LiveStep {
    /// Make the text and the raw file readable up to here.
    bool flush = false;
    /// This packet's line is the first of its text, which can be opened
    /// once flushed (LiveObserver::firstPacket).
    bool firstOfText = false;
    /// Hand out a LiveSnapshot of what was converted so far.
    bool snapshot = false;
    /// The capture ends with this packet, by this condition.
    StopCondition stop = StopCondition::None;
};

/**
 * The Live Output: decides, for a live conversion, packet by packet,
 * whether the capture stops and by which condition, when its output is
 * flushed and a snapshot goes out, and when a ring buffer's next file
 * starts, all measured by one clock, so that a test drives it with a fake
 * clock, packet sizes and fake files alone.  It owns the capture's files
 * (LiveFiles) once its format is known (open()).  The Converter asks it
 * before each packet's line (beforePacket()), after it (packet()) and before
 * each wait for the stream (beforeWait()), and does what the LiveStep says;
 * each step counts as done when it is handed out.
 *
 * The stop conditions, the first reached winning, and if one packet reaches
 * several, in this order: LiveLimits::packets, LiveLimits::bytes,
 * LiveLimits::duration and the last packet number.  The duration also ends
 * a wait for the stream (durationOver()).
 *
 * The cadence: the first packet of a text flushes it, opens it and sends a
 * snapshot; after that, lines are flushed at least every kLiveFlushInterval
 * and before every wait, and a snapshot goes out at most every
 * kLiveSnapshotInterval, while packets come.  So that a burst's last packets
 * do not wait for the next packet to be in one, a snapshot due while the
 * stream is idle waits for its turn (snapshotWaits()).
 *
 * The ring buffer (LiveLimits::ringBuffer()): a file that a packet filled,
 * by LiveLimits::fileBytes, or whose LiveLimits::fileDuration is over, ends
 * when the next packet comes, after the record of the last one before it;
 * the next raw file and its text start then (LiveFiles::startNext()), and
 * a snapshot goes out at once, so that the Packet Panel's index follows the
 * files, and the next packet opens the new text.  A file is never left
 * without a packet, and its duration counts from when it started.
 */
class LiveOutput {
public:
    /// A live capture that @p limits stop, measured by @p clock (empty: the
    /// steady clock), whose last packet is numbered @p lastPacketNumber.
    /// It starts now.
    LiveOutput( const LiveLimits& limits, LiveClock clock,
                uint32_t lastPacketNumber = kMaxPacketNumber );

    /// Write the capture to @p files from now on, once its format is known;
    /// its packets are read by @p reader, which says where a packet's record
    /// ends and the headers a file after it needs.
    void open( std::unique_ptr<LiveFiles> files, const CaptureReader& reader );

    /// The files written; open() first.
    LiveFiles& files()
    {
        return *files_;
    }

    /**
     * A packet was read, its line not written yet: a ring buffer's file that
     * is full or old ends before it, and the next file and its text start.
     *
     * @return What to do now: a snapshot, once a file started; nothing if
     *         the next file cannot start, which files().error() says why.
     */
    std::optional<LiveStep> beforePacket();

    /**
     * The packet numbered @p packets was converted and its line written,
     * @p bytesRead bytes of the stream read so far.  With a ring buffer,
     * whether it filled its file, and where its record ends.
     *
     * @return What to do now, and whether the capture ends with it.
     */
    LiveStep packet( uint64_t packets, uint64_t bytesRead );

    /// The stream has nothing to read: flush what was written, and send a
    /// snapshot whose turn has come.
    LiveStep beforeWait();

    /// Packets came since the last snapshot, whose turn has not come yet:
    /// while the stream is idle, the Converter waits for it, then asks
    /// beforeWait() again.
    bool snapshotWaits() const;

    /// Whether LiveLimits::duration is over: a wait for the stream ends.
    bool durationOver() const;

    /// The time from the start to the last snapshot, the one handed out.
    std::chrono::milliseconds elapsed() const;

private:
    /// The time on the clock the Live Output was given.
    std::chrono::steady_clock::time_point now() const;
    /// Whether LiveLimits::duration is over at @p now.
    bool durationOverAt( std::chrono::steady_clock::time_point now ) const;
    /// The stop condition reached with @p packets and @p bytesRead at
    /// @p now, the first in their order; None if none is.
    StopCondition stopAt( uint64_t packets, uint64_t bytesRead,
                          std::chrono::steady_clock::time_point now ) const;
    /// Add a snapshot to @p step if one is due at @p now.
    void snapshotAt( LiveStep& step, std::chrono::steady_clock::time_point now );
    /// Whether the ring buffer's file ends before the next packet.
    bool fileOver( std::chrono::steady_clock::time_point now ) const;

    LiveLimits limits_;
    LiveClock clock_;
    uint32_t lastPacketNumber_;
    std::chrono::steady_clock::time_point started_;
    std::chrono::steady_clock::time_point lastFlush_;
    std::chrono::steady_clock::time_point lastSnapshot_;
    bool firstOfText_ = true;      ///< The next packet opens the text.
    bool snapshotPending_ = false; ///< Packets came since the last snapshot.

    std::unique_ptr<LiveFiles> files_;
    const CaptureReader* reader_ = nullptr;
    // A ring buffer's file: when it started, whether a packet is in it and
    // filled it, and where the last packet's record ends, with the packets
    // up to it and the headers a file after it needs.
    std::chrono::steady_clock::time_point fileStarted_;
    bool fileHasPacket_ = false;
    bool fileFull_ = false;
    uint64_t fileEnd_ = 0;
    uint32_t packetsInFiles_ = 0;
    CaptureHeaders fileHeaders_;
};

} // namespace tcpdump
