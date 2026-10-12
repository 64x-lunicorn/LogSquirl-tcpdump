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
 * @brief Decides, packet by packet, when a live capture stops and when its
 *        output is flushed and its snapshots go out, on one clock.
 */

#pragma once

#include "pcap_parser.h"

#include <chrono>
#include <cstdint>
#include <functional>

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
 * whether the capture stops and by which condition, and when its output is
 * flushed and a snapshot goes out, all measured by one clock, so that a test
 * drives it with a fake clock and packet sizes alone.  The Converter asks
 * it after each packet (packet()) and before each wait for the stream
 * (beforeWait()), and does what the LiveStep says; each step counts as done
 * when it is handed out.
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
 */
class LiveOutput {
public:
    /// A live capture that @p limits stop, measured by @p clock (empty: the
    /// steady clock), whose last packet is numbered @p lastPacketNumber.
    /// It starts now.
    LiveOutput( const LiveLimits& limits, LiveClock clock,
                uint32_t lastPacketNumber = kMaxPacketNumber );

    /**
     * The packet numbered @p packets was converted and its line written,
     * @p bytesRead bytes of the stream read so far.
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

    /// A ring buffer's next text was started: a snapshot goes out at once,
    /// so that the Packet Panel's index follows the files, and the next
    /// packet opens the text.
    LiveStep textStarted();

    /// Whether LiveLimits::duration is over: a wait for the stream ends.
    bool durationOver() const;

    /// The time of the clock, which a ring buffer's file durations are
    /// measured with too.
    std::chrono::steady_clock::time_point now() const;

    /// The time from the start to the last snapshot, the one handed out.
    std::chrono::milliseconds elapsed() const;

private:
    StopCondition stopAt( uint64_t packets, uint64_t bytesRead,
                          std::chrono::steady_clock::time_point now ) const;
    void snapshotAt( LiveStep& step, std::chrono::steady_clock::time_point now );

    LiveLimits limits_;
    LiveClock clock_;
    uint32_t lastPacketNumber_;
    std::chrono::steady_clock::time_point started_;
    std::chrono::steady_clock::time_point lastFlush_;
    std::chrono::steady_clock::time_point lastSnapshot_;
    bool firstOfText_ = true;      ///< The next packet opens the text.
    bool snapshotPending_ = false; ///< Packets came since the last snapshot.
};

} // namespace tcpdump
