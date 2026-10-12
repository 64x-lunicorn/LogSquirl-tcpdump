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
 * @brief Implementation of the Live Output's stop and cadence decisions.
 */

#include "live_output.h"

#include <utility>

namespace tcpdump {

LiveOutput::LiveOutput( const LiveLimits& limits, LiveClock clock, uint32_t lastPacketNumber )
    : limits_( limits )
    , clock_( std::move( clock ) )
    , lastPacketNumber_( lastPacketNumber )
    , started_( now() )
    , lastFlush_( started_ )
    , lastSnapshot_( started_ )
{
}

LiveStep LiveOutput::packet( uint64_t packets, uint64_t bytesRead )
{
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

LiveStep LiveOutput::textStarted()
{
    const auto at = now();
    firstOfText_ = true;
    LiveStep step;
    snapshotAt( step, at );
    lastFlush_ = at;
    return step;
}

bool LiveOutput::durationOver() const
{
    return limits_.duration.count() > 0 && now() - started_ >= limits_.duration;
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
    if ( limits_.duration.count() > 0 && now - started_ >= limits_.duration ) {
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
