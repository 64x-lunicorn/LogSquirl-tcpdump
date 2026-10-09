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
 * @file byte_stream_orderer.cpp
 * @brief Implementation of the Byte Stream Orderer.
 */

#include "byte_stream_orderer.h"

#include <utility>

namespace tcpdump {

void ByteStreamOrderer::reset( uint32_t nextSeq )
{
    nextSeq_ = nextSeq;
    early_.clear();
}

ByteStreamOrderer::Place ByteStreamOrderer::place( uint32_t seq, size_t len ) const
{
    const auto ahead = seqAfter( seq, nextSeq_ );
    if ( ahead > 0 ) {
        return { Fit::Early, 0 };
    }
    if ( ahead + static_cast<int64_t>( len ) <= 0 ) {
        return { Fit::Taken, 0 };
    }
    return { Fit::Next, static_cast<size_t>( -ahead ) };
}

bool ByteStreamOrderer::holds( uint32_t seq, size_t len ) const
{
    for ( const auto& segment : early_ ) {
        if ( segment.seq == seq && segment.bytes.size() >= len ) {
            return true;
        }
    }
    return false;
}

void ByteStreamOrderer::holdEarly( uint32_t seq, ByteView bytes )
{
    early_.push_back( { seq, std::vector<uint8_t>( bytes.data, bytes.data + bytes.size ) } );
}

bool ByteStreamOrderer::popNext( std::vector<uint8_t>& bytes )
{
    for ( auto it = early_.begin(); it != early_.end(); ) {
        const auto ahead = seqAfter( it->seq, nextSeq_ );
        if ( ahead > 0 ) {
            ++it;
            continue;
        }
        auto segment = std::move( *it );
        early_.erase( it );
        const auto overlap = static_cast<size_t>( -ahead );
        if ( overlap < segment.bytes.size() ) {
            bytes = std::move( segment.bytes );
            bytes.erase( bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>( overlap ) );
            return true;
        }
        it = early_.begin(); // all taken already: look again from the start
    }
    return false;
}

std::optional<uint32_t> ByteStreamOrderer::firstEarlySeq() const
{
    std::optional<uint32_t> first;
    for ( const auto& segment : early_ ) {
        if ( !first || seqAfter( segment.seq, *first ) < 0 ) {
            first = segment.seq;
        }
    }
    return first;
}

uint32_t ByteStreamOrderer::skipTo( uint32_t seq )
{
    const auto ahead = seqAfter( seq, nextSeq_ );
    if ( ahead <= 0 ) {
        return 0;
    }
    nextSeq_ = seq;
    return static_cast<uint32_t>( ahead );
}

size_t ByteStreamOrderer::earlyBytes() const
{
    size_t bytes = 0;
    for ( const auto& segment : early_ ) {
        bytes += segment.bytes.size();
    }
    return bytes;
}

} // namespace tcpdump
