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
 * @file shared_chunks.h
 * @brief An append-only array whose copies share its storage, a chunk at a
 *        time, copy on write.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <vector>

namespace tcpdump {

/**
 * Elements in chunks of kChunk, each held by a shared_ptr: a copy takes
 * the chunks' pointers, not their elements, so that a snapshot of a large
 * array taken every second costs a pointer per chunk.  A write to a chunk
 * another copy shares copies that chunk first, so that the copies never
 * see each other's changes.  Copies may be read on other threads while
 * this one is written: a shared chunk is never written.
 */
template <typename T, size_t kChunk>
class SharedChunks {
public:
    size_t size() const
    {
        return size_;
    }

    const T& operator[]( size_t i ) const
    {
        return ( *chunks_[ i / kChunk ] )[ i % kChunk ];
    }

    /// Element @p i to write, its chunk copied first if a copy shares it.
    T& writable( size_t i )
    {
        auto& chunk = chunks_[ i / kChunk ];
        if ( chunk.use_count() > 1 ) {
            chunk = std::make_shared<Chunk>( *chunk );
        }
        return ( *chunk )[ i % kChunk ];
    }

    /// Grow to @p size elements, the new ones default-constructed.
    void growTo( size_t size )
    {
        while ( size_ < size ) {
            if ( size_ % kChunk == 0 ) {
                chunks_.push_back( std::make_shared<Chunk>() );
                chunks_.back()->reserve( kChunk );
            }
            else if ( chunks_.back().use_count() > 1 ) {
                auto copy = std::make_shared<Chunk>();
                copy->reserve( kChunk );
                copy->assign( chunks_.back()->begin(), chunks_.back()->end() );
                chunks_.back() = std::move( copy );
            }
            auto& last = *chunks_.back();
            const auto add = std::min( kChunk - last.size(), size - size_ );
            last.resize( last.size() + add );
            size_ += add;
        }
    }

    /// Chunks this and @p other hold the same, for the tests.
    size_t chunksSharedWith( const SharedChunks& other ) const
    {
        size_t shared = 0;
        for ( size_t i = 0; i < chunks_.size() && i < other.chunks_.size(); ++i ) {
            shared += chunks_[ i ] == other.chunks_[ i ] ? 1 : 0;
        }
        return shared;
    }

private:
    using Chunk = std::vector<T>;
    std::vector<std::shared_ptr<Chunk>> chunks_;
    size_t size_ = 0;
};

} // namespace tcpdump
