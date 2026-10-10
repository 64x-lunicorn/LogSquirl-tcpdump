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
 * @file gzip_source.cpp
 * @brief Decompressing a gzip stream on the fly, with access points.
 */

#include "gzip_source.h"

#include <zlib.h>

#include <algorithm>
#include <cstring>

namespace tcpdump {

namespace {

/// Compressed bytes read at a time.
constexpr size_t kInputChunk = 64 * 1024;

/// inflateInit2()'s window bits: a gzip stream, or raw deflate data.
constexpr int kGzipBits = 15 + 16;
constexpr int kRawBits = -15;

/// The bytes of a gzip member's trailer: its CRC-32 and length.
constexpr int kTrailerSize = 8;

constexpr uint8_t kGzipMagic1 = 0x1f;
constexpr uint8_t kGzipMagic2 = 0x8b;
constexpr uint8_t kDeflate = 8;
constexpr uint8_t kReservedFlags = 0xe0;

const char* kCutOff = "the gzip stream is cut off";

} // namespace

bool findGzipStart( const uint8_t* data, size_t size, size_t& offset )
{
    for ( size_t i = 0; i <= kMaxPreamble && i + 2 <= size; ++i ) {
        if ( data[ i ] == kGzipMagic1 && data[ i + 1 ] == kGzipMagic2
             && ( i == 0
                  || ( i + 4 <= size && data[ i + 2 ] == kDeflate
                       && ( data[ i + 3 ] & kReservedFlags ) == 0 ) ) ) {
            offset = i;
            return true;
        }
        if ( !isPreambleText( data[ i ] ) ) {
            return false;
        }
    }
    return false;
}

// ── GzipAccessPoints ─────────────────────────────────────────────────────

const GzipAccessPoint* GzipAccessPoints::before( uint64_t out ) const
{
    const auto after = std::upper_bound(
        points_.begin(), points_.end(), out,
        []( uint64_t offset, const GzipAccessPoint& point ) { return offset < point.out; } );
    return after == points_.begin() ? nullptr : &*std::prev( after );
}

// ── GzipSource ───────────────────────────────────────────────────────────

struct GzipSource::Stream {
    z_stream z{};
    bool initialised = false;
};

GzipSource::GzipSource( ByteSource& input, uint64_t start )
    : input_( input )
    , start_( start )
    , stream_( std::make_unique<Stream>() )
    , inputPos_( start )
    , in_( kInputChunk )
    , window_( kGzipWindow, 0 )
{
    stream_->initialised = inflateInit2( &stream_->z, kGzipBits ) == Z_OK;
    if ( !stream_->initialised ) {
        end( "the gzip stream cannot be decompressed (out of memory)" );
    }
}

GzipSource::~GzipSource()
{
    if ( stream_->initialised ) {
        inflateEnd( &stream_->z );
    }
}

void GzipSource::keepAccessPoints( uint64_t span )
{
    span_ = std::max<uint64_t>( span, 1 );
    keeping_ = std::make_shared<GzipAccessPoints>();
    points_ = keeping_;
}

void GzipSource::useAccessPoints( std::shared_ptr<const GzipAccessPoints> points )
{
    keeping_.reset();
    points_ = std::move( points );
}

uint64_t GzipSource::compressedRead() const
{
    return inputPos_ - stream_->z.avail_in;
}

void GzipSource::end( const std::string& error )
{
    state_ = State::Ended;
    if ( !error.empty() ) {
        cutOff_ = true;
        error_ = error;
    }
}

bool GzipSource::fillInput()
{
    auto& z = stream_->z;
    if ( z.avail_in > 0 ) {
        return true;
    }
    const auto got = input_.read( in_.data(), in_.size() );
    inputPos_ += got;
    z.next_in = in_.data();
    z.avail_in = static_cast<uInt>( got );
    return got > 0;
}

void GzipSource::keepPoint( int bits )
{
    GzipAccessPoint point;
    point.out = out_;
    point.in = compressedRead();
    point.bits = bits;
    // The ring holds the last kGzipWindow bytes, the oldest at writePos_.
    point.window.reserve( kGzipWindow );
    point.window.insert( point.window.end(),
                         window_.begin() + static_cast<std::ptrdiff_t>( writePos_ ),
                         window_.end() );
    point.window.insert( point.window.end(), window_.begin(),
                         window_.begin() + static_cast<std::ptrdiff_t>( writePos_ ) );
    keeping_->add( std::move( point ) );
}

/// At least @p n compressed bytes in zlib's input, fewer only where the
/// input ends: their number.
size_t GzipSource::peekInput( size_t n )
{
    auto& z = stream_->z;
    if ( z.avail_in >= n ) {
        return z.avail_in;
    }
    if ( z.avail_in > 0 ) {
        std::memmove( in_.data(), z.next_in, z.avail_in );
    }
    z.next_in = in_.data();
    while ( z.avail_in < n ) {
        const auto got = input_.read( in_.data() + z.avail_in, in_.size() - z.avail_in );
        if ( got == 0 ) {
            break;
        }
        inputPos_ += got;
        z.avail_in += static_cast<uInt>( got );
    }
    return z.avail_in;
}

bool GzipSource::produce()
{
    auto& z = stream_->z;
    while ( state_ != State::Ended ) {
        if ( state_ == State::Trailer ) {
            // Entered at an access point, zlib read raw deflate data: the
            // member's trailer is skipped here (and its CRC not checked).
            while ( trailerLeft_ > 0 ) {
                if ( !fillInput() ) {
                    end( kCutOff );
                    return false;
                }
                const auto step = std::min<uInt>( z.avail_in, static_cast<uInt>( trailerLeft_ ) );
                z.next_in += step;
                z.avail_in -= step;
                trailerLeft_ -= static_cast<int>( step );
            }
            state_ = State::Between;
        }
        if ( state_ == State::Between ) {
            // Another member, or the end.  Bytes that start no member after
            // a complete one, its magic and deflate's method, are ignored,
            // as gzip ignores trailing garbage.
            if ( peekInput( 3 ) < 3 || z.next_in[ 0 ] != kGzipMagic1
                 || z.next_in[ 1 ] != kGzipMagic2 || z.next_in[ 2 ] != kDeflate ) {
                end( {} );
                return false;
            }
            inflateReset2( &z, kGzipBits );
            raw_ = false;
            state_ = State::Inflating;
        }

        if ( writePos_ == kGzipWindow ) { // all of it was read: go round
            readPos_ = writePos_ = 0;
        }
        if ( !fillInput() ) {
            end( kCutOff );
            return false;
        }
        z.next_out = window_.data() + writePos_;
        z.avail_out = static_cast<uInt>( kGzipWindow - writePos_ );
        const auto room = z.avail_out;
        // Z_BLOCK stops at every block boundary, where a point can be kept.
        const int status = inflate( &z, keeping_ ? Z_BLOCK : Z_NO_FLUSH );
        const auto produced = room - z.avail_out;
        writePos_ += produced;
        out_ += produced;
        if ( status == Z_NEED_DICT || status == Z_DATA_ERROR || status == Z_STREAM_ERROR
             || status == Z_MEM_ERROR ) {
            end( std::string( "the gzip data is corrupt (" ) + ( z.msg ? z.msg : "unknown error" )
                 + ")" );
            return produced > 0;
        }
        const bool atBlockStart = ( z.data_type & 128 ) && !( z.data_type & 64 );
        if ( keeping_ && atBlockStart && status != Z_STREAM_END ) {
            const auto& points = keeping_->points();
            const uint64_t last = points.empty() ? 0 : points.back().out;
            if ( out_ >= last + span_ ) {
                keepPoint( z.data_type & 7 );
            }
        }
        if ( status == Z_STREAM_END ) {
            state_ = raw_ ? State::Trailer : State::Between;
            trailerLeft_ = kTrailerSize;
        }
        if ( produced > 0 ) {
            return true;
        }
    }
    return false;
}

size_t GzipSource::read( uint8_t* dst, size_t n )
{
    size_t got = 0;
    while ( got < n ) {
        if ( readPos_ == writePos_ && !produce() && readPos_ == writePos_ ) {
            break;
        }
        const auto step = std::min( n - got, writePos_ - readPos_ );
        std::memcpy( dst + got, window_.data() + readPos_, step );
        readPos_ += step;
        got += step;
    }
    return got;
}

bool GzipSource::discard( uint64_t n )
{
    while ( n > 0 ) {
        if ( readPos_ == writePos_ && !produce() && readPos_ == writePos_ ) {
            return false;
        }
        const auto step = static_cast<size_t>( std::min<uint64_t>( n, writePos_ - readPos_ ) );
        readPos_ += step;
        n -= step;
    }
    return true;
}

bool GzipSource::skip( uint64_t n )
{
    return seek( position() + n );
}

bool GzipSource::seek( uint64_t offset )
{
    const auto here = position();
    if ( offset == here ) {
        return true;
    }
    // Going back needs a fresh start, at the last access point before the
    // offset or the beginning; going ahead, a point past here saves the
    // decompression up to it.
    const auto* point = points_ ? points_->before( offset ) : nullptr;
    if ( offset < here || ( point && point->out > here ) ) {
        if ( !( point ? resumeAt( *point ) : startOver() ) ) {
            return false;
        }
    }
    return discard( offset - position() );
}

bool GzipSource::startOver()
{
    auto& z = stream_->z;
    if ( !stream_->initialised || !input_.seek( start_ ) ) {
        return false;
    }
    inputPos_ = start_;
    z.avail_in = 0;
    inflateReset2( &z, kGzipBits );
    raw_ = false;
    state_ = State::Inflating;
    out_ = 0;
    readPos_ = writePos_ = 0;
    cutOff_ = false;
    error_.clear();
    return true;
}

bool GzipSource::resumeAt( const GzipAccessPoint& point )
{
    auto& z = stream_->z;
    const auto from = point.in - ( point.bits > 0 ? 1 : 0 );
    if ( !stream_->initialised || point.window.size() != kGzipWindow || !input_.seek( from ) ) {
        return false;
    }
    inputPos_ = from;
    z.avail_in = 0;
    inflateReset2( &z, kRawBits );
    if ( point.bits > 0 ) {
        if ( !fillInput() ) {
            return false;
        }
        const int byte = z.next_in[ 0 ];
        ++z.next_in;
        --z.avail_in;
        inflatePrime( &z, point.bits, byte >> ( 8 - point.bits ) );
    }
    inflateSetDictionary( &z, point.window.data(), static_cast<uInt>( kGzipWindow ) );
    raw_ = true;
    state_ = State::Inflating;
    // The ring as it was there, all of it read: the next output goes round.
    std::copy( point.window.begin(), point.window.end(), window_.begin() );
    readPos_ = writePos_ = kGzipWindow;
    out_ = point.out;
    cutOff_ = false;
    error_.clear();
    return true;
}

} // namespace tcpdump
