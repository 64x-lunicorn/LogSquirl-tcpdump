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
 * @file gzip_source.h
 * @brief Reading a gzip-compressed capture: a ByteSource that decompresses
 *        it on the fly, and access points to go on decompressing anywhere.
 *
 * Wireshark opens `.pcap.gz` and `.pcapng.gz` files as they are; so does
 * the plugin.  A GzipSource reads the compressed bytes from another
 * ByteSource and returns the capture in them, a window of 32 KB at a time,
 * so that a multi-GB capture never sits in memory, decompressed or not.
 * A file of several gzip members (`cat a.gz b.gz`) reads as one capture.
 * A stream that ends early, or whose data is corrupt, ends there as a file
 * cut off would: cutOff() tells, error() says why.
 *
 * Offsets in the decompressed capture are what the readers, the
 * CaptureIndex and Export Packets work with.  Going back to one, or far
 * ahead, needs the decompression state there: a deflate stream cannot be
 * entered in the middle.  While the Converter reads a capture, its
 * GzipSource keeps an access point every kAccessSpan bytes of output, at
 * the start of a deflate block (zlib's examples/zran.c): where it lies in
 * both streams and the 32 KB of output before it, which the next block may
 * refer back to.  A GzipSource given them seeks to the last one before an
 * offset and decompresses from there, at most kAccessSpan bytes; without
 * one it starts again at the beginning.
 *
 * zlib does the decompression: a copy built with the plugin (CMake
 * FetchContent, see NOTICE), whose symbols are prefixed (Z_PREFIX) and
 * hidden, so that it never clashes with the zlib Qt or the host loads.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tcpdump {

/// The output a deflate block may refer back to, and so an access point keeps.
constexpr size_t kGzipWindow = 32768;

/**
 * Where a gzip stream starts in the first bytes of a file: at 0, or behind
 * up to kMaxPreamble bytes of text, as tcpdump's stderr comes ahead of a
 * capture run through adb (findCaptureStart()).  Past offset 0 a full gzip
 * header start is needed (magic, deflate, no reserved flag), as a stray
 * magic must not be taken for a stream.  False if @p data has none.
 */
bool findGzipStart( const uint8_t* data, size_t size, size_t& offset );

/// A place in a gzip stream to go on decompressing from: see the file comment.
struct GzipAccessPoint {
    uint64_t out = 0; ///< Where it lies in the decompressed bytes.
    uint64_t in = 0;  ///< The first whole compressed byte after it, in the input.
    /// Bits of the byte before `in` that belong to the block it starts (0-7).
    int bits = 0;
    /// The kGzipWindow bytes of output before it, oldest first.
    std::vector<uint8_t> window;
};

/// The access points of a gzip stream, by ascending offset.
class GzipAccessPoints {
public:
    /// The last point at or before decompressed offset @p out, or null.
    const GzipAccessPoint* before( uint64_t out ) const;

    void add( GzipAccessPoint point )
    {
        points_.push_back( std::move( point ) );
    }

    const std::vector<GzipAccessPoint>& points() const
    {
        return points_;
    }

private:
    std::vector<GzipAccessPoint> points_;
};

/**
 * A ByteSource that decompresses the gzip stream another one holds.
 * Reads never wait; seek() and skip() work in decompressed offsets and need
 * an input that can seek to go back or to jump to an access point.
 */
class GzipSource : public ByteSource {
public:
    /// Decompressed bytes between two access points the Converter keeps:
    /// about 1 KB of memory per MB of capture, and at most this much to
    /// decompress again to reach a packet.
    static constexpr uint64_t kAccessSpan = 32ull * 1024 * 1024;

    /// @param input  The compressed bytes, read from @p start on, where it
    ///               must be positioned; it must outlive the source.
    explicit GzipSource( ByteSource& input, uint64_t start = 0 );
    ~GzipSource() override;
    GzipSource( const GzipSource& ) = delete;
    GzipSource& operator=( const GzipSource& ) = delete;

    /// Keep an access point every @p span bytes of output from now on,
    /// which seeks then use too.  Call before the first read.
    void keepAccessPoints( uint64_t span = kAccessSpan );

    /// Seek by @p points, which a GzipSource of the same file kept.
    void useAccessPoints( std::shared_ptr<const GzipAccessPoints> points );

    /// The access points kept or used; null if there are none.
    std::shared_ptr<const GzipAccessPoints> accessPoints() const
    {
        return points_;
    }

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;
    bool seek( uint64_t offset ) override;

    /// Decompressed bytes read so far: the offset of the next one.
    uint64_t position() const
    {
        return out_ - ( writePos_ - readPos_ );
    }

    /// Compressed bytes consumed: where the input is, for progress.
    uint64_t compressedRead() const;

    /// Whether the stream ended before its end: cut off, or corrupt.
    bool cutOff() const
    {
        return cutOff_;
    }

    /// Why it did, for the user; empty if it did not.
    const std::string& error() const
    {
        return error_;
    }

private:
    struct Stream; // zlib's state, kept out of this header
    enum class State {
        Inflating, ///< In a member's deflate data.
        Trailer,   ///< In the trailer of a member entered at an access point.
        Between,   ///< After a member: another one or the end follows.
        Ended,
    };

    bool produce();
    bool fillInput();
    bool startOver();
    bool resumeAt( const GzipAccessPoint& point );
    bool discard( uint64_t n );
    void keepPoint( int bits );
    void end( const std::string& error );

    ByteSource& input_;
    const uint64_t start_;
    std::unique_ptr<Stream> stream_;
    State state_ = State::Inflating;
    bool raw_ = false;      ///< Entered at an access point: no gzip header to read.
    int trailerLeft_ = 0;   ///< Of the trailer, in State::Trailer.
    uint64_t inputPos_ = 0; ///< Where the input is: after the bytes in the input buffer.
    std::vector<uint8_t> in_;
    /// The output, a ring of the last kGzipWindow bytes; [readPos_, writePos_)
    /// is not read yet.
    std::vector<uint8_t> window_;
    size_t readPos_ = 0;
    size_t writePos_ = 0;
    uint64_t out_ = 0;                          ///< Decompressed bytes so far.
    std::shared_ptr<GzipAccessPoints> keeping_; ///< Being kept, or null.
    std::shared_ptr<const GzipAccessPoints> points_;
    uint64_t span_ = kAccessSpan;
    bool cutOff_ = false;
    std::string error_;
};

} // namespace tcpdump
