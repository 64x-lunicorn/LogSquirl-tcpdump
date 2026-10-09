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
 * @file hpack.cpp
 * @brief Implementation of the HPACK decoder.
 */

#include "hpack.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <utility>

namespace tcpdump {

namespace {

/// A symbol's Huffman code (RFC 7541, Appendix B): its bits, right-aligned.
struct HuffmanCode {
    uint32_t code;
    uint8_t bits;
};

/// An entry of the static table (RFC 7541, Appendix A).
struct StaticEntry {
    const char* name;
    const char* value;
};

constexpr HuffmanCode kHuffmanCodes[ 257 ] = {
    { 0x1ff8, 13 },     { 0x7fffd8, 23 },   { 0xfffffe2, 28 },  { 0xfffffe3, 28 },
    { 0xfffffe4, 28 },  { 0xfffffe5, 28 },  { 0xfffffe6, 28 },  { 0xfffffe7, 28 },
    { 0xfffffe8, 28 },  { 0xffffea, 24 },   { 0x3ffffffc, 30 }, { 0xfffffe9, 28 },
    { 0xfffffea, 28 },  { 0x3ffffffd, 30 }, { 0xfffffeb, 28 },  { 0xfffffec, 28 },
    { 0xfffffed, 28 },  { 0xfffffee, 28 },  { 0xfffffef, 28 },  { 0xffffff0, 28 },
    { 0xffffff1, 28 },  { 0xffffff2, 28 },  { 0x3ffffffe, 30 }, { 0xffffff3, 28 },
    { 0xffffff4, 28 },  { 0xffffff5, 28 },  { 0xffffff6, 28 },  { 0xffffff7, 28 },
    { 0xffffff8, 28 },  { 0xffffff9, 28 },  { 0xffffffa, 28 },  { 0xffffffb, 28 },
    { 0x14, 6 },        { 0x3f8, 10 },      { 0x3f9, 10 },      { 0xffa, 12 },
    { 0x1ff9, 13 },     { 0x15, 6 },        { 0xf8, 8 },        { 0x7fa, 11 },
    { 0x3fa, 10 },      { 0x3fb, 10 },      { 0xf9, 8 },        { 0x7fb, 11 },
    { 0xfa, 8 },        { 0x16, 6 },        { 0x17, 6 },        { 0x18, 6 },
    { 0x0, 5 },         { 0x1, 5 },         { 0x2, 5 },         { 0x19, 6 },
    { 0x1a, 6 },        { 0x1b, 6 },        { 0x1c, 6 },        { 0x1d, 6 },
    { 0x1e, 6 },        { 0x1f, 6 },        { 0x5c, 7 },        { 0xfb, 8 },
    { 0x7ffc, 15 },     { 0x20, 6 },        { 0xffb, 12 },      { 0x3fc, 10 },
    { 0x1ffa, 13 },     { 0x21, 6 },        { 0x5d, 7 },        { 0x5e, 7 },
    { 0x5f, 7 },        { 0x60, 7 },        { 0x61, 7 },        { 0x62, 7 },
    { 0x63, 7 },        { 0x64, 7 },        { 0x65, 7 },        { 0x66, 7 },
    { 0x67, 7 },        { 0x68, 7 },        { 0x69, 7 },        { 0x6a, 7 },
    { 0x6b, 7 },        { 0x6c, 7 },        { 0x6d, 7 },        { 0x6e, 7 },
    { 0x6f, 7 },        { 0x70, 7 },        { 0x71, 7 },        { 0x72, 7 },
    { 0xfc, 8 },        { 0x73, 7 },        { 0xfd, 8 },        { 0x1ffb, 13 },
    { 0x7fff0, 19 },    { 0x1ffc, 13 },     { 0x3ffc, 14 },     { 0x22, 6 },
    { 0x7ffd, 15 },     { 0x3, 5 },         { 0x23, 6 },        { 0x4, 5 },
    { 0x24, 6 },        { 0x5, 5 },         { 0x25, 6 },        { 0x26, 6 },
    { 0x27, 6 },        { 0x6, 5 },         { 0x74, 7 },        { 0x75, 7 },
    { 0x28, 6 },        { 0x29, 6 },        { 0x2a, 6 },        { 0x7, 5 },
    { 0x2b, 6 },        { 0x76, 7 },        { 0x2c, 6 },        { 0x8, 5 },
    { 0x9, 5 },         { 0x2d, 6 },        { 0x77, 7 },        { 0x78, 7 },
    { 0x79, 7 },        { 0x7a, 7 },        { 0x7b, 7 },        { 0x7ffe, 15 },
    { 0x7fc, 11 },      { 0x3ffd, 14 },     { 0x1ffd, 13 },     { 0xffffffc, 28 },
    { 0xfffe6, 20 },    { 0x3fffd2, 22 },   { 0xfffe7, 20 },    { 0xfffe8, 20 },
    { 0x3fffd3, 22 },   { 0x3fffd4, 22 },   { 0x3fffd5, 22 },   { 0x7fffd9, 23 },
    { 0x3fffd6, 22 },   { 0x7fffda, 23 },   { 0x7fffdb, 23 },   { 0x7fffdc, 23 },
    { 0x7fffdd, 23 },   { 0x7fffde, 23 },   { 0xffffeb, 24 },   { 0x7fffdf, 23 },
    { 0xffffec, 24 },   { 0xffffed, 24 },   { 0x3fffd7, 22 },   { 0x7fffe0, 23 },
    { 0xffffee, 24 },   { 0x7fffe1, 23 },   { 0x7fffe2, 23 },   { 0x7fffe3, 23 },
    { 0x7fffe4, 23 },   { 0x1fffdc, 21 },   { 0x3fffd8, 22 },   { 0x7fffe5, 23 },
    { 0x3fffd9, 22 },   { 0x7fffe6, 23 },   { 0x7fffe7, 23 },   { 0xffffef, 24 },
    { 0x3fffda, 22 },   { 0x1fffdd, 21 },   { 0xfffe9, 20 },    { 0x3fffdb, 22 },
    { 0x3fffdc, 22 },   { 0x7fffe8, 23 },   { 0x7fffe9, 23 },   { 0x1fffde, 21 },
    { 0x7fffea, 23 },   { 0x3fffdd, 22 },   { 0x3fffde, 22 },   { 0xfffff0, 24 },
    { 0x1fffdf, 21 },   { 0x3fffdf, 22 },   { 0x7fffeb, 23 },   { 0x7fffec, 23 },
    { 0x1fffe0, 21 },   { 0x1fffe1, 21 },   { 0x3fffe0, 22 },   { 0x1fffe2, 21 },
    { 0x7fffed, 23 },   { 0x3fffe1, 22 },   { 0x7fffee, 23 },   { 0x7fffef, 23 },
    { 0xfffea, 20 },    { 0x3fffe2, 22 },   { 0x3fffe3, 22 },   { 0x3fffe4, 22 },
    { 0x7ffff0, 23 },   { 0x3fffe5, 22 },   { 0x3fffe6, 22 },   { 0x7ffff1, 23 },
    { 0x3ffffe0, 26 },  { 0x3ffffe1, 26 },  { 0xfffeb, 20 },    { 0x7fff1, 19 },
    { 0x3fffe7, 22 },   { 0x7ffff2, 23 },   { 0x3fffe8, 22 },   { 0x1ffffec, 25 },
    { 0x3ffffe2, 26 },  { 0x3ffffe3, 26 },  { 0x3ffffe4, 26 },  { 0x7ffffde, 27 },
    { 0x7ffffdf, 27 },  { 0x3ffffe5, 26 },  { 0xfffff1, 24 },   { 0x1ffffed, 25 },
    { 0x7fff2, 19 },    { 0x1fffe3, 21 },   { 0x3ffffe6, 26 },  { 0x7ffffe0, 27 },
    { 0x7ffffe1, 27 },  { 0x3ffffe7, 26 },  { 0x7ffffe2, 27 },  { 0xfffff2, 24 },
    { 0x1fffe4, 21 },   { 0x1fffe5, 21 },   { 0x3ffffe8, 26 },  { 0x3ffffe9, 26 },
    { 0xffffffd, 28 },  { 0x7ffffe3, 27 },  { 0x7ffffe4, 27 },  { 0x7ffffe5, 27 },
    { 0xfffec, 20 },    { 0xfffff3, 24 },   { 0xfffed, 20 },    { 0x1fffe6, 21 },
    { 0x3fffe9, 22 },   { 0x1fffe7, 21 },   { 0x1fffe8, 21 },   { 0x7ffff3, 23 },
    { 0x3fffea, 22 },   { 0x3fffeb, 22 },   { 0x1ffffee, 25 },  { 0x1ffffef, 25 },
    { 0xfffff4, 24 },   { 0xfffff5, 24 },   { 0x3ffffea, 26 },  { 0x7ffff4, 23 },
    { 0x3ffffeb, 26 },  { 0x7ffffe6, 27 },  { 0x3ffffec, 26 },  { 0x3ffffed, 26 },
    { 0x7ffffe7, 27 },  { 0x7ffffe8, 27 },  { 0x7ffffe9, 27 },  { 0x7ffffea, 27 },
    { 0x7ffffeb, 27 },  { 0xffffffe, 28 },  { 0x7ffffec, 27 },  { 0x7ffffed, 27 },
    { 0x7ffffee, 27 },  { 0x7ffffef, 27 },  { 0x7fffff0, 27 },  { 0x3ffffee, 26 },
    { 0x3fffffff, 30 },
};
constexpr StaticEntry kStaticTable[ 61 ] = {
    { ":authority", "" },
    { ":method", "GET" },
    { ":method", "POST" },
    { ":path", "/" },
    { ":path", "/index.html" },
    { ":scheme", "http" },
    { ":scheme", "https" },
    { ":status", "200" },
    { ":status", "204" },
    { ":status", "206" },
    { ":status", "304" },
    { ":status", "400" },
    { ":status", "404" },
    { ":status", "500" },
    { "accept-charset", "" },
    { "accept-encoding", "gzip, deflate" },
    { "accept-language", "" },
    { "accept-ranges", "" },
    { "accept", "" },
    { "access-control-allow-origin", "" },
    { "age", "" },
    { "allow", "" },
    { "authorization", "" },
    { "cache-control", "" },
    { "content-disposition", "" },
    { "content-encoding", "" },
    { "content-language", "" },
    { "content-length", "" },
    { "content-location", "" },
    { "content-range", "" },
    { "content-type", "" },
    { "cookie", "" },
    { "date", "" },
    { "etag", "" },
    { "expect", "" },
    { "expires", "" },
    { "from", "" },
    { "host", "" },
    { "if-match", "" },
    { "if-modified-since", "" },
    { "if-none-match", "" },
    { "if-range", "" },
    { "if-unmodified-since", "" },
    { "last-modified", "" },
    { "link", "" },
    { "location", "" },
    { "max-forwards", "" },
    { "proxy-authenticate", "" },
    { "proxy-authorization", "" },
    { "range", "" },
    { "referer", "" },
    { "refresh", "" },
    { "retry-after", "" },
    { "server", "" },
    { "set-cookie", "" },
    { "strict-transport-security", "" },
    { "transfer-encoding", "" },
    { "user-agent", "" },
    { "vary", "" },
    { "via", "" },
    { "www-authenticate", "" },
};

constexpr size_t kStaticEntries = std::size( kStaticTable );
/// The end-of-string symbol, which no string may contain.
constexpr int kEos = 256;
/// HPACK counts this many bytes per entry besides its name and value.
constexpr size_t kEntryOverhead = 32;

/// The Huffman code as a binary tree: node 0 is the root, a child below 0
/// is the leaf of symbol -child - 1.
class HuffmanTree {
public:
    HuffmanTree()
    {
        nodes_.push_back( { 0, 0 } );
        for ( int symbol = 0; symbol < 257; ++symbol ) {
            const auto& code = kHuffmanCodes[ symbol ];
            size_t node = 0;
            for ( int bit = code.bits - 1; bit >= 0; --bit ) {
                const auto side = ( code.code >> bit ) & 1;
                if ( bit == 0 ) {
                    nodes_[ node ][ side ] = -symbol - 1;
                    break;
                }
                if ( nodes_[ node ][ side ] == 0 ) {
                    nodes_[ node ][ side ] = static_cast<int>( nodes_.size() );
                    nodes_.push_back( { 0, 0 } );
                }
                node = static_cast<size_t>( nodes_[ node ][ side ] );
            }
        }
    }

    /// Decode the @p len bytes at @p data into @p out; false if they hold
    /// EOS, a code no symbol has, or padding other than up to 7 one bits.
    bool decode( const uint8_t* data, size_t len, std::string& out ) const
    {
        size_t node = 0;
        int depth = 0;       ///< Bits read since the last symbol.
        bool allOnes = true; ///< Those bits are all ones.
        for ( size_t i = 0; i < len; ++i ) {
            for ( int bit = 7; bit >= 0; --bit ) {
                const auto side = ( data[ i ] >> bit ) & 1;
                const int next = nodes_[ node ][ side ];
                ++depth;
                allOnes = allOnes && side == 1;
                if ( next == 0 ) {
                    return false;
                }
                if ( next < 0 ) {
                    const int symbol = -next - 1;
                    if ( symbol == kEos ) {
                        return false;
                    }
                    out += static_cast<char>( symbol );
                    node = 0;
                    depth = 0;
                    allOnes = true;
                }
                else {
                    node = static_cast<size_t>( next );
                }
            }
        }
        return depth <= 7 && allOnes;
    }

private:
    std::vector<std::array<int, 2>> nodes_;
};

const HuffmanTree& huffmanTree()
{
    static const HuffmanTree tree;
    return tree;
}

/// Reads the representations of a header block, never beyond it.
class BlockReader {
public:
    BlockReader( const uint8_t* data, size_t len )
        : p_( data )
        , end_( data + len )
    {
    }

    bool atEnd() const
    {
        return p_ == end_;
    }
    uint8_t peek() const
    {
        return *p_;
    }

    /// An integer with an @p prefixBits-bit prefix (RFC 7541, 5.1), at
    /// most 2^28, more than any table or string a block can hold.
    bool integer( int prefixBits, size_t& value )
    {
        if ( p_ == end_ ) {
            return false;
        }
        const auto max = static_cast<size_t>( ( 1u << prefixBits ) - 1 );
        value = *p_++ & max;
        if ( value < max ) {
            return true;
        }
        for ( int shift = 0; shift <= 21; shift += 7 ) {
            if ( p_ == end_ ) {
                return false;
            }
            const auto byte = *p_++;
            value += static_cast<size_t>( byte & 0x7F ) << shift;
            if ( ( byte & 0x80 ) == 0 ) {
                return true;
            }
        }
        return false;
    }

    /// A string literal (RFC 7541, 5.2), Huffman-coded or not.
    bool string( std::string& out )
    {
        if ( p_ == end_ ) {
            return false;
        }
        const bool huffman = ( *p_ & 0x80 ) != 0;
        size_t len = 0;
        if ( !integer( 7, len ) || len > static_cast<size_t>( end_ - p_ ) ) {
            return false;
        }
        const auto* data = p_;
        p_ += len;
        out.clear();
        if ( huffman ) {
            return huffmanTree().decode( data, len, out );
        }
        out.assign( reinterpret_cast<const char*>( data ), len );
        return true;
    }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};

} // namespace

HpackDecoder::HpackDecoder( size_t maxTableSize )
    : capacity_( std::min( kDefaultTableSize, maxTableSize ) )
    , maxCapacity_( maxTableSize )
{
}

bool HpackDecoder::field( size_t index, HeaderField& out ) const
{
    if ( index == 0 ) {
        return false;
    }
    if ( index <= kStaticEntries ) {
        out.name = kStaticTable[ index - 1 ].name;
        out.value = kStaticTable[ index - 1 ].value;
        return true;
    }
    const auto dynamic = index - kStaticEntries - 1;
    if ( dynamic >= table_.size() ) {
        return false;
    }
    out = table_[ dynamic ];
    return true;
}

void HpackDecoder::evict( size_t capacity )
{
    while ( size_ > capacity && !table_.empty() ) {
        size_ -= table_.back().name.size() + table_.back().value.size() + kEntryOverhead;
        table_.pop_back();
    }
}

void HpackDecoder::insert( HeaderField entry )
{
    const auto size = entry.name.size() + entry.value.size() + kEntryOverhead;
    if ( size > capacity_ ) {
        evict( 0 ); // an entry larger than the table empties it (RFC 7541, 4.4)
        return;
    }
    evict( capacity_ - size );
    size_ += size;
    table_.push_front( std::move( entry ) );
}

void HpackDecoder::abandon()
{
    broken_ = true;
    std::deque<HeaderField>().swap( table_ );
    size_ = 0;
}

bool HpackDecoder::decode( const uint8_t* data, size_t len, std::vector<HeaderField>& fields )
{
    if ( broken_ ) {
        return false;
    }
    BlockReader block( data, len );
    bool fieldSeen = false;
    while ( !block.atEnd() ) {
        const auto first = block.peek();
        size_t index = 0;
        HeaderField decoded;
        if ( first & 0x80 ) { // indexed header field
            if ( !block.integer( 7, index ) || !field( index, decoded ) ) {
                abandon();
                return false;
            }
            fields.push_back( std::move( decoded ) );
            fieldSeen = true;
            continue;
        }
        if ( ( first & 0xE0 ) == 0x20 ) { // dynamic table size update
            size_t capacity = 0;
            // Only at the start of a block (RFC 7541, 4.2).
            if ( fieldSeen || !block.integer( 5, capacity ) || capacity > maxCapacity_ ) {
                abandon();
                return false;
            }
            capacity_ = capacity;
            evict( capacity_ );
            continue;
        }
        // A literal: with incremental indexing (01), without (0000) or
        // never indexed (0001).
        const bool indexing = ( first & 0xC0 ) == 0x40;
        if ( !block.integer( indexing ? 6 : 4, index ) ) {
            abandon();
            return false;
        }
        if ( index == 0 ? !block.string( decoded.name ) : !field( index, decoded ) ) {
            abandon();
            return false;
        }
        if ( !block.string( decoded.value ) ) {
            abandon();
            return false;
        }
        if ( indexing ) {
            insert( decoded );
        }
        fields.push_back( std::move( decoded ) );
        fieldSeen = true;
    }
    return true;
}

} // namespace tcpdump
