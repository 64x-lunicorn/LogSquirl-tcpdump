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
 * @file hpack.h
 * @brief Decodes the header blocks of HTTP/2 (HPACK, RFC 7541).
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace tcpdump {

/// A header field of an HTTP/2 header block, as HPACK decoded it.
struct HeaderField {
    std::string name;
    std::string value;
};

/**
 * The HPACK decoder of one direction of an HTTP/2 connection: the header
 * blocks it carries must all be decoded, in order, as each may refer to the
 * fields of the dynamic table those before it filled.
 *
 * Memory is bounded: the dynamic table holds at most maxTableSize bytes as
 * HPACK counts them (a field's name, value and 32), however large a size
 * the encoder asks for.  A block that breaks a rule of RFC 7541, or asks for
 * a larger table, breaks the decoder: it lets its table go and decodes no
 * later block, which might refer to fields it does not know.
 */
class HpackDecoder {
public:
    /// The table size each side starts with (SETTINGS_HEADER_TABLE_SIZE).
    static constexpr size_t kDefaultTableSize = 4096;
    /// The largest table a decoder holds by default, as large as browsers
    /// let it grow.
    static constexpr size_t kMaxTableSize = 64 * 1024;

    explicit HpackDecoder( size_t maxTableSize = kMaxTableSize );

    /**
     * Decode the header block of @p len bytes at @p data, appending its
     * fields to @p fields.  False if it breaks a rule, which breaks the
     * decoder, or the decoder was broken before.
     */
    bool decode( const uint8_t* data, size_t len, std::vector<HeaderField>& fields );

    /// Let the table go and decode no later block, as when a block broke
    /// a rule: for a caller that missed a block.
    void abandon();

    /// A block broke a rule, or the decoder was abandoned: no later one is
    /// decoded.
    bool broken() const
    {
        return broken_;
    }

    /// Bytes of the dynamic table as HPACK counts them.
    size_t tableSize() const
    {
        return size_;
    }

private:
    bool field( size_t index, HeaderField& out ) const;
    void insert( HeaderField entry );
    void evict( size_t capacity );

    std::deque<HeaderField> table_; ///< The newest entry first.
    size_t size_ = 0;
    size_t capacity_ = kDefaultTableSize;
    size_t maxCapacity_;
    bool broken_ = false;
};

} // namespace tcpdump
