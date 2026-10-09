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
 * @file capture_reader.cpp
 * @brief Choosing a capture's reader, and reading a whole capture in memory.
 */

#include "capture_reader.h"

#include "pcapng_reader.h"

#include <utility>

namespace tcpdump {

// ── Choosing the reader ──────────────────────────────────────────────────

namespace {

/// Why a file shorter than a pcap global header is no capture.
constexpr const char* kTooSmall = "File too small to be a valid pcap (< 24 bytes)";

/// The reader for a file that holds no capture: open() says why.
class NoCaptureReader : public CaptureReader {
public:
    NoCaptureReader( ByteSource& source, std::string error )
        : CaptureReader( source, 0 )
    {
        error_ = std::move( error );
    }

    bool open() override
    {
        return false;
    }

    bool next( PacketRecord& ) override
    {
        return false;
    }

    TimePrecision precision() const override
    {
        return TimePrecision::Microseconds;
    }

    std::vector<uint32_t> linkTypes() const override
    {
        return {};
    }
};

} // anonymous namespace

std::unique_ptr<CaptureReader> makeCaptureReader( HeadSource& source )
{
    // Look at no more than the next step of the decision needs: on a stream,
    // bytes beyond the header may take long to come.
    size_t needed = 24;
    for ( ;; ) {
        const auto& head = source.peek( needed );
        size_t offset = 0;
        CaptureFormat format = CaptureFormat::Pcap;
        std::string error;
        switch ( findCaptureStart( head.data(), head.size(), offset, format, error ) ) {
        case CaptureStart::Found:
            if ( format == CaptureFormat::Pcapng ) {
                return std::make_unique<PcapngReader>( source, offset );
            }
            return std::make_unique<PcapReader>( source, offset );
        case CaptureStart::None:
            return std::make_unique<NoCaptureReader>( source, error );
        case CaptureStart::NeedMore:
            if ( head.size() < needed ) { // the source ended before deciding it
                return std::make_unique<NoCaptureReader>( source,
                                                          head.size() < 24 ? kTooSmall : error );
            }
            needed = offset;
            break;
        }
    }
}

// ── Whole-buffer convenience ─────────────────────────────────────────────

ParseResult parsePcap( const uint8_t* data, size_t size )
{
    ParseResult result;
    MemorySource memory( data, size );
    HeadSource source( memory );
    const auto reader = makeCaptureReader( source );
    if ( !reader->open() ) {
        result.error = reader->error();
        return result;
    }
    if ( const auto* pcap = dynamic_cast<const PcapReader*>( reader.get() ) ) {
        result.header = pcap->header();
    }
    result.precision = reader->precision();

    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        result.packets.push_back( std::move( pkt ) );
    }
    result.linkTypes = reader->linkTypes();
    result.truncated = reader->truncated();
    result.ok = true;
    return result;
}

} // namespace tcpdump
