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
    // Look at what may hold a text preamble and the first header.
    const auto& head = source.peek( kMaxPreamble + 24 );
    if ( head.size() < 24 ) {
        return std::make_unique<NoCaptureReader>( source, kTooSmall );
    }
    CaptureFormat format = CaptureFormat::Pcap;
    std::string error;
    const auto start = findCaptureStart( head.data(), head.size(), format, error );
    if ( start == head.size() ) {
        return std::make_unique<NoCaptureReader>( source, error );
    }
    if ( format == CaptureFormat::Pcapng ) {
        return std::make_unique<PcapngReader>( source, start );
    }
    return std::make_unique<PcapReader>( source, start );
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
