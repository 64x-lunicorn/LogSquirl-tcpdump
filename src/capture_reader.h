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
 * @file capture_reader.h
 * @brief The way into a capture: the CaptureReader for its format.
 *
 * makeCaptureReader() tells a capture's format from its first block and
 * hands out the reader for it, a PcapReader (pcap_parser.h) or a
 * PcapngReader (pcapng_reader.h); parsePcap() reads a whole capture held in
 * memory through it.  Kept apart from both readers, so that the pcap parser
 * does not depend on the pcapng reader built on it.  Pure C++.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace tcpdump {

/**
 * The reader for the capture in @p source, chosen by its first block as
 * findCaptureStart() finds it: a PcapngReader for a pcapng section header, a
 * PcapReader for a pcap global header.  For a file that holds neither, a
 * reader whose open() fails and says why.  It is not open yet; @p source
 * must outlive it.
 *
 * Only the bytes the decision needs are looked at, as they come: on a
 * stream that has sent its header and nothing more, the reader is chosen
 * without waiting for more.  A source that ends before the bytes decide it
 * holds no capture.
 */
std::unique_ptr<CaptureReader> makeCaptureReader( HeadSource& source );

/// Result of parsing a whole capture buffer.
struct ParseResult {
    bool ok = false;
    std::string error;
    PcapGlobalHeader header; ///< A pcap's global header; empty for a pcapng.
    TimePrecision precision = TimePrecision::Microseconds; ///< What the reader announced.
    std::vector<uint32_t> linkTypes;                       ///< What the capture declared.
    std::vector<PacketRecord> packets;
    bool truncated = false; ///< The capture ends in the middle of a record.
};

/**
 * Parse a pcap or pcapng capture held in memory, keeping every packet.
 *
 * @param data  Pointer to the raw capture file contents.
 * @param size  Size of the buffer in bytes.
 * @return ParseResult with packets on success, or an error string.
 */
ParseResult parsePcap( const uint8_t* data, size_t size );

} // namespace tcpdump
