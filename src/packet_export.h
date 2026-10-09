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
 * @file packet_export.h
 * @brief Export Packets: the packets of chosen lines, written to a new
 *        capture file as they are in the capture.
 *
 * The packets are found by their numbers (the No. column) through the
 * capture's CaptureIndex and read with one CaptureCursor, in ascending
 * order, so that the capture is read once from front to back.  Each
 * packet's record is copied from the capture file byte for byte, its
 * timestamp, lengths and bytes as they are; nothing is written from what
 * was dissected.  A gzip-compressed capture's records are copied
 * decompressed: the export is an uncompressed pcap or pcapng.
 *
 * A pcap's packets go to a pcap with the capture's global header, so that
 * link-layer type, snaplen and timestamp precision stay the same.  A
 * pcapng's go to a pcapng: ahead of its first exported packet, each
 * section's header block and the interface description blocks it declared,
 * all of them in their order, so that every packet block's interface ID
 * still names its interface and its record needs no change.  Other blocks
 * (name resolution, statistics, custom) are not exported.  The section
 * header's section length is set to "unknown", since the section holds
 * fewer blocks than it did.
 */

#pragma once

#include "capture_index.h"

#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

namespace tcpdump {

/// Packet numbers a user chose, from packet lines or as numbers and ranges.
struct PacketSet {
    std::vector<uint32_t> numbers; ///< Ascending, each once.
    /// Lines and numbers that named no packet of the capture: neither a
    /// packet line nor a number or range of its packets.
    int skipped = 0;
};

/**
 * The packets @p text names, of a capture of @p packets packets: each line
 * a packet line, whose No. column counts, or numbers and ranges ("7",
 * "12-40") separated by commas or spaces.  What is neither, and a number
 * the capture has no packet of, is skipped and counted.
 */
PacketSet parsePacketSet( const QString& text, uint32_t packets );

/// The packets of the packet lines in @p text, such as the selected lines
/// the host tells; every other line is skipped and counted.
PacketSet packetLinesOf( const QString& text, uint32_t packets );

/// @p numbers, ascending, as ranges: "1-5, 9, 12-40".
QString formatPacketRanges( const std::vector<uint32_t>& numbers );

/// The format of the capture file at @p path, as findCaptureStart() tells
/// it; a pcap if it cannot be read.
CaptureFormat captureFormatOf( const QString& path );

/// What exportPackets() did.
struct ExportResult {
    enum class Status {
        Exported,
        Cancelled, ///< Nothing is left behind.
        Failed,    ///< error says why; nothing is left behind.
    };
    Status status = Status::Failed;
    QString error;
    uint32_t packets = 0; ///< Packets written.
    CaptureFormat format = CaptureFormat::Pcap;
};

/**
 * Write the packets @p numbers of the capture @p index points into to a new
 * capture file at @p outputPath, in ascending order, each once.  The file
 * appears only when all are written; one there already is replaced.
 *
 * @param cancel    If set, checked between packets; stops the export.
 * @param progress  Called with the share of packets written, in permille.
 */
ExportResult exportPackets( std::shared_ptr<const CaptureIndex> index,
                            std::vector<uint32_t> numbers, const QString& outputPath,
                            const std::atomic_bool* cancel = nullptr,
                            const std::function<void( int permille )>& progress = {} );

} // namespace tcpdump
