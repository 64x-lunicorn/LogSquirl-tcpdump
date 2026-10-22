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
 * @file packet_line.h
 * @brief A packet line read back: the columns the Packet Formatter
 *        (packet_formatter.h) wrote.
 *
 * The plugin acts on the lines it wrote: the Packet Panel shows the
 * selected line's packet, Filter stream in Regex Lab picks the lines of its
 * stream, Export packets takes the packets of the selected lines.  Each
 * reads the line here, in any Line Layout, so that the grammar that writes
 * a line and the one that reads it sit side by side, and
 * packet_line_test.cpp checks that a line reads back as it was written.
 */

#pragma once

#include "stream_tracker.h"

#include <QRegularExpression>
#include <QString>

#include <cstdint>
#include <optional>

namespace tcpdump {

/// A packet line, as the Log Format formats/tcpdump_log.json reads it, with
/// the same named groups: the two must be the same, which
/// logformat_test.cpp checks.
const QRegularExpression& packetLineRegex();

/// The columns of a packet line that the plugin acts on.
struct PacketLine {
    /// No.: the packet's number in its capture, from 1; 0 when the column
    /// holds a number no packet has.
    uint32_t number = 0;
    /// Stream: its number from the Stream Tracker, or kNoStream ("-") or
    /// kUnnumbered ("?", and when the column holds a number no stream has).
    int stream = kNoStream;
    /// Source and Destination, with the name host names put behind the
    /// address (LineLayout::hostNames), "-" for none.
    QString source;
    QString destination;
    QString protocol;
    /// Info, after the MAC columns a Line Layout may put at its start: the
    /// rest of the line, as the Log Format's body.
    QString body;
    /// The handshake's initial round-trip time in seconds, "0.012345", that
    /// the TCP Analysis puts in Info of the ACK that completes it
    /// ("[iRTT=0.012345]"); empty on every other line.
    QString irtt;
};

/// @p line read as a packet line, or none when it is not one: another
/// log's line, the column header, a line cut short.  @p line is one line,
/// without its newline.
std::optional<PacketLine> readPacketLine( const QString& line );

} // namespace tcpdump
