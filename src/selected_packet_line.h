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
 * @file selected_packet_line.h
 * @brief Selected Packet Line: the packet of the first Log Line selected in
 *        the tab in front, read through the host, or why there is none.
 *
 * The Packet Panel shows the selected line's packet, and Show stream
 * content and Stream lines in Regex Lab act on its stream.  Each asks here,
 * so that the host's answer and each kind of line turn into the same reason
 * for the user, written once, and a button and the action it starts decide
 * on the same reading of the selection.
 */

#pragma once

#include "packet_line.h"

#include <QByteArray>
#include <QString>

#include <cstddef>
#include <optional>

namespace tcpdump {

/// What the host told of the selected Log Lines.
struct SelectedLines {
    /// get_selected_log_lines()'s result: LOGSQUIRL_LOG_LINES_OK or _TRUNCATED
    /// with the lines, a negative one without.
    int result = 0;
    QByteArray text;      ///< The selected lines, '\n' between them, UTF-8.
    size_t lineCount = 0; ///< How many lines @c text holds.

    bool operator==( const SelectedLines& other ) const
    {
        return result == other.result && text == other.text && lineCount == other.lineCount;
    }
};

/// Ask the host for the selected Log Lines of the tab in front.  Call only
/// when g_state.hostCapabilities has the selected lines, on the UI thread.
SelectedLines readSelectedLines();

/// The first selected line read as a packet line, or why there is none.
struct SelectedPacketLine {
    /// The packet line, its number not 0; none: see reason.
    std::optional<PacketLine> packet;
    /// Why no packet line is selected, for the user: no selection, a tab
    /// without a Log File, a line that is no packet line, a packet number
    /// no packet has.
    QString reason;

    /// Why Show stream content cannot show the packet's stream, for the
    /// user: the reason, or a packet of no stream; empty when it can.
    QString streamContentProblem() const;

    /// Why Stream lines in Regex Lab cannot pick the lines of the packet's
    /// stream, as streamContentProblem(), or because the stream has no
    /// number (the capture has more conversations than the plugin
    /// numbers); empty when it can.
    QString streamLinesProblem() const;
};

/// The packet line of the first line of @p selection, or why there is none.
SelectedPacketLine selectedPacketLine( const SelectedLines& selection );

/// selectedPacketLine() of readSelectedLines(), with its precondition.
SelectedPacketLine readSelectedPacketLine();

/// The reason when no Log Line is selected, which the Packet Panel's empty
/// views say in their own words.
QString selectPacketLineReason();

} // namespace tcpdump
