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
 * @file follow_stream.h
 * @brief Follow stream: a Regex Lab pattern for the conversation of a
 *        selected packet line.
 *
 * The packet line's Stream column numbers TCP and UDP conversations each on
 * their own, so a stream number alone names two conversations.  The pattern
 * also requires the packet's two addresses and two ports, in either
 * direction, which a TCP and a UDP conversation of the same number share
 * only in the rarest of captures.
 */

#pragma once

#include <QString>

namespace tcpdump {

/// The pattern that follows a packet line's stream, or why there is none.
struct FollowStream {
    QString pattern; ///< Matches the lines of the stream; empty: see reason.
    QString reason;  ///< Why the line has no stream to follow, for the user.
};

/// The Regex Lab pattern that matches exactly the lines of the stream of
/// @p packetLine, a line of the packet list.
FollowStream followStreamPattern( const QString& packetLine );

/// Plugins > tcpdump > Follow stream: open the Regex Lab with the pattern
/// for the first Log Line selected in the tab in front, or notify the user
/// why not.  The pattern the user applies or the cancel is logged.  Call
/// only when g_state.hostCapabilities has the Regex Lab and the selected
/// lines, on the UI thread.
void followSelectedStream();

} // namespace tcpdump
