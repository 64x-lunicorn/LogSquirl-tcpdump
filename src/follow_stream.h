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
 * @brief Filter stream in Regex Lab: a Regex Lab pattern for the
 *        conversation of a selected packet line.
 *
 * The packet line's Stream column numbers TCP and UDP conversations each on
 * their own, so a stream number alone names two conversations.  The pattern
 * also requires the packet's two addresses and two ports, in either
 * direction, which a TCP and a UDP conversation of the same number share
 * only in the rarest of captures.
 */

#pragma once

#include "packet_line.h"

#include <QString>

#include <cstdint>

namespace tcpdump {

/// The Regex Lab pattern that matches exactly the lines of the stream of
/// @p packet, a line of the packet list; empty when its stream has no
/// number (SelectedPacketLine::streamLinesProblem() says why).
QString followStreamPattern( const PacketLine& packet );

/// The Regex Lab pattern that matches exactly the lines of stream @p stream
/// between @p addressA port @p portA and @p addressB port @p portB, as the
/// Conversations table lists it; the transport is told by the ports, as
/// followStreamPattern() tells it.
QString conversationPattern( int stream, const QString& addressA, uint16_t portA,
                             const QString& addressB, uint16_t portB );

/// Open the Regex Lab with the pattern of the lines of @p packet's stream.
/// The pattern the user applies or the cancel is logged.  Plugins > tcpdump
/// > Filter stream in Regex Lab and the sidebar's button call it through
/// SidebarWidget::openStreamLines() with the packet line the Packet Panel
/// read from the selection, once its streamLinesProblem() is empty.  Call
/// only when g_state.hostCapabilities has the Regex Lab, on the UI thread.
void followStream( const PacketLine& packet );

} // namespace tcpdump
