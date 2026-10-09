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
 * @file icmp.h
 * @brief The Info of ICMP and ICMPv6 messages.
 *
 * Names a message's type and code in Wireshark's words, and adds what tells
 * one message from another: an echo's id and sequence number, the packet an
 * error message quotes (dissected by dissectQuotedPacket()), the target and
 * link-layer address of neighbor discovery, a router advertisement's flags.
 *
 *     Echo (ping) request id=0x1234, seq=7
 *     Destination unreachable (Port unreachable) for 10.0.0.1:51234 → 192.168.1.5:53 UDP
 *     Neighbor advertisement fe80::2 (rtr, sol, ovr) is at 00:11:22:33:44:55
 *
 * The quoted packet and the options are whatever the sender put there, and
 * often cut: every field is checked against the captured bytes before it is
 * read.  Pure C++ — no Qt dependency.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace tcpdump {

/// Info for the ICMP message at @p data, @p len captured bytes of it, at
/// least its 8-byte header.
std::string describeIcmp( const uint8_t* data, size_t len );

/// Info for the ICMPv6 message at @p data, @p len captured bytes of it, at
/// least its 8-byte header.
std::string describeIcmpv6( const uint8_t* data, size_t len );

} // namespace tcpdump
