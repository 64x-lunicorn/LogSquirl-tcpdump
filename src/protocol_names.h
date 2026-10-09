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
 * @file protocol_names.h
 * @brief The name tables: IP protocol numbers, EtherTypes and well-known
 *        service ports.
 *
 * Names only, no dissection: the Parser asks for the name of an IP protocol
 * or EtherType it does not dissect further, the Payload Describer for the
 * service a port suggests.  A name is one word, as the Protocol column
 * needs it; an unknown number has none (nullptr), and the caller keeps its
 * numeric form.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstdint>

namespace tcpdump {

/// The name of IP protocol @p protocol ("IGMP", "ESP", …), or nullptr.
const char* ipProtocolName( uint8_t protocol );

/// The name of EtherType @p etherType ("LLDP", "PPPoES", …), or nullptr.
const char* etherTypeName( uint16_t etherType );

/// The service @p port is assigned to on @p transport ("SNMP" on UDP 161,
/// "RDP" on TCP 3389, …), or nullptr.  A service is named only on the
/// transport it runs over.
const char* servicePortName( Transport transport, uint16_t port );

} // namespace tcpdump
