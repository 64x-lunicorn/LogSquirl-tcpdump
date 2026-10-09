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
 * @file payload_describer.h
 * @brief Names the application protocol of a transport payload and describes it.
 *
 * The Payload Describer is the only place that knows which application
 * protocols exist on which transport and in which order they are tried.
 * It takes the captured payload bytes and the two ports, and returns a
 * protocol label and a one-line description, or no match.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace tcpdump {

/// The transport a payload was carried by.
enum class Transport { Tcp, Udp };

/// What the describer knows about a payload.
struct PayloadDescription {
    std::string label;       ///< Protocol name ("TLS", "HTTP", …); empty: unknown.
    std::string description; ///< One line about the payload; empty: nothing to say.
};

/**
 * Describe the @p len captured payload bytes at @p payload, sent from
 * @p srcPort to @p dstPort over @p transport.
 *
 * The detectors of the transport are tried in a fixed order; the first that
 * recognises the payload names it.  A payload none recognises gets the
 * protocol its port suggests, if any, and a preview of its text.
 */
PayloadDescription describePayload( Transport transport, const uint8_t* payload, size_t len,
                                    uint16_t srcPort, uint16_t dstPort );

} // namespace tcpdump
