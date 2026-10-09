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
 * @file link_layers.h
 * @brief The link layers beyond Ethernet and the cooked captures: IEEE
 *        802.11 (with or without a Radiotap header), PPP, Cisco HDLC and
 *        PPPoE.
 *
 * Each dissector reads its header within the captured bytes and either
 * hands the network layer it carries back to dissectPacket(), or describes
 * the frame itself (`protocol` and `info`): an 802.11 management or control
 * frame, an encrypted data frame, a PPP control protocol, a PPPoE discovery
 * message.  Pure C++, no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace tcpdump {

/// The network layer a link layer carries: what dissectPacket() goes on with.
struct NetworkLayer {
    uint16_t etherType = 0; ///< As an Ethernet header would name it
    const uint8_t* data = nullptr;
    size_t len = 0;
};

/// Whether dissectLinkLayer() reads link-layer type @p linkType.
bool dissectsLinkLayer( uint32_t linkType );

/**
 * Dissect the link-layer header of a packet of one of the link-layer types
 * dissectsLinkLayer() names into @p pkt: the MAC addresses of an 802.11
 * frame, and the frame's protocol and Info when it carries no network layer.
 *
 * @param data  The captured bytes, @p len of them.
 * @return The network layer the frame carries, or nothing when it carries
 *         none, which @p pkt then describes.
 */
std::optional<NetworkLayer> dissectLinkLayer( PacketRecord& pkt, uint32_t linkType,
                                              const uint8_t* data, size_t len );

/**
 * Dissect a PPPoE header and what follows it into @p pkt: a session frame's
 * PPP frame, bounded by the PPPoE length, or a discovery message, which
 * @p pkt then describes.
 *
 * @param data  The bytes behind the Ethernet header (EtherType 0x8863 or
 *              0x8864), @p len of them.
 * @return The network layer a session frame carries, or nothing.
 */
std::optional<NetworkLayer> dissectPppoe( PacketRecord& pkt, const uint8_t* data, size_t len );

} // namespace tcpdump
