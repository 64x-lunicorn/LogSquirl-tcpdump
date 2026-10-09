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
 * @file packet_layers.h
 * @brief The layers of one packet as the Packet Panel shows them: each
 *        header the Parser read, with its named fields and the bytes of each.
 *
 * The dissectors that write a packet's columns also describe its layers,
 * when asked to: a PacketRecord whose `layers` points at a PacketLayers
 * gets every header the Parser reads added to it, outermost first, so the
 * tree the panel shows is the one the line was made from, not a second
 * reading of Info.  The Converter never asks, and pays nothing for it.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump {

/// A named field of a layer, and where its bytes are in the packet.
struct LayerField {
    std::string name;  ///< "Source Port", "Flags", …
    std::string value; ///< As shown: "443", "0x018 (PSH, ACK)", …
    size_t offset = 0; ///< From the first captured byte of the packet.
    size_t length = 0; ///< 0 for a field that has no bytes of its own.
};

/// A layer of a packet: a header the Parser read, or the payload it carries.
struct PacketLayer {
    std::string name;  ///< "Ethernet II", "Internet Protocol Version 4", "TCP", …
    size_t offset = 0; ///< From the first captured byte of the packet.
    size_t length = 0; ///< Captured bytes of the layer.
    std::vector<LayerField> fields;
};

/**
 * Collects the layers of one packet while it is dissected.  The dissectors
 * pass where a header or field starts as a pointer into the packet's bytes;
 * it is turned into an offset here and cut to the captured bytes, so that
 * a header cut short never claims bytes the capture lacks.
 */
class PacketLayers {
public:
    /// For the packet whose captured bytes are @p packet, @p len of them.
    PacketLayers( const uint8_t* packet, size_t len )
        : packet_( packet )
        , len_( len )
    {
    }

    /// Begin a layer named @p name, @p length bytes from @p at.
    void layer( std::string name, const uint8_t* at, size_t length );

    /// Make the layer begun last @p length bytes long, cut to the packet:
    /// for a header whose length is only known once its first fields are read.
    void setLength( size_t length );

    /// Add a field to the layer begun last; ignored before the first.
    void field( std::string name, std::string value, const uint8_t* at, size_t length );

    /// The layers so far, outermost first.
    const std::vector<PacketLayer>& layers() const
    {
        return layers_;
    }

    /// Take the layers out.
    std::vector<PacketLayer> take()
    {
        return std::move( layers_ );
    }

private:
    /// Offset and length of @p length bytes at @p at, cut to the packet.
    std::pair<size_t, size_t> span( const uint8_t* at, size_t length ) const;

    const uint8_t* packet_;
    size_t len_;
    std::vector<PacketLayer> layers_;
};

/**
 * The layers of @p record, a packet a CaptureReader returned, from its
 * captured bytes @p data (@p len of them, as the reader kept them) and the
 * capture's byte order @p swap: a Frame layer for the record itself, then
 * every layer dissectPacket() reads.  The payload's layer is named as the
 * Payload Describer recognises it from the packet alone; what only the
 * packet's stream tells (describeInStream()) is not known here.
 */
std::vector<PacketLayer> dissectLayers( const PacketRecord& record, const uint8_t* data, size_t len,
                                        bool swap );

/// @p value as "0x" and @p digits hex digits, upper case: "0x0800".
std::string hexField( uint64_t value, int digits );

/// An EtherType as a field shows it: "IPv4 (0x0800)", or "0x88B5".
std::string etherTypeField( uint16_t etherType );

/// An IP protocol as a field shows it: "TCP (6)", or "253".
std::string ipProtocolField( uint8_t protocol );

} // namespace tcpdump
