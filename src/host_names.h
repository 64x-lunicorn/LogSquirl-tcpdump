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
 * @file host_names.h
 * @brief The Host Names: the names DNS answers in the capture gave
 *        addresses, which the Source and Destination columns show.
 *
 * Passive name resolution, as Wireshark's from the capture: no lookup is
 * made; a name is known once a DNS or mDNS response in the capture has
 * given it (dnsResolvedNames()), and from then on.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <list>
#include <string>
#include <unordered_map>

namespace tcpdump {

/**
 * The names the capture's DNS answers gave addresses, learned packet by
 * packet in capture order: a name labels an address from the packet after
 * the answer that gave it, never a packet before; there is no look-ahead,
 * so that a live capture and a file read the same.
 *
 * An address has one name, the one learned last: a later answer that gives
 * it another replaces it.  Names come from the responses as they are, not
 * checked against anything: a spoofed answer is learned as any other.
 *
 * Memory is bounded: at most maxNames addresses keep a name, each costing
 * its address and its name (at most kMaxHostName bytes) and some
 * bookkeeping, about 300 bytes at most, 2.5 MB for kMaxNames.  Past the
 * cap, the address whose name was learned longest ago loses it, and shows
 * as before.
 */
class HostNames {
public:
    /// Addresses that keep a name at most, by default.
    static constexpr size_t kMaxNames = 8192;

    explicit HostNames( size_t maxNames = kMaxNames );

    /**
     * Learn the names of @p pkt, if it carries DNS responses: a UDP
     * datagram from port 53 (DNS) or 5353 (mDNS), its @p payload one
     * message; a TCP segment from port 53, the whole DNS messages it
     * completed in @p tcpMessages, each behind its 2-byte length, as the
     * TCP Reassembly hands them out.  Other packets teach nothing; DNS over
     * TLS or HTTPS is not read.
     */
    void learn( const PacketRecord& pkt, ByteView payload, ByteView tcpMessages );

    /// Give @p address the name @p name, in place of any it had.
    void add( const std::string& address, const std::string& name );

    /// The name of @p address, or null without one.  Valid until the next
    /// learn() or add().
    const std::string* find( const std::string& address ) const;

    /// Addresses with a name.
    size_t size() const
    {
        return names_.size();
    }

private:
    struct Entry {
        std::string name;
        std::list<std::string>::iterator age; ///< Its place in order_.
    };

    void learnMessage( const uint8_t* message, size_t len );

    size_t maxNames_;
    std::unordered_map<std::string, Entry> names_;
    std::list<std::string> order_; ///< The addresses, the name learned longest ago first.
};

} // namespace tcpdump
