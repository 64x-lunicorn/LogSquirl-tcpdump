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
#include <cstdint>
#include <list>
#include <string>
#include <unordered_map>
#include <vector>

namespace tcpdump {

/// An address a DNS response resolved, and the name it resolved it from.
struct ResolvedName {
    std::string address; ///< As the Source and Destination columns write it.
    std::string name;    ///< "www.example.com"
};

/**
 * The names the DNS response of @p len bytes at @p message (a DNS or mDNS
 * message, without the length DNS over TCP puts before it) gives addresses,
 * in the order of its answers: an A or AAAA answer names its address with
 * the name the client asked for, its owner followed back through the
 * CNAME answers of the message ("www.example.com CNAME example.com,
 * example.com A 93.184.216.34" names 93.184.216.34 www.example.com); a
 * PTR answer for an in-addr.arpa or ip6.arpa name names the address that
 * name spells.  Only the answer section is read, with @p mdns (a
 * message of mDNS, whose responses put the addresses of a service in it)
 * the additional section too, at most kMaxResolvedNames records in all,
 * and only a standard query's response without an error; a record cut
 * short ends the list.  An mDNS record with TTL 0, a goodbye, names
 * nothing.  A name that is not a host name (isHostName()) names nothing.
 * Nothing is validated beyond that: a response that claims a name gets
 * it.  Defined in describe_dns.cpp, with the DNS parser it reads by.
 */
std::vector<ResolvedName> dnsResolvedNames( const uint8_t* message, size_t len, bool mdns = false );

/// Answers of one DNS message dnsResolvedNames() reads at most.
constexpr size_t kMaxResolvedNames = 32;

/// Besides ASCII letters and digits, the characters a host name may hold
/// (isHostName()), as the Regex Lab's patterns match a name behind an
/// address (nameSuffixPattern(), regex_lab.h): in this order, '-' last, so
/// that they stand in a regular expression's character class as they are.
constexpr const char* kHostNamePunctuation = "_.-";

/**
 * Whether @p name can stand in a column as a host name: 1 to kMaxHostName
 * ASCII letters, digits and kHostNamePunctuation, not starting with '.',
 * so that it neither breaks a column into two nor reads as anything but a
 * name.
 */
bool isHostName( const std::string& name );

/// The longest host name kept, in bytes (RFC 1035 allows 253 characters).
constexpr size_t kMaxHostName = 120;

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

    /// Learn the names of a DNS message, of mDNS's with @p mdns.
    void learnMessage( const uint8_t* message, size_t len, bool mdns );

    size_t maxNames_;
    std::unordered_map<std::string, Entry> names_;
    std::list<std::string> order_; ///< The addresses, the name learned longest ago first.
};

} // namespace tcpdump
