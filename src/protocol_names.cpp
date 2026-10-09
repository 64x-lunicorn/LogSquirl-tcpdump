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
 * @file protocol_names.cpp
 * @brief The name tables: IP protocol numbers, EtherTypes and service ports.
 *
 * Each table is a list of number and name, searched front to back; the
 * tables are short and only asked for packets nothing dissects further.
 * Names follow the IANA registries, or what Wireshark shows where that is
 * the better known: a single word, so that the Protocol column stays one.
 */

#include "protocol_names.h"

#include <algorithm>
#include <iterator>

namespace tcpdump {

namespace {

template <typename Number>
struct Name {
    Number number;
    const char* name;
};

/// The name of @p number in @p table, or nullptr.
template <typename Number, size_t N>
const char* lookUp( const Name<Number> ( &table )[ N ], Number number )
{
    const auto entry = std::find_if( std::begin( table ), std::end( table ),
                                     [ number ]( const auto& e ) { return e.number == number; } );
    return entry != std::end( table ) ? entry->name : nullptr;
}

// ── IP protocol numbers ──────────────────────────────────────────────────

constexpr Name<uint8_t> kIpProtocols[] = {
    { 0, "HOPOPT" },       { 1, "ICMP" },        { 2, "IGMP" },        { 3, "GGP" },
    { 4, "IPIP" },         { 6, "TCP" },         { 8, "EGP" },         { 17, "UDP" },
    { 33, "DCCP" },        { 41, "6in4" },       { 43, "IPv6-Route" }, { 44, "IPv6-Frag" },
    { 46, "RSVP" },        { 47, "GRE" },        { 50, "ESP" },        { 51, "AH" },
    { 58, "ICMPv6" },      { 59, "IPv6-NoNxt" }, { 60, "IPv6-Opts" },  { 88, "EIGRP" },
    { 89, "OSPF" },        { 97, "EtherIP" },    { 98, "ENCAP" },      { 103, "PIM" },
    { 108, "IPComp" },     { 112, "VRRP" },      { 113, "PGM" },       { 115, "L2TP" },
    { 124, "ISIS" },       { 132, "SCTP" },      { 135, "Mobility" },  { 136, "UDPLite" },
    { 137, "MPLS-in-IP" }, { 139, "HIP" },       { 140, "Shim6" },     { 143, "Ethernet" },
};

// ── EtherTypes ───────────────────────────────────────────────────────────

constexpr Name<uint16_t> kEtherTypes[] = {
    { EthertypeIpv4, "IPv4" }, { EthertypeArp, "ARP" },
    { 0x0842, "WOL" }, // Wake-on-LAN magic packet
    { 0x22F0, "AVTP" },        { 0x22F3, "TRILL" },
    { 0x6003, "DECnet" },      { 0x8035, "RARP" },
    { 0x809B, "AppleTalk" },   { 0x80F3, "AARP" },
    { EthertypeVlan, "VLAN" }, { 0x8137, "IPX" },
    { EthertypeIpv6, "IPv6" }, { 0x8808, "MAC-Control" }, // Pause frames, priority flow control
    { 0x8809, "LACP" },                                   // The slow protocols: LACP, marker, OAM
    { 0x8847, "MPLS" },        { 0x8848, "MPLS" },        // Multicast
    { 0x8863, "PPPoED" },                                 // PPPoE discovery
    { 0x8864, "PPPoES" },                                 // PPPoE session
    { 0x888E, "EAPOL" },                                  // 802.1X
    { 0x8892, "PROFINET" },    { 0x88A2, "AoE" },
    { 0x88A4, "EtherCAT" },    { EthertypeQinQ, "QinQ" },
    { 0x88AB, "POWERLINK" },   { 0x88B8, "GOOSE" },
    { 0x88BA, "SV" },          { 0x88CC, "LLDP" },
    { 0x88D9, "LLTD" },        { 0x88E1, "HomePlug" },
    { 0x88E3, "MRP" },         { 0x88E5, "MACsec" },
    { 0x88E7, "PBB" },         { 0x88F7, "PTP" },
    { 0x88F8, "NC-SI" },       { 0x88FB, "PRP" },
    { 0x8902, "CFM" },         { 0x8906, "FCoE" },
    { 0x8914, "FIP" },         { 0x8915, "RoCE" },
    { 0x892F, "HSR" },         { 0x893A, "IEEE1905" },
    { 0x9000, "Loopback" },    { EthertypeQinQLegacy, "QinQ" },
};

// ── Service ports ────────────────────────────────────────────────────────

/// The transports a service runs over.
enum On : uint8_t { kTcp = 1, kUdp = 2, kBoth = kTcp | kUdp };

struct Service {
    uint16_t port;
    On on;
    const char* name;
};

constexpr Service kServices[] = {
    { 7, kBoth, "Echo" },
    { 20, kTcp, "FTP-DATA" },
    { 21, kTcp, "FTP" },
    { 22, kTcp, "SSH" },
    { 23, kTcp, "Telnet" },
    { 25, kTcp, "SMTP" },
    { 49, kTcp, "TACACS+" },
    { 53, kBoth, "DNS" },
    { 67, kUdp, "DHCP" },
    { 68, kUdp, "DHCP" },
    { 69, kUdp, "TFTP" },
    { 80, kTcp, "HTTP" },
    { 88, kBoth, "Kerberos" },
    { 110, kTcp, "POP3" },
    { 111, kBoth, "Portmap" },
    { 113, kTcp, "Ident" },
    { 119, kTcp, "NNTP" },
    { 123, kUdp, "NTP" },
    { 137, kUdp, "NBNS" },
    { 138, kUdp, "NBDS" },
    { 139, kTcp, "NBSS" },
    { 143, kTcp, "IMAP" },
    { 161, kUdp, "SNMP" },
    { 162, kUdp, "SNMP-Trap" },
    { 179, kTcp, "BGP" },
    { 389, kBoth, "LDAP" },
    { 427, kBoth, "SLP" },
    { 443, kBoth, "HTTPS" }, // UDP: HTTP/3 over QUIC
    { 445, kTcp, "SMB" },
    { 464, kBoth, "Kpasswd" },
    { 465, kTcp, "SMTPS" },
    { 500, kUdp, "IKE" },
    { 502, kTcp, "Modbus" },
    { 514, kUdp, "Syslog" },
    { 515, kTcp, "LPD" },
    { 520, kUdp, "RIP" },
    { 521, kUdp, "RIPng" },
    { 546, kUdp, "DHCPv6" },
    { 547, kUdp, "DHCPv6" },
    { 554, kTcp, "RTSP" },
    { 587, kTcp, "SMTP" }, // Submission
    { 631, kTcp, "IPP" },
    { 636, kTcp, "LDAPS" },
    { 646, kBoth, "LDP" },
    { 853, kTcp, "DoT" },
    { 853, kUdp, "DoQ" },
    { 873, kTcp, "rsync" },
    { 990, kTcp, "FTPS" },
    { 993, kTcp, "IMAPS" },
    { 995, kTcp, "POP3S" },
    { 1080, kTcp, "SOCKS" },
    { 1194, kBoth, "OpenVPN" },
    { 1433, kTcp, "MSSQL" },
    { 1521, kTcp, "Oracle" },
    { 1701, kUdp, "L2TP" },
    { 1723, kTcp, "PPTP" },
    { 1812, kUdp, "RADIUS" },
    { 1813, kUdp, "RADIUS" }, // Accounting
    { 1883, kTcp, "MQTT" },
    { 1900, kUdp, "SSDP" },
    { 1985, kUdp, "HSRP" },
    { 2049, kBoth, "NFS" },
    { 2123, kUdp, "GTP-C" },
    { 2152, kUdp, "GTP-U" },
    { 3268, kTcp, "LDAP" }, // Global catalog
    { 3306, kTcp, "MySQL" },
    { 3389, kBoth, "RDP" },
    { 3478, kBoth, "STUN" }, // And TURN
    { 3544, kUdp, "Teredo" },
    { 3702, kUdp, "WS-Discovery" },
    { 3784, kUdp, "BFD" },
    { 4500, kUdp, "IPsec-NAT-T" },
    { 4789, kUdp, "VXLAN" },
    { 4840, kTcp, "OPC-UA" },
    { 5060, kBoth, "SIP" },
    { 5061, kTcp, "SIPS" },
    { 5222, kTcp, "XMPP" },
    { 5349, kTcp, "STUN" }, // STUN and TURN over TLS
    { 5353, kUdp, "mDNS" },
    { 5355, kBoth, "LLMNR" },
    { 5432, kTcp, "PostgreSQL" },
    { 5555, kTcp, "ADB" },
    { 5672, kTcp, "AMQP" },
    { 5683, kUdp, "CoAP" },
    { 5900, kTcp, "VNC" },
    { 6081, kUdp, "Geneve" },
    { 6379, kTcp, "Redis" },
    { 6514, kTcp, "Syslog" }, // Over TLS
    { 6667, kTcp, "IRC" },
    { 8080, kTcp, "HTTP-Alt" },
    { 8443, kTcp, "HTTP-Alt" },
    { 9092, kTcp, "Kafka" },
    { 11211, kBoth, "Memcached" },
    { 27017, kTcp, "MongoDB" },
    { 44818, kBoth, "EtherNet/IP" },
    { 47808, kUdp, "BACnet" },
    { 51820, kUdp, "WireGuard" },
};

} // namespace

const char* ipProtocolName( uint8_t protocol )
{
    return lookUp( kIpProtocols, protocol );
}

const char* etherTypeName( uint16_t etherType )
{
    return lookUp( kEtherTypes, etherType );
}

const char* servicePortName( Transport transport, uint16_t port )
{
    const On on = transport == Transport::Tcp ? kTcp : kUdp;
    const auto service
        = std::find_if( std::begin( kServices ), std::end( kServices ), [ & ]( const Service& s ) {
              return s.port == port && ( s.on & on ) != 0;
          } );
    return service != std::end( kServices ) ? service->name : nullptr;
}

} // namespace tcpdump
