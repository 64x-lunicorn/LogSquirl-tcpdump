#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/tunnels.pcap, the corpus's capture of tunnelled packets.

Every byte is made up here, so the capture holds no one's traffic.  Two
tunnel endpoints, 203.0.113.1 and 203.0.113.2 (2001:db8:ffff::1 and ::2 for
IPv6), carry the packets of hosts behind them.  The capture holds:

1. VXLAN, VNI 100: a TCP handshake and a request in it, then an ARP request.
2. GRE without options carrying an ICMP echo; GRE with key and sequence
   number carrying a DNS query; GRE with a key carrying an Ethernet frame
   (NVGRE); GRE carrying a protocol that is not dissected (ERSPAN).
3. IPv4-in-IPv4, IPv6-in-IPv4 (6in4), IPv4-in-IPv6 and IPv6-in-IPv6.
4. A GRE tunnel inside VXLAN, and a packet nested in five IP-in-IP tunnels,
   one more than are unwrapped.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
EDGE_A, EDGE_B = "203.0.113.1", "203.0.113.2"
EDGE6_A, EDGE6_B = "2001:db8:ffff::1", "2001:db8:ffff::2"
CLIENT, SERVER = "10.1.0.10", "10.2.0.20"
CLIENT6, SERVER6 = "2001:db8:1::10", "2001:db8:2::20"
EDGE_MAC_A, EDGE_MAC_B = bytes.fromhex("02005e00ff01"), bytes.fromhex("02005e00ff02")
CLIENT_MAC, SERVER_MAC = bytes.fromhex("02005e000110"), bytes.fromhex("02005e000220")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ttl: int = 64) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x5501, 0x4000, ttl,
                         protocol, 0, ipaddress.IPv4Address(src).packed,
                         ipaddress.IPv4Address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hops: int = 64) -> bytes:
    return (struct.pack("!IHBB", 0x60000000, len(payload), next_header, hops)
            + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload)


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    """A TCP segment; its checksum is left 0, as nothing here checks it."""
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 64240, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(ident: int, seq: int) -> bytes:
    message = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + b"made-up ping payload"
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return struct.pack("!HHHHHH", 0x5E5E, 0x0100, 1, 0, 0, 0) + labels + b"\0" + \
        struct.pack("!HH", 1, 1)


def ether(src: bytes, dst: bytes, ether_type: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ether_type) + payload


def vxlan(vni: int, frame: bytes) -> bytes:
    return struct.pack("!BxxxI", 0x08, vni << 8) + frame


def gre(protocol_type: int, payload: bytes, key: int = None, seq: int = None) -> bytes:
    flags = (0x2000 if key is not None else 0) | (0x1000 if seq is not None else 0)
    header = struct.pack("!HH", flags, protocol_type)
    if key is not None:
        header += struct.pack("!I", key)
    if seq is not None:
        header += struct.pack("!I", seq)
    return header + payload


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 2500
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def edge4(self, protocol: int, payload: bytes, back: bool = False) -> None:
        """@p payload in an IPv4 packet from one tunnel endpoint to the other."""
        src, dst = (EDGE_B, EDGE_A) if back else (EDGE_A, EDGE_B)
        macs = (EDGE_MAC_B, EDGE_MAC_A) if back else (EDGE_MAC_A, EDGE_MAC_B)
        self.add(ether(*macs, 0x0800, ipv4(src, dst, protocol, payload)))

    def edge6(self, next_header: int, payload: bytes) -> None:
        self.add(ether(EDGE_MAC_A, EDGE_MAC_B, 0x86DD, ipv6(EDGE6_A, EDGE6_B, next_header,
                                                            payload)))

    def vxlan(self, frame: bytes, back: bool = False) -> None:
        self.edge4(17, udp(49152 + len(self.records), 4789, vxlan(100, frame)), back)

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


def main() -> None:
    capture = Capture()

    # VXLAN: a TCP handshake and a request, then an ARP request
    def inner(src, dst, segment, back=False):
        macs = (SERVER_MAC, CLIENT_MAC) if back else (CLIENT_MAC, SERVER_MAC)
        return ether(*macs, 0x0800, ipv4(src, dst, 6, segment))

    capture.vxlan(inner(CLIENT, SERVER, tcp(50000, 8080, 1000, 0, 0x02)))
    capture.vxlan(inner(SERVER, CLIENT, tcp(8080, 50000, 5000, 1001, 0x12), True), True)
    capture.vxlan(inner(CLIENT, SERVER, tcp(50000, 8080, 1001, 5001, 0x10)))
    capture.vxlan(inner(CLIENT, SERVER, tcp(50000, 8080, 1001, 5001, 0x18,
                                            b"GET /status HTTP/1.1\r\nHost: tunnelled.test\r\n\r\n")))
    arp = struct.pack("!HHBBH6s4s6s4s", 1, 0x0800, 6, 4, 1, CLIENT_MAC,
                      ipaddress.IPv4Address(CLIENT).packed, bytes(6),
                      ipaddress.IPv4Address("10.1.0.1").packed)
    capture.vxlan(ether(CLIENT_MAC, b"\xff" * 6, 0x0806, arp))

    # GRE
    capture.edge4(47, gre(0x0800, ipv4(CLIENT, SERVER, 1, icmp_echo(0x4E01, 1))))
    capture.edge4(47, gre(0x0800, ipv4(CLIENT, SERVER, 17,
                                       udp(53053, 53, dns_query("tunnelled.test"))),
                          key=42, seq=1))
    capture.edge4(47, gre(0x6558, inner(CLIENT, SERVER, tcp(50001, 8080, 2000, 0, 0x02)),
                          key=0x00012300))
    capture.edge4(47, gre(0x88BE, bytes(24), seq=7))

    # IP in IP
    capture.edge4(4, ipv4(CLIENT, SERVER, 17, udp(53054, 53, dns_query("ipip.test"))))
    capture.edge4(41, ipv6(CLIENT6, SERVER6, 6, tcp(50002, 443, 3000, 0, 0x02)))
    capture.edge6(4, ipv4(CLIENT, SERVER, 1, icmp_echo(0x4E02, 1)))
    capture.edge6(41, ipv6(CLIENT6, SERVER6, 17, udp(53055, 53, dns_query("6in6.test"))))

    # Nesting: GRE inside VXLAN, and one IP-in-IP tunnel too many
    capture.vxlan(ether(EDGE_MAC_A, EDGE_MAC_B, 0x0800,
                        ipv4("192.0.2.1", "192.0.2.2", 47,
                             gre(0x0800, ipv4(CLIENT, SERVER, 1, icmp_echo(0x4E03, 1))))))
    packet = ipv4(CLIENT, SERVER, 1, icmp_echo(0x4E04, 1))
    for hop in range(4):
        packet = ipv4("198.51.100.%d" % (hop * 2 + 1), "198.51.100.%d" % (hop * 2 + 2), 4, packet)
    capture.edge4(4, packet)

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "tunnels.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
