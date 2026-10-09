#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/icmp.pcap, the corpus's ICMP and ICMPv6 capture.

Every byte is made up here, so the capture holds no one's traffic.  Error
messages quote the packet they report as routers and hosts do: an ICMP one
its IP header and the first 8 bytes behind it, an ICMPv6 one as much of it
as fits into the minimum MTU.  The capture holds:

1. ICMP: an echo request and its reply, a port unreachable for a DNS query,
   a TTL exceeded for a traceroute probe, a fragmentation needed with the
   next hop's MTU, a redirect, and a port unreachable whose quote is cut
   inside the IP header.
2. ICMPv6: an echo request and its reply, a router solicitation and
   advertisement, a neighbor solicitation and advertisement, a port
   unreachable and a packet too big.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
HOST, ROUTER, SERVER = "192.0.2.10", "192.0.2.1", "198.51.100.53"
HOST6, ROUTER6, SERVER6 = "2001:db8::10", "fe80::1", "2001:db8:1::53"
HOST_MAC, ROUTER_MAC = bytes.fromhex("02005e000010"), bytes.fromhex("02005e000001")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, protocol: int, payload: bytes, ttl: int = 64,
         total: int = 0) -> bytes:
    """An IPv4 packet; @p total overrides its total length, as a quote's keeps the original's."""
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total or 20 + len(payload), 0x2F01, 0x4000,
                         ttl, protocol, 0, ipaddress.IPv4Address(src).packed,
                         ipaddress.IPv4Address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes, hops: int = 64) -> bytes:
    return (struct.pack("!IHBB", 0x60000000, len(payload), next_header, hops)
            + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload)


def icmp(kind: int, code: int, rest: int, body: bytes = b"") -> bytes:
    message = struct.pack("!BBHI", kind, code, 0, rest) + body
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def icmp6(src: str, dst: str, kind: int, code: int, rest: int, body: bytes = b"") -> bytes:
    message = struct.pack("!BBHI", kind, code, 0, rest) + body
    pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
              + struct.pack("!IxxxB", len(message), 58))
    return message[:2] + struct.pack("!H", checksum(pseudo + message)) + message[4:]


def ether(src: bytes, dst: bytes, ether_type: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ether_type) + payload


def quote(packet: bytes) -> bytes:
    """What a router quotes of an IPv4 packet: its header and 8 bytes."""
    return packet[:28]


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 1500
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def v4(self, src: str, dst: str, message: bytes, ttl: int = 64) -> None:
        self.add(ether(HOST_MAC, ROUTER_MAC, 0x0800, ipv4(src, dst, 1, message, ttl)))

    def v6(self, src: str, dst: str, kind: int, code: int, rest: int, body: bytes = b"") -> None:
        message = icmp6(src, dst, kind, code, rest, body)
        self.add(ether(HOST_MAC, ROUTER_MAC, 0x86DD, ipv6(src, dst, 58, message, 255)))

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


def main() -> None:
    capture = Capture()

    # ICMP
    capture.v4(HOST, SERVER, icmp(8, 0, 0x4D2A0001, b"made-up ping payload"))
    capture.v4(SERVER, HOST, icmp(0, 0, 0x4D2A0001, b"made-up ping payload"))
    dns = ipv4(HOST, SERVER, 17, struct.pack("!HHHH", 53001, 53, 37, 0) + bytes(29))
    capture.v4(SERVER, HOST, icmp(3, 3, 0, quote(dns)))
    probe = ipv4(HOST, SERVER, 17, struct.pack("!HHHH", 33434, 33435, 40, 0) + bytes(32), ttl=1)
    capture.v4(ROUTER, HOST, icmp(11, 0, 0, quote(probe)))
    big = ipv4(HOST, SERVER, 6, struct.pack("!HHIIBBHHH", 50100, 443, 1000, 1, 0x50, 0x18, 64240,
                                            0, 0) + bytes(1460))
    capture.v4(ROUTER, HOST, icmp(3, 4, 1400, quote(big)))
    capture.v4(ROUTER, HOST, icmp(5, 1, 0xC00002FE, quote(dns)))
    capture.v4(SERVER, HOST, icmp(3, 3, 0, quote(dns)[:12]))

    # ICMPv6
    capture.v6(HOST6, SERVER6, 128, 0, 0x4D2B0001, b"made-up ping payload")
    capture.v6(SERVER6, HOST6, 129, 0, 0x4D2B0001, b"made-up ping payload")
    source_link = bytes([1, 1]) + HOST_MAC
    router_link = bytes([1, 1]) + ROUTER_MAC
    capture.v6("fe80::10", "ff02::2", 133, 0, 0, source_link)
    # Hop limit 64, managed and other configuration, lifetime 1800 s.
    capture.v6(ROUTER6, "ff02::1", 134, 0, 0x40C00708, bytes(8) + router_link)
    target = ipaddress.IPv6Address(ROUTER6).packed
    capture.v6("fe80::10", "ff02::1:ff00:1", 135, 0, 0, target + source_link)
    capture.v6(ROUTER6, "fe80::10", 136, 0, 0xE0000000, target + bytes([2, 1]) + ROUTER_MAC)
    query = ipv6(HOST6, SERVER6, 17, struct.pack("!HHHH", 53002, 53, 37, 0) + bytes(29))
    capture.v6(SERVER6, HOST6, 1, 4, 0, query)
    segment = ipv6(HOST6, SERVER6, 6, struct.pack("!HHIIBBHHH", 50200, 443, 1000, 1, 0x50, 0x18,
                                                  64240, 0, 0) + bytes(1400))
    capture.v6(ROUTER6, HOST6, 2, 0, 1280, segment[:1280 - 48])

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "icmp.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
