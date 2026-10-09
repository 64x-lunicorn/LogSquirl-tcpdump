#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/interfaces.pcapng, the corpus's self-made pcapng capture.

Every byte is made up here, so the capture is free of anyone's traffic and
of licence questions.  It holds two sections:

1. Little-endian: a name resolution block, an Ethernet interface with the
   default microsecond unit, a Raw IP interface with nanoseconds (if_tsresol
   9), and packets on both, with a statistics and a custom block in between.
2. Big-endian: a Linux SLL2 interface with a unit of 2^-20 seconds, and a
   packet on it.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet


def pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


class Section:
    def __init__(self, endian: str):
        self.e = endian  # "<" or ">"

    def block(self, kind: int, body: bytes) -> bytes:
        body = pad(body)
        length = len(body) + 12
        return struct.pack(self.e + "II", kind, length) + body + struct.pack(self.e + "I", length)

    def option(self, code: int, value: bytes) -> bytes:
        return struct.pack(self.e + "HH", code, len(value)) + pad(value)

    def end(self) -> bytes:
        return self.option(0, b"")

    def shb(self) -> bytes:
        body = struct.pack(self.e + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        return self.block(0x0A0D0D0A, body + self.option(4, b"make_pcapng_corpus.py") + self.end())

    def idb(self, link_type: int, name: bytes, tsresol=None) -> bytes:
        body = struct.pack(self.e + "HHI", link_type, 0, 262144) + self.option(2, name)
        if tsresol is not None:
            body += self.option(9, bytes([tsresol]))
        return self.block(1, body + self.end())

    def epb(self, interface: int, timestamp: int, data: bytes, comment=None) -> bytes:
        body = struct.pack(self.e + "IIIII", interface, timestamp >> 32, timestamp & 0xFFFFFFFF,
                           len(data), len(data)) + pad(data)
        if comment:
            body += self.option(1, comment) + self.end()
        return self.block(6, body)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(proto: int, src: str, dst: str, payload: bytes) -> bytes:
    addr = lambda a: bytes(int(x) for x in a.split("."))
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x1C46, 0x4000, 64, proto, 0,
                         addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(next_header: int, src: bytes, dst: bytes, payload: bytes) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64) + src + dst + payload


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload


def ether(ethertype: int, payload: bytes) -> bytes:
    dst = bytes.fromhex("02005e000001")
    src = bytes.fromhex("02005e000002")
    return dst + src + struct.pack("!H", ethertype) + payload


def sll2(ethertype: int, payload: bytes) -> bytes:
    # protocol, reserved, interface index, ARPHRD_ETHER, outgoing, address length 6
    return struct.pack("!HHIHBB", ethertype, 0, 2, 1, 4, 6) + bytes.fromhex("02005e0000030000") + payload


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x2A2A, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def icmp_echo(kind: int, ident: int, seq: int) -> bytes:
    """An echo request (kind 8) or reply (kind 0)."""
    body = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + b"pcapng-corpus"
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def main() -> None:
    le = Section("<")
    us = lambda s, f: (BASE + s) * 1000000 + f  # microsecond interface
    ns = lambda s, f: (BASE + s) * 1000000000 + f  # nanosecond interface

    host, router, server = "192.0.2.10", "192.0.2.1", "198.51.100.7"
    first = (
        le.shb()
        + le.block(4, struct.pack("<HH", 1, 4 + len(b"router.example\0")) + bytes([192, 0, 2, 1])
                   + pad(b"router.example\0") + struct.pack("<HH", 0, 0))
        + le.idb(1, b"eth0")
        + le.idb(101, b"tun0", 9)
        + le.epb(0, us(0, 0), ether(0x0800, ipv4(17, host, router,
                                                  udp(53001, 53, dns_query("example.org")))))
        + le.epb(1, ns(0, 1234567), ipv4(1, "10.8.0.2", "10.8.0.1", icmp_echo(8, 0x77, 1)),
                 b"on the tunnel")
        + le.epb(0, us(0, 2500), ether(0x0800, ipv4(6, host, server, tcp(50100, 443, 1000, 0, 0x02))))
        + le.block(5, struct.pack("<III", 0, us(0, 3000) >> 32, us(0, 3000) & 0xFFFFFFFF) + le.end())
        + le.block(0x40000BAD, struct.pack("<I", 32473) + b"custom data")
        + le.epb(1, ns(0, 3000001), ipv4(1, "10.8.0.1", "10.8.0.2", icmp_echo(0, 0x77, 1)))
        + le.epb(0, us(0, 4000), ether(0x0800, ipv4(6, server, host,
                                                    tcp(443, 50100, 5000, 1001, 0x12))))
    )

    be = Section(">")
    a = bytes.fromhex("20010db8000000000000000000000001")
    b = bytes.fromhex("20010db8000000000000000000000002")
    second = (
        be.shb()
        + be.idb(276, b"any", 0x80 | 20)
        + be.epb(0, ((BASE + 1) << 20) + (1 << 19), sll2(0x86DD, ipv6(17, a, b, udp(5353, 5353, dns_query("printer.local")))))
    )

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "interfaces.pcapng"
    out.write_bytes(first + second)


if __name__ == "__main__":
    main()
