#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/dhcp-ntp.pcap, the corpus's DHCP, DHCPv6 and NTP capture.

Every byte is made up here, so the capture holds no one's traffic.  The
capture holds:

1. DHCP: a Discover with a host name, the server's Offer, the Request for
   the offered address and the ACK, as a client asks for a lease; then a
   Request whose options overflow into the file field (option overload).
2. DHCPv6: a Solicit, the server's Advertise, and a Solicit relayed by a
   relay agent (Relay-forw).
3. NTP: a client request and a stratum 2 server's reply, a stratum 1
   server's reply naming its reference (GPS), and a kiss-o'-death (RATE).

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT_MAC, SERVER_MAC = bytes.fromhex("02005e000010"), bytes.fromhex("02005e000001")
BROADCAST_MAC = b"\xff" * 6
SERVER, LEASED = "192.0.2.1", "192.0.2.50"
CLIENT6, SERVER6, RELAY6 = "fe80::10", "fe80::1", "2001:db8:1::1"
NTP_CLIENT, NTP_SERVER = "192.0.2.10", "198.51.100.123"
XID = 0x3903F326


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x2F01, 0, 64, 17, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def udp4(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    """A UDP datagram over IPv4, without a checksum (0), as UDP over IPv4 may be."""
    return ipv4(src, dst, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def udp6(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    datagram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = (ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed
              + struct.pack("!IxxxB", len(datagram), 17))
    datagram = datagram[:6] + struct.pack("!H", checksum(pseudo + datagram)) + datagram[8:]
    return (struct.pack("!IHBB", 0x60000000, len(datagram), 17, 255)
            + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + datagram)


def ether(src: bytes, dst: bytes, ether_type: int, payload: bytes) -> bytes:
    return dst + src + struct.pack("!H", ether_type) + payload


def option(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def dhcp(op: int, message_type: int, options: bytes, yiaddr: str = "0.0.0.0",
         file: bytes = b"") -> bytes:
    """A DHCP message from or to CLIENT_MAC, with transaction id XID."""
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, XID, 0, 0x8000, bytes(4),
                         ipaddress.IPv4Address(yiaddr).packed, bytes(4), bytes(4), CLIENT_MAC,
                         b"", file)
    return (header + struct.pack("!I", 0x63825363) + option(53, bytes([message_type])) + options
            + b"\xff")


def option6(code: int, value: bytes) -> bytes:
    return struct.pack("!HH", code, len(value)) + value


DUID = struct.pack("!HHI", 1, 1, 0x1C39CF88) + CLIENT_MAC  # DUID-LLT
SERVER_DUID = struct.pack("!HHI", 1, 1, 0x1C39CF00) + SERVER_MAC


def dhcpv6(message_type: int, options: bytes) -> bytes:
    return bytes([message_type, 0x1A, 0x2B, 0x3C]) + options


def ntp(mode: int, stratum: int, reference: bytes) -> bytes:
    """A 48-byte NTPv4 header: poll 6, precision -20, timestamps left 0."""
    return struct.pack("!BBbbII4s", (4 << 3) | mode, stratum, 6, -20, 0, 0, reference) + bytes(32)


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 1500
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def v4(self, src_mac: bytes, dst_mac: bytes, packet: bytes) -> None:
        self.add(ether(src_mac, dst_mac, 0x0800, packet))

    def v6(self, src_mac: bytes, dst_mac: bytes, packet: bytes) -> None:
        self.add(ether(src_mac, dst_mac, 0x86DD, packet))

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


def main() -> None:
    capture = Capture()
    server_id = option(54, ipaddress.IPv4Address(SERVER).packed)
    leased = ipaddress.IPv4Address(LEASED).packed
    lease = server_id + option(51, struct.pack("!I", 86400)) + option(1, bytes([255, 255, 255, 0]))

    # DHCP
    capture.v4(CLIENT_MAC, BROADCAST_MAC, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp(
        1, 1, option(12, b"made-up-laptop") + option(55, bytes([1, 3, 6, 15])))))
    capture.v4(SERVER_MAC, CLIENT_MAC, udp4(SERVER, LEASED, 67, 68, dhcp(2, 2, lease, LEASED)))
    capture.v4(CLIENT_MAC, BROADCAST_MAC, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp(
        1, 3, option(50, leased) + server_id + option(12, b"made-up-laptop"))))
    capture.v4(SERVER_MAC, CLIENT_MAC, udp4(SERVER, LEASED, 67, 68, dhcp(2, 5, lease, LEASED)))
    overflow = option(50, leased) + option(12, b"made-up-laptop") + b"\xff"
    capture.v4(CLIENT_MAC, BROADCAST_MAC, udp4("0.0.0.0", "255.255.255.255", 68, 67, dhcp(
        1, 3, option(52, b"\x01"), file=overflow)))

    # DHCPv6
    solicit = dhcpv6(1, option6(1, DUID) + option6(8, b"\0\0") + option6(6, struct.pack("!HH", 23,
                                                                                         24)))
    capture.v6(CLIENT_MAC, bytes.fromhex("333300010002"), udp6(CLIENT6, "ff02::1:2", 546, 547,
                                                                solicit))
    capture.v6(SERVER_MAC, CLIENT_MAC, udp6(SERVER6, CLIENT6, 547, 546, dhcpv6(
        2, option6(1, DUID) + option6(2, SERVER_DUID))))
    relayed = (bytes([12, 0]) + ipaddress.IPv6Address(RELAY6).packed
               + ipaddress.IPv6Address(CLIENT6).packed + option6(9, solicit))
    capture.v6(SERVER_MAC, CLIENT_MAC, udp6(RELAY6, "2001:db8::547", 547, 547, relayed))

    # NTP
    capture.v4(CLIENT_MAC, SERVER_MAC, udp4(NTP_CLIENT, NTP_SERVER, 50123, 123, ntp(3, 0, bytes(4))))
    capture.v4(SERVER_MAC, CLIENT_MAC, udp4(NTP_SERVER, NTP_CLIENT, 123, 50123,
                                            ntp(4, 2, ipaddress.IPv4Address("192.0.2.123").packed)))
    capture.v4(SERVER_MAC, CLIENT_MAC, udp4(NTP_SERVER, NTP_CLIENT, 123, 50124,
                                            ntp(4, 1, b"GPS\0")))
    capture.v4(SERVER_MAC, CLIENT_MAC, udp4(NTP_SERVER, NTP_CLIENT, 123, 50125, ntp(4, 0, b"RATE")))

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "dhcp-ntp.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
