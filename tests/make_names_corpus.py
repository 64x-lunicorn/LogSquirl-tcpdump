#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/names.pcap, the corpus's capture for the host names.

Every byte is made up here, so the capture holds no one's traffic.  DNS
answers name addresses, and packets to and from those addresses come
before and after the answers, so that a conversion with host names shown
(LineLayout::hostNames) names some of their lines and not others.  The
capture holds:

1. A TCP connection to 93.184.216.34 whose handshake comes before the
   answer that names the address (www.example.com, behind a CNAME), the
   rest after it.
2. An AAAA answer, then a TCP connection over IPv6 to its address.
3. A PTR answer for 198.51.100.7, then NTP to that address.
4. An mDNS response in which 192.0.2.20 announces its own name, then a
   datagram from it.
5. A DNS-over-TCP answer for 192.0.2.80, then a datagram to it.
6. An answer whose name has a space in it, which names nothing, then a
   datagram to its address.
7. An answer that gives 93.184.216.34 another name, as a spoofed one
   would, then the rest of the connection of 1.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

from make_dns_corpus import (A, AAAA, CNAME, PTR, QUERY, RESPONSE, Capture, Connection,
                             Message, checksum, framed, host, tcp_frame, udp_frame)

CLIENT, SERVER = "192.0.2.10", "192.0.2.53"
WEB = "93.184.216.34"
CLIENT6, WEB6 = "2001:db8::10", "2001:db8::1"
MDNS_RESPONSE = 0x8400  # an authoritative answer, as mDNS sends it


def addr(a: str) -> bytes:
    return ipaddress.ip_address(a).packed


def tcp6_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
               flags: int) -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    pseudo = addr(src) + addr(dst) + struct.pack("!IxxxB", len(segment), 6)
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    header = struct.pack("!IHBB16s16s", 0x60000000, len(segment), 6, 64, addr(src), addr(dst))
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x86DD)
    return ether + header + segment


def main() -> None:
    capture = Capture()

    # 1. The handshake before the name is known.
    capture.add(tcp_frame(CLIENT, WEB, 50000, 443, 100, 0, 0x02))
    capture.add(tcp_frame(WEB, CLIENT, 443, 50000, 900, 101, 0x12))
    capture.exchange(53001, Message(0x1A2B, QUERY).question("www.example.com", A),
                     Message(0x1A2B, RESPONSE).question("www.example.com", A)
                     .answer("www.example.com", CNAME, host("example.com"))
                     .answer("example.com", A, addr(WEB)))
    capture.add(tcp_frame(CLIENT, WEB, 50000, 443, 101, 901, 0x10))
    capture.add(tcp_frame(CLIENT, WEB, 50000, 443, 101, 901, 0x18, b"hello"))
    capture.add(tcp_frame(WEB, CLIENT, 443, 50000, 901, 106, 0x10))

    # 2. IPv6.
    capture.exchange(53002, Message(0x2B3C, QUERY).question("example.com", AAAA),
                     Message(0x2B3C, RESPONSE).question("example.com", AAAA)
                     .answer("example.com", AAAA, addr(WEB6)))
    capture.add(tcp6_frame(CLIENT6, WEB6, 50001, 80, 200, 0, 0x02))
    capture.add(tcp6_frame(WEB6, CLIENT6, 80, 50001, 700, 201, 0x12))

    # 3. A reverse lookup.
    capture.exchange(53003, Message(0x3C4D, QUERY).question("7.100.51.198.in-addr.arpa", PTR),
                     Message(0x3C4D, RESPONSE).question("7.100.51.198.in-addr.arpa", PTR)
                     .answer("7.100.51.198.in-addr.arpa", PTR, host("ntp.example.net")))
    ntp = bytes([0x23]) + bytes(47)  # version 4, client
    capture.add(udp_frame(CLIENT, "198.51.100.7", 50123, 123, ntp))

    # 4. mDNS: a host announces its own name.
    capture.add(udp_frame("192.0.2.20", "224.0.0.251", 5353, 5353,
                          Message(0, MDNS_RESPONSE).answer("printer.local", A,
                                                           addr("192.0.2.20")).bytes()))
    capture.add(udp_frame("192.0.2.20", CLIENT, 50631, 50631, b"status: ready"))

    # 5. DNS over TCP.
    connection = Connection(capture, 53100)
    connection.send(True, framed(Message(0xA3B4, QUERY).question("example.org", A)))
    connection.send(False, framed(Message(0xA3B4, RESPONSE).question("example.org", A)
                                  .answer("example.org", A, addr("192.0.2.80"))))
    capture.add(udp_frame(CLIENT, "192.0.2.80", 50080, 50080, b"ping"))

    # 6. A name no column could show.
    capture.exchange(53004, Message(0x4D5E, QUERY).question("bad name.example", A),
                     Message(0x4D5E, RESPONSE).question("bad name.example", A)
                     .answer("bad name.example", A, addr("203.0.113.5")))
    capture.add(udp_frame(CLIENT, "203.0.113.5", 50113, 50113, b"ping"))

    # 7. Another name for the address of 1, as a spoofed answer gives it.
    capture.exchange(53005, Message(0x5E6F, QUERY).question("other.example", A),
                     Message(0x5E6F, RESPONSE).question("other.example", A)
                     .answer("other.example", A, addr(WEB)))
    capture.add(tcp_frame(CLIENT, WEB, 50000, 443, 106, 901, 0x11))
    capture.add(tcp_frame(WEB, CLIENT, 443, 50000, 901, 107, 0x11))

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "names.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
