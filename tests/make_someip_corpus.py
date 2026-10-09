#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/someip.pcap, the corpus's SOME/IP capture.

Every byte is made up here, so the capture holds no one's traffic.  The
messages are encoded as AUTOSAR's SOME/IP and SOME/IP-SD protocol
specifications lay them out.  The capture holds:

1. SOME/IP-SD on UDP port 30490: a server offers service 0x1234 with a UDP
   and a TCP endpoint, a client looks for service 0x5678 and subscribes to
   eventgroup 0x0010 with its own endpoint, the server acknowledges with a
   multicast endpoint and refuses another eventgroup (a Nack), and at last
   withdraws its offer.
2. SOME/IP on UDP port 30501, which only the headers tell to be SOME/IP: a
   request and its response, two notifications in one datagram, an error
   (E_NOT_OK), and the first segment of a SOME/IP-TP message.
3. SOME/IP on TCP port 30502: a magic cookie and a request in one segment,
   and a response split over two segments, which the TCP Reassembly puts
   together.
4. A message on port 30490 with protocol version 2: malformed.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
SERVER, CLIENT, SD_MULTICAST = "192.0.2.10", "192.0.2.20", "224.224.224.245"
SD_PORT, UDP_PORT, TCP_PORT, CLIENT_PORT = 30490, 30501, 30502, 40001

REQUEST, NOTIFICATION, RESPONSE, ERROR, TP_NOTIFICATION = 0x00, 0x02, 0x80, 0x81, 0x22
UDP, TCP = 0x11, 0x06


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def addr(a: str) -> bytes:
    return ipaddress.IPv4Address(a).packed


def ip_frame(src: str, dst: str, protocol: int, segment: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x5049, 0x4000, 64,
                         protocol, 0, addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x0800)
    return ether + header + segment


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    datagram = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 17, len(datagram))
    datagram = datagram[:6] + struct.pack("!H", checksum(pseudo + datagram) or 0xFFFF) + datagram[8:]
    return ip_frame(src, dst, 17, datagram)


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
              payload: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return ip_frame(src, dst, 6, segment)


def someip(service: int, method: int, msg_type: int, payload: bytes = b"", return_code: int = 0,
           client: int = 0x0010, session: int = 1, version: int = 1) -> bytes:
    return struct.pack("!HHIHHBBBB", service, method, 8 + len(payload), client, session, version,
                       1, msg_type, return_code) + payload


def service_entry(kind: int, service: int, instance: int, major: int, ttl: int, minor: int,
                  index: int = 0, count: int = 0) -> bytes:
    return struct.pack("!BBBBHHB", kind, index, 0, count << 4, service, instance, major) \
        + ttl.to_bytes(3, "big") + struct.pack("!I", minor)


def eventgroup_entry(kind: int, service: int, instance: int, eventgroup: int, ttl: int,
                     index: int = 0, count: int = 0) -> bytes:
    return struct.pack("!BBBBHHB", kind, index, 0, count << 4, service, instance, 1) \
        + ttl.to_bytes(3, "big") + struct.pack("!BBH", 0, 0, eventgroup)


def ipv4_option(address: str, l4: int, port: int, kind: int = 0x04) -> bytes:
    return struct.pack("!HBB4sBBH", 9, kind, 0, addr(address), 0, l4, port)


def sd(entries: bytes, options: bytes = b"", session: int = 1) -> bytes:
    payload = bytes([0xC0, 0, 0, 0]) + struct.pack("!I", len(entries)) + entries \
        + struct.pack("!I", len(options)) + options
    return someip(0xFFFF, 0x8100, NOTIFICATION, payload, client=0x0000, session=session)


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 2000
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


def service_discovery(capture: Capture) -> None:
    offer = service_entry(0x01, 0x1234, 0x0001, 1, 3, 0, 0, 2)
    endpoints = ipv4_option(SERVER, UDP, UDP_PORT) + ipv4_option(SERVER, TCP, TCP_PORT)
    capture.add(udp_frame(SERVER, SD_MULTICAST, SD_PORT, SD_PORT, sd(offer, endpoints)))
    find = service_entry(0x00, 0x5678, 0xFFFF, 0xFF, 3, 0xFFFFFFFF)
    capture.add(udp_frame(CLIENT, SD_MULTICAST, SD_PORT, SD_PORT, sd(find)))
    subscribe = eventgroup_entry(0x06, 0x1234, 0x0001, 0x0010, 3, 0, 1) \
        + eventgroup_entry(0x06, 0x1234, 0x0001, 0x0020, 3, 0, 1)
    capture.add(udp_frame(CLIENT, SERVER, SD_PORT, SD_PORT,
                          sd(subscribe, ipv4_option(CLIENT, UDP, CLIENT_PORT), 2)))
    acks = eventgroup_entry(0x07, 0x1234, 0x0001, 0x0010, 3, 0, 1) \
        + eventgroup_entry(0x07, 0x1234, 0x0001, 0x0020, 0)
    capture.add(udp_frame(SERVER, CLIENT, SD_PORT, SD_PORT,
                          sd(acks, ipv4_option("239.0.0.1", UDP, 30600, 0x14), 2)))


def over_udp(capture: Capture) -> None:
    def to_server(data: bytes) -> None:
        capture.add(udp_frame(CLIENT, SERVER, CLIENT_PORT, UDP_PORT, data))

    def to_client(data: bytes) -> None:
        capture.add(udp_frame(SERVER, CLIENT, UDP_PORT, CLIENT_PORT, data))

    to_server(someip(0x1234, 0x0001, REQUEST, struct.pack("!I", 42)))
    to_client(someip(0x1234, 0x0001, RESPONSE, b"route-42"))
    to_client(someip(0x1234, 0x8001, NOTIFICATION, b"\x01\x02", client=0, session=5)
              + someip(0x1234, 0x8002, NOTIFICATION, b"\x03", client=0, session=6))
    to_server(someip(0x1234, 0x0003, REQUEST, session=2))
    to_client(someip(0x1234, 0x0003, ERROR, return_code=0x01, session=2))
    to_client(someip(0x1234, 0x8003, TP_NOTIFICATION, struct.pack("!I", 0 | 1) + bytes(1392),
                     client=0, session=7))


def over_tcp(capture: Capture) -> None:
    client_seq, server_seq = 1000, 5000

    def segment(from_client: bool, flags: int, data: bytes = b"") -> None:
        nonlocal client_seq, server_seq
        if from_client:
            capture.add(tcp_frame(CLIENT, SERVER, CLIENT_PORT, TCP_PORT, client_seq,
                                  server_seq if flags != 0x02 else 0, flags, data))
            client_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            capture.add(tcp_frame(SERVER, CLIENT, TCP_PORT, CLIENT_PORT, server_seq, client_seq,
                                  flags, data))
            server_seq += len(data) + (1 if flags & 0x03 else 0)

    segment(True, 0x02)
    segment(False, 0x12)
    segment(True, 0x10)
    cookie = someip(0xFFFF, 0x0000, 0x01, client=0xDEAD, session=0xBEEF)
    segment(True, 0x18, cookie + someip(0x1234, 0x0002, REQUEST, b"map?", session=3))
    response = someip(0x1234, 0x0002, RESPONSE, bytes(range(256)) * 4, session=3)
    segment(False, 0x18, response[:600])
    segment(False, 0x18, response[600:])
    segment(True, 0x11)
    segment(False, 0x11)
    segment(True, 0x10)


def withdrawn_and_malformed(capture: Capture) -> None:
    stop = service_entry(0x01, 0x1234, 0x0001, 1, 0, 0)
    capture.add(udp_frame(SERVER, SD_MULTICAST, SD_PORT, SD_PORT, sd(stop, session=3)))
    capture.add(udp_frame(CLIENT, SERVER, SD_PORT, SD_PORT,
                          someip(0x1234, 0x0001, REQUEST, version=2)))


def main() -> None:
    capture = Capture()
    service_discovery(capture)
    over_udp(capture)
    over_tcp(capture)
    withdrawn_and_malformed(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "someip.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
