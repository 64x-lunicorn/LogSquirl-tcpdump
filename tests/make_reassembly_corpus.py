#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/reassembly.pcap, messages that span TCP segments.

The TCP Reassembly describes such a message once, on the segment that
completes it, and the segments before as "[TCP segment of a reassembled
PDU]".  The capture is made up here, byte for byte, free of anyone's
traffic.  It holds, each on a connection of its own:

1. A TLS ClientHello for example.com split over 3 segments, port 443.
2. An HTTP request split in its headers, and a response whose header
   section ends in its second segment, the body behind it, port 80.
3. A DNS-over-TCP query in one segment and its answer split across 2.
4. TLS Application Data records in 3 segments, the third captured before
   the second, then the first segment again (a retransmission) and one
   that overlaps the bytes before it.
5. A ClientHello whose second segment the capture lost: the server
   acknowledges it, the hello is given up, and the next record, whole in
   its segment, is described as it is.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT, SERVER = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 7])
FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(from_server: bool, sport: int, dport: int, seq: int, ack: int, flags: int,
          payload: bytes) -> bytes:
    """An Ethernet frame with an IPv4 packet and a TCP segment."""
    src, dst = (SERVER, CLIENT) if from_server else (CLIENT, SERVER)
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0)
    segment += payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    macs = bytes.fromhex("02005e000002" "02005e000001")
    if from_server:
        macs = macs[6:] + macs[:6]
    return macs + struct.pack("!H", 0x0800) + ip + segment


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 1500
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


class Connection:
    """A TCP connection from @p client_port to @p server_port, its handshake
    captured.  Sequence numbers are relative, as Info shows them."""

    def __init__(self, capture: Capture, client_port: int, server_port: int):
        self.capture, self.ports = capture, (client_port, server_port)
        self.isn = (1000, 5000)
        self.next = [1, 1]  # the next relative sequence number of client, server
        self.segment(False, SYN, 0, 0)
        self.segment(True, SYN | ACK, 0, 1)
        self.segment(False, ACK, 1, 1)

    def segment(self, from_server: bool, flags: int, seq: int, ack: int,
                payload: bytes = b"") -> None:
        ports = self.ports[::-1] if from_server else self.ports
        own, other = self.isn[::-1] if from_server else self.isn
        self.capture.add(frame(from_server, ports[0], ports[1], own + seq,
                               other + ack if flags & ACK else 0, flags, payload))

    def send(self, from_server: bool, data: bytes, cuts=()) -> None:
        """@p data from one side, cut into segments at the offsets @p cuts."""
        bounds = [0, *cuts, len(data)]
        side = 1 if from_server else 0
        for start, end in zip(bounds, bounds[1:]):
            self.segment(from_server, PSH | ACK, self.next[side] + start, self.next[1 - side],
                         data[start:end])
        self.next[side] += len(data)

    def ack(self, from_server: bool) -> None:
        side = 1 if from_server else 0
        self.segment(from_server, ACK, self.next[side], self.next[1 - side])


def tls_record(content_type: int, fragment: bytes) -> bytes:
    return struct.pack("!BHH", content_type, 0x0303, len(fragment)) + fragment


def client_hello(server_name: str) -> bytes:
    """A ClientHello naming @p server_name, offering TLS 1.3 and 1.2, padded
    to some 600 bytes as a browser's is."""
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    versions = bytes([4, 0x03, 0x04, 0x03, 0x03])
    extensions = (struct.pack("!HH", 0x0000, len(sni)) + sni
                  + struct.pack("!HH", 0x002B, len(versions)) + versions
                  + struct.pack("!HH", 0x0015, 480) + bytes(480))
    body = (bytes([0x03, 0x03]) + bytes(range(32)) + b"\x00"
            + struct.pack("!HHH", 4, 0x1301, 0x1302) + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    return tls_record(0x16, handshake)


def dns_name(dotted: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in dotted.split(".")) + b"\0"


def dns(ident: int, flags: int, question: str, answers=()) -> bytes:
    """A DNS message over TCP, behind its 2-byte length: a question for the
    A records of @p question and the addresses @p answers."""
    message = struct.pack("!HHHHHH", ident, flags, 1, len(answers), 0, 0)
    message += dns_name(question) + struct.pack("!HH", 1, 1)
    for address in answers:
        message += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(address)
    return struct.pack("!H", len(message)) + message


def main() -> None:
    capture = Capture()

    # 1. A ClientHello over 3 segments.
    hello = Connection(capture, 50001, 443)
    data = client_hello("example.com")
    hello.send(False, data, (200, 400))
    hello.ack(True)

    # 2. HTTP split in the headers, both ways.
    http = Connection(capture, 50002, 80)
    request = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: corpus/1.0\r\n"
               b"Accept: */*\r\n\r\n")
    http.send(False, request, (30,))
    http.ack(True)
    body = b"<html><body>Hello</body></html>"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
    http.send(True, response, (24,))
    http.ack(False)

    # 3. DNS over TCP, the answer split across 2 segments.
    resolver = Connection(capture, 50003, 53)
    resolver.send(False, dns(0x4D2E, 0x0100, "www.example.com"))
    resolver.send(True, dns(0x4D2E, 0x8180, "www.example.com",
                            [(93, 184, 216, 34), (93, 184, 216, 35)]), (20,))
    resolver.ack(False)

    # 4. Out of order, retransmitted, overlapping.
    records = Connection(capture, 50004, 443)
    first = tls_record(0x17, bytes(range(256)) * 2)
    second = tls_record(0x17, bytes(300))
    records.segment(False, PSH | ACK, 1, 1, first[:200])
    records.segment(False, PSH | ACK, 401, 1, first[400:])
    records.segment(False, PSH | ACK, 201, 1, first[200:400])
    records.segment(False, PSH | ACK, 1, 1, first[:200])
    at = 1 + len(first)
    records.segment(False, PSH | ACK, at, 1, second[:100])
    records.segment(False, PSH | ACK, at + 50, 1, second[50:])
    records.next[0] = at + len(second)
    records.ack(True)

    # 5. A lost segment, acknowledged, then a record whole in its segment.
    lost = Connection(capture, 50005, 443)
    data = client_hello("lost.example.com")
    lost.segment(False, PSH | ACK, 1, 1, data[:300])
    lost.segment(True, ACK, 1, 1 + len(data))  # the capture lacks data[300:]
    alert = tls_record(0x15, bytes([1, 0]))
    lost.segment(False, PSH | ACK, 1 + len(data), 1, alert)

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "reassembly.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
