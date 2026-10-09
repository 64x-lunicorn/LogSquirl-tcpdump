#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/stream-labels.pcap, streams whose protocol sticks.

Once a detector has recognised a stream's protocol, its later packets carry
that label, also those no detector recognises.  The capture is made up here,
byte for byte, free of anyone's traffic.  It shows, in order:

- HTTP on port 8080, whose port hint is HTTP-Alt: a handshake (the port's
  guess), a request and a response (HTTP), then the rest of the response
  body, text and binary, and bare ACKs (HTTP, "Continuation")
- a new connection on the same addresses and ports, which forgets the
  label: a SYN and a payload no detector recognises (HTTP-Alt again)
- TLS on port 443 with a Client Hello split over two segments: the second
  is TLS, not HTTPS
- NMEA over UDP, then a datagram that is no sentence: NMEA too.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet

CLIENT = bytes([10, 0, 0, 1])
SERVER = bytes([10, 0, 0, 2])

FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(from_server: bool, proto: int, transport: bytes) -> bytes:
    """An Ethernet frame with an IPv4 packet around @p transport."""
    src, dst = (SERVER, CLIENT) if from_server else (CLIENT, SERVER)
    pseudo = src + dst + struct.pack("!BBH", 0, proto, len(transport))
    at = 16 if proto == 6 else 6
    transport = (transport[:at] + struct.pack("!H", checksum(pseudo + transport))
                 + transport[at + 2:])
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0x4000, 64, proto, 0,
                     src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    mac_client = bytes([0x02, 0, 0, 0, 0, 1])
    mac_server = bytes([0x02, 0, 0, 0, 0, 2])
    macs = mac_client + mac_server if from_server else mac_server + mac_client
    return macs + struct.pack("!H", 0x0800) + ip + transport


class Connection:
    """A TCP connection from the client's @p client_port to @p server_port."""

    def __init__(self, client_port: int, server_port: int, client_isn: int, server_isn: int):
        self.ports = (client_port, server_port)
        self.isn = (client_isn, server_isn)

    def segment(self, from_server: bool, flags: int, seq: int, ack: int,
                payload: bytes = b"") -> bytes:
        """A segment; seq and ack are relative."""
        ports = self.ports[::-1] if from_server else self.ports
        own, other = self.isn[::-1] if from_server else self.isn
        seq = (own + seq) % 2**32
        ack = (other + ack) % 2**32 if flags & ACK else 0
        tcp = struct.pack("!HHIIBBHHH", ports[0], ports[1], seq, ack, 5 << 4, flags, 64240, 0, 0)
        return frame(from_server, 6, tcp + payload)


def datagram(src_port: int, dst_port: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return frame(False, 17, udp + payload)


C, S = False, True
HTTP = Connection(40000, 8080, 1000, 5000)
REQUEST = b"GET /status HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
HEADER = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 49\r\n\r\n"
BODY = b'{"status": "ok", "uptime": 86400'
REST = b', "load": [\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f]}'
R, H, B = len(REQUEST), len(HEADER), len(BODY)
AGAIN = Connection(40000, 8080, 70000, 90000)
TLS = Connection(40001, 443, 2000, 6000)
HELLO = bytes([0x16, 0x03, 0x01, 0x00, 0x40, 0x01, 0x00, 0x00, 0x3C, 0x03, 0x03]) + bytes(21)
HELLO_REST = bytes(range(0x80, 0x80 + 32))
# (seconds after BASE, frame)
PACKETS = [
    (0.000, HTTP.segment(C, SYN, 0, 0)),
    (0.001, HTTP.segment(S, SYN | ACK, 0, 1)),
    (0.002, HTTP.segment(C, ACK, 1, 1)),
    (0.003, HTTP.segment(C, PSH | ACK, 1, 1, REQUEST)),
    (0.004, HTTP.segment(S, ACK, 1, 1 + R)),
    (0.010, HTTP.segment(S, PSH | ACK, 1, 1 + R, HEADER)),
    (0.011, HTTP.segment(S, PSH | ACK, 1 + H, 1 + R, BODY)),
    (0.012, HTTP.segment(S, PSH | ACK, 1 + H + B, 1 + R, REST)),
    (0.013, HTTP.segment(C, ACK, 1 + R, 1 + H + B + len(REST))),
    (0.020, HTTP.segment(C, FIN | ACK, 1 + R, 1 + H + B + len(REST))),
    (0.021, HTTP.segment(S, FIN | ACK, 1 + H + B + len(REST), 2 + R)),
    (0.022, HTTP.segment(C, ACK, 2 + R, 2 + H + B + len(REST))),
    (1.000, AGAIN.segment(C, SYN, 0, 0)),
    (1.001, AGAIN.segment(S, SYN | ACK, 0, 1)),
    (1.002, AGAIN.segment(C, PSH | ACK, 1, 1, b"plain text, no protocol")),
    (2.000, TLS.segment(C, PSH | ACK, 1, 1, HELLO)),
    (2.001, TLS.segment(C, PSH | ACK, 1 + len(HELLO), 1, HELLO_REST)),
    (2.010, TLS.segment(S, ACK, 1, 1 + len(HELLO) + len(HELLO_REST))),
    (3.000, datagram(40002, 10110, b"$GPGGA,123519,4807.038,N,01131.000,E*47\r\n")),
    (3.001, datagram(40002, 10110, b"garbled line")),
]


def main() -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for time, data in PACKETS:
        usec = round(time * 1000000)
        out += struct.pack("<IIII", BASE + usec // 1000000, usec % 1000000, len(data), len(data))
        out += data
    path = pathlib.Path(__file__).resolve().parent / "corpus" / "stream-labels.pcap"
    path.write_bytes(out)


if __name__ == "__main__":
    main()
