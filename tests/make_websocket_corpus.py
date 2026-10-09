#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/websocket.pcap, the corpus's WebSocket capture.

Every byte is made up here, so the capture holds no one's traffic: the
frames are laid out as RFC 6455 says, the client's masked with made-up
keys.  The capture holds:

1. A chat on port 80: the upgrade request and the 101 response, a masked
   text frame from the client, an unmasked one from the server, a ping and
   its pong, a message in two fragments (text, then continuation), a binary
   frame with a 16-bit length, a long text frame split over two segments,
   which the TCP Reassembly puts together, three frames in one segment, and
   the closing handshake with status code and reason.
2. A connection on port 8080 that negotiated permessage-deflate: its
   compressed text frames both ways, and a close without status code.
3. Frames that break their opcode's rules after an upgrade on port 8081:
   a ping without FIN, a close with a one-byte payload.
4. The same frames on port 8082 without an upgrade: not WebSocket.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct
import zlib

BASE = 1760100000  # seconds since the epoch of the first packet
CLIENT, SERVER = "192.0.2.50", "192.0.2.60"


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
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x1340, 0x4000, 64,
                         protocol, 0, addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x0800)
    return ether + header + segment


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
              payload: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    return ip_frame(src, dst, 6, segment)


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



class Connection:
    """One TCP connection between the client and the server's port."""

    def __init__(self, capture: Capture, client_port: int, server_port: int,
                 handshake: bool = True):
        self.capture, self.client_port, self.server_port = capture, client_port, server_port
        self.client_seq, self.server_seq = 1000, 5000
        if handshake:
            self.send(True, 0x02)
            self.send(False, 0x12)
            self.send(True, 0x10)

    def send(self, from_client: bool, flags: int, data: bytes = b"") -> None:
        if from_client:
            self.capture.add(tcp_frame(CLIENT, SERVER, self.client_port, self.server_port,
                                       self.client_seq, self.server_seq if flags != 0x02 else 0,
                                       flags, data))
            self.client_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            self.capture.add(tcp_frame(SERVER, CLIENT, self.server_port, self.client_port,
                                       self.server_seq, self.client_seq, flags, data))
            self.server_seq += len(data) + (1 if flags & 0x03 else 0)

    def client(self, data: bytes) -> None:
        self.send(True, 0x18, data)

    def server(self, data: bytes) -> None:
        self.send(False, 0x18, data)

    def close(self) -> None:
        self.send(True, 0x11)
        self.send(False, 0x11)
        self.send(True, 0x10)



def frame(opcode: int, payload: bytes, mask: bytes | None = None, fin: bool = True,
          rsv1: bool = False) -> bytes:
    """A WebSocket frame, its length in the shortest form, masked with
    mask if given."""
    first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    mask_bit = 0x80 if mask else 0
    n = len(payload)
    if n < 126:
        header = struct.pack("!BB", first, mask_bit | n)
    elif n <= 0xFFFF:
        header = struct.pack("!BBH", first, mask_bit | 126, n)
    else:
        header = struct.pack("!BBQ", first, mask_bit | 127, n)
    if not mask:
        return header + payload
    return header + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload))


def close(code: int, reason: bytes = b"") -> bytes:
    return struct.pack("!H", code) + reason


def deflated(text: bytes) -> bytes:
    """A message as permessage-deflate sends it (RFC 7692, 7.2.1)."""
    compressor = zlib.compressobj(wbits=-15)
    data = compressor.compress(text) + compressor.flush(zlib.Z_SYNC_FLUSH)
    assert data.endswith(b"\x00\x00\xff\xff")
    return data[:-4]


KEYS = [bytes([0x37, 0xFA, 0x21, 0x3D]), bytes([0x5C, 0x0E, 0x9B, 0x41]),
        bytes([0xA2, 0x13, 0x77, 0x08]), bytes([0x19, 0xC4, 0x6E, 0xD5])]


def upgrade(c: "Connection", path: str, extensions: str = "") -> None:
    offer = "Sec-WebSocket-Extensions: permessage-deflate\r\n" if extensions else ""
    c.client(("GET %s HTTP/1.1\r\n"
              "Host: chat.example.com\r\n"
              "Upgrade: websocket\r\n"
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
              "Sec-WebSocket-Version: 13\r\n%s\r\n" % (path, offer)).encode())
    accept = "Sec-WebSocket-Extensions: %s\r\n" % extensions if extensions else ""
    c.server(("HTTP/1.1 101 Switching Protocols\r\n"
              "Upgrade: websocket\r\n"
              "Connection: Upgrade\r\n"
              "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n%s\r\n" % accept).encode())


def chat(capture: Capture) -> None:
    c = Connection(capture, 50180, 80)
    upgrade(c, "/chat")
    c.client(frame(0x1, b"Hello, server!", KEYS[0]))
    c.server(frame(0x1, b"Hello, client!"))
    c.client(frame(0x9, b"", KEYS[1]))
    c.server(frame(0xA, b""))
    c.client(frame(0x1, b"Part one, ", KEYS[2], fin=False))
    c.client(frame(0x0, b"part two", KEYS[3]))
    c.server(frame(0x2, bytes(range(256)) + bytes(44)))
    long_text = frame(0x1, b"The quick brown fox jumps over the lazy dog. " * 40, KEYS[0])
    c.client(long_text[:1000])
    c.client(long_text[1000:])
    c.server(frame(0x1, b'{"type":"presence","user":"alice"}')
             + frame(0x1, b'{"type":"message","text":"hi"}') + frame(0x9, b"keepalive"))
    c.client(frame(0x8, close(1000, b"bye"), KEYS[1]))
    c.server(frame(0x8, close(1000)))
    c.close()


def compressed(capture: Capture) -> None:
    c = Connection(capture, 50181, 8080)
    upgrade(c, "/feed", "permessage-deflate")
    c.client(frame(0x1, deflated(b"subscribe ticker"), KEYS[2], rsv1=True))
    c.server(frame(0x1, deflated(b'{"ticker":"ACME","price":42.5}'), rsv1=True))
    c.client(frame(0x8, b"", KEYS[3]))
    c.server(frame(0x8, b""))
    c.close()


def malformed(capture: Capture) -> None:
    c = Connection(capture, 50182, 8081)
    upgrade(c, "/broken")
    c.server(frame(0x9, b"x", fin=False))
    c.client(frame(0x8, b"\x03", KEYS[0]))
    c.close()


def without_upgrade(capture: Capture) -> None:
    c = Connection(capture, 50183, 8082)
    c.client(frame(0x1, b"Hello, server!", KEYS[0]))
    c.server(frame(0x1, b"Hello, client!"))
    c.close()


def main() -> None:
    capture = Capture()
    chat(capture)
    compressed(capture)
    malformed(capture)
    without_upgrade(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "websocket.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
