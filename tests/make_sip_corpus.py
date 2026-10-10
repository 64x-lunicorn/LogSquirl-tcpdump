#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/sip.pcap, the corpus's SIP, SDP, RTP and RTCP capture.

Every byte is made up here, so the capture holds no one's traffic.  The SIP
messages and SDP bodies follow RFC 3261 and RFC 4566, RTP and RTCP RFC 3550.
The capture holds:

1. A call over UDP: INVITE with an SDP offer, 100 Trying, 180 Ringing,
   200 OK with the SDP answer, ACK; RTP both ways (PCMU, the first with
   the marker), RTCP sender and receiver reports on the next ports, UDP
   between the same hosts on ports SDP did not announce, then BYE and its
   200 OK.
2. SIP over TCP: two REGISTER transactions, a 401 and the second REGISTER
   in one segment; an INVITE whose SDP body (dynamic payload type 96,
   rtcp-mux) goes on in the next segment, its 200 OK, and the media of
   that call, RTP and RTCP on one port.
3. An OPTIONS request and its answer on UDP port 5080, which only their
   start lines tell to be SIP.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
ALICE, BOB, PROXY = "192.0.2.10", "192.0.2.20", "192.0.2.5"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def addr(a: str) -> bytes:
    return ipaddress.IPv4Address(a).packed


def ip_frame(src: str, dst: str, proto: int, segment: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x5060, 0x4000, 64, proto,
                         0, addr(src), addr(dst))
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


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes, step: int = 20000) -> None:
        self.time += step
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def udp(self, src, dst, sport, dport, payload, step=20000):
        self.add(udp_frame(src, dst, sport, dport, payload), step)

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


def sdp(user: str, ip: str, port: int, formats: str, extra: str = "") -> bytes:
    return ("v=0\r\n"
            f"o={user} 2890844526 2890844526 IN IP4 {ip}\r\n"
            "s=-\r\n"
            f"c=IN IP4 {ip}\r\n"
            "t=0 0\r\n"
            f"m=audio {port} RTP/AVP {formats}\r\n" + extra).encode()


def sip(start: str, cseq: str, call_id: str, transport: str = "UDP", body: bytes = b"",
        headers: str = "") -> bytes:
    text = (f"{start}\r\n"
            f"Via: SIP/2.0/{transport} pc33.example.com;branch=z9hG4bK{cseq.replace(" ", "").lower()}\r\n"
            "Max-Forwards: 70\r\n"
            "From: Alice <sip:alice@example.com>;tag=1928301774\r\n"
            "To: Bob <sip:bob@example.com>\r\n"
            f"Call-ID: {call_id}\r\n"
            f"CSeq: {cseq}\r\n" + headers)
    if body:
        text += "Content-Type: application/sdp\r\n"
    text += f"Content-Length: {len(body)}\r\n\r\n"
    return text.encode() + body


def rtp(pt: int, seq: int, ts: int, ssrc: int, marker: bool = False, size: int = 160) -> bytes:
    return struct.pack("!BBHII", 0x80, (0x80 if marker else 0) | pt, seq, ts, ssrc) + b"\xff" * size


def rtcp(kind: int, words: int, count: int = 0) -> bytes:
    return struct.pack("!BBH", 0x80 | count, kind, words) + b"\0" * (4 * words)


def udp_call(c: Capture) -> None:
    call = "a84b4c76e66710@pc33.example.com"
    invite = sip("INVITE sip:bob@example.com SIP/2.0", "314159 INVITE", call,
                 body=sdp("alice", ALICE, 49170, "0 8 101"),
                 headers="Contact: <sip:alice@192.0.2.10>\r\n")
    c.udp(ALICE, BOB, 5060, 5060, invite)
    c.udp(BOB, ALICE, 5060, 5060, sip("SIP/2.0 100 Trying", "314159 INVITE", call))
    c.udp(BOB, ALICE, 5060, 5060, sip("SIP/2.0 180 Ringing", "314159 INVITE", call))
    c.udp(BOB, ALICE, 5060, 5060, sip("SIP/2.0 200 OK", "314159 INVITE", call,
                                      body=sdp("bob", BOB, 3456, "0")))
    c.udp(ALICE, BOB, 5060, 5060, sip("ACK sip:bob@192.0.2.20 SIP/2.0", "314159 ACK", call))
    for i in range(3):
        c.udp(ALICE, BOB, 49170, 3456, rtp(0, 1000 + i, 8000 + 160 * i, 0x1234ABCD, i == 0))
        c.udp(BOB, ALICE, 3456, 49170, rtp(0, 20 + i, 160 * i, 0x0BADCAFE, i == 0))
    c.udp(ALICE, BOB, 49171, 3457, rtcp(200, 6) + rtcp(202, 3, 1))
    c.udp(BOB, ALICE, 3457, 49171, rtcp(201, 1))
    c.udp(ALICE, BOB, 40000, 40002, bytes([0x80, 0, 0, 1]) + b"\x00" * 20)
    c.udp(ALICE, BOB, 5060, 5060, sip("BYE sip:bob@192.0.2.20 SIP/2.0", "314160 BYE", call))
    c.udp(BOB, ALICE, 5060, 5060, sip("SIP/2.0 200 OK", "314160 BYE", call))


class Connection:
    """One TCP connection from Alice to the proxy."""

    def __init__(self, capture: Capture, port: int):
        self.capture, self.port = capture, port
        self.client_seq, self.server_seq = 1000, 5000
        self.segment(True, 0x02)
        self.segment(False, 0x12)
        self.segment(True, 0x10)

    def segment(self, from_client: bool, flags: int, data: bytes = b"") -> None:
        if from_client:
            self.capture.add(tcp_frame(ALICE, PROXY, self.port, 5060, self.client_seq,
                                       self.server_seq if flags != 0x02 else 0, flags, data))
            self.client_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            self.capture.add(tcp_frame(PROXY, ALICE, 5060, self.port, self.server_seq,
                                       self.client_seq, flags, data))
            self.server_seq += len(data) + (1 if flags & 0x03 else 0)

    def send(self, from_client: bool, data: bytes) -> None:
        self.segment(from_client, 0x18, data)


def tcp_session(c: Capture) -> None:
    t = Connection(c, 50600)
    reg = "f81d4fae7dec11d0a76500a0c91e6bf6@pc33.example.com"
    t.send(True, sip("REGISTER sip:example.com SIP/2.0", "1 REGISTER", reg, "TCP"))
    t.send(False, sip("SIP/2.0 401 Unauthorized", "1 REGISTER", reg, "TCP",
                      headers='WWW-Authenticate: Digest realm="example.com", nonce="ab12"\r\n'))
    t.send(True, sip("REGISTER sip:example.com SIP/2.0", "2 REGISTER", reg, "TCP",
                     headers='Authorization: Digest username="alice", realm="example.com"\r\n'))
    t.send(False, sip("SIP/2.0 100 Trying", "2 REGISTER", reg, "TCP")
           + sip("SIP/2.0 200 OK", "2 REGISTER", reg, "TCP"))
    call = "3848276298220188511@pc33.example.com"
    invite = sip("INVITE sip:carol@example.com SIP/2.0", "1 INVITE", call, "TCP",
                 body=sdp("alice", ALICE, 52000, "96", "a=rtpmap:96 opus/48000/2\r\na=rtcp-mux\r\n"))
    t.send(True, invite[:-20])
    t.send(True, invite[-20:])
    t.send(False, sip("SIP/2.0 200 OK", "1 INVITE", call, "TCP",
                      body=sdp("carol", PROXY, 52500, "96",
                               "a=rtpmap:96 opus/48000/2\r\na=rtcp-mux\r\n")))
    c.udp(ALICE, PROXY, 52000, 52500, rtp(96, 1, 0, 0x5EED, True, 80))
    c.udp(PROXY, ALICE, 52500, 52000, rtp(96, 1, 0, 0xFEED, True, 80))
    c.udp(ALICE, PROXY, 52000, 52500, rtcp(200, 6))
    t.send(True, sip("BYE sip:carol@example.com SIP/2.0", "2 BYE", call, "TCP"))
    t.send(False, sip("SIP/2.0 200 OK", "2 BYE", call, "TCP"))


def options_other_port(c: Capture) -> None:
    call = "options-1@pc33.example.com"
    c.udp(ALICE, BOB, 5080, 5080, sip("OPTIONS sip:bob@192.0.2.20:5080 SIP/2.0", "1 OPTIONS", call,
                                      headers="Accept: application/sdp\r\n"))
    c.udp(BOB, ALICE, 5080, 5080, sip("SIP/2.0 200 OK", "1 OPTIONS", call,
                                      headers="Allow: INVITE, ACK, CANCEL, OPTIONS, BYE\r\n"))


def main() -> None:
    capture = Capture()
    udp_call(capture)
    tcp_session(capture)
    options_other_port(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "sip.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
