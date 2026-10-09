#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/tcp-analysis.pcap, a TCP connection with every marker.

The TCP Analysis marks segments as Wireshark does ([TCP Retransmission],
[TCP Dup ACK n#m], ...).  A real capture with each of them would take a
deliberately lossy link (e.g. Linux's tc netem, which needs root) and a
receiver that stops reading, and would differ from run to run; so the
connection is made up here, byte for byte, as such a link would have shown
it, free of anyone's traffic and of licence questions.  It shows, in order:

- a handshake, then four segments of data, the second of them lost on the
  way to the capture point: [TCP Previous segment not captured]
- three ACKs for the lost data: [TCP Dup ACK n#1], [TCP Dup ACK n#2]
- the lost data sent again right away: [TCP Fast Retransmission]
- data sent again after it was acknowledged: [TCP Spurious Retransmission]
- data sent again after a timeout: [TCP Retransmission]
- two segments in swapped order: [TCP Out-Of-Order]
- the server's window running full: [TCP ZeroWindow], the client's probe
  and its answer: [TCP ZeroWindowProbe], [TCP ZeroWindowProbeAck]
- the window opening again: [TCP Window Update]
- a keep-alive after 45 s and its answer: [TCP Keep-Alive],
  [TCP Keep-Alive ACK]
- the connection closed.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet

CLIENT = (bytes([10, 0, 0, 1]), 40000)
SERVER = (bytes([10, 0, 0, 2]), 80)
CLIENT_ISN = 3000000000
SERVER_ISN = 123456789

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def segment(from_server: bool, flags: int, seq: int, ack: int, payload: bytes = b"",
            window: int = 64240) -> bytes:
    """An Ethernet frame with one TCP segment; seq and ack are relative."""
    src, dst = (SERVER, CLIENT) if from_server else (CLIENT, SERVER)
    seq = ((SERVER_ISN if from_server else CLIENT_ISN) + seq) % 2**32
    ack = ((CLIENT_ISN if from_server else SERVER_ISN) + ack) % 2**32 if flags & ACK else 0
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], seq, ack, 5 << 4, flags, window, 0, 0)
    tcp += payload
    pseudo = src[0] + dst[0] + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0x4000, 64, 6, 0, src[0], dst[0])
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    mac_client = bytes([0x02, 0, 0, 0, 0, 1])
    mac_server = bytes([0x02, 0, 0, 0, 0, 2])
    macs = mac_client + mac_server if from_server else mac_server + mac_client
    return macs + struct.pack("!H", 0x0800) + ip + tcp


def data(n: int) -> bytes:
    return bytes([0x61 + n % 26]) * 100


C, S = False, True
# (seconds after BASE, segment); relative numbers: the client's data starts
# at 1, the server's at 1.
PACKETS = [
    (0.000000, segment(C, SYN, 0, 0)),
    (0.010000, segment(S, SYN | ACK, 0, 1, window=65535)),
    (0.020000, segment(C, ACK, 1, 1)),
    (0.021000, segment(C, PSH | ACK, 1, 1, data(0))),
    # 101..200 is lost before the capture point.
    (0.021500, segment(C, PSH | ACK, 201, 1, data(2))),
    (0.022000, segment(C, PSH | ACK, 301, 1, data(3))),
    (0.031000, segment(S, ACK, 1, 101, window=65535)),
    (0.031500, segment(S, ACK, 1, 101, window=65535)),
    (0.032000, segment(S, ACK, 1, 101, window=65535)),
    (0.033000, segment(C, PSH | ACK, 101, 1, data(1))),
    (0.043000, segment(S, ACK, 1, 401, window=65535)),
    (0.300000, segment(C, PSH | ACK, 301, 1, data(3))),
    (0.310000, segment(C, PSH | ACK, 401, 1, data(4))),
    (0.530000, segment(C, PSH | ACK, 401, 1, data(4))),
    (0.539000, segment(S, ACK, 1, 501, window=65535)),
    (0.540000, segment(C, PSH | ACK, 601, 1, data(6))),
    (0.540200, segment(C, PSH | ACK, 501, 1, data(5))),
    (0.550000, segment(S, ACK, 1, 701, window=0)),
    (0.750000, segment(C, ACK, 701, 1, b"g")),
    (0.760000, segment(S, ACK, 1, 701, window=0)),
    (1.000000, segment(S, ACK, 1, 701, window=65535)),
    (46.000000, segment(C, ACK, 700, 1)),
    (46.010000, segment(S, ACK, 1, 701, window=65535)),
    (50.000000, segment(C, FIN | ACK, 701, 1)),
    (50.010000, segment(S, FIN | ACK, 1, 702, window=65535)),
    (50.020000, segment(C, ACK, 702, 2)),
]


def main() -> None:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)
    for time, frame in PACKETS:
        usec = round(time * 1000000)
        out += struct.pack("<IIII", BASE + usec // 1000000, usec % 1000000, len(frame), len(frame))
        out += frame
    path = pathlib.Path(__file__).resolve().parent / "corpus" / "tcp-analysis.pcap"
    path.write_bytes(out)


if __name__ == "__main__":
    main()
