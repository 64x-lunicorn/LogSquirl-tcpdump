#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/doip.pcap, the corpus's DoIP capture.

Every byte is made up here, so the capture holds no one's traffic.  The
messages are encoded as ISO 13400-2 (DoIP) and ISO 14229-1 (UDS) lay them
out.  The capture holds:

1. DoIP on UDP port 13400: a tester asks for every vehicle, then for one by
   its VIN; the DoIP entity answers with a vehicle announcement and
   announces itself unasked; the tester asks for the entity's status and
   its diagnostic power mode.
2. DoIP on TCP port 13400: routing activation, then diagnostic messages
   with UDS in them, each acknowledged, the acknowledgement and the answer
   in one segment: an extended session, ReadDataByIdentifier of the VIN, a
   negative response (requestOutOfRange), a response pending before a
   routine's result, TesterPresent with the suppress bit, a TransferData
   split over two segments, which the TCP Reassembly puts together, a
   diagnostic message NACK, and an alive check.
3. Two malformed messages: an inverse version that does not match, and a
   payload length the type does not allow.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
TESTER, ECU, BROADCAST = "192.0.2.30", "192.0.2.40", "192.0.2.255"
DOIP_PORT, TESTER_UDP_PORT, TESTER_TCP_PORT = 13400, 50000, 50001
TESTER_ADDRESS, ECU_ADDRESS = 0x0E00, 0x1000
VIN = b"WP0ZZZ99ZTS392124"
EID = bytes.fromhex("02005e000040")
GID = bytes.fromhex("02005e0000ff")


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


def doip(payload_type: int, payload: bytes = b"", version: int = 0x02,
         inverse: int | None = None) -> bytes:
    if inverse is None:
        inverse = ~version & 0xFF
    return struct.pack("!BBHI", version, inverse, payload_type, len(payload)) + payload


def diagnostic(uds: bytes, source: int = TESTER_ADDRESS, target: int = ECU_ADDRESS) -> bytes:
    return doip(0x8001, struct.pack("!HH", source, target) + uds)


def diagnostic_ack(code: int = 0x00) -> bytes:
    return doip(0x8002, struct.pack("!HHB", ECU_ADDRESS, TESTER_ADDRESS, code))


def answer(uds: bytes) -> bytes:
    return diagnostic(uds, ECU_ADDRESS, TESTER_ADDRESS)


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


def vehicle_identification(capture: Capture) -> None:
    def to_entity(data: bytes, dst: str = BROADCAST) -> None:
        capture.add(udp_frame(TESTER, dst, TESTER_UDP_PORT, DOIP_PORT, data))

    def to_tester(data: bytes) -> None:
        capture.add(udp_frame(ECU, TESTER, DOIP_PORT, TESTER_UDP_PORT, data))

    announcement = doip(0x0004, VIN + struct.pack("!H", ECU_ADDRESS) + EID + GID + b"\x00\x00")
    to_entity(doip(0x0001, version=0xFF))
    to_tester(announcement)
    to_entity(doip(0x0003, VIN, version=0xFF))
    to_tester(announcement)
    capture.add(udp_frame(ECU, BROADCAST, DOIP_PORT, DOIP_PORT,
                          doip(0x0004, VIN + struct.pack("!H", ECU_ADDRESS) + EID + GID
                               + b"\x10\x10")))
    to_entity(doip(0x4001), ECU)
    to_tester(doip(0x4002, bytes([0x00, 4, 1]) + struct.pack("!I", 4096)))
    to_entity(doip(0x4003), ECU)
    to_tester(doip(0x4004, b"\x01"))


def diagnostics(capture: Capture) -> None:
    tester_seq, ecu_seq = 1000, 5000

    def segment(from_tester: bool, flags: int, data: bytes = b"") -> None:
        nonlocal tester_seq, ecu_seq
        if from_tester:
            capture.add(tcp_frame(TESTER, ECU, TESTER_TCP_PORT, DOIP_PORT, tester_seq,
                                  ecu_seq if flags != 0x02 else 0, flags, data))
            tester_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            capture.add(tcp_frame(ECU, TESTER, DOIP_PORT, TESTER_TCP_PORT, ecu_seq, tester_seq,
                                  flags, data))
            ecu_seq += len(data) + (1 if flags & 0x03 else 0)

    def ask(uds: bytes, *answers: bytes) -> None:
        segment(True, 0x18, diagnostic(uds))
        segment(False, 0x18, diagnostic_ack() + b"".join(answer(a) for a in answers))

    segment(True, 0x02)
    segment(False, 0x12)
    segment(True, 0x10)
    segment(True, 0x18, doip(0x0005, struct.pack("!HBI", TESTER_ADDRESS, 0x00, 0)))
    segment(False, 0x18, doip(0x0006, struct.pack("!HHBI", TESTER_ADDRESS, ECU_ADDRESS, 0x10, 0)))
    ask(b"\x10\x03", b"\x50\x03\x00\x32\x01\xf4")
    ask(b"\x22\xf1\x90", b"\x62\xf1\x90" + VIN)
    ask(b"\x22\xf1\x99", b"\x7f\x22\x31")
    ask(b"\x31\x01\xff\x00", b"\x7f\x31\x78")
    segment(False, 0x18, answer(b"\x71\x01\xff\x00\x00"))
    segment(True, 0x18, diagnostic(b"\x3e\x80"))
    segment(False, 0x18, diagnostic_ack())
    transfer = diagnostic(b"\x36\x01" + bytes(range(256)) * 4)
    segment(True, 0x18, transfer[:600])
    segment(True, 0x18, transfer[600:])
    segment(False, 0x18, diagnostic_ack() + answer(b"\x76\x01"))
    segment(True, 0x18, diagnostic(b"\x3e\x00", target=0x2000))
    segment(False, 0x18, doip(0x8003, struct.pack("!HHB", 0x2000, TESTER_ADDRESS, 0x03)))
    segment(False, 0x18, doip(0x0007))
    segment(True, 0x18, doip(0x0008, struct.pack("!H", TESTER_ADDRESS)))
    segment(True, 0x11)
    segment(False, 0x11)
    segment(True, 0x10)


def malformed(capture: Capture) -> None:
    capture.add(udp_frame(TESTER, BROADCAST, TESTER_UDP_PORT, DOIP_PORT,
                          doip(0x0001, version=0x02, inverse=0xFF)))
    capture.add(udp_frame(TESTER, ECU, TESTER_UDP_PORT, DOIP_PORT, doip(0x4001, b"\x00")))


def main() -> None:
    capture = Capture()
    vehicle_identification(capture)
    diagnostics(capture)
    malformed(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "doip.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
