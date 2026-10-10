#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/mqtt.pcap, the corpus's MQTT capture.

Every byte is made up here, so the capture holds no one's traffic.  The MQTT
packets are encoded as clients and brokers send them (MQTT 3.1.1 and 5.0).
The capture holds:

1. An MQTT 3.1.1 session on port 1883: CONNECT with a user name and
   password, CONNACK, SUBSCRIBE and SUBACK, two PUBLISH packets in one
   segment, a retained QoS 1 PUBLISH and its PUBACK, a QoS 2 PUBLISH whose
   payload goes on in a second segment and its PUBREC, PUBREL and PUBCOMP,
   UNSUBSCRIBE and UNSUBACK, a ping, DISCONNECT.
2. An MQTT 5.0 session on port 1883, with properties: CONNECT, CONNACK,
   SUBSCRIBE and SUBACK, a PUBLISH acknowledged with a reason code and a
   reason string, and the broker's DISCONNECT with a reason.
3. An MQTT 3.1.1 session on port 18830, which only its CONNECT tells to be
   MQTT.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT, CLIENT5, BROKER = "192.0.2.10", "192.0.2.11", "192.0.2.83"

CONNECT, CONNACK, PUBLISH, PUBACK, PUBREC, PUBREL, PUBCOMP = 1, 2, 3, 4, 5, 6, 7
SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT = 8, 9, 10, 11, 12, 13, 14


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def addr(a: str) -> bytes:
    return ipaddress.IPv4Address(a).packed


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
              payload: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x1883, 0x4000, 64, 6, 0,
                         addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x0800)
    return ether + header + segment


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte, value = value & 0x7F, value >> 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def string(s) -> bytes:
    data = s.encode() if isinstance(s, str) else s
    return struct.pack("!H", len(data)) + data


def props(*properties: bytes) -> bytes:
    body = b"".join(properties)
    return varint(len(body)) + body


def packet(kind: int, body: bytes = b"", flags: int = 0) -> bytes:
    return bytes([kind << 4 | flags]) + varint(len(body)) + body


def publish(topic: str, payload: bytes, qos: int = 0, ident: int = 0, retain: bool = False,
            properties: bytes = None) -> bytes:
    body = string(topic) + (struct.pack("!H", ident) if qos else b"")
    if properties is not None:
        body += properties
    return packet(PUBLISH, body + payload, qos << 1 | int(retain))


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
    """One TCP connection from a client to the broker."""

    def __init__(self, capture: Capture, client: str, port: int, broker_port: int):
        self.capture, self.client, self.port, self.broker_port = capture, client, port, broker_port
        self.client_seq, self.broker_seq = 1000, 5000
        self.segment(True, 0x02)
        self.segment(False, 0x12)
        self.segment(True, 0x10)

    def segment(self, from_client: bool, flags: int, data: bytes = b"") -> None:
        if from_client:
            self.capture.add(tcp_frame(self.client, BROKER, self.port, self.broker_port,
                                       self.client_seq, self.broker_seq if flags != 0x02 else 0,
                                       flags, data))
            self.client_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            self.capture.add(tcp_frame(BROKER, self.client, self.broker_port, self.port,
                                       self.broker_seq, self.client_seq, flags, data))
            self.broker_seq += len(data) + (1 if flags & 0x03 else 0)

    def send(self, from_client: bool, data: bytes) -> None:
        self.segment(from_client, 0x18, data)


def mqtt311_session(capture: Capture) -> None:
    c = Connection(capture, CLIENT, 50001, 1883)
    c.send(True, packet(CONNECT, string("MQTT") + bytes([4, 0xC2]) + struct.pack("!H", 60)
                        + string("sensor-1") + string("bob") + string("secret")))
    c.send(False, packet(CONNACK, bytes([0, 0])))
    c.send(True, packet(SUBSCRIBE, struct.pack("!H", 1) + string("sensors/+/temp") + b"\x01"
                        + string("alerts/#") + b"\x00", 0x2))
    c.send(False, packet(SUBACK, struct.pack("!H", 1) + bytes([1, 0])))
    c.send(False, publish("sensors/kitchen/temp", b"21.5") + publish("sensors/hall/temp", b"19.0"))
    c.send(True, publish("alerts/door", b"open", qos=1, ident=2, retain=True))
    c.send(False, packet(PUBACK, struct.pack("!H", 2)))
    log = b"".join(b"line %04d of the sensor log\n" % i for i in range(20))
    big = publish("logs/raw", log, qos=2, ident=3)
    c.send(True, big[:200])
    c.send(True, big[200:])
    c.send(False, packet(PUBREC, struct.pack("!H", 3)))
    c.send(True, packet(PUBREL, struct.pack("!H", 3), 0x2))
    c.send(False, packet(PUBCOMP, struct.pack("!H", 3)))
    c.send(True, packet(UNSUBSCRIBE, struct.pack("!H", 4) + string("alerts/#"), 0x2))
    c.send(False, packet(UNSUBACK, struct.pack("!H", 4)))
    c.send(True, packet(PINGREQ))
    c.send(False, packet(PINGRESP))
    c.send(True, packet(DISCONNECT))


def mqtt5_session(capture: Capture) -> None:
    c = Connection(capture, CLIENT5, 50002, 1883)
    session_expiry = b"\x11" + struct.pack("!I", 3600)
    receive_maximum = b"\x21" + struct.pack("!H", 20)
    c.send(True, packet(CONNECT, string("MQTT") + bytes([5, 0x02]) + struct.pack("!H", 30)
                        + props(session_expiry, receive_maximum) + string("dev-5")))
    c.send(False, packet(CONNACK, bytes([0, 0]) + props(b"\x22" + struct.pack("!H", 10),
                                                         b"\x24\x01")))
    c.send(True, packet(SUBSCRIBE, struct.pack("!H", 1) + props(b"\x0b\x07") + string("cmd/#")
                        + b"\x01", 0x2))
    c.send(False, packet(SUBACK, struct.pack("!H", 1) + props() + b"\x01"))
    c.send(True, publish("status/dev-5", b'{"up":true}', qos=1, ident=2,
                         properties=props(b"\x01\x01", b"\x03" + string("application/json"))))
    c.send(False, packet(PUBACK, struct.pack("!H", 2) + b"\x10"
                         + props(b"\x1f" + string("nobody listening"))))
    c.send(False, packet(DISCONNECT, b"\x8b" + props(b"\x1f" + string("maintenance"))))


def other_port_session(capture: Capture) -> None:
    c = Connection(capture, CLIENT, 50003, 18830)
    c.send(True, packet(CONNECT, string("MQTT") + bytes([4, 0x02]) + struct.pack("!H", 15)
                        + string("probe")))
    c.send(False, packet(CONNACK, bytes([0, 0])))
    c.send(True, publish("test/topic", b"hello"))
    c.send(True, packet(PINGREQ))
    c.send(False, packet(PINGRESP))


def main() -> None:
    capture = Capture()
    mqtt311_session(capture)
    mqtt5_session(capture)
    other_port_session(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "mqtt.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
