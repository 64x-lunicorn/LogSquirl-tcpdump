#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/dns.pcap, the corpus's DNS capture.

Every byte is made up here, so the capture holds no one's traffic.  The DNS
messages are encoded as resolvers and servers send them: names compressed
against every name before them, an EDNS OPT record in the additional
section, the SOA of the zone in the authority section of a negative answer.
The capture holds:

1. Over UDP, queries and responses for A (behind a CNAME), AAAA, MX, TXT,
   SRV and PTR records, a name that does not exist, and an address list
   longer than the describer lists.
2. Over TCP to port 53, a query and its response, the response cut over two
   segments, then two queries sent in one segment and their responses.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT, SERVER = "192.0.2.10", "192.0.2.53"

A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV, OPT = 1, 2, 5, 6, 12, 15, 16, 28, 33, 41


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
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, protocol, len(segment))
    at = 6 if protocol == 17 else 16
    segment = segment[:at] + struct.pack("!H", checksum(pseudo + segment)) + segment[at + 2:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x2F01, 0x4000, 64,
                         protocol, 0, addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x0800)
    return ether + header + segment


def udp_frame(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    return ip_frame(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload)


def tcp_frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
              payload: bytes = b"") -> bytes:
    return ip_frame(src, dst, 6, struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags,
                                             64240, 0, 0) + payload)


class Message:
    """A DNS message, its names compressed against the names before them."""

    def __init__(self, ident: int, flags: int):
        self.ident, self.flags = ident, flags
        self.sections = [[], [], [], []]  # question, answer, authority, additional
        self.data = bytearray(12)
        self.names = {}  # a name's suffix, as a tuple of labels, and where it is

    def name(self, dotted: str) -> bytes:
        labels = tuple(label for label in dotted.split(".") if label)
        out = bytearray()
        for i in range(len(labels)):
            suffix = labels[i:]
            if suffix in self.names:
                return bytes(out) + struct.pack("!H", 0xC000 | self.names[suffix])
            where = len(self.data) + len(out)
            if where < 0x4000:
                self.names[suffix] = where
            out += bytes([len(labels[i])]) + labels[i].encode()
        return bytes(out) + b"\0"

    def question(self, dotted: str, rtype: int) -> "Message":
        self.data += self.name(dotted) + struct.pack("!HH", rtype, 1)
        self.sections[0].append(rtype)
        return self

    def record(self, section: int, dotted: str, rtype: int, rdata) -> "Message":
        """rdata: bytes, or a function that encodes it at its place."""
        self.data += self.name(dotted) + struct.pack("!HHI", rtype, 1, 300)
        at = len(self.data)
        self.data += b"\0\0"
        body = rdata(self) if callable(rdata) else rdata
        self.data += body
        self.data[at:at + 2] = struct.pack("!H", len(body))
        self.sections[section].append(rtype)
        return self

    def answer(self, dotted, rtype, rdata):
        return self.record(1, dotted, rtype, rdata)

    def edns(self) -> "Message":
        self.data += b"\0" + struct.pack("!HHIH", OPT, 1232, 0, 0)
        self.sections[3].append(OPT)
        return self

    def bytes(self) -> bytes:
        counts = [len(section) for section in self.sections]
        return struct.pack("!HHHHHH", self.ident, self.flags, *counts) + bytes(self.data[12:])


def host(dotted: str):
    return lambda message: message.name(dotted)


def mx(preference: int, dotted: str):
    return lambda message: struct.pack("!H", preference) + message.name(dotted)


def srv(priority: int, weight: int, port: int, dotted: str):
    return lambda message: struct.pack("!HHH", priority, weight, port) + message.name(dotted)


def soa(primary: str, mailbox: str):
    return lambda message: (message.name(primary) + message.name(mailbox)
                            + struct.pack("!IIIII", 2026100901, 7200, 3600, 1209600, 3600))


def txt(*strings: str) -> bytes:
    return b"".join(bytes([len(s)]) + s.encode() for s in strings)


QUERY, RESPONSE, NXDOMAIN = 0x0100, 0x8180, 0x8183


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes) -> None:
        self.time += 1500
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(data), len(data)) + data)

    def exchange(self, port: int, query: Message, response: Message) -> None:
        self.add(udp_frame(CLIENT, SERVER, port, 53, query.bytes()))
        self.add(udp_frame(SERVER, CLIENT, 53, port, response.bytes()))

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


class Connection:
    """One TCP connection from a client port to port 53."""

    def __init__(self, capture: Capture, port: int):
        self.capture, self.port = capture, port
        self.client_seq, self.server_seq = 1000, 5000
        capture.add(tcp_frame(CLIENT, SERVER, port, 53, self.client_seq, 0, 0x02))
        capture.add(tcp_frame(SERVER, CLIENT, 53, port, self.server_seq, self.client_seq + 1, 0x12))
        self.client_seq += 1
        self.server_seq += 1
        capture.add(tcp_frame(CLIENT, SERVER, port, 53, self.client_seq, self.server_seq, 0x10))

    def send(self, from_client: bool, data: bytes) -> None:
        if from_client:
            self.capture.add(tcp_frame(CLIENT, SERVER, self.port, 53, self.client_seq,
                                       self.server_seq, 0x18, data))
            self.client_seq += len(data)
        else:
            self.capture.add(tcp_frame(SERVER, CLIENT, 53, self.port, self.server_seq,
                                       self.client_seq, 0x18, data))
            self.server_seq += len(data)


def framed(message: Message) -> bytes:
    data = message.bytes()
    return struct.pack("!H", len(data)) + data


def main() -> None:
    capture = Capture()

    capture.exchange(53001, Message(0x1A2B, QUERY).question("www.example.com", A).edns(),
                     Message(0x1A2B, RESPONSE).question("www.example.com", A)
                     .answer("www.example.com", CNAME, host("example.com"))
                     .answer("example.com", A, addr("93.184.216.34")).edns())
    capture.exchange(53002, Message(0x2B3C, QUERY).question("example.com", AAAA).edns(),
                     Message(0x2B3C, RESPONSE).question("example.com", AAAA)
                     .answer("example.com", AAAA, ipaddress.IPv6Address("2001:db8::1").packed)
                     .edns())
    capture.exchange(53003, Message(0x3C4D, QUERY).question("example.com", MX),
                     Message(0x3C4D, RESPONSE).question("example.com", MX)
                     .answer("example.com", MX, mx(10, "mail.example.com"))
                     .answer("example.com", MX, mx(20, "mail2.example.com"))
                     .record(3, "mail.example.com", A, addr("192.0.2.25")))
    capture.exchange(53004, Message(0x4D5E, QUERY).question("example.com", TXT),
                     Message(0x4D5E, RESPONSE).question("example.com", TXT)
                     .answer("example.com", TXT, txt("v=spf1 -all"))
                     .answer("example.com", TXT, txt("site-verification=", "abc123")))
    capture.exchange(53005, Message(0x5E6F, QUERY).question("_sip._udp.example.com", SRV),
                     Message(0x5E6F, RESPONSE).question("_sip._udp.example.com", SRV)
                     .answer("_sip._udp.example.com", SRV, srv(10, 60, 5060, "sip.example.com")))
    capture.exchange(53006, Message(0x6F70, QUERY).question("34.216.184.93.in-addr.arpa", PTR),
                     Message(0x6F70, RESPONSE).question("34.216.184.93.in-addr.arpa", PTR)
                     .answer("34.216.184.93.in-addr.arpa", PTR, host("example.com")))
    capture.exchange(53007, Message(0x7081, QUERY).question("nx.example.com", A),
                     Message(0x7081, NXDOMAIN).question("nx.example.com", A)
                     .record(2, "example.com", SOA, soa("ns1.example.com",
                                                        "hostmaster.example.com")))
    many = Message(0x8192, RESPONSE).question("pool.example.net", A)
    for i in range(1, 7):
        many.answer("pool.example.net", A, addr("198.51.100.%d" % i))
    capture.exchange(53008, Message(0x8192, QUERY).question("pool.example.net", A), many)

    connection = Connection(capture, 53100)
    connection.send(True, framed(Message(0x92A3, QUERY).question("example.com", NS)))
    response = framed(Message(0x92A3, RESPONSE).question("example.com", NS)
                      .answer("example.com", NS, host("ns1.example.com"))
                      .answer("example.com", NS, host("ns2.example.com"))
                      .record(3, "ns1.example.com", A, addr("192.0.2.1"))
                      .record(3, "ns2.example.com", A, addr("192.0.2.2")))
    connection.send(False, response[:48])
    connection.send(False, response[48:])
    connection.send(True, framed(Message(0xA3B4, QUERY).question("example.org", A))
                    + framed(Message(0xA3B5, QUERY).question("example.org", AAAA)))
    connection.send(False, framed(Message(0xA3B4, RESPONSE).question("example.org", A)
                                  .answer("example.org", A, addr("192.0.2.80")))
                    + framed(Message(0xA3B5, RESPONSE).question("example.org", AAAA)
                             .answer("example.org", AAAA,
                                     ipaddress.IPv6Address("2001:db8::80").packed)))

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "dns.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
