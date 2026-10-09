#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/smb.pcap, the corpus's SMB capture.

Every byte is made up here, so the capture holds no one's traffic.  The
messages are encoded as RFC 1002 (NetBIOS Session Service) and MS-SMB2 lay
them out.  The capture holds:

1. SMB on TCP port 445: an SMB1 Negotiate Protocol Request the server
   answers with SMB2's wildcard dialect, the SMB2 negotiation (3.1.1), a
   session setup in two rounds (STATUS_MORE_PROCESSING_REQUIRED), a tree
   connect, one refused (STATUS_ACCESS_DENIED), FSCTL_VALIDATE_NEGOTIATE_INFO,
   a compounded Create, GetInfo and Close, a Create of a file that does not
   exist, a Read whose response spans three segments, which the TCP
   Reassembly puts together, a Write, a directory listing (Find, then
   STATUS_NO_MORE_FILES), a change notification (STATUS_PENDING), two
   messages in one segment, encrypted and compressed SMB 3 messages, then
   tree disconnect and logoff.
2. SMB over NetBIOS on TCP port 139: the session request and its positive
   response before the negotiation.
3. Two malformed messages: a header of the wrong size, and a NextCommand
   beyond its message.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT, SERVER = "192.0.2.50", "192.0.2.60"
CLIENT_PORT, NBSS_CLIENT_PORT, SMB_PORT, NBSS_PORT = 50100, 50101, 445, 139
SESSION_ID = 0x0000100000000041
MAX_SEGMENT = 1460


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


def smb2(command: int, body: bytes = b"", response: bool = False, status: int = 0,
         message_id: int = 0, tree_id: int = 1, next_command: int = 0) -> bytes:
    flags = 0x00000001 if response else 0x00000000
    header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 1, status, command, 1, flags,
                         next_command, message_id, 0xFEFF, tree_id, SESSION_ID, bytes(16))
    return header + body


def utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def nbss(message: bytes, message_type: int = 0x00) -> bytes:
    if message_type == 0x00:
        return struct.pack("!I", len(message)) + message
    return struct.pack("!BBH", message_type, 0, len(message)) + message


def error(command: int, status: int, message_id: int) -> bytes:
    return smb2(command, struct.pack("<HBBI", 9, 0, 0, 0) + b"\0", True, status, message_id)


def negotiate_request(dialects: list[int], message_id: int) -> bytes:
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 0x0001, 0, 0x7F, bytes(range(16)), 0)
    return smb2(0x00, body + b"".join(struct.pack("<H", d) for d in dialects),
                message_id=message_id)


def negotiate_response(dialect: int, message_id: int) -> bytes:
    body = struct.pack("<HHHH16sIIII", 65, 0x0001, dialect, 0, bytes(range(16, 32)), 0x2F,
                       8388608, 8388608, 8388608) + bytes(64 - 40)
    return smb2(0x00, body, True, message_id=message_id)


def session_setup(blob: bytes, message_id: int) -> bytes:
    body = struct.pack("<HBBIIHHQ", 25, 0, 0x01, 0x01, 0, 64 + 24, len(blob), 0)
    return smb2(0x01, body + blob, message_id=message_id)


def session_setup_response(blob: bytes, status: int, message_id: int) -> bytes:
    body = struct.pack("<HHHH", 9, 0, 64 + 8, len(blob))
    return smb2(0x01, body + blob, True, status, message_id)


def tree_connect(path: str, message_id: int) -> bytes:
    name = utf16(path)
    return smb2(0x03, struct.pack("<HHHH", 9, 0, 64 + 8, len(name)) + name, message_id=message_id,
                tree_id=0)


def tree_connect_response(message_id: int) -> bytes:
    return smb2(0x03, struct.pack("<HBBIII", 16, 0x01, 0, 0, 0, 0x001F01FF), True,
                message_id=message_id)


def create(path: str, message_id: int, next_command: int = 0) -> bytes:
    name = utf16(path)
    body = struct.pack("<HBBIQQIIIIIHHII", 57, 0, 0, 2, 0, 0, 0x00120089, 0, 7, 1, 0x40,
                       64 + 56, len(name), 0, 0)
    return smb2(0x05, body + name, message_id=message_id, next_command=next_command)


FILE_ID = bytes.fromhex("0100000000000000ffffffffffffffff")


def create_response(message_id: int) -> bytes:
    body = struct.pack("<HBBIQQQQQQII16sII", 89, 0, 0, 1, 0, 0, 0, 0, 4096, 2900, 0x20, 0,
                       FILE_ID, 0, 0)
    return smb2(0x05, body, True, message_id=message_id)


def get_info(message_id: int, next_command: int = 0) -> bytes:
    body = struct.pack("<HBBIHHII16s", 41, 0x01, 0x12, 4096, 0, 0, 0, 0, FILE_ID)
    return smb2(0x10, body, message_id=message_id, next_command=next_command)


def close(message_id: int) -> bytes:
    return smb2(0x06, struct.pack("<HHI16s", 24, 0, 0, FILE_ID), message_id=message_id)


def close_response(message_id: int) -> bytes:
    return smb2(0x06, struct.pack("<HHI", 60, 0, 0) + bytes(56), True, message_id=message_id)


def padded(message: bytes) -> bytes:
    return message + bytes(-len(message) % 8)


def compounded(*commands: bytes) -> bytes:
    """Commands one after another, each one's NextCommand pointing at the next."""
    out = b""
    for i, command in enumerate(commands):
        if i + 1 < len(commands):
            command = padded(command)
            command = command[:20] + struct.pack("<I", len(command)) + command[24:]
        out += command
    return out


def read(length: int, offset: int, message_id: int) -> bytes:
    body = struct.pack("<HBBIQ16sIIIHH", 49, 0x50, 0, length, offset, FILE_ID, 1, 0, 0, 0, 0)
    return smb2(0x08, body + b"\0", message_id=message_id)


def read_response(data: bytes, message_id: int) -> bytes:
    body = struct.pack("<HBBIII", 17, 0x50, 0, len(data), 0, 0)
    return smb2(0x08, body + data, True, message_id=message_id)


def write(data: bytes, offset: int, message_id: int) -> bytes:
    body = struct.pack("<HHIQ16sIIHHI", 49, 0x70, len(data), offset, FILE_ID, 0, 0, 0, 0, 0)
    return smb2(0x09, body + data, message_id=message_id)


def write_response(count: int, message_id: int) -> bytes:
    return smb2(0x09, struct.pack("<HHIIHH", 17, 0, count, 0, 0, 0), True, message_id=message_id)


def ioctl(code: int, data: bytes, message_id: int, response: bool = False) -> bytes:
    if response:
        body = struct.pack("<HHI16sIIIIII", 49, 0, code, bytes([0xFF] * 16), 64 + 48, 0,
                           64 + 48, len(data), 0, 0)
    else:
        body = struct.pack("<HHI16sIIIIIIII", 57, 0, code, bytes([0xFF] * 16), 64 + 56,
                           len(data), 0, 0, 0, 65536, 0x00000001, 0)
    return smb2(0x0B, body + data, response, message_id=message_id)


def find(pattern: str, message_id: int) -> bytes:
    name = utf16(pattern)
    body = struct.pack("<HBBI16sHHI", 33, 0x25, 0, 0, FILE_ID, 64 + 32, len(name), 65536)
    return smb2(0x0E, body + name, message_id=message_id)


def find_response(entries: bytes, message_id: int) -> bytes:
    return smb2(0x0E, struct.pack("<HHI", 9, 64 + 8, len(entries)) + entries, True,
                message_id=message_id)


def notify(message_id: int) -> bytes:
    return smb2(0x0F, struct.pack("<HHI16sII", 32, 0, 4096, FILE_ID, 0x17, 0),
                message_id=message_id)


def encrypted(plain_length: int, nonce: int) -> bytes:
    header = struct.pack("<4s16s16sIHHQ", b"\xfdSMB", bytes([0xA5] * 16),
                         nonce.to_bytes(16, "little"), plain_length, 0, 0x0001, SESSION_ID)
    return header + bytes((i * 37 + nonce) & 0xFF for i in range(plain_length))


def compressed(original: int, data: bytes) -> bytes:
    return struct.pack("<4sIHHI", b"\xfcSMB", original, 0x0002, 0x0000, 0) + data


def smb1_negotiate() -> bytes:
    dialects = b"".join(b"\x02" + d + b"\0" for d in (b"NT LM 0.12", b"SMB 2.002", b"SMB 2.???"))
    header = struct.pack("<4sBIBHH8sHHHHH", b"\xffSMB", 0x72, 0, 0x18, 0xC853, 0, bytes(8), 0,
                         0xFFFF, 0xFEFF, 0, 0)
    return header + struct.pack("<BH", 0, len(dialects)) + dialects


class Connection:
    def __init__(self, capture: "Capture", client_port: int, server_port: int):
        self.capture = capture
        self.client_port, self.server_port = client_port, server_port
        self.client_seq, self.server_seq = 1000, 7000

    def segment(self, from_client: bool, flags: int, data: bytes = b"") -> None:
        if from_client:
            self.capture.add(tcp_frame(CLIENT, SERVER, self.client_port, self.server_port,
                                       self.client_seq, self.server_seq if flags != 0x02 else 0,
                                       flags, data))
            self.client_seq += len(data) + (1 if flags & 0x03 else 0)
        else:
            self.capture.add(tcp_frame(SERVER, CLIENT, self.server_port, self.client_port,
                                       self.server_seq, self.client_seq, flags, data))
            self.server_seq += len(data) + (1 if flags & 0x03 else 0)

    def send(self, from_client: bool, data: bytes) -> None:
        """Data in segments of at most MAX_SEGMENT bytes."""
        for at in range(0, len(data), MAX_SEGMENT):
            self.segment(from_client, 0x18, data[at:at + MAX_SEGMENT])

    def ask(self, request: bytes, *responses: bytes) -> None:
        self.send(True, nbss(request))
        self.send(False, b"".join(nbss(r) for r in responses))

    def open(self) -> None:
        self.segment(True, 0x02)
        self.segment(False, 0x12)
        self.segment(True, 0x10)

    def close(self) -> None:
        self.segment(True, 0x11)
        self.segment(False, 0x11)
        self.segment(True, 0x10)


def negotiation(c: Connection) -> None:
    c.ask(smb1_negotiate(), negotiate_response(0x02FF, 0))
    c.ask(negotiate_request([0x0202, 0x0210, 0x0300, 0x0302, 0x0311], 1),
          negotiate_response(0x0311, 1))
    c.ask(session_setup(b"NTLMSSP\0\x01\0\0\0" + bytes(32), 2),
          session_setup_response(b"NTLMSSP\0\x02\0\0\0" + bytes(48), 0xC0000016, 2))
    c.ask(session_setup(b"NTLMSSP\0\x03\0\0\0" + bytes(64), 3),
          session_setup_response(b"", 0, 3))


def file_access(c: Connection) -> None:
    c.ask(tree_connect("\\\\fileserver\\docs", 4), tree_connect_response(4))
    c.ask(tree_connect("\\\\fileserver\\secret", 5), error(0x03, 0xC0000022, 5))
    validate = struct.pack("<I16sHH", 0x7F, bytes(range(16)), 1, 1) + struct.pack("<H", 0x0311)
    c.ask(ioctl(0x00140204, validate, 6),
          ioctl(0x00140204, struct.pack("<I16sHH", 0x2F, bytes(range(16, 32)), 1, 0x0311), 6,
                True))
    c.ask(compounded(create("reports\\q3.txt", 7), get_info(8), close(9)),
          create_response(7), smb2(0x10, struct.pack("<HHI", 9, 72, 8) + bytes(8), True,
                                   message_id=8), close_response(9))
    c.ask(create("reports\\q4.txt", 10), error(0x05, 0xC0000034, 10))
    c.ask(create("reports\\q3.txt", 11), create_response(11))
    c.ask(read(4096, 0, 12),
          read_response(bytes((i * 7) & 0xFF for i in range(2900)), 12))
    c.ask(write(b"Quarterly figures, revised.\n" * 10, 2900, 13), write_response(280, 13))
    c.ask(close(14), close_response(14))
    c.ask(create("reports", 15), create_response(15))
    c.ask(find("*", 16), find_response(bytes(104), 16))
    c.ask(find("*", 17), error(0x0E, 0x80000006, 17))
    c.send(True, nbss(notify(18)))
    c.send(False, nbss(error(0x0F, 0x00000103, 18)))
    c.send(True, nbss(close(19)) + nbss(smb2(0x0D, struct.pack("<HH", 4, 0), message_id=20)))
    c.send(False, nbss(error(0x0F, 0xC0000120, 18)) + nbss(close_response(19))
           + nbss(smb2(0x0D, struct.pack("<HH", 4, 0), True, message_id=20)))


def encryption(c: Connection) -> None:
    c.ask(encrypted(120, 1), encrypted(160, 2))
    c.send(True, nbss(compressed(4096, bytes(range(200)))))
    c.ask(smb2(0x04, struct.pack("<HH", 4, 0), message_id=21),
          smb2(0x04, struct.pack("<HH", 4, 0), True, message_id=21))
    c.ask(smb2(0x02, struct.pack("<HH", 4, 0), message_id=22),
          smb2(0x02, struct.pack("<HH", 4, 0), True, message_id=22))


def over_netbios(c: Connection) -> None:
    called = b" " + b"EMEFEMECECEMEFENFEFDEECACACACACA" + b"\0"
    calling = b" " + b"EDEMEJEFEOFECACACACACACACACACAAA" + b"\0"
    c.send(True, nbss(called + calling, 0x81))
    c.send(False, nbss(b"", 0x82))
    c.ask(negotiate_request([0x0202, 0x0210, 0x0300, 0x0302, 0x0311], 0),
          negotiate_response(0x0311, 0))


def malformed(c: Connection) -> None:
    wrong_size = bytearray(smb2(0x05, b"", message_id=30))
    wrong_size[4] = 32
    c.send(True, nbss(bytes(wrong_size)))
    beyond = bytearray(close(31))
    beyond[20:24] = struct.pack("<I", 4096)
    c.send(True, nbss(bytes(beyond)))


def main() -> None:
    capture = Capture()
    smb = Connection(capture, CLIENT_PORT, SMB_PORT)
    smb.open()
    negotiation(smb)
    file_access(smb)
    encryption(smb)
    malformed(smb)
    smb.close()
    netbios = Connection(capture, NBSS_CLIENT_PORT, NBSS_PORT)
    netbios.open()
    over_netbios(netbios)
    netbios.close()
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "smb.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
