#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/ssh.pcap, the corpus's SSH capture.

Every byte is made up here, so the capture holds no one's traffic: the
packets are laid out as RFC 4253 says, the keys, signatures and encrypted
packets are filler.  The capture holds:

1. SSH on port 22: the server's and the client's banner, the client's
   KEXINIT split over two segments, which the TCP Reassembly puts together,
   the server's KEXINIT, the ECDH key exchange, the server's reply and
   NEWKEYS in one segment, the client's NEWKEYS with its first encrypted
   packet behind it, then encrypted packets both ways.
2. SSH on port 2222, told by its banner: the client's banner and KEXINIT in
   one segment, the Diffie-Hellman group exchange, NEWKEYS, an encrypted
   packet.
3. A connection on port 22 whose key exchange the capture did not see:
   encrypted packets, named by the port.
4. Two malformed packets after a banner on port 22: a packet_length the
   unencrypted phase does not allow, a padding_length beyond the packet.

Run it from anywhere; it rewrites the capture.  Then regenerate the expected
text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

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


def string(data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + data


def name_list(*names: str) -> bytes:
    return string(",".join(names).encode())


def packet(code: int, body: bytes = b"") -> bytes:
    """A binary packet of the unencrypted phase, padded to a multiple of 8."""
    padding = 8 - (6 + len(body)) % 8
    if padding < 4:
        padding += 8
    return struct.pack("!IBB", 2 + len(body) + padding, padding, code) + body + bytes(padding)


def kexinit(kex: list[str], hostkey: list[str], cookie: int) -> bytes:
    ciphers = ["chacha20-poly1305@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr"]
    macs = ["umac-64-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"]
    compression = ["none", "zlib@openssh.com"]
    lists = [kex, hostkey, ciphers, ciphers, macs, macs, compression, compression, [], []]
    return packet(20, bytes([cookie]) * 16 + b"".join(name_list(*names) for names in lists)
                  + b"\x00" + struct.pack("!I", 0))


def filler(n: int, seed: int) -> bytes:
    """Bytes that look random, as an encrypted packet's do."""
    out, x = bytearray(), seed
    for _ in range(n):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


CLIENT_KEX = ["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256",
              "diffie-hellman-group-exchange-sha256", "ext-info-c",
              "kex-strict-c-v00@openssh.com"]
SERVER_KEX = ["sntrup761x25519-sha512", "curve25519-sha256", "kex-strict-s-v00@openssh.com"]
HOSTKEYS = ["ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512", "rsa-sha2-256"]
ED25519_KEY = string(string(b"ssh-ed25519") + string(filler(32, 7)))
ED25519_SIG = string(string(b"ssh-ed25519") + string(filler(64, 8)))


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


def openssh(capture: Capture) -> None:
    c = Connection(capture, 50122, 22)
    c.server(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5\r\n")
    c.client(b"SSH-2.0-OpenSSH_9.6\r\n")
    client_kexinit = kexinit(CLIENT_KEX, HOSTKEYS, 0x11)
    c.client(client_kexinit[:400])
    c.client(client_kexinit[400:])
    c.server(kexinit(SERVER_KEX, HOSTKEYS[:3], 0x22))
    c.client(packet(30, string(filler(32, 1))))
    c.server(packet(31, ED25519_KEY + string(filler(32, 2)) + ED25519_SIG) + packet(21))
    c.client(packet(21) + filler(64, 3))
    c.server(filler(64, 4))
    c.client(filler(112, 5))
    c.server(filler(48, 6))
    c.close()


def group_exchange(capture: Capture) -> None:
    c = Connection(capture, 50123, 2222)
    c.client(b"SSH-2.0-PuTTY_Release_0.81\r\n"
             + kexinit(["diffie-hellman-group-exchange-sha256"], ["ssh-ed25519"], 0x33))
    c.server(b"SSH-2.0-dropbear_2024.85\r\n")
    c.server(kexinit(["diffie-hellman-group-exchange-sha256", "curve25519-sha256"],
                     ["ssh-ed25519"], 0x44))
    c.client(packet(34, struct.pack("!III", 2048, 3072, 8192)))
    c.server(packet(31, string(b"\x00" + filler(384, 9)) + string(b"\x02")))
    c.client(packet(32, string(filler(384, 10))))
    c.server(packet(33, ED25519_KEY + string(filler(384, 11)) + ED25519_SIG) + packet(21))
    c.client(packet(21))
    c.client(filler(80, 12))
    c.close()


def mid_session(capture: Capture) -> None:
    c = Connection(capture, 50124, 22, handshake=False)
    c.client(filler(36, 13))
    c.server(filler(68, 14))
    c.send(True, 0x10)


def malformed(capture: Capture) -> None:
    c = Connection(capture, 50125, 22)
    c.client(b"SSH-2.0-OpenSSH_9.6\r\n")
    c.client(struct.pack("!I", 13) + bytes(12))
    c.client(struct.pack("!IBB", 12, 11, 21) + bytes(10))
    c.close()


def main() -> None:
    capture = Capture()
    openssh(capture)
    group_exchange(capture)
    mid_session(capture)
    malformed(capture)
    out = pathlib.Path(__file__).resolve().parent / "corpus" / "ssh.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
