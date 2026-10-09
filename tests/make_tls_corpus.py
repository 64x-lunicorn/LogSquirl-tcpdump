#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/tls.pcap, the corpus's TLS capture.

The TLS bytes are real: Python's ssl module (OpenSSL) runs a client and a
server against each other in memory, with a throw-away self-signed
certificate made by the openssl command.  The frames around them, Ethernet,
IPv4 and TCP, are made up here, so the capture holds no one's traffic.  It
holds three connections to port 443, the server's flights cut into TCP
segments of at most 1448 bytes:

1. TLS 1.3 with the server name example.com and ALPN h2 and http/1.1.
2. TLS 1.2 with the server name www.example.org and no ALPN.
3. A ClientHello captured with a snaplen of 128 bytes, cut within it.

Run it from anywhere; it rewrites the capture, with new random bytes in the
handshakes.  Then regenerate the expected text with TCPDUMP_UPDATE_CORPUS=1
and review it.  Needs the openssl command.
"""

import pathlib
import ssl
import struct
import subprocess
import tempfile

BASE = 1760000000  # seconds since the epoch of the first packet
MSS = 1448
CLIENT, SERVER = "192.0.2.10", "198.51.100.7"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def addr(a: str) -> bytes:
    return bytes(int(x) for x in a.split("."))


def frame(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int,
          payload: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + payload
    pseudo = addr(src) + addr(dst) + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0x1C46, 0x4000, 64, 6, 0,
                         addr(src), addr(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    ether = bytes.fromhex("02005e000001") + bytes.fromhex("02005e000002") + struct.pack("!H", 0x0800)
    return ether + header + segment


class Capture:
    def __init__(self):
        self.records = []
        self.time = 0  # microseconds since BASE

    def add(self, data: bytes, snaplen: int = 65535) -> None:
        self.time += 1500
        captured = data[:snaplen]
        self.records.append(struct.pack("<IIII", BASE + self.time // 1000000, self.time % 1000000,
                                        len(captured), len(data)) + captured)

    def bytes(self) -> bytes:
        header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        return header + b"".join(self.records)


class Connection:
    """One TCP connection on the capture, from a client port to 443."""

    def __init__(self, capture: Capture, port: int):
        self.capture, self.port = capture, port
        self.client_seq, self.server_seq = 1000, 5000
        capture.add(frame(CLIENT, SERVER, port, 443, self.client_seq, 0, 0x02))
        capture.add(frame(SERVER, CLIENT, 443, port, self.server_seq, self.client_seq + 1, 0x12))
        self.client_seq += 1
        self.server_seq += 1
        capture.add(frame(CLIENT, SERVER, port, 443, self.client_seq, self.server_seq, 0x10))

    def send(self, from_client: bool, data: bytes, snaplen: int = 65535) -> None:
        for i in range(0, len(data), MSS):
            chunk = data[i:i + MSS]
            if from_client:
                self.capture.add(frame(CLIENT, SERVER, self.port, 443, self.client_seq,
                                       self.server_seq, 0x18, chunk), snaplen)
                self.client_seq += len(chunk)
            else:
                self.capture.add(frame(SERVER, CLIENT, 443, self.port, self.server_seq,
                                       self.client_seq, 0x18, chunk), snaplen)
                self.server_seq += len(chunk)


def handshake(capture: Capture, port: int, certs: pathlib.Path, server_name: str,
              version: ssl.TLSVersion, alpn) -> None:
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.check_hostname = False
    client_ctx.verify_mode = ssl.CERT_NONE
    client_ctx.maximum_version = version
    if alpn:
        client_ctx.set_alpn_protocols(alpn)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(certs / "cert.pem", certs / "key.pem")
    if alpn:
        server_ctx.set_alpn_protocols(alpn)

    to_server, to_client = ssl.MemoryBIO(), ssl.MemoryBIO()
    from_server, from_client = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = client_ctx.wrap_bio(to_client, from_client, server_hostname=server_name)
    server = server_ctx.wrap_bio(to_server, from_server, server_side=True)

    connection = Connection(capture, port)
    done = set()
    while len(done) < 2:
        for name, side, outgoing, peer_in, from_client_side in (
                ("client", client, from_client, to_server, True),
                ("server", server, from_server, to_client, False)):
            try:
                side.do_handshake()
                done.add(name)
            except ssl.SSLWantReadError:
                pass
            data = outgoing.read()
            if data:
                connection.send(from_client_side, data)
                peer_in.write(data)

    client.write(b"GET / HTTP/1.1\r\nHost: " + server_name.encode() + b"\r\n\r\n")
    data = from_client.read()
    connection.send(True, data)
    to_server.write(data)
    server.read()
    server.write(b"HTTP/1.1 204 No Content\r\n\r\n")
    data = from_server.read()  # with TLS 1.3, the session tickets come first
    connection.send(False, data)


def cut_client_hello(capture: Capture, port: int) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    client = ctx.wrap_bio(incoming, outgoing, server_hostname="cut.example.net")
    try:
        client.do_handshake()
    except ssl.SSLWantReadError:
        pass
    Connection(capture, port).send(True, outgoing.read(), snaplen=128)


def main() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        certs = pathlib.Path(tmp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj",
                        "/CN=example.com", "-keyout", str(certs / "key.pem"), "-out",
                        str(certs / "cert.pem")], check=True, capture_output=True)
        capture = Capture()
        handshake(capture, 50443, certs, "example.com", ssl.TLSVersion.TLSv1_3,
                  ["h2", "http/1.1"])
        handshake(capture, 50444, certs, "www.example.org", ssl.TLSVersion.TLSv1_2, None)
        cut_client_hello(capture, 50445)

    out = pathlib.Path(__file__).resolve().parent / "corpus" / "tls.pcap"
    out.write_bytes(capture.bytes())


if __name__ == "__main__":
    main()
