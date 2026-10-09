#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# /// script
# requires-python = ">=3.9"
# dependencies = ["cryptography"]
# ///
"""Write tests/corpus/tls-decrypt.pcap and its key log, tls-decrypt.keys.

TLS sessions whose records the TLS Decryption decrypts with the key log's
secrets, and describes: HTTP/1.1 and HTTP/2 inside.  Everything is made up
here, byte for byte, from a fixed seed: the randoms, the secrets, the
handshakes (whose certificates and signatures are filler, as nothing checks
them) and the records, encrypted with the keys the secrets give.  No one's
traffic, no real key.  Each session has a connection of its own:

1. TLS 1.2, ECDHE-RSA-AES128-GCM-SHA256: an HTTP/1.1 request and response,
   then close_notify alerts.
2. TLS 1.3, TLS_AES_128_GCM_SHA256, ALPN h2: two HTTP/2 requests, the
   second referring to the HPACK dynamic table the first filled, and the
   responses.
3. TLS 1.3, TLS_CHACHA20_POLY1305_SHA256: HTTP/1.1, a response record split
   over 2 segments, a KeyUpdate of the client, and a request record the
   capture lost before the last one.
4. TLS 1.2, ECDHE-RSA-CHACHA20-POLY1305: HTTP/1.1, the response a 404.
5. TLS 1.2, ECDHE-RSA-AES256-SHA with encrypt-then-MAC (RFC 7366): HTTP/1.1.
6. TLS 1.2, AES128-SHA256, MAC-then-encrypt: HTTP/1.1.
7. TLS 1.3, TLS_AES_256_GCM_SHA384, its secrets not in the key log: the
   lines stay as without one.
8. TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384, a wrong secret in the key log:
   the lines stay as without one.

Run it with `uv run tests/make_tls_decrypt_corpus.py` (it needs the
`cryptography` package); it rewrites both files.  Then regenerate the
expected text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import hashlib
import hmac
import pathlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

BASE = 1760000000  # seconds since the epoch of the first packet
CLIENT, SERVER = bytes([192, 0, 2, 10]), bytes([198, 51, 100, 7])
FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10

CHANGE_CIPHER_SPEC, ALERT, HANDSHAKE, APPLICATION_DATA = 0x14, 0x15, 0x16, 0x17


def deterministic(label: str, n: int) -> bytes:
    """@p n bytes that stand in for random ones, the same on every run."""
    out = b""
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(f"tls-decrypt corpus/{label}/{counter}".encode()).digest()
        counter += 1
    return out[:n]


# ── Packets ──────────────────────────────────────────────────────────────

def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def frame(from_server: bool, sport: int, dport: int, seq: int, ack: int, flags: int,
          payload: bytes) -> bytes:
    """An Ethernet frame with an IPv4 packet and a TCP segment."""
    src, dst = (SERVER, CLIENT) if from_server else (CLIENT, SERVER)
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          5 << 4, flags, 64240, 0, 0)
    segment += payload
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(segment))
    segment = segment[:16] + struct.pack("!H", checksum(pseudo + segment)) + segment[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(segment), 0, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    macs = bytes.fromhex("02005e000002" "02005e000001")
    if from_server:
        macs = macs[6:] + macs[:6]
    return macs + struct.pack("!H", 0x0800) + ip + segment


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
    """A TCP connection from @p client_port to @p server_port, its handshake
    captured.  Sequence numbers are relative, as Info shows them."""

    def __init__(self, capture: Capture, client_port: int, server_port: int):
        self.capture, self.ports = capture, (client_port, server_port)
        self.isn = (1000, 5000)
        self.next = [1, 1]  # the next relative sequence number of client, server
        self.segment(False, SYN, 0, 0)
        self.segment(True, SYN | ACK, 0, 1)
        self.segment(False, ACK, 1, 1)

    def segment(self, from_server: bool, flags: int, seq: int, ack: int,
                payload: bytes = b"") -> None:
        ports = self.ports[::-1] if from_server else self.ports
        own, other = self.isn[::-1] if from_server else self.isn
        self.capture.add(frame(from_server, ports[0], ports[1], own + seq,
                               other + ack if flags & ACK else 0, flags, payload))

    def send(self, from_server: bool, data: bytes, cuts=(), lost=False) -> None:
        """@p data from one side, cut into segments at the offsets @p cuts;
        with @p lost, sent but not captured."""
        bounds = [0, *cuts, len(data)]
        side = 1 if from_server else 0
        for start, end in zip(bounds, bounds[1:]):
            if not lost:
                self.segment(from_server, PSH | ACK, self.next[side] + start,
                             self.next[1 - side], data[start:end])
        self.next[side] += len(data)

    def ack(self, from_server: bool) -> None:
        side = 1 if from_server else 0
        self.segment(from_server, ACK, self.next[side], self.next[1 - side])

    def close(self) -> None:
        self.segment(False, FIN | ACK, self.next[0], self.next[1])
        self.next[0] += 1
        self.segment(True, FIN | ACK, self.next[1], self.next[0])
        self.next[1] += 1
        self.ack(False)


# ── TLS ──────────────────────────────────────────────────────────────────

def record(content_type: int, fragment: bytes) -> bytes:
    return struct.pack("!BHH", content_type, 0x0303, len(fragment)) + fragment


def handshake_message(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, "big") + body


def extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def alpn(*protocols: bytes) -> bytes:
    names = b"".join(bytes([len(p)]) + p for p in protocols)
    return extension(0x0010, struct.pack("!H", len(names)) + names)


def client_hello(random: bytes, server_name: str, suites, protocols) -> bytes:
    name = server_name.encode()
    sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    extensions = (extension(0x0000, sni)
                  + extension(0x002B, bytes([4, 0x03, 0x04, 0x03, 0x03]))
                  + alpn(*protocols))
    body = (b"\x03\x03" + random + b"\x00"
            + struct.pack("!H", 2 * len(suites)) + b"".join(struct.pack("!H", s) for s in suites)
            + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions)
    return record(HANDSHAKE, handshake_message(1, body))


def server_hello(random: bytes, suite: int, extensions: bytes) -> bytes:
    body = (b"\x03\x03" + random + b"\x00" + struct.pack("!H", suite) + b"\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    return handshake_message(2, body)


def hkdf_expand_label(secret: bytes, label: str, length: int, hash_name: str) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!HB", length, len(full)) + full + b"\x00"
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]), hash_name).digest()
        out += block
        counter += 1
    return out[:length]


def prf(secret: bytes, label: bytes, seed: bytes, length: int, hash_name: str) -> bytes:
    seed = label + seed
    a, out = seed, b""
    while len(out) < length:
        a = hmac.new(secret, a, hash_name).digest()
        out += hmac.new(secret, a + seed, hash_name).digest()
    return out[:length]


SUITES = {
    # id: (TLS 1.3, AEAD or CBC, key bytes, PRF/HKDF hash, MAC hash)
    0x1301: (True, "gcm", 16, "sha256", None),
    0x1302: (True, "gcm", 32, "sha384", None),
    0x1303: (True, "chacha", 32, "sha256", None),
    0xC02F: (False, "gcm", 16, "sha256", None),
    0xC030: (False, "gcm", 32, "sha384", None),
    0xCCA8: (False, "chacha", 32, "sha256", None),
    0xC014: (False, "cbc", 32, "sha256", "sha1"),
    0x003C: (False, "cbc", 16, "sha256", "sha256"),
}


class Protection:
    """The keys of one direction, and its sequence number."""

    def __init__(self, suite: int, key: bytes, iv: bytes, mac_key: bytes = b"",
                 encrypt_then_mac: bool = False):
        self.tls13, self.mode, _, _, self.mac_hash = SUITES[suite]
        self.key, self.iv, self.mac_key = key, iv, mac_key
        self.encrypt_then_mac = encrypt_then_mac
        self.seq = 0

    def aead(self):
        return ChaCha20Poly1305(self.key) if self.mode == "chacha" else AESGCM(self.key)

    def xor_nonce(self) -> bytes:
        padded = self.seq.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, padded))

    def protect(self, content_type: int, plaintext: bytes) -> bytes:
        seq = self.seq
        self.seq += 1
        if self.tls13:
            inner = plaintext + bytes([content_type])
            header = struct.pack("!BHH", APPLICATION_DATA, 0x0303, len(inner) + 16)
            nonce = bytes(a ^ b for a, b in zip(self.iv, seq.to_bytes(12, "big")))
            return header + self.aead().encrypt(nonce, inner, header)
        additional = struct.pack("!QBHH", seq, content_type, 0x0303, len(plaintext))
        if self.mode == "gcm":
            explicit = seq.to_bytes(8, "big")
            fragment = explicit + self.aead().encrypt(self.iv + explicit, plaintext, additional)
        elif self.mode == "chacha":
            nonce = bytes(a ^ b for a, b in zip(self.iv, seq.to_bytes(12, "big")))
            fragment = self.aead().encrypt(nonce, plaintext, additional)
        else:
            iv = deterministic(f"cbc iv {self.key.hex()} {seq}", 16)
            mac_bytes = hashlib.new(self.mac_hash).digest_size
            if self.encrypt_then_mac:
                body = plaintext
            else:
                body = plaintext + hmac.new(self.mac_key, additional + plaintext,
                                            self.mac_hash).digest()
            padding = 15 - len(body) % 16
            body += bytes([padding]) * (padding + 1)
            encryptor = Cipher(algorithms.AES(self.key), modes.CBC(iv)).encryptor()
            fragment = iv + encryptor.update(body) + encryptor.finalize()
            if self.encrypt_then_mac:
                covered = struct.pack("!QBHH", seq, content_type, 0x0303, len(fragment))
                fragment += hmac.new(self.mac_key, covered + fragment, self.mac_hash).digest()
            assert len(fragment) % 16 == (mac_bytes % 16 if self.encrypt_then_mac else 0)
        return record(content_type, fragment)


def tls13_protection(suite: int, secret: bytes) -> Protection:
    _, _, key_bytes, hash_name, _ = SUITES[suite]
    return Protection(suite, hkdf_expand_label(secret, "key", key_bytes, hash_name),
                      hkdf_expand_label(secret, "iv", 12, hash_name))


def tls12_protections(suite: int, master: bytes, client_random: bytes, server_random: bytes,
                      encrypt_then_mac: bool = False):
    _, mode, key_bytes, hash_name, mac_hash = SUITES[suite]
    mac_bytes = hashlib.new(mac_hash).digest_size if mode == "cbc" else 0
    iv_bytes = {"gcm": 4, "chacha": 12, "cbc": 0}[mode]
    block = prf(master, b"key expansion", server_random + client_random,
                2 * (mac_bytes + key_bytes + iv_bytes), hash_name)
    at = 0

    def cut(n):
        nonlocal at
        part = block[at:at + n]
        at += n
        return part

    client_mac, server_mac = cut(mac_bytes), cut(mac_bytes)
    client_key, server_key = cut(key_bytes), cut(key_bytes)
    client_iv, server_iv = cut(iv_bytes), cut(iv_bytes)
    return (Protection(suite, client_key, client_iv, client_mac, encrypt_then_mac),
            Protection(suite, server_key, server_iv, server_mac, encrypt_then_mac))


class KeyLog:
    def __init__(self):
        self.lines = ["# SSL/TLS secrets log file, made up by tests/make_tls_decrypt_corpus.py"]

    def add(self, label: str, client_random: bytes, secret: bytes) -> None:
        self.lines.append(f"{label} {client_random.hex()} {secret.hex()}")

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


# ── HTTP ─────────────────────────────────────────────────────────────────

def http_request(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: corpus/1.0\r\n"
            f"Accept: */*\r\n\r\n").encode()


def http_response(body: bytes, content_type: str = "text/html", status: str = "200 OK") -> bytes:
    return (f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\n"
            f"Content-Length: {len(body)}\r\n\r\n").encode() + body


PAGE = b"<html><body>Hello, TLS</body></html>"


def h2_frame(frame_type: int, flags: int, stream: int, payload: bytes) -> bytes:
    return len(payload).to_bytes(3, "big") + bytes([frame_type, flags]) + struct.pack(
        "!I", stream) + payload


def hpack_string(value: str) -> bytes:
    data = value.encode()
    assert len(data) < 127
    return bytes([len(data)]) + data


def hpack_indexed(index: int) -> bytes:
    assert index < 127
    return bytes([0x80 | index])


def hpack_literal_indexed_name(index: int, value: str) -> bytes:
    """A literal with incremental indexing, its name from the tables."""
    assert index < 63
    return bytes([0x40 | index]) + hpack_string(value)


def hpack_literal_new_name(name: str, value: str) -> bytes:
    """A literal without indexing, a new name."""
    return b"\x00" + hpack_string(name) + hpack_string(value)


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


# ── The sessions ─────────────────────────────────────────────────────────

def tls12_session(capture: Capture, keys: KeyLog, port: int, suite: int, host: str,
                  encrypt_then_mac: bool = False, wrong_secret: bool = False,
                  status: str = "200 OK") -> None:
    conn = Connection(capture, port, 443)
    client_random = deterministic(f"{port} client random", 32)
    server_random = deterministic(f"{port} server random", 32)
    master = deterministic(f"{port} master secret", 48)
    keys.add("CLIENT_RANDOM", client_random,
             deterministic(f"{port} wrong", 48) if wrong_secret else master)
    client, server = tls12_protections(suite, master, client_random, server_random,
                                       encrypt_then_mac)

    conn.send(False, client_hello(client_random, host, [suite], [b"http/1.1"]))
    extensions = alpn(b"http/1.1") + (extension(0x0016, b"") if encrypt_then_mac else b"")
    flight = (server_hello(server_random, suite, extensions)
              + handshake_message(11, deterministic(f"{port} certificate", 400))
              + handshake_message(12, deterministic(f"{port} key exchange", 100))
              + handshake_message(14, b""))
    conn.send(True, record(HANDSHAKE, flight))
    conn.send(False, record(HANDSHAKE, handshake_message(16, deterministic(f"{port} cke", 33)))
              + record(CHANGE_CIPHER_SPEC, b"\x01")
              + client.protect(HANDSHAKE, handshake_message(20, deterministic(f"{port} cf", 12))))
    conn.send(True, record(CHANGE_CIPHER_SPEC, b"\x01")
              + server.protect(HANDSHAKE, handshake_message(20, deterministic(f"{port} sf", 12))))
    conn.send(False, client.protect(APPLICATION_DATA, http_request(host, "/index.html")))
    conn.send(True, server.protect(APPLICATION_DATA, http_response(PAGE, status=status)))
    conn.send(False, client.protect(ALERT, b"\x01\x00"))
    conn.send(True, server.protect(ALERT, b"\x01\x00"))
    conn.close()


def tls13_server_flight(port: int, server_random: bytes, suite: int, server_hs: Protection,
                        protocol: bytes) -> bytes:
    extensions = alpn(protocol)
    encrypted_extensions = handshake_message(8, struct.pack("!H", len(extensions)) + extensions)
    return (record(HANDSHAKE, server_hello(server_random, suite, extension(0x002B, b"\x03\x04")
                                           + extension(0x0033, deterministic(f"{port} share", 36))))
            + record(CHANGE_CIPHER_SPEC, b"\x01")
            + server_hs.protect(HANDSHAKE, encrypted_extensions
                                + handshake_message(11, deterministic(f"{port} certificate", 400)))
            + server_hs.protect(HANDSHAKE, handshake_message(15, deterministic(f"{port} cv", 72))
                                + handshake_message(20, deterministic(f"{port} sf", 32))))


def tls13_secrets(keys: KeyLog, port: int, client_random: bytes, hash_bytes: int,
                  logged: bool = True):
    names = ["CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
             "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0"]
    secrets = [deterministic(f"{port} {name}", hash_bytes) for name in names]
    if logged:
        for name, secret in zip(names, secrets):
            keys.add(name, client_random, secret)
    return secrets


def tls13_http2_session(capture: Capture, keys: KeyLog) -> None:
    port, suite, host = 50102, 0x1301, "h2.example.org"
    conn = Connection(capture, port, 443)
    client_random = deterministic(f"{port} client random", 32)
    server_random = deterministic(f"{port} server random", 32)
    chs, shs, cap, sap = tls13_secrets(keys, port, client_random, 32)
    client_hs, server_hs = tls13_protection(suite, chs), tls13_protection(suite, shs)
    client_app, server_app = tls13_protection(suite, cap), tls13_protection(suite, sap)

    conn.send(False, client_hello(client_random, host, [suite], [b"h2", b"http/1.1"]))
    conn.send(True, tls13_server_flight(port, server_random, suite, server_hs, b"h2"))

    settings = h2_frame(0x4, 0, 0, struct.pack("!HI", 0x3, 100) + struct.pack("!HI", 0x4, 65535))
    first = (hpack_indexed(2) + hpack_indexed(7)  # :method GET, :scheme https
             + hpack_literal_indexed_name(1, host)  # :authority, into the dynamic table
             + hpack_literal_indexed_name(4, "/app.js")  # :path
             + hpack_literal_new_name("user-agent", "corpus/1.0"))
    conn.send(False, record(CHANGE_CIPHER_SPEC, b"\x01")
              + client_hs.protect(HANDSHAKE, handshake_message(20, deterministic(f"{port} cf", 32)))
              + client_app.protect(APPLICATION_DATA, H2_PREFACE + settings
                                   + h2_frame(0x1, 0x5, 1, first)))
    response = (hpack_indexed(8)  # :status 200
                + hpack_literal_indexed_name(31, "application/javascript")  # content-type
                + hpack_literal_indexed_name(28, "12"))  # content-length
    conn.send(True, server_app.protect(APPLICATION_DATA, settings + h2_frame(0x4, 0x1, 0, b"")
                                       + h2_frame(0x1, 0x4, 1, response)
                                       + h2_frame(0x0, 0x1, 1, b"console.log(")))
    # The second request names the authority by its dynamic table entry, the
    # newest but one (62 is /app.js, 63 the authority).
    second = hpack_indexed(2) + hpack_indexed(7) + hpack_indexed(63) + hpack_indexed(5)
    conn.send(False, client_app.protect(APPLICATION_DATA, h2_frame(0x4, 0x1, 0, b"")
                                        + h2_frame(0x1, 0x5, 3, second)))
    conn.send(True, server_app.protect(APPLICATION_DATA,
                                       h2_frame(0x1, 0x4, 3, hpack_indexed(8)
                                                + hpack_literal_indexed_name(31, "text/html"))
                                       + h2_frame(0x0, 0x1, 3, PAGE)))
    conn.send(False, client_app.protect(APPLICATION_DATA, h2_frame(0x7, 0, 0, bytes(8))))
    conn.close()


def tls13_http1_session(capture: Capture, keys: KeyLog, port: int, suite: int, host: str,
                        logged: bool = True, extras: bool = False) -> None:
    conn = Connection(capture, port, 443)
    hash_bytes = 48 if SUITES[suite][3] == "sha384" else 32
    client_random = deterministic(f"{port} client random", 32)
    server_random = deterministic(f"{port} server random", 32)
    chs, shs, cap, sap = tls13_secrets(keys, port, client_random, hash_bytes, logged)
    client_hs, server_hs = tls13_protection(suite, chs), tls13_protection(suite, shs)
    client_app, server_app = tls13_protection(suite, cap), tls13_protection(suite, sap)

    conn.send(False, client_hello(client_random, host, [suite], [b"http/1.1"]))
    conn.send(True, tls13_server_flight(port, server_random, suite, server_hs, b"http/1.1"))
    conn.send(False, record(CHANGE_CIPHER_SPEC, b"\x01")
              + client_hs.protect(HANDSHAKE, handshake_message(20, deterministic(f"{port} cf", 32))))
    conn.send(True, server_app.protect(HANDSHAKE, handshake_message(4, deterministic(f"{port} t", 60))))
    conn.send(False, client_app.protect(APPLICATION_DATA, http_request(host, "/")))
    big = b"<html><body>" + b"TLS 1.3 " * 300 + b"</body></html>"
    response = server_app.protect(APPLICATION_DATA, http_response(big))
    conn.send(True, response, (1200,) if extras else ())
    conn.ack(False)
    if extras:
        # The client updates its keys (RFC 8446, 4.6.3): the records after
        # the KeyUpdate are protected by the next generation.
        conn.send(False, client_app.protect(HANDSHAKE, handshake_message(24, b"\x00")))
        _, _, _, hash_name, _ = SUITES[suite]
        updated = tls13_protection(suite, hkdf_expand_label(cap, "traffic upd", hash_bytes,
                                                            hash_name))
        conn.send(False, updated.protect(APPLICATION_DATA, http_request(host, "/lost")), lost=True)
        conn.send(False, updated.protect(APPLICATION_DATA, http_request(host, "/after-loss")))
        conn.ack(True)
    conn.close()


def main() -> None:
    capture = Capture()
    keys = KeyLog()
    tls12_session(capture, keys, 50101, 0xC02F, "www.example.com")
    tls13_http2_session(capture, keys)
    tls13_http1_session(capture, keys, 50103, 0x1303, "chacha.example.net", extras=True)
    tls12_session(capture, keys, 50104, 0xCCA8, "chacha12.example.com", status="404 Not Found")
    tls12_session(capture, keys, 50105, 0xC014, "cbc.example.com", encrypt_then_mac=True)
    tls12_session(capture, keys, 50106, 0x003C, "mte.example.com")
    tls13_http1_session(capture, keys, 50107, 0x1302, "nokeys.example.org", logged=False)
    tls12_session(capture, keys, 50108, 0xC030, "wrongkey.example.org", wrong_secret=True)

    corpus = pathlib.Path(__file__).resolve().parent / "corpus"
    (corpus / "tls-decrypt.pcap").write_bytes(capture.bytes())
    (corpus / "tls-decrypt.keys").write_text(keys.text())


if __name__ == "__main__":
    main()
