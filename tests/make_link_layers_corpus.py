#!/usr/bin/env python3
# Copyright (C) 2026 LogSquirl Contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write tests/corpus/wifi.pcap and tests/corpus/ppp.pcapng, the corpus's
802.11 and PPP captures.

Every byte is made up here, so the captures hold no one's traffic (a real
monitor-mode capture would hold every neighbour's beacons).  They hold:

1. wifi.pcap (Radiotap, link type 127): a station joining an access point,
   its beacon (with a frame check sequence), probe request and response,
   authentication, association and the first EAPOL key message; then ARP and
   an ICMP echo in QoS data frames, RTS/CTS and an acknowledgement, a
   CCMP-protected data frame, a null function frame and a deauthentication.
2. ppp.pcapng, three interfaces: PPPoE on Ethernet (discovery, LCP, PAP,
   IPCP, an ICMP echo in the session, an LCP echo and the teardown), PPP in
   HDLC-like framing (link type 50) with LCP, IPv6CP and IPv4, and Cisco
   HDLC (link type 104) carrying a DNS query.

Run it from anywhere; it rewrites the captures.  Then regenerate the
expected text with TCPDUMP_UPDATE_CORPUS=1 and review it.
"""

import ipaddress
import pathlib
import struct

BASE = 1760000000  # seconds since the epoch of the first packet
AP = bytes.fromhex("02005e000001")
STATION = bytes.fromhex("02005e000010")
BROADCAST = b"\xff" * 6
CONCENTRATOR = bytes.fromhex("02005e0000ac")
SSID = b"CorpusNet"


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0x2F01, 0x4000, 64,
                         protocol, 0, ipaddress.IPv4Address(src).packed,
                         ipaddress.IPv4Address(dst).packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def ipv6(src: str, dst: str, next_header: int, payload: bytes) -> bytes:
    return (struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64)
            + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload)


def icmp_echo(kind: int, ident: int, seq: int) -> bytes:
    """An echo request (kind 8) or reply (kind 0)."""
    body = struct.pack("!BBHHH", kind, 0, 0, ident, seq) + b"link-layers-corpus"
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


def udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", 0x3C3C, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def arp(op: int, sender_mac: bytes, sender: str, target_mac: bytes, target: str) -> bytes:
    return (struct.pack("!HHBBH", 1, 0x0800, 6, 4, op) + sender_mac
            + ipaddress.IPv4Address(sender).packed + target_mac
            + ipaddress.IPv4Address(target).packed)


# ── 802.11 ───────────────────────────────────────────────────────────────

TO_DS, FROM_DS, PROTECTED = 0x01, 0x02, 0x40


def radiotap(flags: int = 0, signal: int = -48) -> bytes:
    """TSFT, flags, rate (24 Mb/s), channel 6 (2437 MHz, 2.4 GHz OFDM), signal."""
    fields = struct.pack("<QBBHHb", 0x1122334455, flags, 48, 2437, 0x00C0, signal)
    return struct.pack("<BBHI", 0, 0, 8 + len(fields), 0x2F) + fields


def frame(kind: int, subtype: int, flags: int, a1: bytes, a2: bytes, a3: bytes, seq: int,
          body: bytes = b"") -> bytes:
    fc = struct.pack("<BB", (subtype << 4) | (kind << 2), flags)
    return fc + struct.pack("<H", 44) + a1 + a2 + a3 + struct.pack("<H", seq << 4) + body


def element(ident: int, value: bytes) -> bytes:
    return bytes([ident, len(value)]) + value


RATES = element(1, bytes([0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]))


def beacon_body() -> bytes:
    return (struct.pack("<QHH", 0x1122334455, 100, 0x0411) + element(0, SSID) + RATES
            + element(3, bytes([6])))


def snap(ether_type: int, payload: bytes) -> bytes:
    return bytes.fromhex("aaaa03000000") + struct.pack("!H", ether_type) + payload


def qos(payload: bytes) -> bytes:
    return struct.pack("<H", 0) + payload


def control(subtype: int, ra: bytes, ta: bytes = b"") -> bytes:
    return struct.pack("<BBH", (subtype << 4) | (1 << 2), 0, 44) + ra + ta


def wifi() -> bytes:
    frames = []
    sta_ip, ap_ip = "192.168.50.23", "192.168.50.1"
    beacon = frame(0, 8, 0, BROADCAST, AP, AP, 1000, beacon_body())
    frames.append(radiotap(0x10) + beacon + struct.pack("<I", 0x1BADF00D))  # FCS
    frames.append(radiotap(signal=-60)
                  + frame(0, 4, 0, BROADCAST, STATION, BROADCAST, 1, element(0, b"") + RATES))
    frames.append(radiotap() + frame(0, 5, 0, STATION, AP, AP, 1001, beacon_body()))
    frames.append(radiotap(signal=-60) + control(13, AP))
    frames.append(radiotap(signal=-60)
                  + frame(0, 11, 0, AP, STATION, AP, 2, struct.pack("<HHH", 0, 1, 0)))
    frames.append(radiotap() + frame(0, 11, 0, STATION, AP, AP, 1002, struct.pack("<HHH", 0, 2, 0)))
    frames.append(radiotap(signal=-60)
                  + frame(0, 0, 0, AP, STATION, AP, 3,
                          struct.pack("<HH", 0x0411, 10) + element(0, SSID) + RATES))
    frames.append(radiotap() + frame(0, 1, 0, STATION, AP, AP, 1003,
                                     struct.pack("<HHH", 0x0411, 0, 0xC001) + RATES))
    eapol = bytes([2, 3]) + struct.pack("!H", 95) + bytes([2]) + bytes(94)  # key message 1 of 4
    frames.append(radiotap() + frame(2, 8, FROM_DS, STATION, AP, AP, 0, qos(snap(0x888E, eapol))))
    frames.append(radiotap(signal=-60)
                  + frame(2, 8, TO_DS, AP, STATION, BROADCAST, 4,
                          qos(snap(0x0806, arp(1, STATION, sta_ip, bytes(6), ap_ip)))))
    frames.append(radiotap() + frame(2, 8, FROM_DS, STATION, AP, AP, 1,
                                     qos(snap(0x0806, arp(2, AP, ap_ip, STATION, sta_ip)))))
    frames.append(radiotap(signal=-60) + control(11, AP, STATION))
    frames.append(radiotap() + control(12, STATION))
    frames.append(radiotap(signal=-60)
                  + frame(2, 8, TO_DS, AP, STATION, AP, 5,
                          qos(snap(0x0800, ipv4(sta_ip, ap_ip, 1, icmp_echo(8, 0x5A, 1))))))
    frames.append(radiotap() + frame(2, 8, FROM_DS, STATION, AP, AP, 2,
                                     qos(snap(0x0800, ipv4(ap_ip, sta_ip, 1, icmp_echo(0, 0x5A, 1))))))
    # CCMP: an 8-byte header, ciphertext and an 8-byte MIC, all made up.
    frames.append(radiotap(signal=-60)
                  + frame(2, 8, TO_DS | PROTECTED, AP, STATION, AP, 6,
                          qos(bytes.fromhex("0100002000000000") + bytes(range(48)) + bytes(8))))
    frames.append(radiotap(signal=-60) + frame(2, 4, TO_DS | 0x10, AP, STATION, AP, 7))
    frames.append(radiotap() + frame(0, 12, 0, STATION, AP, AP, 1004, struct.pack("<H", 3)))

    records = []
    for i, data in enumerate(frames):
        time = i * 2048  # microseconds since BASE
        records.append(struct.pack("<IIII", BASE + time // 1000000, time % 1000000, len(data),
                                   len(data)) + data)
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127) + b"".join(records)


# ── PPP ──────────────────────────────────────────────────────────────────


def pad(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def block(kind: int, body: bytes) -> bytes:
    body = pad(body)
    return struct.pack("<II", kind, len(body) + 12) + body + struct.pack("<I", len(body) + 12)


def option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + pad(value)


def idb(link_type: int, name: bytes) -> bytes:
    return block(1, struct.pack("<HHI", link_type, 0, 65535) + option(2, name) + option(0, b""))


def epb(interface: int, time: int, data: bytes) -> bytes:
    timestamp = (BASE * 1000000) + time
    return block(6, struct.pack("<IIIII", interface, timestamp >> 32, timestamp & 0xFFFFFFFF,
                                len(data), len(data)) + pad(data))


def ppp_control(code: int, ident: int, data: bytes = b"") -> bytes:
    return struct.pack("!BBH", code, ident, 4 + len(data)) + data


def pppoe(src: bytes, dst: bytes, code: int, session: int, payload: bytes) -> bytes:
    ether_type = 0x8864 if code == 0 else 0x8863
    frame = dst + src + struct.pack("!H", ether_type)
    frame += struct.pack("!BBHH", 0x11, code, session, len(payload)) + payload
    return frame + bytes(max(0, 60 - len(frame)))  # Ethernet pads to 60 bytes


def tag(kind: int, value: bytes) -> bytes:
    return struct.pack("!HH", kind, len(value)) + value


def session(src: bytes, dst: bytes, protocol: int, payload: bytes) -> bytes:
    return pppoe(src, dst, 0, 0x0042, struct.pack("!H", protocol) + payload)


def hdlc(protocol: int, payload: bytes) -> bytes:
    return bytes([0xFF, 0x03]) + struct.pack("!H", protocol) + payload


def ppp() -> bytes:
    client, ac = STATION, CONCENTRATOR
    host, peer = "203.0.113.77", "203.0.113.1"
    magic = lambda m: bytes([5, 6]) + struct.pack("!I", m)
    mru = bytes([1, 4]) + struct.pack("!H", 1492)
    address = lambda a: bytes([3, 6]) + ipaddress.IPv4Address(a).packed
    service = tag(0x0101, b"")
    host_uniq = tag(0x0103, bytes.fromhex("c0ffee00"))
    pap = bytes([6]) + b"corpus" + bytes([7]) + b"made-up"

    eth = [
        pppoe(client, BROADCAST, 0x09, 0, service + host_uniq),
        pppoe(ac, client, 0x07, 0, service + tag(0x0102, b"corpus-ac") + host_uniq),
        pppoe(client, ac, 0x19, 0, service + host_uniq),
        pppoe(ac, client, 0x65, 0x0042, service + host_uniq),
        session(client, ac, 0xC021, ppp_control(1, 1, mru + magic(0x11223344))),
        session(ac, client, 0xC021, ppp_control(1, 1, mru + bytes([3, 4, 0xC0, 0x23])
                                                + magic(0x55667788))),
        session(client, ac, 0xC021, ppp_control(2, 1, mru + bytes([3, 4, 0xC0, 0x23])
                                                + magic(0x55667788))),
        session(ac, client, 0xC021, ppp_control(2, 1, mru + magic(0x11223344))),
        session(client, ac, 0xC023, ppp_control(1, 1, pap)),
        session(ac, client, 0xC023, ppp_control(2, 1, bytes([0]))),
        session(client, ac, 0x8021, ppp_control(1, 1, address("0.0.0.0"))),
        session(ac, client, 0x8021, ppp_control(3, 1, address(host))),
        session(client, ac, 0x8021, ppp_control(1, 2, address(host))),
        session(ac, client, 0x8021, ppp_control(2, 2, address(host))),
        session(client, ac, 0x0021, ipv4(host, peer, 1, icmp_echo(8, 0x77, 1))),
        session(ac, client, 0x0021, ipv4(peer, host, 1, icmp_echo(0, 0x77, 1))),
        session(ac, client, 0xC021, ppp_control(9, 2, struct.pack("!I", 0x55667788))),
        session(client, ac, 0xC021, ppp_control(10, 2, struct.pack("!I", 0x11223344))),
        session(client, ac, 0xC021, ppp_control(5, 3)),
        session(ac, client, 0xC021, ppp_control(6, 3)),
        pppoe(client, ac, 0xA7, 0x0042, b""),
    ]
    serial = [
        hdlc(0xC021, ppp_control(1, 1, magic(0x0BADCAFE))),
        hdlc(0xC021, ppp_control(2, 1, magic(0x0BADCAFE))),
        hdlc(0x8057, ppp_control(1, 1, bytes([1, 10]) + bytes.fromhex("0200005efffe0001"))),
        hdlc(0x0057, ipv6("fe80::200:5eff:fe00:1", "ff02::1", 58,
                          bytes([128, 0, 0, 0]) + struct.pack("!HH", 0x99, 1))),
        hdlc(0x0021, ipv4("198.51.100.1", "198.51.100.2", 1, icmp_echo(8, 0x99, 1))),
    ]
    cisco = [
        bytes([0x0F, 0x00]) + struct.pack("!H", 0x0800)
        + ipv4("198.51.100.9", "198.51.100.53", 17, udp(53053, 53, dns_query("example.net"))),
    ]

    blocks = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
                   + option(4, b"make_link_layers_corpus.py") + option(0, b""))
    blocks += idb(1, b"eth0") + idb(50, b"ppp0") + idb(104, b"serial0")
    time = 0
    for interface, frames in enumerate([eth, serial, cisco]):
        for data in frames:
            time += 1500
            blocks += epb(interface, time, data)
    return blocks


def main() -> None:
    corpus = pathlib.Path(__file__).resolve().parent / "corpus"
    (corpus / "wifi.pcap").write_bytes(wifi())
    (corpus / "ppp.pcapng").write_bytes(ppp())


if __name__ == "__main__":
    main()
