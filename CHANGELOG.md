# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-07-08

### Added
- Initial release of the tcpdump / pcap viewer plugin for LogSquirl.
- **pcap file parsing** — reads pcap files (libpcap format) with support for
  Ethernet, Raw IP, Linux cooked capture (v1 + v2), and BSD loopback link layers.
- **Protocol dissection** — extracts IPv4, IPv6, TCP, UDP, ICMP, ICMPv6,
  ARP fields from each packet.
- **Application-layer detection** — TLS handshake identification (ClientHello,
  ServerHello, Certificate, etc.), HTTP request/response parsing, DNS
  query/response with domain name extraction, NMEA 0183 GPS sentence detection.
- **Port-based protocol hints** — SSH, FTP, SMTP, IMAP, MySQL, PostgreSQL,
  Redis, MongoDB, MQTT, AMQP, Kafka, ADB, and more.
- **Stream tracking** — assigns conversation IDs based on IP+port 4-tuples
  (both directions share the same stream number) for filtering related packets.
- **Wireshark-style output** — formats packets as human-readable text lines
  with columns: No., Stream, Time, Source, Destination, Protocol, Len, Info.
- **Smart payload preview** — shows printable payload text, collapses binary
  runs to spaces, suppresses predominantly binary payloads.
- **Sidebar panel** — "Open pcap…" button with detailed capture summary:
  protocol breakdown with percentages and byte counts, top endpoints,
  packets per second, file size, and link-layer type name.
- **Text preamble scanning** — handles `adb exec-out tcpdump` output where
  stderr text precedes the binary pcap data.
- **Auto-open in LogSquirl** — parsed output opens directly in the main viewer.
- **Big-endian / little-endian** — correct byte-order detection via pcap
  magic number.
- **VLAN support** — strips 802.1Q VLAN tags before dissecting.
- **TCP flag display** — SYN, ACK, FIN, RST, PSH, URG rendered in
  bracket notation like Wireshark.
- **Unit tests** — 26 Catch2 BDD test scenarios with 147 assertions covering
  pcap parsing (TCP, UDP, ICMP, ARP, DNS, TLS, HTTP, NMEA, SLL2, Raw IP,
  VLAN, big-endian, preamble scan, truncated headers, port-based detection,
  payload preview), packet formatting (stream IDs, MAC fallback),
  and plugin metadata.
- **CI/CD** — GitHub Actions workflows for build (Linux, macOS, Windows)
  and tag-triggered releases with per-platform ZIP artifacts.

[Unreleased]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/releases/tag/v0.1.0
