# Developer Guide — logsquirl-tcpdump

## Architecture

The plugin is structured into three layers:

### 1. pcap Parser (`pcap_parser.h/cpp`)
Pure C++ (no Qt dependency). Reads libpcap binary format:
- Detects byte order from the pcap magic number (`0xa1b2c3d4` / `0xd4c3b2a1`)
- Scans for magic number past text preamble (e.g. `adb exec-out tcpdump` stderr)
- Parses the 24-byte global header
- Iterates 16-byte packet headers + packet data
- Dissects link-layer (Ethernet, Raw IP, Linux SLL, Linux SLL2, BSD loopback)
- Strips 802.1Q VLAN tags
- Dissects network layer (IPv4, IPv6, ARP)
- Dissects transport layer (TCP, UDP, ICMP, ICMPv6)
- Detects application protocols: TLS, HTTP, DNS, NMEA 0183
- Falls back to port-based protocol hints (SSH, FTP, ADB, etc.)
- Generates smart payload previews (printable text with binary collapsing)

### 2. Packet Formatter (`packet_formatter.h/cpp`)
Converts `PacketRecord` structs into Wireshark-style text lines with
fixed-width columns: No., Stream, Time, Source, Destination, Protocol,
Len, Info.

Stream IDs are computed from IP+port 4-tuples — both directions of a
conversation share the same stream number. Non-TCP/UDP packets (ICMP,
ARP) show `-` as stream.

### 3. Sidebar Widget (`sidebarwidget.h/cpp`)
Qt UI that provides:
- "Open pcap…" button triggering a QFileDialog
- Detailed capture summary: protocol breakdown (count + percentage + bytes),
  top endpoints, packets per second, file size, link-layer type name
- Orchestrates parse → format → write temp file → open in host

### Plugin Entry (`plugin.h/cpp`)
C ABI entry points (`logsquirl_plugin_*`) that register the sidebar tab
with the host application.

## Adding Protocol Support

To add a new protocol:
1. Add constants to `pcap_parser.h`
2. Add a parse function in `pcap_parser.cpp` (called from `parseTransport`
   or the appropriate layer)
3. Set `pkt.protocol` and `pkt.info`
4. Add test cases in `tests/pcap_parser_test.cpp`

## Testing

```bash
cmake -B build -S . -DBUILD_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure
```

Tests use synthetic pcap byte buffers — no real capture files needed.
