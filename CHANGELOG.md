# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **pcapng captures.** Files saved by Wireshark (its default format) or by
  macOS's `tcpdump -P` open like a pcap, in either byte order and with several
  sections. Each packet is dissected with the link type of the interface it
  was captured on and shown at that interface's timestamp resolution
  (`if_tsresol`), so a capture of an Ethernet and a Raw IP interface, or of a
  microsecond and a nanosecond one, reads right; the Capture Summary lists
  every link type. Name resolution, statistics, custom and other blocks are
  skipped. A pcapng without packets converts to just the header line, and one
  that is cut off is reported like a cut-off pcap. The file dialog offers
  `.pcapng`.
- **Absolute UTC time column.** Every packet line shows the packet's
  wall-clock time in UTC, `2026-10-09 08:41:12.123456Z` (nine decimals for a
  nanosecond capture), in a `UTC Time` column before the relative `Time`, so
  that a capture can be lined up with a log of the same incident. The text
  does not depend on the computer's time zone. A packet recorded before the
  first one shows its own time there, while its relative time is negative.
  The sidebar summary shows the first and last packet time in UTC.
- **Open pcap… in the Plugins menu.** `Plugins → tcpdump → Open pcap…`, and
  so the Command Palette, opens the same dialog as the sidebar button. Chosen
  while a capture is being read, it shows a notification instead.

### Changed
- **IPv6 addresses in RFC 5952 form.** IPv6 addresses are shown as Wireshark
  shows them: lowercase hexadecimal, the longest run of zero groups (the
  leftmost on a tie, never a single group) collapsed to `::`, so `fe80::1`
  instead of `fe80:0:0:0:0:0:0:1` and `::` for the unspecified address. This
  applies to the Source and Destination columns and the Capture Summary
  endpoints alike. A SOCKS5 IPv6 destination puts the address in brackets
  before its port, `[2001:db8::1]:443`, as RFC 5952 recommends.
- **The Length column shows the length on the wire.** The column, headed
  `Length` instead of `Len`, shows how long the packet was on the wire, as
  Wireshark's Length column does, instead of how many bytes were captured:
  a capture taken with a snaplen no longer looks like it carried small
  packets. A packet captured shorter than on the wire ends its Info with
  `[cut to 96 bytes]`, naming the bytes captured, so it is clear why its
  description stops short; the sidebar summary counts these cut packets.
  `Len=` in Info remains the TCP or UDP payload length.
- **Only TCP and UDP have streams, numbered per transport.** TCP and UDP
  conversations are numbered independently, each from 0, as Wireshark's
  `tcp.stream` and `udp.stream` are; the Protocol column says which one a
  number belongs to. Conversations are followed by a module of their own,
  the Stream Tracker, which keeps a state slot per stream for later
  analyses.
- **Link type and time precision come with each packet.** Internally, every
  packet carries the link-layer type it was dissected with and the precision
  of its timestamp, read through one reader interface, so that a capture
  holding several of each (pcapng) can be read later. The sidebar lists the
  capture's link types comma-separated; for a pcap that is still one, and the
  converted text is unchanged.
- **One separator in the Info column.** The description of a payload follows
  the transport summary after ` | `, whatever the protocol: `Len=9 | Client
  Hello` instead of `Len=9 [Client Hello]` for TLS, and `Len=29 | Query
  example.com` instead of `Len=29 Query example.com` for DNS. HTTP, NMEA,
  SOCKS and the payload previews already used it.

### Fixed
- **ICMP, ARP and IP fragments no longer get a stream.** As documented, they
  show `-`: before, every packet with IP addresses was numbered, so ICMP and
  a fragment between the same two hosts shared one "conversation", and ARP
  got a number of its own.

## [0.2.0] — 2026-09-30

### Added
- **SOCKS4 and SOCKS5 handshakes are described** on the usual proxy ports
  (1080, 1081, 3128, 9050, 9051): greeting and method choice, connect, bind
  and UDP associate requests and their replies with destination and bound
  address, SOCKS4/4a requests with user id and domain, and the RFC 1929
  username/password exchange — user name and password included, since they
  cross the wire in clear text. Only messages whose length matches their
  fields exactly, travelling towards or away from the proxy port as they
  should, are labelled.
- **Nanosecond captures.** Files with nanosecond timestamps (magic
  `0xa1b23c4d`, e.g. from `tcpdump --time-stamp-precision=nano`) are read in
  either byte order, and their Time column shows nine decimals.
- **Progress and Cancel.** While a capture is read, the sidebar shows a
  progress bar and a Cancel button.
- IPv6 extension headers (hop-by-hop, routing, fragment, destination options,
  authentication) are walked to the TCP, UDP or ICMPv6 layer behind them.
- Stacked VLAN tags are stripped, including 802.1ad (QinQ) service tags
  (`0x88a8`, `0x9100`), also in Linux cooked captures.
- DLT_LOOP loopback captures are read.
- The sidebar summary says when a capture ends in the middle of a packet.

### Changed
- **Requires LogSquirl 26.10.0 or later.** This release is built with the Qt of
  LogSquirl 26.10.0 (Qt 6.11.3); an older LogSquirl cannot load it.
- The payload preview shows every byte from the start of the payload,
  printable ones as themselves and all others as a dot, instead of skipping
  to the first run of text and collapsing binary runs to a space. It stops
  after 200 characters with an ellipsis, and payloads that are mostly binary
  still get none.
- Each capture's text is written to its own new file, `<name>.log`, in a
  new `logsquirl-tcpdump-<pid>-XXXXXX` directory in the temporary directory
  that only you can enter, and removed when LogSquirl quits. When the plugin
  is disabled or updated while LogSquirl keeps running, the files are kept
  for the tabs that still show them, and the plugin, once enabled again,
  still removes them at quit. Directories left behind by a LogSquirl that no
  longer runs, e.g. after a crash, are removed when the plugin starts.
- A pcap header past the start of the file is accepted only behind text, as
  tcpdump's stderr puts it there, and only if it is a valid header; a stray
  magic number in other data is no longer taken for a capture. A file with a
  pcap format version other than 2.x is rejected with that version named.
- Bytes outside printable ASCII in HTTP lines, DNS names, NMEA sentences and
  SOCKS fields are shown as `\xNN`, so every packet stays on one line.

### Fixed
- **Large captures no longer freeze or crash LogSquirl.** The whole file was
  read into memory, every packet copied once more, and all lines formatted on
  the GUI thread before any was written, so a multi-GB capture froze
  LogSquirl and then took it down when memory ran out. Captures are now read,
  formatted and written packet by packet on a worker thread, and a corrupt
  packet length no longer makes the plugin allocate up to 4 GiB. Stream
  numbers are given to the first 1,000,000 conversations and endpoints are
  counted for the first 100,000 addresses, so a port scan cannot exhaust
  memory either; later conversations show stream `?`, further addresses are
  counted as other endpoints, and the summary says when either happened.
- **The temporary text file could be used against you.** It had a fixed name
  in the shared temporary directory, was opened with truncation and readable
  by everyone: another local user could have it overwrite a file of theirs
  choosing through a symlink, or read your capture's text. A second capture
  with the same name also overwrote the file a tab still showed, and nothing
  ever removed the files.
- Ethernet padding and link-layer trailers are no longer counted as payload:
  transport data ends where the IPv4 total length or IPv6 payload length
  says. Outgoing packets captured with TSO/GSO, whose lengths read 0, fall
  back to the captured bytes as in Wireshark.
- BSD loopback (DLT_NULL) captures from a big-endian machine were dissected as
  IPv6 throughout, because the address family was read in the byte order of
  the machine running LogSquirl. It is now read in the capture's byte order,
  and the AF_INET6 values of the BSDs and macOS (24, 28, 30) are recognised;
  an unknown family is shown as such instead of being taken for IPv6.
- IPv4 fragments after the first, and IPv6 fragments with a non-zero offset,
  are shown as fragments instead of being parsed as TCP or UDP with ports
  and flags made up from payload bytes.
- A TCP header shorter than 20 bytes is flagged as bogus, and no payload is
  taken from it; before, its header bytes were shown as payload.
- A packet earlier than the first one shows its negative relative time
  instead of 0, and the summary's duration is measured from the earliest to
  the latest packet, so a capture out of time order no longer shows a
  duration of about 136 years.
- File names, protocol names and addresses in the sidebar summary are no
  longer rendered as markup.
- Log messages, notifications and the path of the opened text file reach
  LogSquirl as UTF-8, so captures in folders with non-ASCII names open and
  are reported correctly on systems whose local encoding is not UTF-8.
- No exception can escape into LogSquirl from the plugin's entry points or
  the conversion; a failing initialisation is logged and cleaned up.
- Shutting the plugin down while a capture is being read stops the reading
  and waits for it.

## [0.1.1] — 2026-09-10

### Fixed
- **Release archives now contain the plugin library.** The v0.1.0 archives held
  an empty `build/` directory and `plugin.json` only — the `.so`, `.dylib` and
  `.dll` were missing on every platform, so the published plugin could not be
  loaded at all. The artifact was uploaded as a nested path while the release
  job archives with `zip *`, which does not recurse. Files are now staged flat,
  and a missing library fails the build instead of shipping silently.

### Added
- Plugin icon, which `plugin.json` had always declared but the repository never
  contained.

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

[Unreleased]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/releases/tag/v0.1.0
