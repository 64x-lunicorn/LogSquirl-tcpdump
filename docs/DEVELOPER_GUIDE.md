# Developer Guide — logsquirl-tcpdump

## Architecture

The plugin is structured into three layers:

### 1. pcap Parser (`pcap_parser.h/cpp`)
Pure C++ (no Qt dependency). `PcapReader` reads libpcap captures from a
`ByteSource` one record at a time, so the capture is never held in memory.
It is the one `CaptureReader` so far (see *The reader seam* below):
- Detects byte order and timestamp precision from the magic number
  (`0xa1b2c3d4` µs, `0xa1b23c4d` ns, either byte order)
- Finds the header behind a text preamble (e.g. `adb exec-out tcpdump`
  stderr): past offset 0 only if everything before it is text and the header
  is valid (magic, version 2.0–2.4), so a stray magic in binary data is not
  taken for a capture
- Parses the 24-byte global header, then 16-byte record headers + data;
  only the first 256 KiB of a record are dissected, the rest is skipped
- Reports a capture cut off inside a record (`truncated()`)
- Dissects link-layer (Ethernet, Raw IP, Linux SLL, Linux SLL2, BSD
  loopback DLT_NULL/DLT_LOOP, family read in the capture's byte order)
- Strips stacked 802.1Q / 802.1ad (QinQ) VLAN tags
- Dissects network layer (IPv4, IPv6 with hop-by-hop, routing, fragment,
  destination options and AH headers, ARP); bounds transport data by the IP
  length fields, falling back to the captured bytes for TSO/GSO lengths of 0;
  fragments after the first are not parsed as TCP/UDP
- Dissects transport layer (TCP, UDP, ICMP, ICMPv6); a TCP header shorter
  than 20 bytes is flagged and yields no payload
- Hands a TCP or UDP payload with its ports to the Payload Describer, and
  appends the description it gets back to the transport summary after ` | `

`parsePcap()` parses a whole buffer in memory, for tests.

#### The reader seam
Everything past the reader (Converter, Stream Tracker, Packet Formatter, `CaptureStats`)
sees a capture through `CaptureReader` only, never through a file header.
Each `PacketRecord` carries the link-layer type it was dissected with
(`linkType`) and the resolution its timestamp was recorded in
(`precision`, a `TimePrecision`). As a whole, the reader announces after
`open()` the finest precision of the capture (`precision()`), which sets
the Time column's decimals before the first packet is read, and the
link-layer types it declares (`linkTypes()`).

The seam exists for pcapng: there one file holds several interfaces, each
with its own link-layer type and timestamp resolution, so neither is a
property of the file. A pcap has one global header, so `PcapReader` fills
both fields of every packet from it and announces the magic number's
precision and the header's link-layer type. A pcapng reader fills them
from the interface each packet was captured on.

### 2. Payload Describer (`payload_describer.h/cpp`)
Pure C++. `describePayload()` takes the captured payload bytes, the two
ports and the transport, and returns a protocol label and a one-line
description, or no match. It is the only module that knows which
application protocols exist on which transport and in which order they are
tried: each transport has a table of detectors, all of the same shape
(payload in, description out if recognised), and the first match wins.
- TCP: TLS, HTTP, NMEA 0183, SOCKS4/5 (only messages of the exact shape, in
  the right direction, on proxy ports), then the port hint
- UDP: DNS and mDNS by port, SSDP, NTP, DHCP, then NMEA and the port hint
- The port hint, the last entry of both tables, names well-known ports
  (SSH, FTP, ADB, etc.) and previews the payload: printable ASCII, other
  bytes as dots, at most 200 characters; predominantly binary payloads get
  none

Everything that turns payload bytes into text lives here: escaping bytes
outside printable ASCII as `\xNN`, the first-line cut (120 bytes), the
preview and its caps. A description is finalised as one line before it
leaves the describer, so one packet is always one line whatever a detector
forgot to escape.

### 3. Packet Formatter (`packet_formatter.h/cpp`), Stream Tracker (`stream_tracker.h/cpp`) and statistics (`capture_stats.h/cpp`)
`PacketFormatter` converts `PacketRecord` structs, one at a time, into
Wireshark-style text lines with fixed-width columns: No., Stream, Time,
Source, Destination, Protocol, Length, Info. Times are relative to the first
packet, with 6 decimals, or 9 when the capture announces nanosecond
precision for any of its packets (`PacketFormatter` takes the reader's
`precision()`; `formatAllPackets()` the finest of its packets).

Length is the packet's length on the wire (`originalLen`), as Wireshark's
Length column is; `Len=` in Info is the TCP or UDP payload length. A packet
captured shorter than on the wire (`capturedLen < originalLen`, cut at the
snaplen) ends its Info with `[cut to N bytes]`, N the bytes captured, so a
reader knows why its description stops short.

The Formatter keeps no conversations: the Stream column shows the stream
number it is handed by the Stream Tracker, `-` for `kNoStream` and `?` for
`kUnnumbered`.

`StreamTracker` (`stream_tracker.h/cpp`, pure C++), owned by the Converter,
follows the conversations of a capture. Only TCP and UDP packets have a
stream: those the parser read a TCP or UDP header of (`PacketRecord::transport`
is set) and that share addresses and ports, in either direction. TCP and
UDP are numbered independently, each from 0, as Wireshark's `tcp.stream`
and `udp.stream` are; the column shows the number alone, the Protocol
column says which transport it belongs to. ICMP, ICMPv6, ARP, IP fragments
after the first and every other packet without TCP/UDP ports show `-`. At
most `StreamTracker::kMaxStreams` (1,000,000) conversations, both transports
together, are numbered; packets of later ones show `?`.

`track()` returns a `Stream`: the number and a pointer to the stream's
`StreamState`, the same slot for every packet of the stream (null without
a number). The slot is empty for now; modules that follow a conversation
(relative sequence numbers, TCP analysis, …) add their fields to it and
read and update them through that pointer. Every field added costs memory
once per numbered stream.

`CaptureStats` collects the sidebar summary's counts packet by packet
(among them the packets cut at the snaplen),
and the link-layer types of the packets in the order they were first seen. It
counts packets for at most `CaptureStats::kMaxEndpoints` (100,000) IP
addresses, and those of further addresses as "other endpoints".

Memory therefore grows with the conversations and addresses in a capture,
not with its size, and both are capped (at roughly 100 MB and 10 MB), so a
port scan or a busy NAT cannot exhaust it. The summary says when a cap was
hit.

### 4. Converter (`pcap_converter.h/cpp`)
`convertPcap()` reads a capture through a `CaptureReader`, has the Stream
Tracker give each packet its stream, formats the packet and appends its line to a new output file, reporting progress and checking a
cancel flag between packets. The file, `<name>.log`, is created with
`NewOnly` and owner-only permissions in a new
`logsquirl-tcpdump-<pid>-XXXXXX` directory (`tempdirs.h/cpp`) below the
output root that only the user can enter. The result is one of three
outcomes and a `CaptureSummary`, whose link-layer types are those of the
packets followed by any the capture declares without a packet of it (so a
pcap with no packets still names its one): Converted (with the output path), Failed
(with a message) or Cancelled. Failed is the only error mode: an unreadable
input, an output that cannot be created or written, a memory allocation
failure or any other exception ends as Failed, and nothing is left behind.
`applyCancelRequest()` decides, for the Converter and its caller alike,
that a cancel request wins even over a conversion that had just finished:
the result becomes Cancelled and the output is removed.

### 5. Sidebar Widget (`sidebarwidget.h/cpp`)
Qt UI that provides:
- "Open pcap…" button triggering a QFileDialog; `chooseAndOpen()` is also
  what the `Plugins → tcpdump → Open pcap…` menu entry calls, which, unlike
  the disabled button, can be chosen during a conversion and then only shows
  a notification. Tests replace the dialog with `setFileChooser()`
- A progress bar and Cancel button while a capture is converted
- Detailed capture summary: protocol breakdown (count + percentage + bytes),
  top endpoints, packets per second, file size, the link-layer type names
  (comma-separated when there are several), and the number of packets cut
  at the snaplen when there are any

It runs `convertPcap()` on a worker thread of its own `QThreadPool`, with
the system's temporary directory as the output root, and shows the outcome
on the GUI thread: it prints the summary it is given and catches nothing
itself. A failed or cancelled conversion leaves no directory behind; a
converted one's is kept for its tab. The process ID in the name is the only
record of the directories of
files opened in tabs, so that it survives a runtime disable, update and
re-enable of the plugin: when LogSquirl quits, every directory with this
process's ID is removed, and at `init()` those of processes that no longer
run (checked with `kill(pid, 0)` on Unix and `OpenProcess()` on Windows).
Directories of running processes, links and, on Unix, other users'
directories are left alone. Only regular files are read, so the worker
cannot block on a FIFO or device; destroying the widget cancels a running
conversion and waits for the worker.

### Plugin Entry (`plugin.h/cpp`)
C ABI entry points (`logsquirl_plugin_*`) that register the sidebar tab
with the host application. No exception may leave them: their work runs
through `guarded()`. Strings go to the host as UTF-8 through `hostLog()`
and `hostNotify()`. The host calls `shutdown()` both when LogSquirl quits
and when the plugin is disabled or updated at runtime, with the tabs kept
open; the plugin notes `QCoreApplication::aboutToQuit` and removes the
temporary files only in the first case.

## Adding Protocol Support

An application protocol is one detector function plus one table entry in
`payload_describer.cpp`:
1. Write the detector with the common shape,
   `std::optional<PayloadDescription> name( const Payload& )`: look at the
   payload bytes and ports, return the label and a description if the
   payload is yours, `std::nullopt` otherwise. Use `escapeBytes()` or
   `firstLine()` for any text taken from the payload.
2. Add it to `kTcpDetectors` or `kUdpDetectors`, for the transport it runs
   on, at the place in the order where it belongs: an entry earlier in the
   table wins over a later one, so a detector that recognises its payload
   by content goes before the port-based ones that could claim it.
3. Test it against the describer in `tests/payload_describer_test.cpp`:
   feed `describePayload()` the payload and ports and check the label and
   description. No frame is needed; the layers below are tested on their
   own. A precedence case (a payload two detectors could claim) is a test
   of the table order, and belongs there too.

A new link or network layer, in contrast, is parsed in `pcap_parser.cpp`
and tested with the frame builders in `tests/pcapbuilder.h`.

## Testing

```bash
cmake -B build -S . -DBUILD_TESTS=ON
cmake --build build
cd build && ctest --output-on-failure
```

The link, network and transport layer tests build synthetic packets with
the helpers in `tests/pcapbuilder.h`; the application protocols are tested
through the Payload Describer with a payload alone. `tests/corpus` holds captures with the text they must
convert to (`corpus_test.cpp`); run the tests with `TCPDUMP_UPDATE_CORPUS=1`
to rewrite that text after an intended change of the output, and review the
difference. Plugin and sidebar tests run against the `FakeHost` in
`tests/fakehost.h`.
