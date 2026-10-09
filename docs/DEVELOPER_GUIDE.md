# Developer Guide — logsquirl-tcpdump

## Architecture

The plugin is structured into three layers:

### 1. pcap Parser (`pcap_parser.h/cpp`, `pcapng_reader.h/cpp`, `capture_reader.h/cpp`)
Pure C++ (no Qt dependency). A `CaptureReader` (see *The reader seam* below)
reads a capture from a `ByteSource` one record at a time, so the capture is
never held in memory. `makeCaptureReader()` (`capture_reader.h`, apart from
both readers, so that the pcap parser does not depend on the pcapng reader
built on it) picks the reader from the
first block, which it looks at through a `HeadSource` without consuming it:
`findCaptureStart()` finds a pcap global header or a pcapng section header,
also behind a text preamble, and the reader it picks is handed where that
header starts, so that the format is told once; a file that holds neither
gets a reader whose `open()` fails and says why. The readers share reading
and skipping, with the byte count for progress, in the `CaptureReader` base.

`PcapReader` reads libpcap captures:
- Detects byte order and timestamp precision from the magic number
  (`0xa1b2c3d4` µs, `0xa1b23c4d` ns, either byte order)
- Reads the header behind a text preamble (e.g. `adb exec-out tcpdump`
  stderr), which `findCaptureStart()` accepts past offset 0 only if
  everything before it is text and the header is valid (magic, version
  2.0–2.4), so a stray magic in binary data is not taken for a capture
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

`PcapngReader` reads pcapng captures block by block and hands each packet
to the same dissection (`dissectPacket()`):
- Section header blocks in either byte order; a file may hold several
  sections, each with its own byte order and interfaces (major version 1)
- Interface description blocks: link-layer type, snaplen and `if_tsresol`,
  in its power-of-ten and power-of-two forms (microseconds by default); at
  most 65,536 interfaces per section
- Enhanced packet blocks, and simple packet blocks, which belong to the
  section's first interface, are cut to its snaplen and have no timestamp
  (time 0)
- Every other block (name resolution, interface statistics, decryption
  secrets, custom, the obsolete packet block) is skipped by its length
- Every block's length is checked against its fields, its trailing copy and
  the end of the file before anything is read past it; a block that fails
  ends the capture as one cut off inside a record (`truncated()`), and only
  the first 256 KiB of a packet are dissected
- `if_tsoffset` is not applied: times are relative to the first packet

`parsePcap()` parses a whole buffer in memory, pcap or pcapng, for tests.

#### The reader seam
Everything past the reader (Converter, Stream Tracker, TCP Analysis, Packet Formatter, `CaptureStats`)
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
precision and the header's link-layer type. `PcapngReader` fills them
from the interface each packet was captured on.

The precision must be known before the first packet, but a pcapng declares
its interfaces in blocks anywhere in the file. `PcapngReader::open()` reads
the blocks up to the first packet block, where Wireshark's dumpcap declares
all its interfaces, and announces the finest precision among them. The
packets of an interface declared later are marked and shown at most at that
precision, so that the promise "no packet is finer" holds; a full pre-scan
would read a large capture twice. Its `linkTypes()` are those of all
interfaces declared so far, each once, so a pcapng without packets names
its interfaces' link types in the summary, as an empty pcap names its
header's.

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
  none. Its label is a guess (`PayloadDescription::guessed`), which the
  parser passes on as `PacketRecord::protocolRecognised` false, so that it
  does not stick to the stream (Stream Labels, below)

Everything that turns payload bytes into text lives here: escaping bytes
outside printable ASCII as `\xNN`, the first-line cut (120 bytes), the
preview and its caps. A description is finalised as one line before it
leaves the describer, so one packet is always one line whatever a detector
forgot to escape.

### 3. Packet Formatter (`packet_formatter.h/cpp`), Stream Tracker (`stream_tracker.h/cpp`), TCP Analysis (`tcp_analysis.h/cpp`) and statistics (`capture_stats.h/cpp`)
`PacketFormatter` converts `PacketRecord` structs, one at a time, into
Wireshark-style text lines with fixed-width columns: No., Stream, UTC Time,
Time, Source, Destination, Protocol, Length, Info. Both times have 6
decimals, or 9 when the capture announces nanosecond precision for any of
its packets (`PacketFormatter` takes the reader's `precision()`;
`formatAllPackets()` the finest of its packets); further digits are cut,
not rounded.

The widths are a minimum: a value as wide as its column, or wider (packet
1,000,000, `ETH(0x88CC)`), is still followed by a space, and an empty value
(Source and Destination of a packet without addresses) is shown as `-`, so
that a line always splits into its columns at runs of spaces. The Log
Format relies on it.

UTC Time is the packet's wall-clock time, written by `formatUtcTime()` as
an ISO 8601 date and time in UTC ending in `Z`:
`2026-10-09 08:41:12.123456Z`, or `2026-10-09 08:41:12.123456789Z`. It is
computed from the calendar alone (no `gmtime`, no time zone), so the text is
the same on every platform and in every zone; a time before 1970 counts
back from the epoch, and a year outside 0000–9999 gets ISO 8601's sign
(`+10000`, `-0001`). The Capture Summary's first and last packet times are
written by the same function. A Log Format reads the column with
`%Y-%m-%d %H:%M:%S.%f%z`: LogSquirl's `%f` takes any number of digits, `%z`
the `Z` as UTC. Time is relative to the first packet in the file, as
Wireshark's default Time column; a packet recorded before it (a merged
capture) has a negative Time but its own UTC Time.

UTC Time comes before Time because it is the line's timestamp: the first
time in the line, the field a Log Format names, and LogSquirl's table view
puts its Δt column right after it, so the relative and the elapsed time sit
side by side instead of Δt splitting the two.

IPv6 addresses are written in the RFC 5952 form (`fe80::1`, `::`) by
`formatIpv6()` in `wire_bytes.h`, the one place that formats them: the
Source and Destination columns, the Capture Summary endpoints, the Stream
Tracker's keys and SOCKS5 destinations (as `[2001:db8::1]:443`) all use it.

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

`track()` returns a `Stream`: the number, a pointer to the stream's
`StreamState`, the same slot for every packet of the stream (null without
a number), and the packet's direction in it, 0 or 1 (the same for every
packet from the same address and port). Modules that follow a conversation
keep their fields in the slot and read and update them through that
pointer. Every field added costs memory once per numbered stream: today a
`TcpDirection` per direction, 32 bytes (a `static_assert` holds it there),
and the stream's label, one byte, so 72 bytes per stream with the
alignment, some 72 MB at the stream cap. A UDP stream pays
for it too, as both transports share `StreamState`.

`analyseTcp()` (`tcp_analysis.h/cpp`, the TCP Analysis, pure C++), called
by the Converter after the Stream Tracker, shows a TCP segment's `Seq=` and
`Ack=` relative to the start of each direction, as Wireshark does by
default. It follows Wireshark's rules: a SYN's sequence number is its
direction's base, so the SYN shows `Seq=0`; a direction whose SYN was not
captured takes one less than its first number seen as base (its first
segment's sequence number, or the other direction's first acknowledgement
number, whichever comes first), so a stream captured mid-way starts at
`Seq=1 Ack=1` like one after its handshake. Without the ACK flag the
acknowledgement field means nothing and `Ack=0` is shown. The arithmetic
is modulo 2^32, so the numbers go on counting when the sequence numbers
wrap. A SYN without ACK whose sequence number differs from its direction's
base is a new connection on the same addresses and ports: both bases are
forgotten and counting starts afresh; a retransmitted SYN keeps them. The
parser writes the numbers as they are with `formatTcpNumbers()`, and the
TCP Analysis replaces that text; segments of a stream past the stream cap
have no state and keep the numbers as they are. `PacketRecord::tcpSeq` and
`tcpAck` stay the raw values.

#### Stream Labels (`stream_labels.h/cpp`)
The describer names one payload at a time, and the parser asks it before
the packet's stream is known, so on its own the Protocol column changes
within a conversation: a 443 stream alternates between `TLS` (a segment
that starts a record) and `HTTPS` (the port's guess for one in the middle
of a record), an HTTP body on port 8080 shows `HTTP-Alt`, on port 3000
`TCP`. `StreamLabels` (pure C++), owned by the Converter next to the Stream
Tracker, puts that right after the fact: `apply()` runs on every packet
after the Stream Tracker and the TCP Analysis. The first label a detector
recognised on a stream (`PacketRecord::protocolRecognised`) sticks to it;
a later packet that no detector recognises takes it, and if it carries
payload, its description becomes `Continuation`, followed by the preview
when there is one (`Continuation: {"status": "ok"}`). A packet a detector
recognises keeps its own label (a TLS record in an HTTP CONNECT tunnel is
`TLS`), and the stream keeps the first. A port's guess never sticks, so the
handshake before the first payload keeps it, and a later content match
overrides it. UDP streams behave the same.

The describer is not moved behind the tracker for this: it looks at the
payload bytes, which only the parser has, and lives on as a pure function
of payload and ports that is tested without a stream. The label is kept as
one byte of `StreamState`, a number into the capture's table of labels seen
(at most 255 stick). A new TCP connection on the same addresses and ports
(a SYN that the TCP Analysis finds starts one) resets the stream's whole
`StreamState`, the label with it.

#### TCP analysis markers
`analyseTcp()` then classifies the segment as Wireshark's TCP analysis does
(`tcp_analyze_sequence_number()` in `epan/dissectors/packet-tcp.c`, with its
default preferences), puts its markers at the start of Info in Wireshark's
words, `[TCP Retransmission] 80 → 54321 [ACK, PSH] Seq=1 …`, and returns
them as `TcpMarkers`, which the Converter counts in `CaptureStats` for the
Capture Summary. Several markers stand in Wireshark's order, the last one
it adds first: `[TCP ZeroWindow] [TCP Keep-Alive] …`. Each direction keeps
what Wireshark's `tcp_flow_t` holds for the rules below, in relative numbers
(0 meaning none seen yet, as in Wireshark): the next sequence number expected
(`nextSeq`, one past the highest sent, a SYN and a FIN counting one), the
last acknowledgement number, window and time, the number of duplicate ACKs
and the packet they count from, and whether the last segment was a
keep-alive or a zero window probe. With `fwd` the segment's direction,
`rev` the other one and `len` its payload on the wire:

| Marker | Rule |
|--------|------|
| `[TCP ZeroWindowProbe]` | `len` 1 at `fwd.nextSeq` while `rev`'s window is 0; it skips the ACK checks below and does not advance `nextSeq` |
| `[TCP ZeroWindow]` | window 0, no SYN, FIN or RST |
| `[TCP Previous segment not captured]` | sequence number beyond `fwd.nextSeq`, no RST |
| `[TCP Keep-Alive]` | `len` 0 or 1 at `fwd.nextSeq - 1`, no SYN, FIN or RST |
| `[TCP Window Update]` | `len` 0, a new window other than 0, same sequence number (`fwd.nextSeq`) and ACK as before |
| `[TCP Keep-Alive ACK]` | `len` 0, the same window (not 0), sequence number and ACK as before, after a keep-alive from `rev` |
| `[TCP ZeroWindowProbeAck]` | `len` 0, window still 0, the same sequence number and ACK (or one more) as before, after a probe from `rev` |
| `[TCP Dup ACK n#m]` | `len` 0, the same window (not 0), sequence number and ACK as before: the `m`th repeat of the ACK of packet `n` |
| `[TCP Spurious Retransmission]` | data (not a keep-alive) that `rev` has acknowledged already |
| `[TCP Fast Retransmission]` | data, a SYN or a FIN before `fwd.nextSeq`, at the sequence number `rev` last acknowledged, after at least two duplicate ACKs of it, within 20 ms of `rev`'s last segment |
| `[TCP Out-Of-Order]` | otherwise before `fwd.nextSeq`, within 3 ms of `rev`'s last segment, and not ending where `fwd.nextSeq` is (or ending there after a segment without data had raised it) |
| `[TCP Retransmission]` | otherwise before `fwd.nextSeq` |

Segments with a bogus TCP header length are not analysed, as in Wireshark.
The limits, all where Wireshark keeps more than a few integers per
direction:

- No list of the segments sent is kept, so a segment within 3 ms of the
  other direction's last one that was captured before is still called
  out of order, where Wireshark knows it was seen and calls it a
  retransmission; and `[TCP ACKed unseen segment]` is not shown.
- The 3 ms out-of-order limit is Wireshark's for a connection whose
  round-trip time it does not know; Wireshark takes the handshake's when it
  saw the handshake, this analysis never does.
- SACK blocks and the window scale option are not read, so there is no
  SACK-based fast retransmission and no `[TCP Window Full]`; windows are
  compared as sent.
- `[TCP Port numbers reused]`, `[TCP Retransmission]`'s RTO and the other
  fields Wireshark shows in its tree only are left out.
- As in Wireshark, sequence numbers compare modulo 2^32, and a segment
  captured before the other direction's last one (a capture that needs
  reordering) counts as 0 ms after it.

`CaptureStats` collects the sidebar summary's counts packet by packet
(among them the packets cut at the snaplen and the TCP segments per
analysis marker kind),
and the link-layer types of the packets in the order they were first seen. It
counts packets for at most `CaptureStats::kMaxEndpoints` (100,000) IP
addresses, and those of further addresses as "other endpoints".

Memory therefore grows with the conversations and addresses in a capture,
not with its size, and both are capped (at roughly 150 MB and 10 MB), so a
port scan or a busy NAT cannot exhaust it. The summary says when a cap was
hit.

#### The Log Format (`formats/tcpdump_log.json`)
An lnav-compatible Log Format definition, as LogSquirl's built-in ones in
its `Resources/formats`, that LogSquirl uses once the user has copied it
into its formats directory (README, *Log Format*). Its one regex names the
columns of a packet line with groups `number`, `stream`, `timestamp`,
`time`, `source`, `destination`, `protocol`, `length` and `body`; LogSquirl
compiles it with `QRegularExpression` and no options, and makes the named
groups the table view's columns in pattern order (only `[A-Za-z_]\w*` names
count). `timestamp` is read with `%Y-%m-%d %H:%M:%S.%f%z`, which gives the
Δt column, *Go to timestamp*, time-range search limits and the Chart
Panel's time axis. `length` is the only `integer` value, so the Chart
Panel's *Numeric Fields* template offers bytes over time and nothing else;
`number` and `time` are declared `string` for that reason.

A change of the packet line's columns is a change of the format too:
`tests/logformat_test.cpp` matches the regex against every line of every
`tests/corpus/*.txt` (header excluded) and checks each field against the
line's columns, split at runs of spaces, and reads every timestamp with a
port of LogSquirl's `TimestampReader` rules
(`src/logformat/src/timestampreader.cpp` in the host). The plugin cannot
register the format with LogSquirl (#50), nor tell whether it is installed,
and the shared CI cannot yet pack it into the release archive (#58);
`cmake --install` puts it next to the library.

### 4. Converter (`pcap_converter.h/cpp`)
`convertPcap()` reads a capture through the `CaptureReader` that
`makeCaptureReader()` picks for it, has the Stream Tracker give each packet
its stream and the TCP Analysis show its numbers relative and mark it,
lets the Stream Labels name it by its stream's protocol, counts its markers
and its protocol, formats the packet and appends its line to a new output file,
reporting progress and checking a
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
  top endpoints, the first and last packet time in UTC, packets per
  second, file size, the link-layer type names
  (comma-separated when there are several), the number of packets cut
  at the snaplen when there are any, and under *Analysis* the TCP segments
  per analysis marker kind when there are any
- On the first converted capture after the plugin is loaded, a link to
  README's *Log Format* section. The plugin cannot know whether LogSquirl
  has the format, so the hint is static and shown once per load

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
difference. The pcapng corpus capture, `interfaces.pcapng`, is made up byte
for byte by `tests/make_pcapng_corpus.py`, and `tcp-analysis.pcap`, a TCP
connection that shows every analysis marker, by
`tests/make_tcp_analysis_corpus.py`: a real lossy capture would need root
for a lossy link (tc netem) and differ from run to run. `stream-labels.pcap`,
streams whose protocol sticks and a new connection that forgets it, is
written by `tests/make_stream_labels_corpus.py`. The pcapng unit tests build their
blocks with `Pcapng` in `tests/pcapbuilder.h`. `logformat_test.cpp` checks
that the Log Format reads every line of every corpus text, so a new capture
in the corpus is covered by it, too. Plugin and sidebar tests run against the `FakeHost` in
`tests/fakehost.h`.
