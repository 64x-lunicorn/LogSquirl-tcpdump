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
  than 20 bytes is flagged and yields no payload. ICMP and ICMPv6 messages
  are described by `icmp.h/cpp` (see below)
- Hands a TCP or UDP payload with its ports to the Payload Describer, and
  appends the description it gets back to the transport summary after ` | `
- Names an IP protocol or EtherType it does not dissect further from the
  name tables (`IGMP`, `ESP`, `LLDP`, `PPPoES`), keeping the number in the
  Info column (`Protocol 2`, `EtherType 0x88CC`); one without a name stays
  numeric, `IP(200)` or `ETH(0x1234)`. An Ethernet type field of 1500 or
  less is the length of an IEEE 802.3 frame, shown as `LLC`

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

#### ICMP and ICMPv6 (`icmp.h/cpp`)
Pure C++. `describeIcmp()` and `describeIcmpv6()` turn a message of at
least its 8-byte header into Info. Type and code names follow Wireshark's
(RFC 792, RFC 4443, RFC 4861), in sentence case; a type without a name is
`Type=42 Code=1`, a code without one `(code=99)`. One form throughout:
the type's name, the code's name in parentheses, then `key=value` fields,
then what the message is about.

| Message | Info |
|---|---|
| Echo, timestamp, information and address mask queries | `Echo (ping) request id=0x1234, seq=7` (id in hexadecimal, seq in decimal, both read big-endian) |
| Destination unreachable, time exceeded, parameter problem, source quench | `Destination unreachable (Port unreachable) for 10.0.0.1:51234 → 192.168.1.5:53 UDP` |
| Fragmentation needed | `Destination unreachable (Fragmentation needed, mtu=1400) for …` |
| Redirect | `Redirect (Redirect for host) gateway=10.0.0.254 for …` |
| ICMPv6 errors | `Time exceeded (Hop limit exceeded in transit) for …`, `Packet too big mtu=1280 for [2001:db8::1]:40000 → [2001:db8::2]:443 TCP` |
| Router solicitation | `Router solicitation from 00:11:22:33:44:55` |
| Router advertisement | `Router advertisement (M, O, prf=high) lifetime=1800s from 00:11:22:33:44:55`: flags M, O, H, P, and the router preference unless medium |
| Neighbor solicitation | `Neighbor solicitation for fe80::2 from 00:11:22:33:44:55` |
| Neighbor advertisement | `Neighbor advertisement fe80::2 (rtr, sol, ovr) is at 00:11:22:33:44:55` |

The ` for …` of an error message describes the packet it quotes, which
`dissectQuotedPacket()` (`pcap_parser.h`) dissects with the same IPv4 and
IPv6 parsers as every packet, extension headers and fragments included, but
reads of its transport only the ports of a TCP or UDP header, the first 4 of
the 8 bytes a router quotes, and never a packet the quote itself quotes. The
protocol is `ipProtocolName()`'s; IPv6 addresses with a port are bracketed.
A quote without its whole IP header adds nothing, one without the ports
shows the addresses alone. The quote and the neighbor discovery options are
whatever the sender put there: every field is checked against the captured
bytes, an option of length 0 or running past them ends the walk. The ports
of a quote are not the message's own: ICMP keeps the stream `-`.

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
- TCP: DNS on port 53, TLS, HTTP, the HTTP/2 preface, NMEA 0183, SOCKS4/5
  (only messages of the exact shape, in the right direction, on proxy
  ports), then the port hint
- HTTP: a request is its request line with the Host header's value put
  before a path, `GET example.com/index.html HTTP/1.1`; a target that is no
  path (a URL, CONNECT's `host:port`, `*`) stays as it is. A response is
  its status line, then `, Content-Type: …` and `, Content-Length: …` when
  it has them, `HTTP/1.1 200 OK, Content-Type: text/html, Content-Length:
  1234`. The request or status line always comes first. A header counts
  only in the header section (before the empty line), on a whole line the
  segment holds up to its line feed, its name in any case; its value is
  shown without the blanks around it, escaped and cut like every field.
  SSDP (UDP 1900) is described the same way
- HTTP/2: the connection preface, `PRI * HTTP/2.0`, is labelled `HTTP2`
  and described as `Magic`, then the frames behind it in the segment. A
  frame is named with its type and stream, `HEADERS[1]`, Wireshark's way,
  up to four in a segment, then `…`. A frame header must keep the rules of
  its type (a known type, a stream for DATA, HEADERS and the like, stream 0
  for SETTINGS, PING and GOAWAY, the fixed length of PING, RST_STREAM,
  PRIORITY and WINDOW_UPDATE, no more than the default maximum frame size
  of 16384 bytes, the reserved bit unset), or the bytes are taken for no
  frames. HPACK header blocks are not decoded; HTTP/2 over TLS is TLS
- TLS: every record of a segment and every handshake message of a record
  is named, in order, up to four, then `…`; a ClientHello adds its server
  name, the highest version it offers (`supported_versions`, GREASE aside,
  else its own) and its ALPN protocols, a ServerHello the version chosen.
  `FieldReader` reads the fields: a read that does not fit fails, and a length
  that claims more than there is yields what there is, so a record cut by
  the snaplen or the segment is described as far as it goes. A version is
  named only if known: a cut hello whose extensions end before a
  `supported_versions` would have shown gets none
- UDP: DNS and mDNS by port, SSDP, NTP, DHCP, DHCPv6, QUIC, then NMEA and
  the port hint
- DHCP (UDP 67, 68): the message type of option 53 in Wireshark's words
  and the transaction id, then the address and the client's MAC (an
  Ethernet `chaddr`) and the host name (option 12, cut like every field),
  `DHCP Offer - Transaction ID 0x3903f326, 192.168.1.50 for
  00:11:22:33:44:55`, `DHCP Discover - Transaction ID 0x3903f326 from
  00:11:22:33:44:55, Host Name: laptop`. The address is the one the server
  assigns (`yiaddr`), else the one requested (option 50), else the one the
  client holds (`ciaddr`). Options are walked within the message: pads
  skipped, up to the end option; an option whose length runs past the
  message ends the walk, one of the wrong length is ignored. An overload
  option (52) in the options field makes the file and sname fields be
  walked too, in that order, but not overload again. Without the magic
  cookie (or option 53) a message is BOOTP, `Boot Request` or `Boot Reply`
- DHCPv6 (UDP 546, 547): the message type, the transaction id and the
  client's DUID (option 1) in hexadecimal, `Solicit XID: 0x1a2b3c CID:
  000100011c39cf88001122334455`, as Wireshark writes it; a relay message
  names its link address and the message it relays (option 9), up to 8
  relays deep, `Relay-forw L: 2001:db8::1, Solicit XID: …`
- NTP (UDP 123): version and mode as Wireshark writes them, then the
  stratum, with the reference identifier of a primary server or a
  kiss-o'-death code, `NTP Version 4, server, stratum 1 (GPS)`; a client
  request's stratum, 0 as a rule, is left out unless set. Control and
  private messages (modes 6 and 7) show their version and mode alone. A
  packet of another version, or shorter than the 48-byte header, is `NTP`
  by its port alone. DNS, mDNS, SSDP, NTP, DHCP and DHCPv6 are named by
  their ports, not guessed: the label sticks to the stream
- DNS: described like Wireshark, `Standard query response 0x1a2b A
  www.example.com CNAME example.com A 93.184.216.34`: the operation, the
  transaction id, the first question's type and name, a response code
  other than "no error" (`[NXDOMAIN]`), then the answers' types and data
  (addresses, names, MX, SRV and TXT data; other types by name alone), up
  to four; answers not listed, beyond the cap or cut off, are counted,
  `… (6 answers)`. Names are put together from their compression pointers
  within the message: a pointer must point before itself, so a chain of
  them always ends; a pointer forward, to itself or beyond the message, a
  reserved label type or a name over 255 bytes fails the name, and with it
  the rest of the message. A name or TXT data is shown up to the field cap
  (120 bytes). Over TCP every message is behind a 2-byte length; the
  messages a segment begins with are described in order, up to four, the
  last as far as the segment holds it. A segment that begins inside a
  message (its header implausible: an unknown opcode, the Z bit set or more
  than one question) is `DNS` by its port alone
- QUIC: by its bytes, not its port. A datagram is QUIC if it begins with a
  long header (header form and fixed bit set) of a version the describer
  knows: v1, v2 (RFC 9369, whose packet types are numbered differently) or
  draft-22 to draft-34 (`0xff0000xx`), or with a Version Negotiation
  packet (version 0) that lists one of them, and with no other version.
  Only the version tells a long header from any UDP datagram whose first
  byte has its two top bits set, so an unknown one is not taken for QUIC;
  and only these versions have the header the describer reads: drafts
  before 22 packed both connection ID lengths into one byte, Google's QUIC
  (`Q0xx`) has headers of its own, and a version not yet known may number
  its packet types differently, as v2 did. It
  is described from its public header, `Initial, Version 1,
  DCID=8394c8f03e515708, SCID=0a0b0c0d`: the packets coalesced in the
  datagram, in order, up to four, then `…`, a short header among them as
  `Protected Payload`, then the version and connection IDs of the first;
  a Version Negotiation packet lists the versions offered. Everything
  behind the header is encrypted, the server name of an Initial too (it
  would take deriving the Initial keys). A short header carries no version
  and its connection ID no length: by its bytes alone it is not QUIC, and
  UDP 443 is still only the port hint `HTTPS`
- `describeInStream()`, run by the Converter after the Stream Tracker, looks
  at a packet again with its stream's state: it records in the stream's
  `QuicConnection` that a long header was seen and how long the connection
  ID its sender chose is, and labels the stream's short header packets
  (fixed bit, no long header bit, long enough for header protection) QUIC,
  `Protected Payload, DCID=…`, replacing the description after the
  ` | ` separator (`kDescriptionSeparator`). Likewise it records in
  `StreamState::http2` that a TCP stream began with the HTTP/2 preface,
  and labels the stream's later segments `HTTP2` when they begin with
  frame headers, naming the frames whose header lies in the kept bytes.
  A segment that begins inside a frame (its first bytes no plausible
  header) is not described again: segments are not reassembled, and the
  Stream Labels make it an `HTTP2` `Continuation`. A packet labelled here
  counts as recognised (`PacketRecord::protocolRecognised`), so its label
  sticks to the stream. For this the parser keeps the
  first `kPayloadHeadBytes` (48) bytes of every TCP and UDP payload in
  `PacketRecord::payloadHead`
- The port hint, the last entry of both tables, names the service of a
  well-known port from the name tables, the source port's before the
  destination port's, and previews the payload: printable ASCII, other
  bytes as dots, at most 200 characters; predominantly binary payloads get
  none. Its label is a guess (`PayloadDescription::guessed`), which the
  parser passes on as `PacketRecord::protocolRecognised` false, so that it
  does not stick to the stream (Stream Labels, below)

Everything that turns payload bytes into text lives here: escaping bytes
outside printable ASCII as `\xNN`, the first-line cut (120 bytes), the
preview and its caps. A description is finalised as one line before it
leaves the describer, so one packet is always one line whatever a detector
forgot to escape.

A preview is marked as such (`PayloadDescription::preview`), and the parser
records its length in `PacketRecord::previewBytes`: it ends the Info, after
the separator. `limitPreview()` cuts it to the length the user chose, with
an ellipsis, or removes it with its separator. The Converter calls it on
each packet as the reader hands it out, before the stream steps touch the
Info, so the dissectors take no options; a packet whose stream continues a
protocol then reads `Continuation` alone, as one without a preview.

#### The name tables (`protocol_names.h/cpp`)
Pure C++, names only: `ipProtocolName()` for IP protocol numbers,
`etherTypeName()` for EtherTypes, `servicePortName()` for the service a
port is assigned to on TCP or on UDP; each answers `nullptr` for a number
it does not know, and the caller keeps the numeric form. A name is one
word, without spaces, as the Protocol column and the Log Format need it.
A service is listed with the transports it runs over (`kTcp`, `kUdp`,
`kBoth`), so that TFTP is named on UDP 69 but not on TCP 69. The tables
name what nothing dissects; a detector that recognises a protocol by its
port or content (DNS, NTP, DHCP, DHCPv6) runs before the port hint and decides
alone, and may take its name from the table to keep the two in step.

### 3. Packet Formatter (`packet_formatter.h/cpp`), Stream Tracker (`stream_tracker.h/cpp`), TCP Analysis (`tcp_analysis.h/cpp`) and statistics (`capture_stats.h/cpp`)
`PacketFormatter` converts `PacketRecord` structs, one at a time, into
Wireshark-style text lines with fixed-width columns: No., Stream, UTC Time,
Time, Source, Destination, Protocol, Length, Info. Both times have 6
decimals, or 9 when the capture announces nanosecond precision for any of
its packets (`PacketFormatter` takes the reader's `precision()`;
`formatAllPackets()` the finest of its packets); further digits are cut,
not rounded.

The widths are a minimum: a value as wide as its column, or wider (packet
1,000,000, `MPLS-in-IP`), is still followed by a space, and an empty value
(Source and Destination of a packet without addresses) is shown as `-`, so
that a line always splits into its columns at runs of spaces. The Log
Format relies on it.

Which columns a line has is its `LineLayout`, which `PacketFormatter`
takes: `timeColumns` (`Both`, the default, `AbsoluteOnly` or
`RelativeOnly`) leaves out Time or UTC Time, and `macColumns` adds Source
MAC and Destination MAC, 17 characters and two spaces each, `-` for a
packet without them, between Length and Info. Each column is written on
its own, so a line in another layout is the default line with a column's
text cut out or put in (`tests/conversion_options_test.cpp` derives the
expected text of each time mode that way). The MAC columns go before Info
rather than next to Source and Destination because the Log Format reads
Info as the rest of the line: there they need no groups of their own, which
every table in the default layout would show empty.

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
the Payload Describer's `QuicConnection` (whether a QUIC long header was
seen, and the connection ID length of each direction), 3 bytes, whether a
TCP stream began with the HTTP/2 preface, 1 byte, and the stream's label,
1 byte, so 72 bytes per stream with the alignment, some 72 MB at the stream
cap. A UDP stream pays for the TCP fields too and a TCP stream for the QUIC
ones, as both transports share `StreamState`.

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

`Win=` is the calculated window, as in Wireshark: the window field shifted
by the sender's window scale (RFC 7323). The parser reads the shift count of
a header's window scale option into `PacketRecord::tcpWindowShift`, walking
the options as Wireshark does (a NOP is one byte; the end of options, or an
option whose length is bogus or runs past the header, ends the walk). A
SYN's option, its shift capped at 14 as RFC 7323 and Wireshark do, is kept
in its direction's `TcpDirection::windowScale` (the shift plus one, 0 when
the SYN carried none), and the TCP Analysis shifts the window of every later
segment of a direction by its scale once both directions' SYNs carried the
option; a SYN's own window is never scaled. Otherwise `Win=` is the window
as sent: one side did not offer scaling, so neither scales, as RFC 7323
says; or the handshake was not captured, which Wireshark shows as window
size scaling factor -1 (unknown) and leaves unscaled with its default
preferences, as here. Unlike Wireshark, which scales a side's windows by its
SYN's shift when only that SYN was captured (and the SYN-ACK was not), this
needs both. A new connection on the same addresses and ports forgets the
scale with the rest of the stream's state. `PacketRecord::tcpWindow` stays
the raw value.

#### Stream Labels (`stream_labels.h/cpp`)
The describer names one payload at a time, and the parser asks it before
the packet's stream is known, so on its own the Protocol column changes
within a conversation: a 443 stream alternates between `TLS` (a segment
that starts a record) and `HTTPS` (the port's guess for one in the middle
of a record), an HTTP body on port 8080 shows `HTTP-Alt`, on port 3000
`TCP`. `StreamLabels` (pure C++), owned by the Converter next to the Stream
Tracker, puts that right after the fact: `apply()` runs on every packet
after the Stream Tracker, the TCP Analysis and `describeInStream()`, so the
QUIC short headers and HTTP/2 frames that only their stream makes
recognisable count as recognised too. The first label a detector
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
(0 meaning none seen yet, as in Wireshark) and with windows scaled, as `Win=`
shows them, so that a window of 0 or a change of it is the same in Info and
in the rules: the next sequence number expected
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
- SACK blocks are not read, so there is no SACK-based fast
  retransmission; `[TCP Window Full]` is not shown.
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
not with its size, and both are capped, so a port scan or a busy NAT cannot
exhaust it. By default the caps are 1,000,000 streams and 100,000
addresses, roughly 150 MB and 10 MB; the options (`settings.h`,
*Advanced* in the dialog) let the user raise each up to tenfold
(`kMaxStreamCap`, `kMaxEndpointCap`: 10,000,000 streams and 1,000,000
addresses, roughly 1.5 GB and 100 MB) or lower it to 1. The summary says
when a cap was hit.

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

The `timestamp` and `time` groups are optional, each with the spaces after
it, so that the format reads a line of every `LineLayout`: a time column
the line does not have is empty, a line without `timestamp` has no time for
LogSquirl, and the MAC columns start `body`. A line of the default layout
matches exactly as with mandatory groups. Code that parses packet lines
with a copy of the regex must take this one.

A change of the packet line's columns is a change of the format too:
`tests/logformat_test.cpp` matches the regex against every line of every
`tests/corpus/*.txt` (header excluded) and checks each field against the
line's columns, split at runs of spaces, the same for the corpus converted
in every `LineLayout`, and reads every timestamp with a
port of LogSquirl's `TimestampReader` rules
(`src/logformat/src/timestampreader.cpp` in the host). The plugin cannot
register the format with LogSquirl (#50), nor tell whether it is installed.
The release archive carries it next to the library (`package_files` in
`.github/plugin-ci.json`, LogSquirl-Plugin-CI v1.1.0), and `cmake --install`
puts it there too.

### 4. Converter (`pcap_converter.h/cpp`)
`convertPcap()` reads a capture through the `CaptureReader` that
`makeCaptureReader()` picks for it, has the Stream Tracker give each packet
its stream and the TCP Analysis show its numbers relative and mark it,
lets the Payload Describer look at it again in its stream and the Stream
Labels name it by its stream's protocol, counts its markers
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

`ConversionOptions` are everything the user can choose: the `LineLayout`,
the payload preview (`preview`, `previewChars`) and the stream and endpoint
caps. The defaults write the text of `tests/corpus`; any other choice is
tested by deriving its text from that one, not by more committed text.

### Settings and configuration dialog (`settings.h/cpp`, `configdialog.h/cpp`)
`loadConversionOptions()` and `saveConversionOptions()` keep the
`ConversionOptions` in `settings.ini` (`QSettings`, INI format, group
`conversion`) in the configuration directory the host names
(`get_config_dir`, part of the API since 26.10). A value that is missing or
not one reads as its default, a number out of range as the nearest allowed:
the preview 1 to `kMaxPreviewChars`, the caps `kMinCap` to ten times their
default. `ConfigDialog` shows and edits the options and says that an open
capture keeps those it was converted with; it does not save them itself.
The sidebar loads the file when a conversion starts, on the GUI thread, and
hands the options to the worker, so a change applies to the next capture
only.

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
temporary files only in the first case. `logsquirl_plugin_configure()`,
which LogSquirl calls for **Configure…** in Plugin Management with its main
window as the parent, runs the `ConfigDialog` modally and saves the options
when it is accepted; `hostConfigDir()` is the directory, empty without a
host, where saving fails with a notification.

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

A protocol that only needs a name, a well-known port, IP protocol number or
EtherType, is one line in the tables of `protocol_names.cpp`, with a check
in `tests/protocol_names_test.cpp`. A new link or network layer, in
contrast, is parsed in `pcap_parser.cpp` and tested with the frame builders
in `tests/pcapbuilder.h`.

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
for byte by `tests/make_pcapng_corpus.py`; `tls.pcap` holds real TLS 1.3 and
1.2 handshakes, which `tests/make_tls_corpus.py` runs through Python's
`ssl` module in memory and frames in made-up TCP segments; `dns.pcap`
holds DNS over UDP and TCP, encoded with name compression by
`tests/make_dns_corpus.py`; `tcp-analysis.pcap`, a TCP
connection that shows every analysis marker, is written by
`tests/make_tcp_analysis_corpus.py`: a real lossy capture would need root
for a lossy link (tc netem) and differ from run to run. `stream-labels.pcap`,
streams whose protocol sticks and a new connection that forgets it, is
written by `tests/make_stream_labels_corpus.py`. `icmp.pcap`, ICMP and
ICMPv6 echoes, error messages with their quoted packets and neighbor
discovery, is written by `tests/make_icmp_corpus.py`; `dhcp-ntp.pcap`, a DHCP
lease exchange, DHCPv6 messages and a relay, and NTP requests and replies,
by `tests/make_dhcp_ntp_corpus.py`. The pcapng unit tests build their
blocks with `Pcapng` in `tests/pcapbuilder.h`. `logformat_test.cpp` checks
that the Log Format reads every line of every corpus text, so a new capture
in the corpus is covered by it, too, in every `LineLayout`.
`conversion_options_test.cpp` converts the corpus with each time mode and
with the preview off or shorter, and checks each line against the default
text. Plugin, sidebar and configuration dialog tests run against the `FakeHost` in
`tests/fakehost.h`.

### Real captures

Captures taken from a real network stack let the Parser, the Payload
Describer and the Packet Formatter see what tcpdump actually writes: TCP
options, a real handshake and teardown, real TLS records, a real DNS exchange,
real ICMP. They are **never committed**: `tests/make_real_corpus.sh` records
them into `tests/corpus/local`, which git ignores, and the corpus and Log
Format tests convert and read them too when that directory exists. They hold
only traffic between local processes on the loopback interface (`lo0` on
macOS, link type `NULL`; `lo` on Linux), 127.0.0.1 to 127.0.0.1, and are each
a few KB. The script needs root for tcpdump:

```bash
sudo bash tests/make_real_corpus.sh              # all four
sudo bash tests/make_real_corpus.sh real-ping    # just the named ones
TCPDUMP_UPDATE_CORPUS=1 build/tests/logsquirl_tcpdump_tests "[corpus]"
```

Each capture is one `tcpdump -i lo0 -s <snaplen> -U -w <name>.pcap
<filter>` around one client command against a server the script starts:

| Capture | Filter | Snaplen | Server | Client |
|---------|--------|---------|--------|--------|
| `real-http` | `tcp port 8080` | 262144 | `python3 -m http.server 8080 --bind 127.0.0.1` serving a one-line `index.html` | `curl -s -o /dev/null http://127.0.0.1:8080/index.html` |
| `real-dns` | `udp port 53` | 262144 | a dozen lines of Python on 127.0.0.1:53 answering every query with `192.0.2.80` | `dig +tries=1 +time=2 +noedns @127.0.0.1 example.org A` |
| `real-ping` | `icmp` | 262144 | the kernel | `ping -c 2 127.0.0.1` |
| `real-tls` | `tcp port 8443` | 512 | `openssl s_server -quiet -accept 127.0.0.1:8443 -www` with a throw-away self-signed certificate for `localhost` | `curl -sk --resolve localhost:8443:127.0.0.1 -o /dev/null https://localhost:8443/` |

The TLS capture keeps 512 bytes of each packet, enough for the whole
ClientHello with its SNI and ALPN; larger records are cut. The macOS firewall
in stealth mode drops echo requests even on loopback; the script switches
stealth mode off while it records `real-ping` and back on afterwards. A
recording keeps the time, client ports and sequence numbers of its moment, so
a new recording changes every line of its text: review it against
`tcpdump -nn -vv -r tests/corpus/local/<name>.pcap` before relying on it.
