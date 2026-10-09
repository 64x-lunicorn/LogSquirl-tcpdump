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
gets a reader whose `open()` fails and says why. Only the bytes the
decision needs are looked at (see *The Capture Source seam* below), so the
same path reads a file and a stream that is still being written. The readers share reading
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
  loopback DLT_NULL/DLT_LOOP, family read in the capture's byte order), and
  hands 802.11, Radiotap, PPP, Cisco HDLC and PPPoE to `link_layers.h/cpp`
  (see below)
- Strips stacked 802.1Q / 802.1ad (QinQ) VLAN tags, then unwraps PPPoE
  (EtherTypes 0x8863 and 0x8864) with `dissectPppoe()`
- Dissects network layer (IPv4, IPv6 with hop-by-hop, routing, fragment,
  destination options and AH headers, ARP); bounds transport data by the IP
  length fields, falling back to the captured bytes for TSO/GSO lengths of 0;
  fragments after the first are not parsed as TCP/UDP
- Unwraps VXLAN, GRE and IP-in-IP tunnels to the packet inside, at most
  `kMaxTunnels` (4) deep (see *Tunnels* below)
- Dissects transport layer (TCP, UDP, ICMP, ICMPv6); a TCP header shorter
  than 20 bytes is flagged and yields no payload. ICMP and ICMPv6 messages
  are described by `icmp.h/cpp` (see below)
- Hands a TCP or UDP payload with its ports to the Payload Describer, and
  appends the description it gets back to the transport summary after ` | `
- Names an IP protocol or EtherType it does not dissect further from the
  name tables (`IGMP`, `ESP`, `LLDP`, `EAPOL`), keeping the number in the
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

#### Link layers beyond Ethernet (`link_layers.h/cpp`)
Pure C++. `dissectsLinkLayer()` says which link-layer types
`dissectLinkLayer()` reads: DLT_IEEE802_11 (105), DLT_IEEE802_11_RADIO
(127), DLT_PPP (9), DLT_PPP_SERIAL (50), DLT_PPP_ETHER (51) and DLT_C_HDLC
(104). A dissector either hands `dissectPacket()` the `NetworkLayer` the
frame carries (an EtherType and its bytes), which goes on through the VLAN,
PPPoE and network steps like an Ethernet frame's, or describes the frame
itself in `protocol` and `info` and returns nothing. Every header is
checked against the captured bytes first; a frame cut inside one is named
as such (`Truncated 802.11 header`).
- **Radiotap**: version 0, its length honoured (`Invalid Radiotap header
  length N` for one shorter than 8 bytes or longer than the packet), the
  extended present bitmaps walked within it. Only the flags field is read,
  behind TSFT aligned to 8 bytes from the header's start: a frame check
  sequence at the end is cut off (when the frame was captured whole), and
  the data pad flag aligns the 802.11 header to 4 bytes.
- **802.11**: frame names are Wireshark's (`Beacon frame`, `Probe
  Request`, `QoS Data`, `Null function (No data)`, `Request-to-send`,
  `Acknowledgement`). Protocol is `802.11`. Management and data frames add
  the sequence and fragment numbers, `SN=…, FN=…`; a beacon and probe
  response the interval `BI=`; those that carry one the SSID from the
  information elements, `SSID="…"` escaped and cut like `fieldText()`, an
  empty one in a probe request `SSID=Wildcard (Broadcast)`. Source and
  Destination MAC are SA and DA, which address they are depending on the
  To DS / From DS flags (the fourth address with both); a control frame has
  its receiver as destination and its transmitter, if it names one, as
  source. A frame with the Protected flag ends in `, Protected`, its body
  not read; a fragment, an A-MSDU and a frame without data are named only.
  A data frame's LLC/SNAP header (OUI 00:00:00 or 00:00:F8) gives the
  EtherType; other LLC frames are `LLC` with their DSAP and SSAP.
- **PPP**: HDLC-like framing (0xFF 0x03) or none, and a compressed
  one-byte protocol field. IPv4 (0x0021) and IPv6 (0x0057) go on as
  EtherTypes; LCP, IPCP, IPv6CP, CCP, PAP and CHAP are their own Protocol,
  with the code's name as Info (`Configuration Request`, `Echo Reply`,
  `Authenticate-Request`, `Challenge`); options, names and passwords are
  not shown. Another protocol is `PPP`, `PPP protocol 0x0281`.
  DLT_PPP_SERIAL tells Cisco HDLC (address 0x0F or 0x8F, then an
  EtherType) from PPP by its first byte.
- **PPPoE** (RFC 2516): the code tells a session frame (0x00), whose PPP
  frame is bounded by the PPPoE length so that Ethernet padding is not
  read, from a discovery message: `PPPoED`, its stage as Wireshark names
  it, `Active Discovery Offer (PADO)`, with the access concentrator's
  `AC-Name='…'` from the tags.

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

#### Tunnels
A tunnelled packet is shown as Wireshark's columns show it: by the packet
inside. Source, Destination, Protocol, the ports and Info come from the
innermost packet; Info starts with the tunnels it came through, outermost
first, each followed by ` | `:

| Tunnel | Recognised by | Named |
|---|---|---|
| VXLAN (RFC 7348), an Ethernet frame inside | UDP destination port 4789, at least the 8-byte header | `VXLAN VNI 100`, `VXLAN` without the I flag |
| GRE (RFC 2784/2890) carrying IPv4, IPv6 or Ethernet (0x6558, NVGRE, gretap) | IP protocol 47, version 0, no source routing | `GRE`, `GRE key=0x0000002A` with a key; checksum and sequence number are skipped |
| IP-in-IP | IP protocol 4 with an IPv4 header inside, 41 with an IPv6 header | `IPv4-in-IPv4`, `IPv6-in-IPv4`, `IPv4-in-IPv6`, `IPv6-in-IPv6` |

`VXLAN VNI 100 | 50000 → 8080 [SYN] Seq=0 Win=64240`; nested:
`VXLAN VNI 100 | GRE | Echo (ping) request id=0x4e03, seq=1`. An Ethernet
frame inside (VXLAN, GRE's transparent bridging) goes through the same
`parseEthernet()` as the outer frame: its MAC addresses replace the outer
frame's, so a non-IP frame inside (ARP, LLDP) is shown by its own
addresses, and `parseNetwork()` strips its VLAN tags, unwraps PPPoE and
dissects its network layer. `dissectPacket()` hands every link layer's
network layer to `parseNetwork()` too, so a step added there reaches
tunnelled frames as well.

Entering a tunnel (`enterTunnel()`) moves the outer packet's addresses into
a `Tunnel` record in `PacketRecord::tunnels`, its name with them, and clears
the transport fields for the packet inside. The tunnels are kept apart
from `info`: the TCP Analysis inserts its markers at the start of `info`,
the Stream Labels and `describeInStream()` look for its first ` | `, and
both must find the inner packet's description there. The Packet Formatter
writes the names before `info` (`GRE | [TCP Retransmission] …`). The
Capture Summary counts the outer addresses apart, as tunnel endpoints
(`CaptureStats::tunnelEndpointPackets`, each packet once per address
however many of its tunnels the address ends), not among the endpoints:
those are the Source and Destination columns, whose summary links open a
pattern over those columns, and no column of a line shows the outer
addresses (Wireshark's do not either), so a link for them would match
nothing. The sidebar lists them under *Tunnel endpoints*, as plain text.
Its protocol breakdown counts the inner protocol. The Stream Tracker keys a tunnelled
packet by its inner addresses and ports alone, as Wireshark's `tcp.stream`
does: a conversation is one stream whichever tunnel, VNI or GRE key carries
it, and also when part of it is seen outside the tunnel.

At most `kMaxTunnels` (4) tunnels are unwrapped; a fifth is left as the
packet that carries it, named and described as such: `IPIP`, `IPv4-in-IPv4
not dissected: more than 4 nested tunnels` (a VXLAN one stays the UDP
datagram, with its stream). Not unwrapped, and shown as the GRE packet with
the outer addresses: GRE carrying any other protocol type (`GRE, protocol
type 0x88BE`), PPTP's enhanced GRE carrying PPP (`GRE version 1, protocol
type 0x880B`, to come with the PPP dissection) and RFC 1701 source routing.
A tunnel header cut short is `Truncated GRE header` or, for VXLAN, the UDP
datagram it would be; a packet inside cut short is described as truncated
by its own parser, after the tunnel's name. A packet an ICMP error quotes
is never unwrapped: its quote shows the tunnel's endpoints and protocol
(`for 10.0.0.1 → 10.0.0.2 GRE`). Geneve and VXLAN-GPE are not unwrapped.

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

A reader can also be stopped and taken up again elsewhere, for the Packet
Panel (see *Packet Panel* below). `checkpoint()`, taken after a packet,
gives a `ReaderCheckpoint`: the packets before it, where the next record
starts in the source, and a `ReaderState` the reader needs to go on there
(none for a pcap, whose global header `open()` reads again; the section's
byte order and interfaces for a pcapng, shared between checkpoints until an
interface is declared). `resume()`, called on a newly opened reader of the
same file, skips to the checkpoint and goes on numbering from it. After
each packet the reader also tells where its record lies (`recordOffset()`,
`recordLength()`: the pcap record header or the pcapng block, header and
all), its bytes as dissected (`packetBytes()`, at most
`kMaxDissectedBytes`) and the byte order they were read in
(`byteSwapped()`).

#### The Capture Source seam (`capture_source.h/cpp`)
A capture need not be a file: a pipe, a FIFO, a socket or a capture
program's stdout holds what has been written so far, and more comes later
or never. Every live source (a local tcpdump or dumpcap, adb, ssh, an
extcap, a custom command) is read through this seam, and only the source
differs; everything from `makeCaptureReader()` on is the file's path.

What a source provides is a `StreamSource`, a `ByteSource` whose `read()`
waits until at least one byte has come and returns what has (possibly
fewer than asked), and 0 once the stream has ended. A subclass implements
two things: `readFor( dst, n, timeout )`, which waits at most `timeout`
and returns the bytes read, 0 at the end (setting `error_` if it broke
off), or -1 if nothing came in time; and `available()`, whether a read
would not wait. Two exist:

- `FdSource` reads an open file descriptor (pipe, FIFO, socket) with
  `poll()`; the descriptor stays the caller's. Unix only.
- `DeviceSource` reads a `QIODevice` that can wait (`waitForReadyRead()`):
  a `QProcess`'s stdout, a `QLocalSocket` (a Windows named pipe), a
  `QTcpSocket`, on the thread it belongs to; no event loop is needed. The
  stream ends when the device has nothing left and stops waiting before the
  timeout, as a finished process or a closed socket does.

A new live source either hands one of these its descriptor or device, or
implements the two functions for its own handle.

**Waits.** A source is given a stop flag (`std::atomic_bool`); `read()`
checks it before every wait, and no wait is longer than
`StreamSource::kWaitSlice` (50 ms), so a read returns within that of a
Stop or Cancel even when nothing is written. A stopped stream reads as
ended (`stopped()` tells it from a closed one). The Converter's own cancel
flag is checked between packets, so a conversion gives the same flag to
the source.

**Detection.** `findCaptureStart()` answers `Found`, `None` or `NeedMore`
with the number of bytes that decide the next step, and
`makeCaptureReader()` peeks exactly that many: a pcap is decided by its
24-byte global header, a pcapng by the start of its section header, each
byte of a text preamble by itself, and a byte that is neither text nor a
header means "not a capture" at once. A stream that has sent its header
and nothing more is thus decided without waiting. `PcapngReader::open()`
then reads the section header and at least the first interface, and on
past it only while `ByteSource::ready()` says blocks have come, so a
capture with no traffic yet opens; a file is always ready and is read up to
its first packet block as before.

**The end.** The writer closing the stream (the process exited, the pipe
was closed) or a stop ends the capture as the end of a file does: a record
cut off there is `truncated()`. A stream that breaks off with a read error
ends the conversion as Failed ("Cannot read the capture: …").

`convertStream( source, name, outputRoot, cancel, options )` converts a
stream as `convertPcap()` converts a file, into `<name>.log`, without
progress, as a stream has no size. Regular files keep their own path:
`convertPcap()` opens them as `FileSource` with size-based progress.

#### The Process Source (`process_source.h/cpp`)
A capture program (tcpdump, dumpcap, adb, ssh, an extcap, a user's
command) writes its capture to stdout and its complaints to stderr. A
`ProcessSource` runs one, given as a `ProcessCommand` (program, argument
list, optional display name), and is the `StreamSource` over its stdout,
read through a `DeviceSource`:

- **Separate channels.** The `QProcess` keeps stdout and stderr apart
  (stdin is the null device): text after a pcap header would corrupt the
  stream. stderr is drained after every wait slice and split by
  `StderrLines` into lines (UTF-8, line ends dropped, blank lines skipped,
  a line without end handed on at 4096 bytes), each handed to the source's
  `onLine` callback on the reading thread, and the last
  `StderrLines::kKept` (10) are kept. The callback runs on the worker
  thread; whoever shows the lines in the log (`hostLog`) or the sidebar
  posts them to the UI thread.
- **No shell.** The program gets its arguments as a list, each one
  argument, untouched (spaces, quotes, `$( )`, `;`). A custom command opts
  into the shell explicitly with `ProcessCommand::shell( commandLine )`
  (`/bin/sh -c`, or `cmd.exe /d /s /c` on Windows), named by its first word.
- **Thread.** The source starts the program when it is constructed and
  owns it on that thread, which needs no event loop: build it on the
  worker thread that converts the stream.
- **The end.** The stream ends when the program has exited (stdout closing
  alone does not end it while the program runs) or on the stop flag. A
  program that could not be started, exited with a code other than 0 or
  crashed breaks the stream off, so `convertStream()` ends Failed with
  `Cannot start <name>: …`, `<name> exited with code N:` or
  `<name> crashed (exit code N):` followed by its last stderr lines. A
  program ended on purpose (`terminate()`, `terminateCaptureProcesses()`)
  did not fail: its stream reads as `stopped()`
  (`StreamSource::endedOnPurpose()`).
- **Ending it.** On Unix the program runs in a process group of its own
  (`setpgid( 0, 0 )` in the child); `terminate()` sends SIGTERM to the
  group and SIGKILL to what is left after `ProcessSource::kTerminateGrace`
  (2 s), and returns when the group is gone (a second more at most, for a
  process of another user, as behind sudo, that cannot be killed). On
  Windows the program is put in a job object with
  `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` right after it starts (what it
  starts later is in the job too), and `terminate()` terminates the job;
  closing the job's last handle, even as LogSquirl crashes, kills what is
  left. The destructor terminates.
- **Stop.** The stop flag ends the stream, not the program: the
  conversion finalises (Converted), then the caller terminates the source,
  or destroys it. A Stop, or a shutdown, before the capture header has come
  ends Stopped: nothing was captured, nothing went wrong.
- **No orphans.** Every started source's group is enrolled in a registry;
  `terminateCaptureProcesses()` ends them all, from any thread, and
  `logsquirl_plugin_shutdown()` calls it after deleting the sidebar
  widget, so no capture program outlives LogSquirl or a disabled plugin.

The tests (`tests/process_source_test.cpp`) run fake capture programs,
shell scripts that write a synthetic pcap to stdout and text to stderr,
exit with an error, crash, start a child and ignore SIGTERM; they need a
Unix shell, so on Windows only the stderr splitting is run. A test never
waits on time for a fake program: it acts on what the program has
signalled, the first packet converted (`LiveObserver::firstPacket`) or a
`child <pid>` line on stderr written once the program is ready, so that the
tests pass on a loaded machine and in parallel runs.

### 2. Payload Describer (`payload_describer.h/cpp`)
Pure C++. `describePayload()` takes the captured payload bytes, the two
ports and the transport, and returns a protocol label and a one-line
description, or no match. It is the only module that knows which
application protocols exist on which transport and in which order they are
tried: each transport has a table of detectors, all of the same shape
(payload in, description out if recognised), and the first match wins.
`payload_describer.cpp` holds the tables, the port hint and preview, and
`describeInStream()`; the protocols' detectors live in a file each,
following `icmp.cpp`: `describe_http.cpp` (HTTP, SSDP's messages, HTTP/2
and its frames in the stream), `describe_tls.cpp`, `describe_quic.cpp`
(with the short headers in the stream), `describe_dns.cpp` (DNS and mDNS,
over UDP and TCP), `describe_dhcp_ntp.cpp` (DHCP, DHCPv6, NTP),
`describe_socks.cpp` and `describe_nmea.cpp`. They share the internal
header `describe_common.h` (namespace `tcpdump::describer`): the payload
text helpers of `describe_text.cpp` (`escapeBytes()`, `fieldText()`,
`hexBytes()`, `joinNames()`, …), the `FieldReader`, and the declarations
of the detectors and in-stream passes the tables use.
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
  their ports before any other detector is tried; a payload that parses is
  recognised and its label sticks to the stream, one that does not is only
  the port's guess (`PayloadDescription::guessed`), which does not
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
  sticks to the stream. The detectors mark the packet that begins such a
  connection, a long header or the preface, with a `StreamCue`
  (`PayloadDescription::streamCue`, kept in `PacketRecord::streamCue`):
  that, not the label's text, is what `describeInStream()` goes by. For this the parser keeps the
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
column says which transport it belongs to. A tunnelled packet is keyed by
the addresses and ports of the packet inside (see *Tunnels*). ICMP, ICMPv6, ARP, IP fragments
after the first and every other packet without TCP/UDP ports show `-`. At
most `StreamTracker::kMaxStreams` (1,000,000) conversations, both transports
together, are numbered; packets of later ones show `?`.

`track()` returns a `Stream`: the number, a pointer to the stream's
`StreamState`, the same slot for every packet of the stream (null without
a number), and the packet's direction in it, 0 or 1 (the same for every
packet from the same address and port). Modules that follow a conversation
keep their fields in the slot and read and update them through that
pointer. Every field added costs memory once per numbered stream: today a
`TcpDirection` per direction, 32 bytes (a `static_assert` holds it there,
and its `flags` and `windowScale` have no bit left but four of the latter),
the Payload Describer's `QuicConnection` (whether a QUIC long header was
seen, and the connection ID length of each direction), 3 bytes, whether a
TCP stream began with the HTTP/2 preface, 1 byte, the stream's label,
1 byte, and what the TCP Reassembly knows of each direction, 1 byte, so 72
bytes per stream with the alignment (2 bytes are still free before it adds
8), some 72 MB at the stream cap. A module that needs more than a few bytes
for some streams only, as the TCP Reassembly does for its buffers, keeps
them in a bounded table of its own and a bit or two here. A UDP stream pays for the TCP fields too and a TCP stream for the QUIC
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
acknowledgement field means nothing and `Ack=` is left out (`[SYN] Seq=0
Win=64240`), by the parser and the TCP Analysis alike. The arithmetic
is modulo 2^32, so the numbers go on counting when the sequence numbers
wrap. A SYN without ACK whose sequence number differs from its direction's
base is a new connection on the same addresses and ports: both bases are
forgotten and counting starts afresh; a retransmitted SYN keeps them. The
parser writes the numbers as they are with `formatTcpNumbers()`, and the
TCP Analysis replaces that text; segments of a stream past the stream cap
have no state and keep the numbers as they are. `PacketRecord::tcpSeq` and
`tcpAck` stay the raw values.

The parser reads a header's options with `parseTcpOptions()`, walking them
as Wireshark does: a NOP is one byte, every other kind, an unknown one too,
the length it gives, and the end of options, or an option whose length is
below 2 or runs past the header, ends the walk; nothing past the captured
header is read. An option counts only with its RFC length (MSS 4, window
scale 3, timestamps 10), except SACK permitted, which Wireshark names
whatever its length. A SYN's Info gets the options after `Len=`, in the
order they come in and in Wireshark's words: `[SYN] Seq=0 Win=64240
MSS=1460 SACK_PERM TSval=12345 TSecr=0 WS=128` (`WS=` is the multiplier,
`1 << shift` with the shift capped at 14). Other segments show none of
them, except the timestamps when `ConversionOptions::tcpTimestamps` asks
for them, as Wireshark does on every segment: the parser keeps them in
`PacketRecord::tcpTimestamps`, and the Converter calls
`showTcpTimestamps()`, which puts ` TSval=… TSecr=…` after the TCP fields
(`tcpFieldsEnd()`, before the payload description), before the TCP
Analysis runs.

`Win=` is the calculated window, as in Wireshark: the window field shifted
by the sender's window scale (RFC 7323). The parser keeps the shift count of
a header's window scale option in `PacketRecord::tcpWindowShift`. A
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

#### TCP Reassembly (`tcp_reassembly.h/cpp`)
The describer sees one segment at a time, so a TLS record, an HTTP header
section or a DNS-over-TCP message that spans segments used to be named, cut,
by its first segment and as `Continuation` by the rest. `TcpReassembly`
(pure C++), owned by the Converter next to the Stream Tracker, puts such a
message together: `apply()` runs on every packet after
`describeInStream()` and before the Stream Labels, with the segment's
captured payload, which the reader hands out
(`CaptureReader::payloadOf()`, a view into its buffer valid until the next
packet; the parser records where the payload lies,
`PacketRecord::payloadOffset` and `payloadCaptured`, and keeps no copy
beyond the 48-byte `payloadHead`).

Which bytes make a message is the describer's to say:
`tcpMessageExtent()` (`payload_describer.h`) asks the framers of
`kTcpFramers`, in the order of their detectors, how many bytes the message
at the start of some bytes takes: a TLS record (5 + its length, at most
2^14 + 2048), a DNS message behind its 2-byte length (port 53), an HTTP/1.x
header section up to its empty line (the body is not held: a segment of
body begins no message and is described as it is). A framer answers more
than it was given while the message is incomplete (one more when its header
does not say how many) and nothing when no message of its protocol begins
there; once a stream's first message is framed, only its protocol is tried.

Per direction, a segment of whole messages, or of none a framer knows, keeps
its own description and costs nothing. A segment that ends in the first
part of one is described as `[TCP segment of a reassembled PDU]` (labelled
with the message's protocol, recognised, so the label sticks) and the bytes
from the message's start are held; whole messages before it in the segment
are described alone. The segment that completes it is described by
`describePayload()` from all held bytes, followed by `[reassembled from k
segments]`, and `apply()` returns those bytes (`ReassembledMessages`) for
a module that wants the whole messages. Bytes are taken in sequence order,
by a `ByteStreamOrderer` per held direction (`byte_stream_orderer.h`, pure
C++, shared with Follow stream content): `place()` says whether a segment
is next (and how many of its first bytes were taken), came early or was
taken already; it holds the early ones (`holdEarly()`), pops them once they
are next (`popNext()`) and skips a gap (`skipTo()`), and leaves the limits
to its user. Here, a segment ahead of the held bytes is held apart (at most
`kMaxEarlySegments`, 32) and also described as a segment of the message,
then appended once the bytes before it come; a segment whose bytes were
all taken (a retransmission) is left as it is, and the part of one that
overlaps them is dropped. A segment that begins a message is only taken
for one if no later bytes of its direction have been seen
(`TcpDirection::nextSeq`), so a retransmission after the message ended
starts nothing. A gap ends the message, its bytes dropped, and reassembly
starts again at the next segment that begins one: the other direction
acknowledges bytes past the held ones (the capture lost them), a segment
was cut at the snaplen, or more segments came early than are held.

The memory budget: a direction holds at most `kStreamLimit` (64 KiB),
counting its buffer's capacity and the segments that came early; all
directions together at most the global limit, `kDefaultMemoryLimit` (64
MiB) or the option *TCP reassembly memory at most*
(`ConversionOptions::reassemblyMegabytes`, 1 to 1,024 MiB), counting
`kEntryOverhead` (128 bytes) for each held direction and
`kEarlySegmentOverhead` (32) for each segment held apart. On top of that,
the messages the last segment completed are kept until the next one (at
most a direction's limit). A message longer than a direction's limit, or
one that outgrows it, is not held: its segment keeps its own description,
followed by `[reassembly limit]`. When the global limit would be passed,
the directions used longest ago are let go (`std::list` order, O(1)) and
their next segment carries the marker; the direction being added to is
never let go for itself. A direction is let go on its FIN, both on a SYN
(a handshake, perhaps a new connection on the same ports, whose
`StreamState` the TCP Analysis resets) or an RST; streams past the stream
cap have no state and are never held. In `StreamState::reassembly`, bit
`1 << d` says direction d holds bytes, so that the table is looked up only
then, and bit `4 << d` that it was let go. HTTP/2 streams are not
reassembled. Conversion of a file and of a capture still being written
go through the same loop, so both are reassembled alike.

To frame a new protocol's messages, write `frameName( payload, len )`
(returning `std::optional<size_t>` as above) in its `describe_name.cpp`,
declare it in `describe_common.h` and add `{ "Label", nameFrame }` to
`kTcpFramers`; its detector then sees whole messages on the completing
segment. Tests go in `tests/tcp_reassembly_test.cpp`, with the Converter's
steps run over a capture built with the frame builders.

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
| `[TCP Window Full]` | data, no SYN, FIN or RST, ending at `rev`'s last ACK plus its last window, scaled as `Win=` showed it, once `rev`'s scale is known: `rev`'s SYN was seen, or `fwd`'s without the window scale option |
| `[TCP Keep-Alive ACK]` | `len` 0, the same window (not 0), sequence number and ACK as before, after a keep-alive from `rev` |
| `[TCP ZeroWindowProbeAck]` | `len` 0, window still 0, the same sequence number and ACK (or one more) as before, after a probe from `rev` |
| `[TCP Dup ACK n#m]` | `len` 0, the same window (not 0), sequence number and ACK as before: the `m`th repeat of the ACK of packet `n` |
| `[TCP Spurious Retransmission]` | data (not a keep-alive) that `rev` has acknowledged already |
| `[TCP Fast Retransmission]` | data, a SYN or a FIN before `fwd.nextSeq`, at the sequence number `rev` last acknowledged, after at least two duplicate ACKs of it, within 20 ms of `rev`'s last segment |
| `[TCP Out-Of-Order]` | otherwise before `fwd.nextSeq`, within 3 ms of `rev`'s last segment, and not ending where `fwd.nextSeq` is (or ending there after a segment without data had raised it) |
| `[TCP Retransmission]` | otherwise before `fwd.nextSeq` |

Segments with a bogus TCP header length are not analysed, as in Wireshark.

The analysis also follows the handshake, with two bits of each direction's
`flags`: `kSynSeen` (a SYN of the direction was seen, so its window scale
is known, also when it has none) and `kSynPending` (its last segment was a
SYN without ACK, whose time `lastTime` still holds). The first segment
with ACK and without SYN of a direction whose SYN is pending, once the
other direction sent its SYN-ACK, completes the handshake: it gets the
initial round-trip time, from the SYN (the last one, if it was sent again,
as Wireshark's `ts_mru_syn`) to it, after its TCP fields, `[iRTT=0.012345]`
in seconds with 6 decimals, or 9 at nanosecond precision, and
`analyseTcp()` returns it with the markers (`TcpAnalysis`). Wireshark shows
`tcp.analysis.initial_rtt` in the packet's details only, and on the first
pure ACK in either direction even without a SYN-ACK; here it is in Info,
and a stream whose handshake was not captured whole has none. Each stream
shows it once: a SYN sent after the handshake does not arm it again, a new
connection on the same ports does. The Converter collects the times in
`CaptureStats::initialRtts`, a `RunningMedian`, for the summary's median:
it keeps the first 4,096 times as they are and gives their exact median,
then counts them in a histogram of fixed size (64 buckets per power of
two, an HDR histogram), whose median is the middle of its bucket and lies
within 1/128 (0.8 %) of the exact one. It holds 32 KB at most, however
long a capture or live capture runs.
The limits, all where Wireshark keeps more than a few integers per
direction:

- No list of the segments sent is kept, so a segment within 3 ms of the
  other direction's last one that was captured before is still called
  out of order, where Wireshark knows it was seen and calls it a
  retransmission; and `[TCP ACKed unseen segment]` is not shown.
- The 3 ms out-of-order limit is Wireshark's for a connection whose
  round-trip time it does not know; Wireshark takes the handshake's iRTT
  when it saw the handshake, this analysis never does: the iRTT is shown,
  but not kept per stream.
- SACK blocks are not read, so there is no SACK-based fast
  retransmission, and Info shows no `SLE=`/`SRE=`.
- `[TCP Port numbers reused]`, `[TCP Retransmission]`'s RTO and the other
  fields Wireshark shows in its tree only are left out.
- As in Wireshark, sequence numbers compare modulo 2^32, and a segment
  captured before the other direction's last one (a capture that needs
  reordering) counts as 0 ms after it.

`CaptureStats` collects the sidebar summary's counts packet by packet
(among them the packets cut at the snaplen, the TCP segments per
analysis marker kind and the handshakes' initial round-trip times, whose
median `medianInitialRttNs()` gives),
and the link-layer types of the packets in the order they were first seen. It
counts packets for at most `CaptureStats::kMaxEndpoints` (100,000) IP
addresses, endpoints and tunnel endpoints together, and those of further
addresses as "other endpoints".

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

#### Highlighter set and filter group (`presets/`)
`tcpdump_highlighter.conf` and `tcpdump_filter.conf` are a LogSquirl
Highlighter Set and Filter Group as its *Export* writes them and its
*Import* reads them: QSettings INI files holding one
`HighlighterSetCollection` or `PredefinedFiltersCollection` with one set
(`groupexchange.cpp`, `highlighterset.cpp`, `predefinedfilters.cpp` in the
host). The plugin API has no call to install either, so the user imports
them (README, *Highlighters and filters*). Each set has a fixed id, so that
importing a newer file offers *Replace*; keep it.

Every pattern starts with `^` and reads the columns up to Protocol, as
`regex_lab.cpp`'s patterns do, so that only a column or the start of Info
decides: a word in a payload's text never does. They read every
`LineLayout`: either time column is optional, as in `upToSourcePattern()`,
and a pattern that reads the start of Info (TCP flags and markers, ICMP
errors) takes the two MAC columns as optional before it, then the names of
the tunnels a packet came through, each with its ` | ` (`VXLAN VNI 100 | `,
`GRE key=0x0000002A | `, `IPv6-in-IPv4 | `, *Tunnels* above), so that it
reads the inner packet's Info; one that reads the payload's description
takes those too, then Info up to its next ` | `. **A new tunnel name** goes
into those patterns and into `readLine()` in the test. Patterns use no
capture groups (a highlighter with groups colours only what they take) and
nothing Vectorscan, LogSquirl's default search engine, cannot compile (no
lookaround, backreference or possessive quantifier), so that a filter is
not left to the slower Qt engine. Highlighters have no names in the file;
the topmost that matches colours the line.

**Update the patterns when a column or an Info text they read changes**: a
column added, moved or removed, a TCP flag or analysis marker renamed, a
protocol label or a DNS, HTTP or ICMP description reworded.
`tests/presets_test.cpp` reads both files as the host does, applies every
pattern to every line of every corpus text (`tests/corpus/*.txt` and the
local `tests/corpus/local/*.txt`) and checks that it matches exactly the
lines its rule picks from the columns, and in the committed texts the
packet numbers listed in the test, also with the committed captures
converted in every `LineLayout`; a new corpus text needs its list there.
A new Wireshark analysis marker that is a problem goes into the *TCP
problems* highlighter and the *TCP errors* filter (the test fails until it
does); Window Update, Keep-Alive and Keep-Alive ACK stay out, as in
Wireshark's "Bad TCP" rule. The files are edited by hand: a backslash in a
pattern is written twice, and a pattern with a comma is quoted. The
release archive carries both next to the library (`package_files` in
`.github/plugin-ci.json`; the archive is flat, so no two packed files may
share a base name), and `cmake --install` puts them there too.

### 4. Converter (`pcap_converter.h/cpp`)
`convertPcap()` reads a capture through the `CaptureReader` that
`makeCaptureReader()` picks for it, has the Stream Tracker give each packet
its stream and the TCP Analysis show its numbers relative and mark it,
lets the Payload Describer look at it again in its stream, the TCP
Reassembly describe a message that spans segments where it completes, and
the Stream Labels name it by its stream's protocol, counts its markers
and its protocol, formats the packet and appends its line to a new output file,
reporting progress and checking a
cancel flag between packets, and notes each packet's place in a
`CaptureIndex` (see *Packet Panel*). `convertStream()` does the same for a
capture read from a stream (*The Capture Source seam*), without progress
but live (see *Live conversion* below): both run one loop
(`convertOrThrow()`), so every packet of a file and of a stream goes
through the same steps. The file, `<name>.log`, is created with
`NewOnly` and owner-only permissions in a new
`logsquirl-tcpdump-<pid>-XXXXXX` directory (`tempdirs.h/cpp`) below the
output root that only the user can enter. The result is one of three
outcomes and a `CaptureSummary`, whose link-layer types are those of the
packets followed by any the capture declares without a packet of it (so a
pcap with no packets still names its one): Converted (with the output path), Failed
(with a message) or Cancelled, and for a stream Stopped: stopped before its
capture header came (`StreamSource::stopped()`), so nothing was captured and
nothing is left, which is not a failure. Failed is the only error mode: an unreadable
input, an output that cannot be created or written, a memory allocation
failure or any other exception ends as Failed, and nothing is left behind.
`applyCancelRequest()` decides, for the Converter and its caller alike,
that a cancel request wins even over a conversion that had just finished:
the result becomes Cancelled and the output is removed.

#### Live conversion
`convertStream()` converts live: a `LiveInput` between the stream and the
reader writes every byte read, unchanged, to the raw capture next to the
text (`<name>.pcap`, or `<name>.pcapng` when the reader is a
`PcapngReader`; `ConversionResult::rawPath`); the bytes read before the
output directory exists, the header the format is told by, are kept until
it does. Before every read that would wait (`ByteSource::ready()` is
false), it flushes the text and the raw file, so a line is readable as soon
as the stream pauses; a stream that never pauses is flushed at least every
`kLiveFlushInterval` (100 ms). A `LiveObserver` is told on the converting
thread: `firstPacket( logPath, rawPath )` once, after the header and the
first packet line are flushed (LogSquirl recognises a Log Format once, at
the first load with lines, LogSquirl#794, so the tab must not open on the
header alone), and `snapshot( LiveSnapshot )` with the first packet and
then at most every `kLiveSnapshotInterval` (1 s): the summary so far
(`summariseSoFar()`, from a copy of the statistics), the time since the
start, the bytes read and a copy of the `CaptureIndex` so far, pointing
into the raw file (flushed first) as `CaptureIndex::Growth::Growing`. The
final result's index points into the closed raw file. So that a burst's last packets are not left out
until the next packet, the wait before a read sleeps until the snapshot's
turn while the stream stays idle (a stop turns `ready()` on). The stream
stopping (Stop) ends Converted with the final summary, which equals that of
converting the raw file (tested); Cancel removes both files. A stream that
breaks off with an error after its first packet ends Failed with the
message *and* `outputPath`, `rawPath` and the summary of what was captured;
before a packet, it leaves nothing behind, as before.

`LiveCapture` (`live_capture.h/cpp`) runs this on a worker thread of its
own and posts what it is told to its own (the UI) thread as signals:
`readyToOpen( logPath, rawPath )`, `snapshotTaken`, `stderrLine` and
`finished( ConversionResult )`. The source is made on the worker by a
`SourceFactory( stop, onStderrLine )` (`LiveCapture::processSource(
ProcessCommand )` for a capture program), as a `ProcessSource` must be.
`stop()` sets the source's stop flag, `cancel()` also the cancel flag. The
outcome is posted before the source is destroyed, so a program that takes
up to `kTerminateGrace` to end does not delay it; the destructor stops and
waits for the worker.

`ConversionOptions` are everything the user can choose: the `LineLayout`,
the payload preview (`preview`, `previewChars`), the stream and endpoint
caps and the TCP Reassembly's memory (`reassemblyMegabytes`). The defaults write the text of `tests/corpus`; any other choice is
the payload preview (`preview`, `previewChars`) and the stream and endpoint
caps; besides, `checkpointInterval`, which tests lower. The defaults write the text of `tests/corpus`; any other choice is
caps, the TCP Reassembly's memory (`reassemblyMegabytes`) and whether
every TCP segment shows its timestamps (`tcpTimestamps`). The defaults write the text of `tests/corpus`; any other choice is
tested by deriving its text from that one, not by more committed text.

While it converts, the Converter notes every packet in a `CaptureIndex`
(`capture_index.h/cpp`), which keeps a `ReaderCheckpoint` every
`kCheckpointInterval` (10,000) packets, the packet count, and the capture
file's canonical path, size and modification time; a Converted result
carries it as `index`. The capture file is opened by `openRegularFile()` and
read through a `FileSource` (`capture_file.h/cpp`), which the
`CaptureCursor` shares.

### Settings and configuration dialog (`settings.h/cpp`, `configdialog.h/cpp`)
`loadConversionOptions()` and `saveConversionOptions()` keep the
`ConversionOptions` in `settings.ini` (`QSettings`, INI format, group
`conversion`) in the configuration directory the host names
(`get_config_dir`, part of the API since 26.10). A value that is missing or
not one reads as its default, a number out of range as the nearest allowed:
the preview 1 to `kMaxPreviewChars`, the caps `kMinCap` to ten times their
default, the reassembly memory 1 to `kMaxReassemblyMegabytes` (1,024 MiB). `ConfigDialog` shows and edits the options and says that an open
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
- A "Follow stream" button, created only when `g_state.hostCapabilities`
  has the Regex Lab and the selected lines (see *Follow stream* below)
- Detailed capture summary: protocol breakdown (count + percentage + bytes),
  top endpoints (on a host with `regexLab`, each protocol and endpoint is a
  link that opens it as a filter; see *Summary filters* below), the first and last packet time in UTC, packets per
  second, file size, the link-layer type names
  (comma-separated when there are several), the number of packets cut
  at the snaplen when there are any, and under *Analysis* the median
  initial round-trip time of the handshakes and how many there were, and
  the TCP segments per analysis marker kind, when there are any
- On the first converted capture after the plugin is loaded, a link to
  README's *Log Format* section. The plugin cannot know whether LogSquirl
  has the format, so the hint is static and shown once per load
- The Packet Panel (see *Packet Panel* below), which takes the room left
- The summary of the capture in the tab in front. Every converted capture's
  summary, and its `CaptureIndex`, is kept for the session, under the path of the text file written
  for it (canonical, so that the host's spelling of the path finds it); the
  plugin's active-file callback calls `showSummaryFor()` on every tab
  switch, which shows the kept summary or "No capture in this tab." for a
  file the plugin did not write or a tab without a Log File. While a capture
  is being read the label keeps saying so. The summaries are lost when the
  plugin is unloaded, so after a runtime disable or update the tabs left
  open show no capture

A live capture, `startLiveCapture( name, SourceFactory )`, runs in a
`LiveCapture`. On `readyToOpen` the sidebar keeps the capture's entry under
its text file and calls `open_file( path, follow = 1 )` on the UI thread
(LogSquirl#796); snapshots replace the entry's summary through
`updateSummary( textPath, summary )`, which redraws it if its tab is in
front, and update a label with packets, bytes, packets/s (as of the
snapshot) and the elapsed time (ticked by a 1 s timer) in place of the
progress bar; the snapshot's index replaces the entry's, so the Packet
Panel shows the packets captured so far. **Stop** calls `stopLiveCapture()`. At the end the final
summary and index replace the last snapshot's; a capture without packets has its files
removed and a notification; a failed one keeps its entry with the error
shown above the summary. **Save capture…**, shown for a tab whose capture
has a raw file, copies it where `setSaveChooser()`'s dialog says. stderr
lines go to the host's log. Opening a file and a live capture exclude each
other; the `LiveCapture` is kept until the next one starts, since its
worker may still be ending the capture program.

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

### 6. Packet Panel (`packet_panel.h/cpp`, `packet_layers.h/cpp`, `capture_index.h/cpp`)
The sidebar's companion to the packet list: the layer tree and hex dump of
the packet of the selected line, as Wireshark's lower panes. Three parts,
each usable on its own by later features (follow-stream content, packet
export, conversation statistics):

- **The line → record index.** `CaptureIndex` (see *Converter*) is kept
  with the capture's summary in the sidebar, as a
  `shared_ptr<const CaptureIndex>`, under the text file's path. A
  `CaptureCursor` over it reads packet N (`read(number, CapturedPacket&)`):
  from the nearest checkpoint before N (`nearest()`), or on from where the
  cursor is when N lies ahead and no checkpoint lies between, so a sorted
  set of packets is read in one pass from front to back. At most
  `kCheckpointInterval - 1` packets are read to reach one; no packet and no
  per-packet offset is kept in memory. A `CapturedPacket` holds the
  `PacketRecord` as the reader dissected it (without what its stream adds:
  stream number, stream labels, TCP analysis), its captured bytes, the byte
  order, and its record's offset and length in the file. Before every read
  the file's size and modification time are compared with those at the
  conversion (`fileProblem()`): a changed or removed file is reported with
  a message for the user, never misread. A live capture's raw file, still
  being written, is set `Growing`: it may grow behind the packets noted, and
  only a shorter file is a changed one; each snapshot brings an index with
  the packets so far, and a packet line newer than the index the panel has
  is reported as not there yet ("The capture has no packet N") until the
  next snapshot.
- **The layer description.** The dissectors describe the layers they read
  when the `PacketRecord`'s `layers` points at a `PacketLayers`: each
  header as a `PacketLayer` (name, offset, length) with its `LayerField`s
  (name, value as shown, offset, length), outermost first. They pass
  pointers into the packet, which `PacketLayers` turns into offsets cut to
  the captured bytes. The payload is a layer named by the Payload
  Describer's label ("Data" without one) with its description as a field;
  what only its stream tells is not known for a packet read alone.
  `dissectLayers()` dissects one record that way behind a Frame layer
  (number, time, lengths, link type). The Converter leaves `layers` null,
  so its output and speed are unchanged; a new dissector should describe
  its header with `layer()` and `field()` behind `if ( auto* layers =
  pkt.layers )`, using `hexField()`, `etherTypeField()` and
  `ipProtocolField()` for values.
- **The widget.** `PacketPanel` gets the tab in front's index from
  `SidebarWidget::showSummaryFor()` (null for a foreign tab) and reads the
  selection through `get_selected_log_lines`. LogSquirl has no
  selection-changed callback, so it asks every `kPollIntervalMs` (250 ms)
  while it is visible: the timer starts in `showEvent()` and stops in
  `hideEvent()`, and a selection whose text and result did not change
  leaves the panel as it is. `refresh()` asks at once; Plugins → tcpdump →
  Packet details calls it through `SidebarWidget::showPacketDetails()`,
  which notifies the packet's layers when the panel is out of view. The
  first selected line is read with `packetLineRegex()`; a line that is not a
  packet line, no selection, a foreign tab or a cursor error show the
  reason in the status line. The tree items keep their layer's or field's
  offset and length; selecting one highlights them in the dump through
  `hexDumpRanges()`, which finds a byte range in `hexDump()`'s text, in hex
  and ASCII on each line. The packet is read on the UI thread: at most
  `kCheckpointInterval` records from a local file.

- **Follow stream content** (`stream_content.h/cpp`,
  `stream_content_view.h/cpp`). The panel's Stream tab, a
  `StreamContentView`, shows the payload of the shown packet's stream when
  the user asks for it: the panel's *Follow stream content* button calls
  `PacketPanel::followStreamContent()`, as Plugins → tcpdump → Follow
  stream content does through `SidebarWidget::followStreamContent()`
  (which notifies where it is shown when the panel is out of view). The
  panel keeps the Stream column of the line it shows (`shownStream_`).
  `StreamContentReader` reads the stream back: `open()` reads the packet
  for its transport, addresses and ports, then `read()` reads the packets
  from the stream's first to its last, which the Converter notes in the
  index (`CaptureIndex::noteStream()`, `streamExtent()`: 8 bytes per
  numbered stream; an unnumbered one is looked for in the whole capture),
  and keeps those of the stream by their addresses and ports. The client,
  end 0, is the side of the stream's first packet (the SYN's side when that
  is a SYN-ACK). A UDP datagram is a `StreamChunk` as it comes (the part cut
  at the snaplen as missing). TCP bytes go through a `ByteStreamOrderer`
  per direction: a SYN starts it, the first data segment when the
  handshake was not captured; early segments are held, at most
  `kMaxEarlySegments` (64) and `kMaxEarlyBytes` (1 MB) a direction, beyond
  which the bytes before them are taken as missing; an ACK of the other
  direction past its bytes (but not past its FIN, which takes a sequence
  number and no byte) takes the bytes it lacks as missing, and so does the
  stream's end for what is still held. A chunk is either bytes or a gap
  (`missing`). `read()` stops at the end of a packet once a budget of bytes
  was handed out (`Status::More`), checks the cancel flag between packets
  and reports progress; it goes on where it stopped. `StreamRenderer`
  turns chunks into text: `streamText()` keeps printable ASCII, tab, line
  breaks (CR LF as one) and valid UTF-8 beyond the C1 controls, and escapes
  every other byte as `\xNN`; each direction's run, each datagram and
  each gap begin a line; the hex dump is Wireshark's, 16 bytes a line,
  the offset counted per direction (gaps included), the server's lines
  indented by 4. `exportStreamContent()` reads the whole stream with a
  fresh reader, a budget at a time, writing raw bytes of the directions
  chosen (gaps left out) or the rendered text; a failed or cancelled export
  removes its file. The view runs reads and exports on a `QThreadPool` of
  its own, one at a time, with a `QFutureWatcher` per task and a
  generation count, so a result of a stream followed before is dropped;
  its destructor cancels and waits. It holds the chunks read, at most
  `kMaxShownBytes` (16 MB), for re-rendering when the format or direction
  changes, and reads `kShowBytes` (1 MB) at first and per Show more.
  `stream_content_test.cpp` checks the reader, renderer and export on
  built captures; `packet_panel_test.cpp` follows streams of
  `reassembly.pcap` and `mixed.pcap` through the `FakeHost` and compares
  the export with the payloads its script wrote.

Without `selectedLogLines` (a host older than 26.11) there is no Packet
details or Follow stream content entry and no polling; the panel says what
it needs.
`capture_index_test.cpp` reads every packet of every corpus capture (pcap
and pcapng) in shuffled order with a checkpoint every 4 packets and checks
it against its line and an in-memory parse, and that its layers stay
within its bytes; `packet_layers_test.cpp` checks layer and field names,
values and offsets on built packets; `packet_panel_test.cpp` drives the
panel through the `FakeHost` (scripted selection, active file, call count
of `get_selected_log_lines`).

### Plugin Entry (`plugin.h/cpp`)
C ABI entry points (`logsquirl_plugin_*`) that register the sidebar tab,
the menu entries (Open pcap…, and Packet details, Follow stream content and
Follow stream where the host can serve them) and the active-file callback with the host application. No exception may leave them: their work runs
through `guarded()`. Strings go to the host as UTF-8 through `hostLog()`
and `hostNotify()`. The host calls `shutdown()` both when LogSquirl quits
and when the plugin is disabled or updated at runtime, with the tabs kept
open; the plugin notes `QCoreApplication::aboutToQuit` and removes the
temporary files only in the first case. In both, it ends every capture program
still running (`terminateCaptureProcesses()`, *The Process Source*). `logsquirl_plugin_configure()`,
which LogSquirl calls for **Configure…** in Plugin Management with its main
window as the parent, runs the `ConfigDialog` modally and saves the options
when it is accepted; `hostConfigDir()` is the directory, empty without a
host, where saving fails with a notification.

#### Host capabilities
The host API grows by appending functions to `LogSquirlHostApi` (the SDK
guide's *A Growing API*). LogSquirl 26.11 and later call
`logsquirl_plugin_init_ex()` with the size of their table; an older host
calls `logsquirl_plugin_init()`, which forwards with
`LOGSQUIRL_HOST_API_BASE_SIZE`. `init_ex()` records what the size covers in
`g_state.hostCapabilities` (`HostCapabilities::of()`, through
`LOGSQUIRL_HOST_API_HAS`): `regexLab`, `goToLogLine` and `selectedLogLines`.
Code that uses one of those functions checks the record first, and offers
nothing that needs it otherwise; it never calls or reads a member the record
does not report, not even to compare it with null, as an older host's table
ends before it. Keep the pointer the host passed: never copy `*api`.

#### Follow stream (`follow_stream.h/cpp`)
`Plugins → tcpdump → Follow stream` and the sidebar button call
`followSelectedStream()`, offered only on a host with `regexLab` and
`selectedLogLines`. It reads the first selected Log Line through
`get_selected_log_lines`, and `followStreamPattern()` turns it into a
pattern for `open_regex_lab` (with Match case); the Lab's answer, the
applied pattern or a cancel, is logged. The line is read with the Log
Format's regex, which `packetLineRegex()` in `regex_lab.cpp` repeats;
`logformat_test.cpp` fails when the two differ.
The pattern requires the line's stream number, its two addresses and the
two ports at the start of a TCP or UDP Info (markers in brackets may come
first), each pair in either order. The Stream column alone is not enough:
TCP and UDP streams are numbered each from 0, and the Protocol column
changes within a stream. The columns up to Source are those of
`upToSourcePattern()`, which takes either time column as optional, and the
ports are looked for anywhere in Info, after the MAC columns a `LineLayout`
may put at its start and the tunnels a tunnelled packet names first (its
ports are the inner packet's, as its stream is); the rest of Info is not read, so a change there does
not break the pattern. A
line that is no packet line, one with stream `-` or `?`, no selection or a
tab without a Log File give a notification with the reason instead.
`follow_stream_test.cpp` checks the pattern against every corpus line,
checks that it finds the same packets in the corpus converted in every
`LineLayout`, and drives the menu entry and the button through the
`FakeHost`.

#### Summary filters (`regex_lab.h/cpp`)
`summaryHtml()` with `filterLinks`, which `showSummaryFor()` passes as
`g_state.hostCapabilities.regexLab`, makes each protocol and endpoint of the
summary a `tcpdump-filter:protocol/<name>` or `tcpdump-filter:endpoint/<name>`
link, the name percent-encoded. The label opens no link itself: its
`linkActivated` goes to `SidebarWidget::openLink()`, which opens a filter
link's pattern with `openRegexLab()` and any other link, such as the README
link, with `QDesktopServices`. `endpointPattern()` and `protocolPattern()`
require the columns before Info as `packetLineRegex()` reads them, through
`upToSourcePattern()` and the Length after Protocol, so they match a whole
Source, Destination or Protocol column and never Info in every
`LineLayout`, and escape the name with `literalPattern()`. Only the
endpoints are links, not the tunnel endpoints: those appear in no column
(see *Tunnels*). `openRegexLab()`, which Follow
stream uses too, opens the Lab with Match case and logs the pattern, then
the applied one or the cancel, under the feature's name ("Filter: …").
`regex_lab_test.cpp` checks every endpoint and protocol of the summary of
each corpus capture, converted in every `LineLayout`, against the columns of
its lines;
`sidebarwidget_test.cpp` clicks the links against the `FakeHost`.

#### The plugin API header
`include/logsquirl_plugin_api.h` is the host's
`src/plugins/include/logsquirl_plugin_api.h`, byte for byte, from the
LogSquirl release named by `host_ref` in `.github/plugin-ci.json`; CI fails
if they differ, and its Format job leaves the file alone. To move to a newer
host, set `host_ref` to that release and refresh the header with
LogSquirl-Plugin-CI's `scripts/sync-plugin.sh <this checkout>` (or copy the
file from the LogSquirl release tag); never edit it by hand. A function the
new header adds goes into `HostCapabilities` before anything calls it.
`host_ref` may name a LogSquirl beta (`v26.11.0-beta1`) while the next host
release is in beta; CI builds against it, but CI Release refuses to publish
a plugin built against a beta, so switch to the final release before
tagging.

## Adding Protocol Support

An application protocol is a detector in a file of its own plus one table
entry in `payload_describer.cpp`:
1. Write `detectName( payload, len )` in `src/describe_name.cpp` (added to
   both CMakeLists), declared in `describe_common.h`: the description if
   the payload is yours, empty otherwise. Use `escapeBytes()`,
   `fieldText()` or `firstLine()` for any text taken from the payload, and
   a `FieldReader` for binary fields. In `payload_describer.cpp`, wrap it
   in a function of the tables' common shape,
   `std::optional<PayloadDescription> name( const Payload& )`, that looks
   at the ports if it must and returns the label and the description, or
   `std::nullopt`.
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
contrast, is parsed in `pcap_parser.cpp`, a link layer beyond Ethernet in
`link_layers.cpp`, and tested with the frame builders in
`tests/pcapbuilder.h`.

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
by `tests/make_dhcp_ntp_corpus.py`; `tunnels.pcap`, packets in VXLAN, GRE
and IP-in-IP tunnels, nested and nested too deep, by
`tests/make_tunnels_corpus.py`; `wifi.pcap`, a station joining an access
point behind Radiotap headers, and `ppp.pcapng`, a PPPoE session from
discovery to teardown, PPP in HDLC-like framing and Cisco HDLC on three
interfaces, by `tests/make_link_layers_corpus.py`; `reassembly.pcap`, a
ClientHello over 3 segments, HTTP split in its headers, a DNS-over-TCP answer
over 2 segments, segments out of order, retransmitted, overlapping and
lost, by `tests/make_reassembly_corpus.py`. The link layers' tests,
`tests/link_layers_test.cpp`, build their 802.11, Radiotap, PPP and PPPoE
frames themselves and end in a fuzz-style run over mutated frames of each. The pcapng unit tests build their
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
