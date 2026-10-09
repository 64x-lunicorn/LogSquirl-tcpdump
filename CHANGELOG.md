# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **TCP details as Wireshark shows them.** A SYN and a SYN-ACK show their
  options after the window, in the order they were sent: `[SYN] Seq=0
  Win=64240 MSS=1460 SACK_PERM TSval=1000 TSecr=0 WS=128`; unknown options
  are skipped by their length, and a malformed length ends the walk
  without reading past the header. The new option *Show TCP timestamps
  (TSval, TSecr) on every segment* (off by default) shows the timestamps
  on the other segments too. The ACK that completes a handshake shows its
  initial round-trip time, from the SYN, `[iRTT=0.012345]`, and the
  summary the median of all handshakes captured whole. A segment that
  fills the window the receiver advertised last, scaled as negotiated, is
  marked `[TCP Window Full]`, counted in the summary and coloured and
  filtered with the other TCP problems. `tests/corpus/tcp-analysis.pcap`
  has a second connection that shows them.
- **TCP reassembly.** A TLS record, an HTTP/1.x header section or a
  DNS-over-TCP message that spans TCP segments is described once, on the
  segment that completes it, from all its bytes: `Client Hello,
  SNI=example.com, TLS 1.3 [reassembled from 3 segments]`, `GET
  example.com/index.html HTTP/1.1 [reassembled from 2 segments]`, the
  whole DNS answer with all its records. The segments before it say `[TCP
  segment of a reassembled PDU]`, labelled with the message's protocol.
  Segments are taken in sequence order: one captured early waits for those
  before it, retransmitted and overlapping bytes are taken once, and a gap
  (bytes the other side acknowledges but the capture lacks, a segment cut
  at the snaplen) gives the message up and starts again at the next one.
  Memory is bounded: at most 64 KB a stream direction and 64 MB all
  together (the new option *TCP reassembly memory at most*, 1 to 1,024 MB);
  a message that does not fit keeps its per-segment description, followed
  by `[reassembly limit]`, and when memory runs out, the streams that waited
  longest are let go. A direction is let go on its FIN, a stream on a SYN or
  an RST; a segment of whole messages costs nothing. A new synthetic
  capture, `tests/corpus/reassembly.pcap` (written by
  `tests/make_reassembly_corpus.py`), shows each case.
- **Packet Panel.** Below the sidebar summary, the packet of the selected
  line is shown as Wireshark's lower panes show it: a layer tree with
  named fields (Frame, Ethernet, VLAN tags, the cooked captures, 802.11
  and Radiotap, PPP, PPPoE, Cisco HDLC, IPv4, IPv6 and its extension
  headers, ARP, TCP, UDP, ICMP, GRE, VXLAN and the application protocol
  the payload was recognised as) and a hex/ASCII dump in which the bytes
  of the selected layer or field are highlighted. It follows the
  selection while the sidebar tab is in view, asking LogSquirl at most
  every 250 ms and not while hidden; **Plugins → tcpdump → Packet
  details** reads it at once. A packet is found by its line's No. and read
  again from the capture file from the nearest of the checkpoints the
  Converter now keeps every 10,000 packets, in pcap and pcapng alike, so
  no packet is held in memory. A capture file changed since it was
  opened is reported, not misread. Needs LogSquirl ≥ 26.11.
- **Tunnels unwrapped.** A packet carried in VXLAN (UDP 4789), GRE (with or
  without checksum, key and sequence number, carrying IPv4, IPv6 or an
  Ethernet frame) or IP-in-IP (IPv4 or IPv6 in IPv4 or IPv6) is shown by
  the packet inside, as Wireshark shows it: Source, Destination, Protocol
  and Info are the inner packet's, and Info names the tunnels first,
  outermost first: `VXLAN VNI 100 | 50000 → 8080 [SYN] Seq=0 Win=64240`,
  `GRE key=0x0000002A | 53053 → 53 Len=32 | Standard query …`,
  `IPv6-in-IPv4 | …`. Streams are keyed by the inner addresses and ports,
  whichever tunnel carries them; the Capture Summary lists the tunnel
  endpoints apart, under *Tunnel endpoints* and without a filter link, as
  no column shows their addresses. The highlighters and filters in
  `presets/` read a tunnelled packet's Info past the tunnels (a SYN in
  VXLAN is a *TCP SYN/FIN*), and Follow stream follows the inner
  conversation. At most 4 tunnels are unwrapped, a
  deeper one is described as such (`IPv4-in-IPv4 not dissected: more than
  4 nested tunnels`). Before, such packets were shown as UDP to port 4789
  (`VXLAN`), `GRE`, `IPIP` or `6in4` between the tunnel endpoints. GRE
  carrying other protocols, PPTP's enhanced GRE among them, is still shown
  as GRE, now with its protocol type.
- **Wi-Fi, PPP and PPPoE link layers.** Captures from a Wi-Fi monitor
  interface (802.11, with or without a Radiotap header) and from PPP links
  (PPP with or without HDLC-like framing, Cisco HDLC, PPPoE) are dissected
  to their IP packets, in pcap and per interface in pcapng. 802.11
  management and control frames are named as Wireshark names them, with
  their sequence number and, where the frame carries one, the SSID: `Beacon
  frame, SN=1000, FN=0, BI=100, SSID="HomeNet"`, `Probe Request, SN=1,
  FN=0, SSID=Wildcard (Broadcast)`, `Authentication`, `Association
  Request`, `Deauthentication`, `Request-to-send`, `Acknowledgement`; their
  Source and Destination are MAC addresses. Data frames reach IPv4, IPv6
  and ARP through LLC/SNAP; protected (encrypted) ones show as `QoS Data,
  SN=6, FN=0, Protected`. The Radiotap header's length is honoured, its
  extended present bitmaps walked, and a frame check sequence it announces
  cut off. PPP control protocols are named with their message: `LCP
  Configuration Request`, `IPCP Configuration Ack`, `PAP
  Authenticate-Request` (no credentials shown), `CHAP Challenge`; PPPoE
  discovery with its stage, `Active Discovery Offer (PADO)
  AC-Name='isp'`. Before, these captures showed `Unsupported link-layer
  type` on every line, and PPPoE frames only their EtherType.
- **Capture Source seam.** The Capture Reader reads a capture that is
  still being written, from a pipe, a FIFO, a socket or a process's stdout
  (`FdSource`, `DeviceSource`), as well as from a file: the format is
  decided as soon as the header has come (a pcap's 24-byte global header,
  a pcapng's section header and first interface), a wait for data ends
  within 100 ms of Stop or Cancel, and the stream closing ends the capture,
  a record cut off there reported as such. The live sources to come plug
  into it; converting a file is unchanged.
- **Process Source.** A capture program (tcpdump, dumpcap, adb, ssh, an
  extcap, a custom command) is run with its stdout as the capture stream
  and its stderr kept apart, handed on line by line and the last lines
  kept, so that "permission denied" or "no such device" can be shown. It
  is started from an argument list, never through a shell, unless a custom
  command opts into one. A program that cannot be started, exits with a
  code other than 0 or crashes ends the capture with a message naming it,
  the code and its last stderr lines. Ending it ends its whole process
  group: SIGTERM, then SIGKILL after 2 s; on Windows it runs in a job
  object that is terminated. Shutting the plugin down, as LogSquirl quits
  or the plugin is disabled, ends every capture program still running.
- **Live conversion.** A capture read from a stream is converted while it
  runs: its packet lines are flushed before every wait for more and at
  least every 100 ms, and its tab opens, following the file, as soon as
  the header and the first packet line are in it (so LogSquirl recognises
  the Log Format and shows the table view); a capture that ends without
  packets opens no tab and says so. The sidebar shows packets, bytes,
  packets/s and the elapsed time instead of a percentage, and the Capture
  Summary of the capture's tab follows snapshots, at most one a second.
  **Stop** ends the capture within a second and finalises it: the last
  lines flushed, the summary final, the same as converting the saved
  capture gives. The bytes read are kept unchanged next to the text, as
  `<name>.pcap` or `<name>.pcapng`, and **Save capture…** in the sidebar
  copies them out of the temporary directory, to convert again or open in
  Wireshark. A source that fails (a capture program that exits with an
  error) ends with its message and keeps what was captured. A live
  capture's lines go through the same TCP reassembly and analysis as a
  file's, and the Packet Panel shows its packets, read from the raw
  capture, while it runs (up to the latest snapshot) and after.

### Changed
- A segment that ends inside a TLS record, an HTTP header section or a
  DNS-over-TCP message no longer names the message as far as it goes
  (`Client Hello` without its server name, `Standard query response … (2
  answers)`), and the segment that ends it no longer says `Continuation`:
  the first says `[TCP segment of a reassembled PDU]`, the last describes
  the whole message (see *TCP reassembly*). A message the capture never
  completes is described by none of its segments.

### Fixed
- An Ethernet frame carried in VXLAN or GRE is dissected as one on the
  wire: a PPPoE session frame inside is unwrapped to its IP packet, a
  discovery message named, where before they showed as `PPPoES` /
  `PPPoED` with `EtherType 0x8864` / `0x8863` (#67).
- A live capture stopped before its capture header came (Stop pressed
  early, or LogSquirl quitting while the capture program was still
  starting) no longer fails with "not a capture": the sidebar says it was
  stopped before anything was captured (`ConversionResult::Status::Stopped`).
  The Process Source tests wait for the fake capture programs to signal
  that they are ready instead of timing them, so they no longer fail on a
  loaded machine (#94).

## [0.3.0] — 2026-10-09

### Added
- **Highlighter set and filter group.** `presets/tcpdump_highlighter.conf`
  colours the packet list in the spirit of Wireshark's default colouring
  rules: TCP analysis problems and a bogus TCP header orange, RST strong red,
  ICMP errors orange, DNS NXDOMAIN and HTTP 4xx/5xx responses red, SYN and
  FIN green, TLS blue, ARP grey. `presets/tcpdump_filter.conf` adds the
  predefined filters *TCP handshakes*, *TCP errors*, *DNS*, *HTTP*, *TLS*,
  *ICMP* and *ARP*. Both are imported once in LogSquirl (README,
  *Highlighters and filters*); their patterns read the columns, so a word in
  a payload's text never matches, and they read the packet list in every
  choice of time and MAC columns. The release archives carry them next to
  the library, as `cmake --install` installs them.
- **Options dialog.** **Configure…** on the plugin's card in **Plugins →
  Plugin Management…** opens the plugin's options: the time columns (UTC
  time and time since the first packet, UTC time only, or time since the
  first packet only), MAC addresses as columns (`Source MAC` and
  `Destination MAC` before Info), the payload preview on or off and its
  length up to 200 characters, and, under *Advanced*, the stream and
  endpoint caps. They are kept in `settings.ini` in the plugin's
  configuration directory and read when a capture is opened; a capture
  already open keeps the options it was converted with. The defaults write
  the packet list as before. The Log Format also reads the lines of the
  other time and MAC choices, a missing time column left empty, the MAC
  addresses as the start of Info; README's *Options* says which choices
  change the columns that highlighters and filters may rely on.
- **DHCP, DHCPv6 and NTP described.** DHCP Info names the message type as
  Wireshark does, with the transaction id, the address assigned, requested
  or held and the client's MAC, and the host name the client sends: `DHCP
  Offer - Transaction ID 0x3903f326, 192.168.1.50 for 00:11:22:33:44:55`,
  `DHCP Discover - Transaction ID 0x3903f326 from 00:11:22:33:44:55, Host
  Name: laptop`; messages without a DHCP message type are `Boot Request`
  or `Boot Reply`. Options are walked within the message, pads, the end
  option and overloaded file and sname fields included; a length that runs
  past the message ends the walk. DHCPv6 (546/547) names its message type,
  transaction id and client DUID, `Solicit XID: 0x1a2b3c CID: 0001…`, and
  relay messages the link and the message they carry; it is now `DHCPv6`
  by its port, as DHCP is, rather than a port guess with a preview of the
  bytes. NTP shows version, mode and stratum, `NTP Version 4, server,
  stratum 2`, with the reference of a primary server or a kiss-o'-death
  code, `stratum 1 (GPS)`. Before, DHCP and NTP lines had no description.
- **ICMP and ICMPv6 in full.** Info names messages in Wireshark's words. An
  echo shows its identifier and sequence number, so request and reply pair
  up: `Echo (ping) request id=0x1234, seq=7` (before: `Echo request`); so do
  timestamp, information and address mask queries. Destination unreachable,
  time exceeded, parameter problem and redirect name their code and the
  packet they quote, dissected with the same IP parsers: `Destination
  unreachable (Port unreachable) for 10.0.0.1:51234 → 192.168.1.5:53 UDP`,
  `Time exceeded (TTL exceeded in transit) for …`, with the next hop's MTU
  of a fragmentation needed and the gateway of a redirect (before:
  `Destination unreachable (code=3)`, `Time exceeded`). ICMPv6 names its
  error codes the same way, `Packet too big mtu=1280 for …`, a neighbor
  solicitation or advertisement its target, flags and link-layer address,
  `Neighbor advertisement fe80::2 (rtr, sol, ovr) is at 00:11:22:33:44:55`,
  a router advertisement its flags and lifetime, `Router advertisement (M,
  O) lifetime=1800s`, and multicast listener messages by name (before:
  `Type=143`). A quote cut short shows what it holds; it is never read past
  the captured bytes.
- **HTTP names the host, the content type and length.** A request line
  shows the Host header's value before its path, `GET
  example.com/index.html HTTP/1.1`, when the header is in the segment; a
  response adds its Content-Type and Content-Length when it has them,
  `HTTP/1.1 200 OK, Content-Type: text/html, Content-Length: 1234`. The
  request or status line still comes first, and header values are escaped
  and cut like every field. SSDP responses gain the same headers.
- **HTTP/2 in clear text.** The connection preface is labelled `HTTP2`,
  `Magic, SETTINGS[0], WINDOW_UPDATE[0]`, and the segments that follow on
  its stream, in both directions, are `HTTP2` when they begin with frame
  headers, each frame named with its type and stream, `HEADERS[1],
  DATA[1]`. Header blocks are not decoded, and a segment that begins inside
  a frame is left as it was.
- **DNS reads like Wireshark's.** A query shows its transaction id, query
  type and name, `Standard query 0x1a2b A www.example.com`; a response adds
  its answers with their data, `Standard query response 0x1a2b A
  www.example.com CNAME example.com A 93.184.216.34`, with names put
  together from their compression pointers. Addresses, names (CNAME, PTR,
  NS, SOA), MX, SRV and TXT data are shown, other record types by name, up
  to four answers, then `…` and the count. NOTIFY and UPDATE are named, and
  `[NXDOMAIN]`, `[SERVFAIL]`, `[REFUSED]` and the other response codes stay.
  A pointer that loops, points forward or beyond the message ends the
  description there, never reading past the payload.
- **DNS over TCP.** Segments to or from TCP port 53 that begin with a DNS
  message behind its 2-byte length are labelled `DNS` and described like
  DNS over UDP; several messages in one segment are listed in order.
- **QUIC on UDP.** A datagram that begins with a QUIC long header of v1, v2
  or a draft version is labelled `QUIC` and described from its public
  header, `Initial, Version 1, DCID=8394c8f03e515708, SCID=0a0b0c0d`: the
  packet types of the datagram in order (Initial, 0-RTT, Handshake, Retry,
  Protected Payload), the version and the connection IDs. A Version
  Negotiation packet lists the versions the server offers. The short header
  packets that follow on the same stream are `QUIC` too, `Protected
  Payload, DCID=…`, with the connection ID the other side chose. Port 443
  alone does not make a datagram QUIC; the server name is out of reach, as
  it is encrypted even in the Initial.
- **TLS hellos name the server, the version and ALPN.** A ClientHello line
  shows the server name the client asks for, the highest version it offers
  and its application protocols, `Client Hello, SNI=example.com, TLS 1.3,
  ALPN=h2,http/1.1`; an extension the hello lacks is left out. A
  ServerHello shows the version chosen, `Server Hello, TLS 1.3`. A segment
  holding several records, or a record several handshake messages, lists
  them in order, `Server Hello, TLS 1.3, Change Cipher Spec, Application
  Data`, up to four, then `…`; a handshake record after Change Cipher Spec
  is an `Encrypted Handshake Message`. A record cut by the snaplen or the
  segment is described as far as it was captured, never read beyond.
- **Names for IP protocols, EtherTypes and more ports.** A packet that is not
  dissected further shows its protocol's name instead of a number: `IGMP`
  instead of `IP(2)`, and likewise GRE, ESP, AH, OSPF, PIM, VRRP, L2TP, SCTP
  and others; `LLDP` instead of `ETH(0x88CC)`, and likewise PPPoE discovery
  and session (`PPPoED`, `PPPoES`), MPLS, 802.1X (`EAPOL`), PTP, Wake-on-LAN
  (`WOL`) and others. The number stays in the Info column, and an unknown
  one keeps its numeric form. An IEEE 802.3 frame, whose type field is a
  length, shows as `LLC`. The port hint learns SNMP, Syslog, TFTP,
  STUN/TURN, WireGuard, LLMNR, NBNS, DHCPv6, RTSP, LDAP, SMB, RDP, VNC,
  Kerberos and some sixty more services.
- **The protocol sticks to the stream.** Once a detector has recognised a
  TCP or UDP stream's protocol (TLS, HTTP, SOCKS, NMEA, …), its later
  packets carry the same label in the Protocol column, also those no
  detector recognises: a segment in the middle of a TLS record or an HTTP
  body, a bare ACK. A segment with payload is described as `Continuation`,
  followed by its preview when it has text. A port's guess (`HTTPS`,
  `HTTP-Alt`) never sticks and gives way to the first recognised protocol;
  a new connection on the same addresses and ports starts without a label.
  So filtering by Protocol finds the whole conversation, and the protocol
  breakdown in the Capture Summary counts it whole. Each numbered stream
  takes 8 bytes more memory.
- **TCP analysis markers.** TCP lines carry Wireshark's expert markers at
  the start of Info, in its words and order: `[TCP Retransmission]`,
  `[TCP Fast Retransmission]`, `[TCP Spurious Retransmission]`,
  `[TCP Out-Of-Order]`, `[TCP Previous segment not captured]`,
  `[TCP Dup ACK n#m]`, `[TCP Window Update]`, `[TCP ZeroWindow]`,
  `[TCP ZeroWindowProbe]`, `[TCP ZeroWindowProbeAck]`, `[TCP Keep-Alive]`
  and `[TCP Keep-Alive ACK]`, by Wireshark's rules as far as a few numbers
  per direction of a stream allow (the Developer Guide lists the limits).
  The Capture Summary counts the segments per marker under *Analysis*. Each
  numbered stream takes 48 bytes more memory, some 48 MB at the stream cap.
- **Relative TCP sequence and acknowledgement numbers.** `Seq=` and `Ack=`
  in Info count from the start of each direction of a TCP stream, as
  Wireshark shows them by default: the SYN is `Seq=0`, the first byte of
  data `Seq=1`. A stream captured mid-way counts from its first segment seen
  (`Seq=1 Ack=1`), the numbers go on counting when the sequence numbers wrap
  past 2^32, and a new connection on the same addresses and ports starts
  afresh. A segment without the ACK flag shows `Ack=0`. Streams past the
  stream cap keep the numbers as they are.
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
- **Log Format for the packet list.** `formats/tcpdump_log.json`, an
  lnav-compatible Log Format definition, names the fields of a packet line:
  number, stream, timestamp (the UTC Time), time, source, destination,
  protocol, length and body (Info). Copied once into LogSquirl's formats
  directory, it gives a converted capture the table view with one column per
  field, the Δt column, *Go to timestamp*, time-range search limits and the
  Chart Panel's templates (packets per second, bytes over time); README's
  *Log Format* section says how. The first sidebar summary after the plugin
  is loaded links to that section. The release archives carry the file next
  to the library, as does `cmake --install`.
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
- **Follow stream.** With a packet line selected, `Plugins → tcpdump →
  Follow stream` or the sidebar's *Follow stream* button opens LogSquirl's
  Regex Lab with a pattern matching that TCP or UDP conversation's lines:
  its stream number, addresses and ports, in either direction. Applied, it
  filters the view to the conversation. No selection, a packet without a
  stream or a line of another log give a notification saying why. The
  pattern reads the lines in every choice of time and MAC columns. Offered
  on LogSquirl 26.11 and later only.
- **Endpoints and protocols as filters.** In the sidebar's Capture Summary,
  each endpoint address and protocol name is a link: a click opens
  LogSquirl's Regex Lab with a pattern matching the lines with that address
  in the Source or Destination column, or that protocol in the Protocol
  column, ready to apply, as Wireshark's *Apply as Filter*. Addresses are
  matched literally (dots, IPv6 colons) and whole, so `192.168.1.1` does not
  find `192.168.1.100`, nor an address only mentioned in Info, in every
  choice of time and MAC columns. On a
  LogSquirl older than 26.11 the summary stays plain text.

### Changed
- **The sidebar summary follows the tab in front.** With several captures
  open, the sidebar shows the Capture Summary of the one in the tab in front
  and switches with the tab; a tab that is not a capture converted by the
  plugin, or holds no log at all, shows "No capture in this tab." instead of
  the last capture's summary. Converting another capture keeps the summaries
  of the others for the rest of the session.
- **Plugin API of LogSquirl 26.11.** The plugin builds against LogSquirl
  26.11's plugin API header and exports `logsquirl_plugin_init_ex` next to
  `logsquirl_plugin_init`, learning from the host's table size whether it
  offers the Regex Lab, *Go to line* and the selected log lines. Nothing
  visible changes yet; it still loads into LogSquirl 26.03 and later.
- **DNS descriptions in Wireshark's words.** `Query example.com` is now
  `Standard query 0x1234 A example.com`, and `Response example.com (1
  answers)` lists the answer instead of counting it in a wrong plural; a
  count is left only for answers not listed, `(1 answer)`, `(6 answers)`.
  `[RCODE=2]` and the like are named, `[SERVFAIL]`.
- **The port hint knows the transport.** A well-known port names its
  service only on the transport the service runs over: TCP 3306 is MySQL,
  UDP 3306 is unnamed; UDP 69 is TFTP, TCP 69 is unnamed. Before, a port
  named the same service on TCP and UDP.
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
- **No `Ack=` without the ACK flag.** A segment without the ACK flag, a
  SYN above all, showed `Ack=0`, though its acknowledgement field means
  nothing; Info now leaves `Ack=` out, as Wireshark does: `[SYN] Seq=0
  Win=64240`.
- **Port 8443 is `HTTPS-Alt`.** The port hint named TCP 8443 `HTTP-Alt`,
  like 8080, although it is the usual alternative HTTPS port (IANA's
  `pcsync-https`): the handshake of a TLS connection to 8443, before its
  Client Hello, said `HTTP-Alt`. It now says `HTTPS-Alt`, and from the
  Client Hello on the stream is `TLS`, as on 443; 8080 stays `HTTP-Alt`.
- **The TCP window is shown scaled.** Once both SYNs of a connection
  carried the window scale option, `Win=` is the window shifted by the
  sender's scale, as Wireshark calculates it (`Win=408320` rather than
  `Win=6380` on macOS, which scales by 64), and the TCP analysis markers
  compare that window, as Wireshark's do. SYNs, connections where only
  one side offered scaling and streams captured after their handshake, whose
  scale is unknown, show the window as sent, as Wireshark does. A shift
  beyond 14 counts as 14. No more memory per stream.
- **Columns no longer run together.** A value as wide as its column, or
  wider, such as packet number 1,000,000, the protocol `ETH(0x88CC)` or a
  length of a million bytes, is still followed by a space, and an empty
  Source, Destination or Protocol (a packet without addresses) shows `-`
  instead of blanks, so every line splits into its columns.
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

[Unreleased]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/64x-lunicorn/LogSquirl-tcpdump/releases/tag/v0.1.0
