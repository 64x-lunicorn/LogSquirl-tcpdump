# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Names from DNS answers.** The new option *Show names from the
  capture's DNS answers with the addresses* (off by default; the default
  output is unchanged) shows an address that a DNS or mDNS answer earlier
  in the capture resolved with its name behind it in Source and
  Destination, `93.184.216.34(www.example.com)`: one word, still starting
  with the address, so the Log Format, the presets, Follow stream, the
  summary's filters and the display filters match as before. A and AAAA
  answers name their address with the name asked for, through CNAMEs; PTR
  answers name the address they spell; over UDP and TCP; an mDNS
  response's additional records too, where a responder puts the addresses
  of the service it answers for, but not a goodbye (TTL 0). Passive and
  streaming: a name labels only the packets after its answer, a later
  answer renames, names are shown unchecked (a spoofed answer is shown as
  any other). At most 8,192 addresses keep a name (about 2.5 MB), the
  oldest let go first. The sidebar summary lists endpoints with their
  names (#54)
- **gzip-compressed captures.** `.pcap.gz`, `.pcapng.gz` and `.cap.gz`
  files open as Wireshark opens them (the Open dialog lists them; the gzip
  magic decides, also behind a text preamble, not the name). They are
  decompressed on the fly, never as a whole, also when made of several
  gzip members; the progress bar counts compressed bytes. A gzip stream
  that is cut off or corrupt ends the capture there, reported in the
  summary as cut off with the reason; bytes after the last member that
  are no member are ignored, as gzip ignores trailing garbage. The Packet
  Panel, Follow stream
  content and Export packets read such a capture too: the Converter keeps
  an access point every 32 MiB of decompressed capture (32 KiB each), so
  that a packet is reached by decompressing at most that much; exported
  packets are written uncompressed. zlib 1.3.1 is fetched by the build,
  pinned by its SHA-256, and linked in statically with hidden, prefixed
  symbols (NOTICE). zstd and xz are not read (#51)
- **Wireshark extcap live capture.** The **Wireshark extcap** source makes
  every extcap a live source (`sshdump`, `androiddump`, `ciscodump`,
  `udpdump`, `randpktdump`, a vendor's), found in `WIRESHARK_EXTCAP_DIR`,
  the personal extcap directory and Wireshark's own on each OS (each with
  its `wireshark` subdirectory). The extcaps are listed with their
  interfaces (`--extcap-interfaces`; one that fails is listed with its
  error), and the chosen interface's arguments (`--extcap-config`) become a
  form: text, numbers with their range, check boxes, drop-down and radio
  choices, multi-check lists and file paths, with their defaults, a
  required one keeping Start disabled. Values are remembered per interface
  in `settings.ini`, except passwords (and arguments the extcap says not to
  save), kept for the session only. It captures with `--capture --fifo`
  into a FIFO the plugin makes in its private temporary directory (a named
  pipe on Windows), every value one argument, never through a shell (on
  Windows a batch-file extcap, which `cmd.exe` runs, refuses a filter,
  interface or value with `&` or `%…%`); **Stop** ends the extcap (#75)
- **Android live capture.** The **Android** source captures on a phone or
  an emulator with the device's tcpdump through `adb` (found on `PATH`,
  below `ANDROID_HOME`/`ANDROID_SDK_ROOT` or where the SDK is usually
  installed). It lists the devices of `adb devices -l` (unauthorized,
  offline or unpermitted ones with what to do) and the device's interfaces
  (`ip -o link`, after `any`), and finds root: adbd running as root (an
  emulator or a userdebug build after `adb root`, which the plugin never
  runs) or a `su -c` that grants it without a prompt; without root or
  tcpdump on the device it says what to do (`adb root`, Magisk, pushing a
  static tcpdump to `/data/local/tmp`). It captures through `adb exec-out`,
  binary-clean, the interface and filter single-quoted for the device's
  shell so that no filter can inject a command; tcpdump's stderr is read
  from the device when a capture fails, and **Stop** kills tcpdump on the
  device too, also in the moment it is starting; the README says what a
  LogSquirl crash leaves on the device (#73)
- **Live capture stop conditions and ring buffer.** A live capture, from
  any source, can stop by itself after a time, a number of packets or a
  size, the first reached ending it as Stop does; the sidebar shows how far
  it is to each, and a notification which one stopped it. A **Ring
  buffer** splits the raw capture into `<name>_00001_<time>.pcap`, … of a
  size or duration and keeps the newest N, each a capture of its own (a
  pcapng's section header and interfaces repeated). Each file has a
  `.log` of its own, opened in a new followed tab at its first packet, so
  no tab grows without bound; a text is never rewritten, the tabs of
  deleted files stay until they are closed, and their Packet Panel says
  *Rotated away*. The index drops the checkpoints of deleted files.
  **Save capture…** writes the files kept as one
  capture; Export packets… reads each packet from its file. The settings
  are fields of the Live capture form, kept in `settings.ini` (#77)
- **Custom command as a live source.** The **Custom command** source runs
  a command whose stdout is a pcap or pcapng stream (a vendor tool, `nc`,
  `ssh router tcpdump -w -`) and converts it live. The line is split like
  a shell would split it (quotes, backslash escapes) but run without one,
  nothing expanded; `{interface}`, `{filter}` and `{snaplen}` are replaced
  inside an argument, never split, and `{interface:sh}` and `{filter:sh}`
  single-quoted for a remote shell (a device's or server's, which the adb
  and ssh examples hand them to). **Run through the shell** (off by
  default, with a warning) is there for pipes and redirections, the
  placeholders then quoted. Commands can be saved by name, chosen,
  edited and deleted, kept in `settings.ini` at once; examples for
  tcpdump, adb and ssh are offered, never run by themselves. A command
  whose output is not a capture fails with *Not a capture*, its stderr and
  what to write instead (#76)
- **Remote live capture over SSH.** The **SSH** source captures on a
  server with its `tcpdump`, over the system's OpenSSH client (Windows:
  `System32\OpenSSH\ssh.exe`). The host is typed as `[user@]host[:port]`,
  or picked from the `Host` entries of `~/.ssh/config`; its interfaces are
  what `sudo -n tcpdump -D` (without sudo while it is turned off) lists
  there, or `ip -o link` when it lists none; the remote commands run with
  `/bin/sh` whatever the login shell. ssh always runs with `-o
  BatchMode=yes -o ConnectTimeout=10 -T` and nothing written to its stdin,
  so only keys and the SSH agent are used: no password, passphrase or host
  key prompt, ever. The
  capture runs `sudo -n tcpdump -i IF -s N -U -w - FILTER` (sudo can be
  turned off), the interface and filter single-quoted for the server's
  shell, and by default excludes its own SSH connection (`not (host
  <client> and tcp port <SSH port>)`, from `$SSH_CLIENT`). An unknown or
  changed host key, refused keys, a sudo that wants a password, tcpdump
  missing or lacking permissions come with what to do. **Stop** ends
  tcpdump on the server too: a watchdog ends it once ssh's stdin, held
  open by the plugin, closes (#74)
- **Local live capture.** The **Local** source captures on this
  computer's interfaces with Wireshark's `dumpcap` (preferred) or
  `tcpdump`, found on `PATH` or where their installers put them; without
  either it says what to install. It lists interfaces with `-D` and passes
  the capture filter as one argument. It never runs sudo or asks for a
  password: when the program may not capture (a permission error, no
  interfaces listed, an unreadable `/dev/bpf0` on macOS), the section says
  what to do on this OS: ChmodBPF or the `access_bpf` group on macOS, the
  `wireshark` group or `setcap` on Linux, Npcap without the
  administrators-only restriction on Windows; the README lists them (#72)
- **Live capture UI.** The sidebar's new **Live capture** section, and
  **Plugins → tcpdump → Start live capture…** (also in the Command
  Palette) with the same fields in a dialog, start a live capture: a
  source picker (a source that cannot be used says why), its devices and
  interfaces, listed in the background with a timeout and refreshable, a
  BPF capture filter (passed as one argument, never through a shell; a
  display filter field, a leading `-`, a line break or unbalanced
  parentheses are pointed out below it) and the snaplen (262144 by
  default). **Start** is disabled while a capture is read or captured;
  **Stop** (also **Plugins → tcpdump → Stop live capture**) finalises it,
  without the UI waiting for the capture program to end; a capture stopped
  before its capture header came is not a failure: the sidebar says it
  was stopped before anything was captured.
  The section shows the live counters, the capture program's stderr lines
  and, when a capture fails, its error and what the source says to do.
  The last choice is remembered in `settings.ini` (group `[live]`); no
  password is ever asked for or stored. One live capture runs at a time:
  the menu entry offers to stop the running one, and starts the new one
  once it has ended. Sources plug in through one small interface, the
  Live Source Kind (#71). Closing the section or the dialog, or shutting
  the plugin down, cancels a device or interface listing that still runs
  (its program is killed) instead of waiting up to its 10 s timeout. A
  source may have options of its own, shown in the form while it is
  chosen and remembered per source in `settings.ini`
- **TLS decryption with an `SSLKEYLOGFILE`.** The new option *TLS
  decryption: key log file* takes the key log browsers, curl and OpenSSL
  applications write (NSS format: `CLIENT_RANDOM` for TLS 1.2, the
  handshake and application traffic secrets for TLS 1.3). The TLS sessions
  it has the secrets of are decrypted, record by record as the TCP
  reassembly puts them together, and described:
  `TLS (decrypted) | GET www.example.com/index.html HTTP/1.1`, labelled
  `HTTP`; HTTP/2 frames with their header blocks decoded (HPACK),
  `HEADERS[1]: GET example.org/app.js`, `HEADERS[1]: 200, Content-Type: …`,
  labelled `HTTP2`; the encrypted handshake messages and alerts. TLS 1.2
  with AES-GCM, ChaCha20-Poly1305 and AES-CBC with HMAC (encrypt-then-MAC
  too), TLS 1.3 with AES-GCM and ChaCha20-Poly1305 and its key updates; a
  lost record is passed over. Sessions without secrets, or with wrong ones,
  keep their lines. A live capture reads the key log again as it grows.
  The *HTTP* filter and the *HTTP 4xx/5xx* highlighter match the decrypted
  HTTP/1.1 lines too.
  The secrets are read only, kept in memory for the conversion and wiped,
  never written or shown; a session keeps its keys and sequence numbers,
  no data, 16,384 sessions at a time, a new one in place of the one idle
  the longest. The sidebar summary counts the
  sessions decrypted. The cryptography is Mbed TLS 3.6.7, fetched by the
  build at that release and hash and linked in (NOTICE).
- **Follow stream content.** The Packet Panel's new **Stream** tab shows
  the payload of the selected packet's TCP or UDP conversation, as
  Wireshark's *Follow TCP/UDP Stream* does: the client's bytes in red, the
  server's in blue, as text (UTF-8 kept, control bytes escaped) or a hex
  dump, both directions or one. TCP bytes come in sequence order, as the
  TCP reassembly orders them (the ordering is now a module of its own, the
  Byte Stream Orderer): out-of-order segments wait, retransmitted and
  overlapping bytes show once, and bytes the capture lacks show as `[n
  bytes missing]`; UDP streams show their datagrams. The stream is read
  again from the capture file, in the background with a progress bar and
  Cancel, from the stream's first packet to its last (the Converter now
  notes them, 8 bytes per stream); 1 MB is shown at first and **Show more**
  reads on, up to 16 MB, with a note. **Export…** writes the whole stream,
  raw bytes per direction or the text as shown, without holding it. Opened
  with the panel's **Follow stream content** button or **Plugins →
  tcpdump → Follow stream content**; *Follow stream* still filters the
  stream's lines in the Regex Lab. Needs LogSquirl ≥ 26.11.
- **TCP details as Wireshark shows them.** A SYN and a SYN-ACK show their
  options after the window, in the order they were sent: `[SYN] Seq=0
  Win=64240 MSS=1460 SACK_PERM TSval=1000 TSecr=0 WS=128`; unknown options
  are skipped by their length, and a malformed length ends the walk
  without reading past the header. The new option *Show TCP timestamps
  (TSval, TSecr) on every segment* (off by default) shows the timestamps
  on the other segments too. The ACK that completes a handshake shows its
  initial round-trip time, from the SYN, `[iRTT=0.012345]`, also in the
  Packet Panel's TCP layer, and the
  summary the median of all handshakes captured whole (exact up to 4,096
  handshakes, within 0.8 % beyond, in 32 KB of memory however long the
  capture). A segment that
  fills the window the receiver advertised last, scaled as negotiated, is
  marked `[TCP Window Full]`, counted in the summary and coloured and
  filtered with the other TCP problems. `tests/corpus/tcp-analysis.pcap`
  has a second connection that shows them.
- **Display filters.** **Plugins → tcpdump → Display filter…** (also in
  the Command Palette), and the *Display filter* field in the sidebar,
  take a Wireshark-style display filter, such as
  `ip.addr == 10.0.0.0/8 && tcp.port == 443 || dns`, and open the Regex
  Lab with the pattern of the packet lines it selects, in every column
  layout. Supported: `ip.addr`/`src`/`dst` (an address or an IPv4
  network), `ipv6.addr`/`src`/`dst`, `tcp.port`/`srcport`/`dstport`, the
  same of `udp`, `tcp.stream`, `udp.stream` and `frame.len`, compared with
  `==`, `!=`, `<`, `>`, `<=`, `>=` (or alone), protocol names as in the
  Protocol column, `tcp`, `udp`, `ip`, `ipv6`, combined with `!`, `&&`,
  `||` and parentheses. `!=` means what it does in Wireshark. Anything
  else is rejected below the field with its column and the reason, never
  approximated. Each condition is a lookahead from the start of the line
  and a number range an exact pattern, so the pattern selects exactly the
  lines the filter means; it runs with Qt's regular expressions, as the
  Regex Lab and LogSquirl's search run a pattern Vectorscan cannot read.
  Needs LogSquirl ≥ 26.11 (#82)
- **TCP reassembly.** A TLS record, an HTTP/1.x header section, a
  DNS-over-TCP message, a SIP message (by its Content-Length), an MQTT
  control packet on port 1883 (by its Remaining Length), a SOME/IP
  message (by its Length), a DoIP message on port 13400 (by its payload
  length), an SSH packet of the key exchange (by its packet_length,
  only before the direction's NEWKEYS), a WebSocket frame (by its
  payload length, on an upgraded stream) or an SMB message on port 445 or
  139 (by its NetBIOS Session Service length) that spans TCP segments is
  described once, on the
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
  an RST; a segment of whole messages costs nothing. The segments after
  the first of a message past the limit, up to where its header says it
  ends (at most 1 GiB away), say `[continuation of a message past the
  reassembly limit]` with its protocol, and the message after it is
  described as usual, also when it begins in the segment that ends the
  large one. A new synthetic
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
- **Conversations table.** Below the packet in the Packet Panel, a row per
  TCP and UDP stream, as Wireshark's *Statistics → Conversations*: Stream,
  protocol (the Stream Label), address and port of ends A and B, packets
  and bytes (on the wire) in all and each way, start and duration; sortable
  by every column. A click on a row, or *Filter on this conversation*,
  opens the Regex Lab with the pattern of the stream's lines, as Follow
  stream builds it. The counts are taken while converting, for the
  numbered streams only, so the stream cap bounds them (some 200 bytes a
  stream for its counts and row; with the Stream Tracker some 390 MB at the
  default cap of 1,000,000 streams); the packets of streams past it are
  one row, *Other streams*. The table is part of the Capture Summary and
  shows a new summary snapshot as it comes, keeping its sort and selection;
  a snapshot shares the rows of the streams that had no packet since the
  last one.
- **Export packets.** *Plugins → tcpdump → Export packets…* writes the
  packets of the selected lines to a new capture file, e.g. the lines of a
  Filtered View, to share a narrowed view or open it in Wireshark. Each
  packet's record is copied byte for byte (timestamps, lengths, link type);
  a pcap gives a pcap with the capture's header, a pcapng a pcapng with
  the section headers and interfaces of the exported packets. A dialog
  shows the packets as numbers and ranges to confirm or change, or to
  paste packet lines into: LogSquirl tells at most the first 1,000
  selected lines (or 1 MiB), and says so, which the dialog and the
  notification after the export repeat. The capture is read once, front to
  back, from the Packet Panel's checkpoints, on a worker thread with
  progress and Cancel. Needs LogSquirl ≥ 26.11.
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
  conversation. An Ethernet frame in VXLAN or GRE is dissected as one on
  the wire, a PPPoE session in it unwrapped to its IP packet. At most 4
  tunnels are unwrapped, a
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
  group: SIGTERM, then SIGKILL after 2 s; on Windows it is started
  suspended and put in a job object before it runs, so that nothing it
  starts escapes, and the job is terminated (a job that cannot be made is
  reported, and the program's process tree is ended instead). A program
  that exits without having written a capture fails with *Not a capture*
  and its last stderr lines. Shutting the plugin down, as LogSquirl quits
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
- **MQTT described.** MQTT 3.1, 3.1.1 and 5.0 on TCP port 1883, and on
  any port behind a CONNECT, is described as Wireshark names its control
  packets, every one in a segment: `Connect Command (MQTT 3.1.1, Keep
  Alive 60, Clean Session, Client ID "sensor-1", User "bob")`, `Connect
  Ack (Connection Accepted)`, `Publish Message (QoS 1, id=2, Retain)
  [alerts/door] "open"`, `Publish Ack/Received/Release/Complete (id=…)`,
  `Subscribe Request (id=1) [sensors/+/temp, alerts/#]`, `Subscribe Ack`,
  `Unsubscribe Request/Ack`, `Ping Request/Response`, `Disconnect Req`,
  `Authentication Exchange`. MQTT 5.0 properties are skipped by their
  length, reason codes named with their reason strings (`Publish Ack
  (id=2, No matching subscribers, "nobody listening")`). A packet that
  goes on in the next segment is reassembled on port 1883 (see *TCP
  reassembly*), and described as far as it goes on another port, its rest
  a `Continuation`; a malformed one is `[Malformed Packet]`. Every length
  is checked against the packet and the captured bytes. MQTT over TLS
  (8883) stays TLS. Before, MQTT was named by its port alone, with a
  preview of its bytes.
- **SIP, SDP, RTP and RTCP described.** SIP on any port, over UDP and
  TCP, is described as Wireshark names its messages: `Request: INVITE
  sip:bob@example.com`, `Status: 200 OK (INVITE)`, with the CSeq number
  and the Call-ID cut short, and an SDP body by its media, `SDP (audio
  49170 RTP/AVP 0 8)`. Over TCP every message of a segment is described,
  told apart by its Content-Length, and one that spans segments is
  reassembled (see *TCP reassembly*), the media its SDP body announces
  expected from the segment that completes it; a message cut at the
  snaplen ends in `…`, a malformed one is `[Malformed Packet]`; CRLF
  keep-alives (RFC 5626) before a message are passed over, and alone on
  port 5060 are `Keep-alive (ping)` or `Keep-alive (pong)`. The addresses
  and ports SDP announces (`c=` and `m=` lines of the offer and the
  answer; RTCP on the next port, `a=rtcp:` or `a=rtcp-mux`) are expected
  for RTP and RTCP, a new SDP body replacing only what the same side of
  the call (its `o=` line) announced before, and the UDP packets to or
  from them are described as `RTP` (`PT=PCMU, SSRC=0x1234ABCD, Seq=1000,
  Time=8000, Mark`, payload types named as RFC
  3551 names them) and `RTCP` (`Sender Report, Source description`).
  UDP on other ports stays UDP. At most 1024 endpoints are expected; one
  is forgotten after 5 minutes without a packet, with its call's BYE, or
  for a newer one past the cap. Before, SIP was named by its port alone,
  with a preview of its text, and RTP was plain UDP.
- **SOME/IP and SOME/IP-SD described.** SOME/IP over UDP and TCP, on
  port 30490, on the ports configured for it (the new option *SOME/IP
  also on ports*) and on any other where every message's header keeps to
  the rules, none is longer than 1 MiB and the messages fill the payload,
  is labelled `SOME/IP` and every message of a datagram or segment is named, up to eight: `Service
  0x1234 Method 0x0001 Client 0x0010 Session 0x0001 REQUEST, 4 bytes`,
  `Event 0x8001 … NOTIFICATION`, `ERROR (E_NOT_OK)`, the SOME/IP-TP
  segments with their offset, the magic cookies of a TCP connection.
  SOME/IP-SD messages are labelled `SOME/IP-SD` and list their entries as
  Wireshark names them, with their endpoint options: `Find Service
  0x1234`, `Offer Service 0x1234 Instance 0x0001 v1.0 TTL=3
  (192.0.2.10:30501 UDP, 192.0.2.10:30502 TCP)`, `Stop Offer Service`,
  `Subscribe Eventgroup`, `Subscribe Eventgroup Ack/Nack`, IPv4 and IPv6,
  unicast, multicast and SD endpoints. An optional name table (the new
  option *SOME/IP name table*, a text file of `service`, `method`, `event`
  and `eventgroup` lines) adds names: `Service 0x1234 (Navigation)`. Every
  length is checked against the captured bytes, entries and options are
  capped at 64, a cut message ends in `…`, a malformed one is `[Malformed
  Packet]`; over TCP a message that spans segments is reassembled by its
  Length. A new synthetic capture, `tests/corpus/someip.pcap` (written by
  `tests/make_someip_corpus.py`), shows each case.
- **DoIP described, with the UDS service of diagnostic messages.** DoIP
  (Diagnostics over IP, ISO 13400-2) on UDP and TCP port 13400 is labelled
  `DoIP` and every message of a datagram or segment is named as Wireshark
  names its payload type, up to eight: `Vehicle identification request`
  (with EID or VIN), `Vehicle announcement message/vehicle identification
  response message, VIN …, Logical address 0x1000, EID …, GID …`,
  `Routing activation request, Source 0x0E00, Activation type Default`,
  `Routing activation response, … Routing successfully activated (0x10)`,
  `Alive check request/response`, entity status, diagnostic power mode,
  `Diagnostic message ACK/NACK` and `Generic DoIP header NACK` with their
  codes. A diagnostic message names its addresses and the UDS service it
  carries (ISO 14229-1), with its sub-function, data identifiers or routine
  and, in a negative response, the NRC: `Diagnostic message 0x0E00 →
  0x1000, UDS ReadDataByIdentifier 0xF190`, `UDS Positive Response
  DiagnosticSessionControl extendedDiagnosticSession`, `UDS Negative
  Response ReadDataByIdentifier NRC=0x31 (requestOutOfRange)`. A header
  whose inverse version does not match its version is `Incorrect pattern
  format … [Malformed Packet]`, a payload length its type does not allow
  `Invalid payload length n [Malformed Packet]`; every length is checked
  against the captured bytes, a cut message ends in `…`, and over TCP a
  message that spans segments is reassembled by its payload length. A new
  synthetic capture, `tests/corpus/doip.pcap` (written by
  `tests/make_doip_corpus.py`), shows each case.
- **SSH described: banners, the key exchange and encrypted packets.** SSH
  is told by its banner on any TCP port, port 22 as a hint, labelled
  `SSHv2` (`SSHv1` for an SSH 1.x banner), and described as Wireshark
  describes it, per direction: `Client: Protocol (SSH-2.0-OpenSSH_9.6)`,
  `Client: Key Exchange Init kex=curve25519-sha256,… hostkey=ssh-ed25519,…
  cipher=chacha20-poly1305@openssh.com,…` (all ten name-lists read, the
  key exchange, host key and cipher lists shown by their first name),
  `Elliptic Curve Diffie-Hellman Key Exchange Init/Reply`, the
  Diffie-Hellman group exchange, `New Keys`, and every packet a direction
  sends after its NEWKEYS as `Encrypted packet (len=64)`; the stream
  remembers each direction's phase. Binary packets of the key exchange
  with no banner before them are SSH on port 22 only, where a connection
  whose key exchange the capture lacks is shown as `SSH` `Encrypted packet
  (len=n)`.
  A packet_length or padding_length the unencrypted phase does not allow
  is `[Malformed Packet]`, every field is read within the captured bytes,
  a cut message ends in `…`, and a KEXINIT or key exchange reply that
  spans segments is reassembled. A new synthetic capture,
  `tests/corpus/ssh.pcap` (written by `tests/make_ssh_corpus.py`), shows
  each case.
- **WebSocket described: the upgrade and its frames.** The `GET … Upgrade:
  websocket` request and the `101 Switching Protocols` response stay HTTP,
  the response showing its `Upgrade` and `Sec-WebSocket-Extensions`
  (`permessage-deflate`); every later segment of the stream, on any port,
  is `WebSocket`, its frames named as Wireshark names them, every one of a
  segment: `WebSocket Text [FIN] [MASKED] len=5 "Hello"` (a client's text
  unmasked for the preview), `WebSocket Binary [FIN] len=300`,
  `Continuation`, `Ping`, `Pong`, `WebSocket Connection Close [FIN] len=5
  Normal Closure (1000) "bye"`, a compressed message `[COMPRESSED]`.
  Lengths of 7, 16 and 64 bits are read; a control frame without FIN or
  longer than 125 bytes, a reserved opcode or a close with a one-byte
  payload is `[Malformed Packet]`, a cut frame ends in `…`, and a frame
  that spans segments is reassembled; frames in the segment of the 101
  response are described after it (`HTTP/1.1 101 …; WebSocket Text [FIN]
  len=5 "hello"`). Detection is by the upgrade in the same stream, not by
  port. A new synthetic capture,
  `tests/corpus/websocket.pcap` (written by
  `tests/make_websocket_corpus.py`), shows each case.
- **SMB2/3 described.** SMB on TCP port 445 and over NetBIOS on 139 (and
  on any port behind an NBSS header with an SMB protocol ID) is labelled
  `SMB2` and every command of a segment, compounded ones too, up to eight,
  is named as Wireshark names it, with its fields: `Negotiate Protocol
  Request Dialects: 2.0.2, 2.1, 3.0, 3.0.2, 3.1.1`, `Negotiate Protocol
  Response Dialect: 3.1.1`, `Session Setup Response, Error:
  STATUS_MORE_PROCESSING_REQUIRED`, `Tree Connect Request Tree:
  \\server\share`, `Create Request File: dir\file.txt`, `Read Request
  Len:65536 Off:0`, `Write Request …`, `Ioctl Request
  FSCTL_VALIDATE_NEGOTIATE_INFO`, `Find Request
  SMB2_FIND_ID_BOTH_DIRECTORY_INFO Pattern: *`, `Close`, `Notify`,
  `GetInfo` and the others; a failed response names its NT status
  (`STATUS_ACCESS_DENIED`, `STATUS_OBJECT_NAME_NOT_FOUND`, …). Names are
  decoded from UTF-16 and capped. An encrypted message is `Encrypted
  SMB3`, a compressed one `Compressed SMB3, LZ77, Original size …`, SMB1
  is labelled `SMB` with its command only, NBSS session setup on port 139
  `NBSS`. Every length and offset is checked against the message and the
  captured bytes; a wrong header size, a NextCommand or name beyond the
  message is `[Malformed Packet]`, a cut message ends in `…`, and a
  message that spans segments is reassembled. A new synthetic capture,
  `tests/corpus/smb.pcap` (written by `tests/make_smb_corpus.py`), shows
  each case.

### Changed
- A segment that ends inside a TLS record, an HTTP header section or a
  DNS-over-TCP message no longer names the message as far as it goes
  (`Client Hello` without its server name, `Standard query response … (2
  answers)`), and the segment that ends it no longer says `Continuation`:
  the first says `[TCP segment of a reassembled PDU]`, the last describes
  the whole message (see *TCP reassembly*). A message the capture never
  completes is described by none of its segments.

### Fixed
- **Packet numbers no longer wrap.** The No. column counted packets in 32
  bits: a capture file of more than 4,294,967,295 packets started again at
  0. The conversion now stops with packet 4,294,967,295, and the summary
  says the rest was not converted; a live capture stops there, as at a
  stop condition, with a notification (#128)

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
