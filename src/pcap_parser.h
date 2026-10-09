/*
 * Copyright (C) 2026 LogSquirl Contributors
 *
 * This file is part of logsquirl-tcpdump.
 *
 * logsquirl-tcpdump is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * logsquirl-tcpdump is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with logsquirl-tcpdump.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file pcap_parser.h
 * @brief Parser for pcap and pcapng capture files.
 *
 * Reads the global header and per-packet records from a pcap capture,
 * one packet at a time, producing PacketRecord structs suitable for
 * formatting.  Supports both big-endian and little-endian byte orders
 * (magic number).  makeCaptureReader() (capture_reader.h) picks the
 * reader for a capture from its first block: this one, or the PcapngReader
 * (pcapng_reader.h).
 *
 * The rest of the plugin sees a capture through the CaptureReader seam
 * only: each PacketRecord carries the link-layer type it was dissected with
 * and the precision its timestamp was recorded in, so that a format whose
 * interfaces differ in both (pcapng) reads through the same seam.
 *
 * This is a pure parser — no Qt dependency.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

class PacketLayers;

// ── pcap global header ───────────────────────────────────────────────────

/// pcap file magic numbers (host byte order after detection).
constexpr uint32_t PcapMagicLE = 0xA1B2C3D4;   ///< pcap in host byte order
constexpr uint32_t PcapMagicBE = 0xD4C3B2A1;   ///< pcap in swapped byte order
constexpr uint32_t PcapNsMagicLE = 0xA1B23C4D; ///< Nanosecond pcap in host byte order
constexpr uint32_t PcapNsMagicBE = 0x4D3CB2A1; ///< Nanosecond pcap in swapped byte order
constexpr uint32_t PcapNgMagic = 0x0A0D0D0A;   ///< pcapng section header block type

/// Parsed pcap global header.
struct PcapGlobalHeader {
    uint32_t magicNumber = 0;
    uint16_t versionMajor = 0;
    uint16_t versionMinor = 0;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 0;
    uint32_t network = 0;     ///< Link-layer type (DLT_*)
    bool nanoseconds = false; ///< Timestamps have nanosecond, not microsecond, fractions.
};

// ── Link-layer types (subset of libpcap DLT_ constants) ─────────────────

constexpr uint32_t DltNull = 0;             ///< BSD loopback
constexpr uint32_t DltEthernet = 1;         ///< Ethernet
constexpr uint32_t DltPpp = 9;              ///< PPP, with or without HDLC-like framing
constexpr uint32_t DltPppSerial = 50;       ///< PPP in HDLC-like framing, or Cisco HDLC
constexpr uint32_t DltPppEther = 51;        ///< PPPoE, without the Ethernet header
constexpr uint32_t DltRaw = 101;            ///< Raw IP (no link-layer header)
constexpr uint32_t DltCiscoHdlc = 104;      ///< Cisco HDLC
constexpr uint32_t DltIeee80211 = 105;      ///< IEEE 802.11 wireless LAN
constexpr uint32_t DltLoop = 108;           ///< OpenBSD loopback (family in network byte order)
constexpr uint32_t DltLinuxSll = 113;       ///< Linux cooked capture v1
constexpr uint32_t DltIeee80211Radio = 127; ///< IEEE 802.11 behind a Radiotap header
constexpr uint32_t DltLinuxSll2 = 276;      ///< Linux cooked capture v2

/// The display name of a link-layer type ("Ethernet", "Linux SLL2", …), or
/// its number for one this parser does not know.
std::string linkTypeName( uint32_t linkType );

// ── Timestamp precision ──────────────────────────────────────────────────

/// The resolution a packet's timestamp was recorded in.  Ordered from
/// coarse to fine, so that std::max picks the finer of two.
enum class TimePrecision : uint8_t {
    Microseconds, ///< pcap's classic resolution
    Nanoseconds,  ///< e.g. tcpdump --time-stamp-precision=nano
};

// ── Ethernet / IP / TCP / UDP constants ──────────────────────────────────

constexpr uint16_t EthertypeIpv4 = 0x0800;
constexpr uint16_t EthertypeIpv6 = 0x86DD;
constexpr uint16_t EthertypeArp = 0x0806;
constexpr uint16_t EthertypeVlan = 0x8100;       ///< 802.1Q customer tag
constexpr uint16_t EthertypeQinQ = 0x88A8;       ///< 802.1ad service tag
constexpr uint16_t EthertypeQinQLegacy = 0x9100; ///< Pre-standard QinQ tag
constexpr uint16_t EthertypePppoeDiscovery = 0x8863;
constexpr uint16_t EthertypePppoeSession = 0x8864;

constexpr uint8_t IpProtoIcmp = 1;
constexpr uint8_t IpProtoTcp = 6;
constexpr uint8_t IpProtoUdp = 17;
constexpr uint8_t IpProtoIcmpv6 = 58;

// ── Tunnels ──────────────────────────────────────────────────────────────

constexpr uint8_t IpProtoIpip = 4;       ///< IPv4 encapsulated in IP (RFC 2003)
constexpr uint8_t IpProtoIpv6Encap = 41; ///< IPv6 encapsulated in IP (RFC 4213, 6in4)
constexpr uint8_t IpProtoGre = 47;       ///< Generic Routing Encapsulation (RFC 2784)
/// GRE's protocol type for an Ethernet frame (NVGRE, gretap).
constexpr uint16_t EthertypeTransparentBridging = 0x6558;
constexpr uint16_t kVxlanPort = 4789; ///< VXLAN's UDP destination port (RFC 7348)

/// Tunnels unwrapped at most, one inside the other; a packet nested deeper
/// is described as the tunnel that was not unwrapped.
constexpr size_t kMaxTunnels = 4;

/// A tunnel a packet was carried through: what Info names it, and the
/// addresses of the packet that carried it, the tunnel's endpoints.
struct Tunnel {
    std::string name;  ///< "VXLAN VNI 100", "GRE", "GRE key=0x0000002A", "IPv6-in-IPv4"
    std::string srcIp; ///< Outer source address
    std::string dstIp; ///< Outer destination address
};

// ── Parsed packet ────────────────────────────────────────────────────────

/// The transport a packet's payload was carried by.
enum class Transport { Tcp, Udp };

/// Separates the transport summary in Info from the description of the payload.
constexpr const char* kDescriptionSeparator = " | ";

/// A TCP timestamps option (RFC 7323), as sent.
struct TcpTimestamps {
    uint32_t value;     ///< TSval
    uint32_t echoReply; ///< TSecr
};

/**
 * What a TCP header's options tell, as parseTcpOptions() read them: the
 * ones Wireshark shows in Info, each only if its length is the one RFC
 * 9293 and RFC 7323 give it.
 */
struct TcpOptions {
    std::optional<uint16_t> mss;        ///< Maximum segment size.
    std::optional<uint8_t> windowShift; ///< The window scale option's shift count, as sent.
    bool sackPermitted = false;         ///< SACK permitted, whatever its length.
    std::optional<TcpTimestamps> timestamps;
    /// The options as Wireshark appends them to Info, in the order they
    /// come in: " MSS=1460 SACK_PERM TSval=1 TSecr=0 WS=128"; empty without any.
    std::string info;
};

/**
 * Read the TCP options at @p options, @p len bytes of them, as Wireshark
 * walks them: an end-of-options ends the walk, a NOP takes one byte, every
 * other kind (also an unknown one) takes the length it gives, and a length
 * below 2 or one that runs past the options ends the walk.  Nothing past
 * @p len is read.
 */
TcpOptions parseTcpOptions( const uint8_t* options, size_t len );

/// What a payload begins that the rest of its stream builds on, as the
/// Payload Describer recognised it: describeInStream() looks at the
/// stream's later packets with it in mind.
enum class StreamCue : uint8_t {
    None,
    QuicLongHeader, ///< A QUIC long header (or Version Negotiation packet).
    Http2Preface,   ///< The HTTP/2 connection preface.
    MqttConnect,    ///< An MQTT CONNECT packet.
};

/// A media stream an SDP body offers or answers (RFC 4566, RFC 3264): the
/// address its RTP is to be sent to, and the ports of its RTP and RTCP.
struct MediaEndpoint {
    std::string ip; ///< As the Source and Destination columns write it
    uint16_t rtpPort = 0;
    uint16_t rtcpPort = 0; ///< The RTP port + 1 unless `a=rtcp:` says otherwise
};

/// What a SIP message says about its call's media, for the Converter's
/// MediaExpectations (media_expectations.h).
struct SipCall {
    std::string callId; ///< The Call-ID header's value, at most kMaxSipCallIdBytes
    /// The RTP media streams its SDP body announces, at most kMaxSdpMedia.
    std::vector<MediaEndpoint> media;
    bool ends = false; ///< A BYE: the call's media is no longer expected.
};

/// Most bytes of a Call-ID a SipCall keeps, and media streams of one SDP
/// body, so that a message cannot grow a PacketRecord without bound.
constexpr size_t kMaxSipCallIdBytes = 128;
constexpr size_t kMaxSdpMedia = 8;
/// Most SIP messages described in one TCP segment.
constexpr size_t kMaxSipMessages = 4;

/// Payload bytes a PacketRecord keeps: enough for a QUIC long header's
/// connection IDs, 1 + 4 + 1 + 20 + 1 + 20 bytes.
constexpr size_t kPayloadHeadBytes = 48;

/// Represents a single parsed network packet.
struct PacketRecord {
    uint32_t number = 0; ///< 1-based packet index
    /// Seconds since the epoch: 64 bits, as a pcapng timestamp counts past
    /// 2106, where 32 bits of seconds end.
    int64_t timestampSec = 0;
    uint32_t timestampNsec = 0; ///< Fraction of the second, in nanoseconds
    uint32_t capturedLen = 0;   ///< Bytes captured
    uint32_t originalLen = 0;   ///< Original packet length on the wire

    /// Link-layer type (DLT_*) the packet was dissected with.
    uint32_t linkType = DltEthernet;
    /// Resolution the timestamp was recorded in; timestampNsec holds it in
    /// nanoseconds either way.
    TimePrecision precision = TimePrecision::Microseconds;

    // Parsed protocol fields (populated if applicable)
    std::string srcMac;
    std::string dstMac;
    uint16_t etherType = 0;

    std::string srcIp;
    std::string dstIp;
    uint8_t ipProtocol = 0;
    uint8_t ipTtl = 0;

    /// TCP or UDP when the packet's header of it was read, and with it the
    /// ports; unset for every other packet, an IP fragment after the first
    /// and a transport header cut short among them.
    std::optional<Transport> transport;
    uint16_t srcPort = 0;
    uint16_t dstPort = 0;

    // TCP-specific
    uint32_t tcpSeq = 0;
    uint32_t tcpAck = 0;
    uint8_t tcpFlags = 0;
    uint16_t tcpWindow = 0;
    /// The TCP header's length in bytes as its data offset gives it; less
    /// than 20 is bogus, and the segment's payload unknown.
    uint8_t tcpHeaderLen = 0;
    /// The shift count of the header's window scale option, as sent (RFC
    /// 7323 allows at most 14); unset without the option.  Only a SYN's
    /// counts, see analyseTcp().
    std::optional<uint8_t> tcpWindowShift;
    /// The header's timestamps option; unset without one.  Info shows it
    /// on a SYN with the other options, on other segments only through
    /// showTcpTimestamps().
    std::optional<TcpTimestamps> tcpTimestamps;

    uint32_t payloadLen = 0; ///< Application payload bytes

    /// The first captured bytes of the TCP or UDP payload, payloadHeadLen
    /// of them, for the Payload Describer to look at again once the packet's
    /// stream is known (describeInStream).
    std::array<uint8_t, kPayloadHeadBytes> payloadHead{};
    size_t payloadHeadLen = 0;
    /// Where the captured TCP or UDP payload lies in the bytes the packet
    /// was dissected from, payloadCaptured bytes of it, which may be fewer
    /// than payloadLen: CaptureReader::payloadOf() hands them out while
    /// they are there, for the TCP Reassembly (tcp_reassembly.h).
    uint32_t payloadOffset = 0;
    uint32_t payloadCaptured = 0;
    /// A detector of the Payload Describer recognised the TCP or UDP payload
    /// and named protocol, rather than the ports suggesting it, by the
    /// payload alone or in its stream (describeInStream).  Such a label
    /// sticks to the packet's stream (StreamLabels).
    bool protocolRecognised = false;
    /// What the payload begins for its stream (describeInStream).
    StreamCue streamCue = StreamCue::None;
    /// The SIP messages of the payload that announce media or end a call,
    /// at most kMaxSipMessages; empty for any other payload.
    std::vector<SipCall> sipCalls;
    /// Info ends in a preview of the payload's text this many bytes long,
    /// after kDescriptionSeparator; 0 without one (limitPreview()).
    size_t previewBytes = 0;

    std::string protocol; ///< High-level protocol name ("TCP", "UDP", …)
    std::string info;     ///< One-line summary (e.g. "80 → 54321 [SYN] Seq=0")

    /// The tunnels the packet was carried through, outermost first, at most
    /// kMaxTunnels.  Everything above (addresses, ports, protocol, info)
    /// then describes the innermost packet, as Wireshark's columns do; the
    /// Packet Formatter names the tunnels before info.
    std::vector<Tunnel> tunnels;

    /// Where the dissectors describe every layer they read, with its fields
    /// and their bytes (packet_layers.h); null, as the Converter leaves it,
    /// to describe none.  Set by dissectLayers() for the Packet Panel.
    PacketLayers* layers = nullptr;
};

/**
 * Render TCP flags (SYN, ACK, FIN, RST, PSH, URG) as a bracket string.
 *
 * @param flags  TCP flags byte.
 * @return String like "[SYN, ACK]", or "[none]" without flags, as tcpdump does.
 */
std::string formatTcpFlags( uint8_t flags );

/**
 * Render a TCP segment's sequence and acknowledgement numbers and its window
 * as Info shows them, after its flags.  Without an @p ack (a segment
 * without the ACK flag, whose acknowledgement field means nothing) Ack is
 * left out, as Wireshark does.
 *
 * @return String like "Seq=1 Ack=1 Win=65535", or "Seq=0 Win=65535".
 */
std::string formatTcpNumbers( uint32_t seq, std::optional<uint32_t> ack, uint32_t window );

/**
 * Show @p pkt's TCP timestamps option in Info, " TSval=… TSecr=…" after
 * the TCP fields and before any payload description, as Wireshark does on
 * every segment; a SYN shows it with its other options already.  Other
 * packets are left as they are.
 */
void showTcpTimestamps( PacketRecord& pkt );

/// Where the TCP fields of @p info end: before the payload description
/// (kDescriptionSeparator), or at its end without one.
size_t tcpFieldsEnd( const std::string& info );

/**
 * Dissect one captured packet into @p pkt, from its link-layer header up.
 *
 * @param linkType  The link-layer type (DLT_*) the packet was captured with.
 * @param swap      The capture was written in the other byte order than this
 *                  host's, which a BSD loopback header (DLT_NULL) is in.
 * @param data      The captured bytes, @p len of them.
 */
void dissectPacket( PacketRecord& pkt, uint32_t linkType, bool swap, const uint8_t* data,
                    size_t len );

/**
 * Dissect the IP packet an ICMP or ICMPv6 error message quotes into @p pkt,
 * with the network parsers that dissect every packet: its addresses, its IP
 * protocol and name (`protocol`, from ipProtocolName()), and the ports of a
 * TCP or UDP header (`transport`), of which 4 bytes suffice, as a router
 * quotes only 8.  Nothing past the ports is read, nor a packet the quote
 * itself quotes.  Without the whole IP header, @p pkt keeps no address.
 *
 * @param data  The quoted bytes, @p len of them, an IPv4 or IPv6 header first.
 */
void dissectQuotedPacket( PacketRecord& pkt, const uint8_t* data, size_t len );

// ── Parser ───────────────────────────────────────────────────────────────

/// Longest text preamble (e.g. tcpdump's stderr) searched for the pcap magic.
constexpr size_t kMaxPreamble = 4096;

/// Bytes of a packet that are dissected; the rest of a longer record is skipped.
constexpr uint32_t kMaxDissectedBytes = 262144;

/// Bytes someone else owns: @p size of them at @p data.
struct ByteView {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

/**
 * Where a CaptureReader reads the capture from: a file, a buffer, or a
 * stream that is still being written (capture_source.h).
 */
class ByteSource {
public:
    virtual ~ByteSource() = default;

    /// Read up to @p n bytes into @p dst; returns how many, 0 at the end or on
    /// error.  A stream may return fewer than @p n while it is written, and
    /// waits until at least one byte has come.
    virtual size_t read( uint8_t* dst, size_t n ) = 0;

    /// Skip @p n bytes; false if the source ends first.  Reads them by default.
    virtual bool skip( uint64_t n );

    /// Whether a read would return without waiting for more to be written:
    /// always for a source whose bytes are all there, a buffer or a file.
    virtual bool ready()
    {
        return true;
    }
};

/// A ByteSource over a buffer in memory.
class MemorySource : public ByteSource {
public:
    MemorySource( const uint8_t* data, size_t size )
        : data_( data )
        , size_( size )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
};

/**
 * A ByteSource that can look at the first bytes of another before they are
 * read, so that a capture's format can be told from its first block.  The
 * bytes looked at are read again from it.
 */
class HeadSource : public ByteSource {
public:
    explicit HeadSource( ByteSource& source )
        : source_( source )
    {
    }
    HeadSource( const HeadSource& ) = delete;
    HeadSource& operator=( const HeadSource& ) = delete;

    /// The next @p n bytes, or fewer at the end of the source, without
    /// consuming them.  On a stream, waits until @p n bytes have come.
    const std::vector<uint8_t>& peek( size_t n );

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;
    bool ready() override;

private:
    ByteSource& source_;
    std::vector<uint8_t> head_; ///< Bytes looked at and not yet read.
};

/// The capture file formats there is a reader for.
enum class CaptureFormat : uint8_t {
    Pcap,
    Pcapng,
};

/// What findCaptureStart() makes of the first bytes of a capture.
enum class CaptureStart : uint8_t {
    Found,    ///< The header was found: its offset and format are set.
    NeedMore, ///< These bytes do not decide it: offset is how many would.
    None,     ///< These bytes are no capture, whatever follows: error says why.
};

/**
 * Find where the capture starts in the first bytes of a file or stream, and
 * its format.
 *
 * tcpdump run through adb (`adb exec-out tcpdump -w -`) mixes its stderr,
 * e.g. "tcpdump: listening on …", into the output ahead of the capture.
 * The header is therefore looked for behind up to kMaxPreamble bytes of
 * text.  Past offset 0 it is only accepted when everything before it is
 * text and it is a valid header (a pcap magic and version, or a pcapng
 * section header with its byte-order magic), not merely 4 magic bytes: a
 * stray magic in binary data, or in the text, must not be taken for a
 * capture.  At offset 0 the magic decides, so that an unsupported version
 * is reported as such.
 *
 * The bytes are looked at in order, and the answer is given as soon as
 * they give it: a header is decided by its first 24 bytes (a pcap's global
 * header, a pcapng section header's start), a byte that is neither text nor
 * a header ends the search.  So a stream is decided once its header has
 * come, whatever follows; until then the answer is NeedMore, with the
 * number of bytes that decide the next step in @p offset.  At the end of
 * the bytes NeedMore means None, with @p error set.
 *
 * @param offset  Where the header starts, when Found; the bytes needed, when
 *                NeedMore.
 */
CaptureStart findCaptureStart( const uint8_t* data, size_t size, size_t& offset,
                               CaptureFormat& format, std::string& error );

/// Where a record of a capture lies in its source: a header, a block, a packet's record.
struct RecordSpan {
    uint64_t offset = 0; ///< Where it starts.
    uint64_t length = 0; ///< Its length, header and all.
};

/**
 * The records a capture file needs ahead of a packet for the packet's record
 * to be read as it is: what a file of some of its packets copies before them.
 */
struct CaptureHeaders {
    CaptureFormat format = CaptureFormat::Pcap;
    /// A pcap's global header; or a pcapng's section header block, then the
    /// interface description blocks its section declared so far, in order,
    /// so that a packet block's interface ID is the index of its own.
    std::vector<RecordSpan> records;
};

/**
 * What a reader needs besides a position to go on reading a capture there,
 * such as the interfaces a pcapng section declared before it: each reader
 * derives its own.  Immutable, so that checkpoints can share one.
 */
struct ReaderState {
    virtual ~ReaderState() = default;
};

/**
 * A place in a capture where a reader can go on reading without reading
 * what comes before it: the start of a packet's record, and the reader's
 * state there.  Taken by CaptureReader::checkpoint() after a packet, handed
 * to CaptureReader::resume() of a reader of the same capture.
 */
struct ReaderCheckpoint {
    uint32_t packetsBefore = 0;               ///< Packets before it: the next is packetsBefore + 1.
    uint64_t offset = 0;                      ///< Where the next record starts in the source.
    std::shared_ptr<const ReaderState> state; ///< Null when the reader needs none.
};

/**
 * Reads a capture one packet at a time, so that a capture of any size needs
 * memory for one packet only: the seam between a file format and the rest
 * of the plugin.
 *
 * A reader knows its format's headers; nothing past it does.  Each packet
 * it returns carries its own link-layer type and timestamp precision,
 * because one capture may hold several of each (a pcapng file has one per
 * interface).  What the capture announces as a whole, the finest precision
 * for the time column and the link-layer types it declares, is known after
 * open().
 *
 * A reader is handed where its format's first header starts, behind any
 * text preamble: the format is told from the first bytes once, by
 * makeCaptureReader(), and not again by the reader.
 */
class CaptureReader {
public:
    virtual ~CaptureReader() = default;

    /// Read the capture's header.  On failure, error() says why.
    virtual bool open() = 0;

    /// Read and dissect the next packet into @p pkt.  False at the end of the
    /// capture, and when it ends in the middle of a record (see truncated()).
    virtual bool next( PacketRecord& pkt ) = 0;

    /// The finest timestamp precision the capture announces; no packet's is
    /// finer.  Valid after a successful open().
    virtual TimePrecision precision() const = 0;

    /// The link-layer types the capture has declared so far, also those of
    /// interfaces that recorded no packet, in the order they were declared.
    virtual std::vector<uint32_t> linkTypes() const = 0;

    const std::string& error() const
    {
        return error_;
    }

    /// Whether the capture ends in the middle of a record, as a capture that
    /// was cut off does.  That record is not returned.
    bool truncated() const
    {
        return truncated_;
    }

    /// Bytes of the source consumed so far, for progress.
    uint64_t bytesRead() const
    {
        return bytesRead_;
    }

    /**
     * The captured TCP or UDP payload of @p pkt, which next() must have
     * returned last: a view into the reader's buffer, valid until next()
     * is called again.  Empty for a packet without one, and for one whose
     * payload does not lie within the buffer (an older packet's).
     */
    ByteView payloadOf( const PacketRecord& pkt ) const;

    /// Packets returned so far; the number of the last one.
    uint32_t packetsRead() const
    {
        return packetCount_;
    }

    /// Where the next packet's record starts, and what the reader needs to
    /// go on reading there.  Take it after a packet was read.
    virtual ReaderCheckpoint checkpoint() const;

    /**
     * Go on reading at @p checkpoint, which a reader of the same capture took:
     * the next packet returned is number checkpoint.packetsBefore + 1.  Call
     * after open(), before any packet is read; the source is skipped up to
     * the checkpoint, never read back.  False if it lies behind what was
     * read already or past the end of the source.
     */
    virtual bool resume( const ReaderCheckpoint& checkpoint );

    /// Where the record of the last packet returned starts in the source:
    /// its pcap record header, or its pcapng block.
    uint64_t recordOffset() const
    {
        return recordOffset_;
    }

    /// The length of that record in the source, header and all.
    uint64_t recordLength() const
    {
        return recordLength_;
    }

    /// The records a file of the last packet returned needs ahead of it;
    /// none before open().
    virtual CaptureHeaders headers() const
    {
        return {};
    }

    /// The captured bytes of the last packet returned, as it was dissected:
    /// at most kMaxDissectedBytes of them.
    const std::vector<uint8_t>& packetBytes() const
    {
        return packet_;
    }

    /// Whether the capture's byte order (that of the section of the last
    /// packet, in a pcapng) is the other one than this host's, as
    /// dissectPacket() is told.
    bool byteSwapped() const
    {
        return swap_;
    }

protected:
    /// @param start  Where the capture's first header starts in @p source.
    CaptureReader( ByteSource& source, uint64_t start )
        : start_( start )
        , source_( source )
    {
    }

    /// Read up to @p n bytes, fewer only at the end of the source, and count
    /// them in bytesRead().
    size_t read( uint8_t* dst, size_t n );

    /// Skip @p n bytes, counted in bytesRead(); false if the source ends first.
    bool skip( uint64_t n );

    /// Whether the source has more to read without waiting (ByteSource::ready()).
    bool ready()
    {
        return source_.ready();
    }

    const uint64_t start_; ///< Where the first header starts; skipped by open().
    std::string error_;
    bool truncated_ = false;
    bool swap_ = false;           ///< The capture is in the other byte order than this host's.
    std::vector<uint8_t> packet_; ///< The last packet's bytes, as dissected.
    uint32_t packetCount_ = 0;
    uint64_t recordOffset_ = 0;
    uint64_t recordLength_ = 0;

private:
    ByteSource& source_;
    uint64_t bytesRead_ = 0;
};

/**
 * Reads a libpcap capture.  Its one global header gives every packet the
 * same link-layer type and precision.
 */
class PcapReader : public CaptureReader {
public:
    /// @param start  Where the global header starts, as findCaptureStart()
    ///               found it for a pcap.
    explicit PcapReader( ByteSource& source, uint64_t start = 0 )
        : CaptureReader( source, start )
    {
    }

    /// Read the global header.
    bool open() override;

    bool next( PacketRecord& pkt ) override;

    /// Nanoseconds for a nanosecond magic number, microseconds otherwise.
    TimePrecision precision() const override
    {
        return header_.nanoseconds ? TimePrecision::Nanoseconds : TimePrecision::Microseconds;
    }

    /// The global header's link-layer type, once open.
    std::vector<uint32_t> linkTypes() const override;

    bool resume( const ReaderCheckpoint& checkpoint ) override;

    /// The global header.
    CaptureHeaders headers() const override;

    const PcapGlobalHeader& header() const
    {
        return header_;
    }

private:
    PcapGlobalHeader header_;
    bool open_ = false;
    bool headerRead_ = false;
};

} // namespace tcpdump
