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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

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

constexpr uint32_t DltNull = 0;        ///< BSD loopback
constexpr uint32_t DltEthernet = 1;    ///< Ethernet
constexpr uint32_t DltRaw = 101;       ///< Raw IP (no link-layer header)
constexpr uint32_t DltLoop = 108;      ///< OpenBSD loopback (family in network byte order)
constexpr uint32_t DltLinuxSll = 113;  ///< Linux cooked capture v1
constexpr uint32_t DltLinuxSll2 = 276; ///< Linux cooked capture v2

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

constexpr uint8_t IpProtoIcmp = 1;
constexpr uint8_t IpProtoTcp = 6;
constexpr uint8_t IpProtoUdp = 17;
constexpr uint8_t IpProtoIcmpv6 = 58;

// ── Parsed packet ────────────────────────────────────────────────────────

/// The transport a packet's payload was carried by.
enum class Transport { Tcp, Udp };

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

    uint32_t payloadLen = 0; ///< Application payload bytes

    std::string protocol; ///< High-level protocol name ("TCP", "UDP", …)
    std::string info;     ///< One-line summary (e.g. "80 → 54321 [SYN] Seq=0")
};

/**
 * Render TCP flags (SYN, ACK, FIN, RST, PSH, URG) as a bracket string.
 *
 * @param flags  TCP flags byte.
 * @return String like "[SYN, ACK]", or "[none]" without flags, as tcpdump does.
 */
std::string formatTcpFlags( uint8_t flags );

/**
 * Render a TCP segment's sequence and acknowledgement numbers as Info shows
 * them, after its flags.
 *
 * @return String like "Seq=1 Ack=1".
 */
std::string formatTcpNumbers( uint32_t seq, uint32_t ack );

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

// ── Parser ───────────────────────────────────────────────────────────────

/// Longest text preamble (e.g. tcpdump's stderr) searched for the pcap magic.
constexpr size_t kMaxPreamble = 4096;

/// Bytes of a packet that are dissected; the rest of a longer record is skipped.
constexpr uint32_t kMaxDissectedBytes = 262144;

/// Where a CaptureReader reads the capture from.
class ByteSource {
public:
    virtual ~ByteSource() = default;

    /// Read up to @p n bytes into @p dst; returns how many, 0 at the end or on error.
    virtual size_t read( uint8_t* dst, size_t n ) = 0;

    /// Skip @p n bytes; false if the source ends first.  Reads them by default.
    virtual bool skip( uint64_t n );
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
    /// consuming them.
    const std::vector<uint8_t>& peek( size_t n );

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;

private:
    ByteSource& source_;
    std::vector<uint8_t> head_; ///< Bytes looked at and not yet read.
};

/// The capture file formats there is a reader for.
enum class CaptureFormat : uint8_t {
    Pcap,
    Pcapng,
};

/**
 * Find where the capture starts in the first bytes of a file, and its format.
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
 * @return The offset of the header, or @p size if there is none; @p error
 *         then says why.
 */
size_t findCaptureStart( const uint8_t* data, size_t size, CaptureFormat& format,
                         std::string& error );

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

    const uint64_t start_; ///< Where the first header starts; skipped by open().
    std::string error_;
    bool truncated_ = false;

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

    const PcapGlobalHeader& header() const
    {
        return header_;
    }

private:
    std::vector<uint8_t> packet_;
    PcapGlobalHeader header_;
    bool swap_ = false;
    bool open_ = false;
    bool headerRead_ = false;
    uint32_t packetCount_ = 0;
};

} // namespace tcpdump
