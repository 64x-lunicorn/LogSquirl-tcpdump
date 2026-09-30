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
 * @brief Parser for pcap and pcap-ng capture files.
 *
 * Reads the global header and per-packet records from a pcap capture,
 * one packet at a time, producing PacketRecord structs suitable for
 * formatting.  Supports both big-endian and little-endian byte orders
 * (magic number).
 *
 * This is a pure parser — no Qt dependency.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tcpdump {

// ── pcap global header ───────────────────────────────────────────────────

/// pcap file magic numbers (host byte order after detection).
constexpr uint32_t PcapMagicLE = 0xA1B2C3D4;   ///< pcap in host byte order
constexpr uint32_t PcapMagicBE = 0xD4C3B2A1;   ///< pcap in swapped byte order
constexpr uint32_t PcapNsMagicLE = 0xA1B23C4D; ///< Nanosecond pcap in host byte order
constexpr uint32_t PcapNsMagicBE = 0x4D3CB2A1; ///< Nanosecond pcap in swapped byte order
constexpr uint32_t PcapNgMagic = 0x0A0D0D0A;   ///< pcap-ng section header

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

/// Represents a single parsed network packet.
struct PacketRecord {
    uint32_t number = 0;        ///< 1-based packet index
    uint32_t timestampSec = 0;  ///< Seconds since epoch
    uint32_t timestampNsec = 0; ///< Fraction of the second, in nanoseconds
    uint32_t capturedLen = 0;   ///< Bytes captured
    uint32_t originalLen = 0;   ///< Original packet length on the wire

    // Parsed protocol fields (populated if applicable)
    std::string srcMac;
    std::string dstMac;
    uint16_t etherType = 0;

    std::string srcIp;
    std::string dstIp;
    uint8_t ipProtocol = 0;
    uint8_t ipTtl = 0;

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

// ── Parser ───────────────────────────────────────────────────────────────

/// Longest text preamble (e.g. tcpdump's stderr) searched for the pcap magic.
constexpr size_t kMaxPreamble = 4096;

/// Bytes of a packet that are dissected; the rest of a longer record is skipped.
constexpr uint32_t kMaxDissectedBytes = 262144;

/// Where a PcapReader reads the capture from.
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
 * Reads a pcap capture one packet at a time, so that a capture of any size
 * needs memory for one packet only.
 */
class PcapReader {
public:
    explicit PcapReader( ByteSource& source )
        : source_( source )
    {
    }

    /// Read the global header, after an optional text preamble.
    /// On failure, error() says why.
    bool open();

    /// Read and dissect the next packet into @p pkt.  False at the end of the
    /// capture, and when it ends in the middle of a record (see truncated()).
    bool next( PacketRecord& pkt );

    const PcapGlobalHeader& header() const
    {
        return header_;
    }

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

private:
    size_t read( uint8_t* dst, size_t n );
    bool skip( uint64_t n );

    ByteSource& source_;
    std::vector<uint8_t> head_; ///< Start of the source, searched for the magic.
    size_t headPos_ = 0;        ///< Next unread byte in head_.
    std::vector<uint8_t> packet_;
    PcapGlobalHeader header_;
    std::string error_;
    bool swap_ = false;
    bool open_ = false;
    bool truncated_ = false;
    uint32_t packetCount_ = 0;
    uint64_t bytesRead_ = 0;
};

/// Result of parsing a whole pcap buffer.
struct ParseResult {
    bool ok = false;
    std::string error;
    PcapGlobalHeader header;
    std::vector<PacketRecord> packets;
    bool truncated = false; ///< The capture ends in the middle of a record.
};

/**
 * Parse a pcap capture held in memory, keeping every packet.
 *
 * @param data  Pointer to the raw pcap file contents.
 * @param size  Size of the buffer in bytes.
 * @return ParseResult with packets on success, or an error string.
 */
ParseResult parsePcap( const uint8_t* data, size_t size );

} // namespace tcpdump
