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
 * Reads the global header and per-packet records from a pcap file,
 * producing PacketRecord structs suitable for formatting.  Supports
 * both big-endian and little-endian byte orders (magic number).
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
constexpr uint32_t PcapMagicLE = 0xA1B2C3D4; ///< Little-endian pcap
constexpr uint32_t PcapMagicBE = 0xD4C3B2A1; ///< Big-endian pcap (swapped)
constexpr uint32_t PcapNgMagic = 0x0A0D0D0A; ///< pcap-ng section header

/// Parsed pcap global header.
struct PcapGlobalHeader {
    uint32_t magicNumber = 0;
    uint16_t versionMajor = 0;
    uint16_t versionMinor = 0;
    int32_t thiszone = 0;
    uint32_t sigfigs = 0;
    uint32_t snaplen = 0;
    uint32_t network = 0; ///< Link-layer type (DLT_*)
};

// ── Link-layer types (subset of libpcap DLT_ constants) ─────────────────

constexpr uint32_t DltNull = 0;        ///< BSD loopback
constexpr uint32_t DltEthernet = 1;    ///< Ethernet
constexpr uint32_t DltRaw = 101;       ///< Raw IP (no link-layer header)
constexpr uint32_t DltLinuxSll = 113;  ///< Linux cooked capture v1
constexpr uint32_t DltLinuxSll2 = 276; ///< Linux cooked capture v2

// ── Ethernet / IP / TCP / UDP constants ──────────────────────────────────

constexpr uint16_t EthertypeIpv4 = 0x0800;
constexpr uint16_t EthertypeIpv6 = 0x86DD;
constexpr uint16_t EthertypeArp = 0x0806;
constexpr uint16_t EthertypeVlan = 0x8100;

constexpr uint8_t IpProtoIcmp = 1;
constexpr uint8_t IpProtoTcp = 6;
constexpr uint8_t IpProtoUdp = 17;
constexpr uint8_t IpProtoIcmpv6 = 58;

// ── Parsed packet ────────────────────────────────────────────────────────

/// Represents a single parsed network packet.
struct PacketRecord {
    uint32_t number = 0;         ///< 1-based packet index
    uint32_t timestampSec = 0;   ///< Seconds since epoch
    uint32_t timestampUsec = 0;  ///< Microseconds fraction
    uint32_t capturedLen = 0;    ///< Bytes captured
    uint32_t originalLen = 0;    ///< Original packet length on the wire

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

    uint32_t payloadLen = 0;     ///< Application payload bytes

    std::string protocol;        ///< High-level protocol name ("TCP", "UDP", …)
    std::string info;            ///< One-line summary (e.g. "80 → 54321 [SYN] Seq=0")

    std::vector<uint8_t> rawData; ///< Raw packet bytes (up to capturedLen)
};

// ── Parser ───────────────────────────────────────────────────────────────

/// Result of parsing a pcap file.
struct ParseResult {
    bool ok = false;
    std::string error;
    PcapGlobalHeader header;
    std::vector<PacketRecord> packets;
};

/**
 * Parse a pcap file from a byte buffer.
 *
 * @param data  Pointer to the raw pcap file contents.
 * @param size  Size of the buffer in bytes.
 * @return ParseResult with packets on success, or an error string.
 */
ParseResult parsePcap( const uint8_t* data, size_t size );

/**
 * Parse a pcap file from disk.
 *
 * @param filePath  Absolute or relative path to the .pcap / .cap file.
 * @return ParseResult with packets on success, or an error string.
 */
ParseResult parsePcapFile( const std::string& filePath );

} // namespace tcpdump
