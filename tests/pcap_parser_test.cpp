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
 * @file pcap_parser_test.cpp
 * @brief BDD tests for the pcap file parser.
 *
 * Tests use synthetic pcap byte buffers to exercise header parsing,
 * Ethernet+IPv4+TCP dissection, endianness handling, and error cases.
 */

#include <catch2/catch.hpp>

#include "pcap_parser.h"

#include <cstring>
#include <vector>

using namespace tcpdump;

namespace {

/// Build a minimal valid pcap global header (little-endian, Ethernet).
std::vector<uint8_t> makeGlobalHeader( uint32_t linkType = DltEthernet )
{
    std::vector<uint8_t> hdr( 24, 0 );

    // Magic number (little-endian native)
    uint32_t magic = PcapMagicLE;
    std::memcpy( hdr.data(), &magic, 4 );

    // Version 2.4
    uint16_t major = 2, minor = 4;
    std::memcpy( hdr.data() + 4, &major, 2 );
    std::memcpy( hdr.data() + 6, &minor, 2 );

    // thiszone = 0, sigfigs = 0
    // snaplen = 65535
    uint32_t snaplen = 65535;
    std::memcpy( hdr.data() + 16, &snaplen, 4 );

    // network (link-layer type)
    std::memcpy( hdr.data() + 20, &linkType, 4 );

    return hdr;
}

/// Build a pcap packet header.
std::vector<uint8_t> makePacketHeader( uint32_t tsSec, uint32_t tsUsec,
                                        uint32_t capturedLen, uint32_t origLen )
{
    std::vector<uint8_t> hdr( 16, 0 );
    std::memcpy( hdr.data(), &tsSec, 4 );
    std::memcpy( hdr.data() + 4, &tsUsec, 4 );
    std::memcpy( hdr.data() + 8, &capturedLen, 4 );
    std::memcpy( hdr.data() + 12, &origLen, 4 );
    return hdr;
}

/// Build a minimal Ethernet + IPv4 + TCP SYN packet.
std::vector<uint8_t> makeTcpSynPacket()
{
    std::vector<uint8_t> pkt;

    // Ethernet header (14 bytes)
    // dst MAC: 00:11:22:33:44:55
    pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
    // src MAC: 66:77:88:99:aa:bb
    pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb } );
    // EtherType: IPv4 (0x0800)
    pkt.push_back( 0x08 );
    pkt.push_back( 0x00 );

    // IPv4 header (20 bytes, no options)
    pkt.push_back( 0x45 ); // Version 4, IHL 5
    pkt.push_back( 0x00 ); // DSCP/ECN
    pkt.push_back( 0x00 );
    pkt.push_back( 0x28 ); // Total length = 40 (20 IP + 20 TCP)
    pkt.push_back( 0x00 );
    pkt.push_back( 0x01 ); // Identification
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 ); // Flags/Fragment
    pkt.push_back( 0x40 ); // TTL = 64
    pkt.push_back( 0x06 ); // Protocol = TCP
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 ); // Checksum (ignored)
    // Src IP: 192.168.1.100
    pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x64 } );
    // Dst IP: 10.0.0.1
    pkt.insert( pkt.end(), { 0x0A, 0x00, 0x00, 0x01 } );

    // TCP header (20 bytes, no options)
    pkt.push_back( 0x00 );
    pkt.push_back( 0x50 ); // Src port: 80
    pkt.push_back( 0xD4 );
    pkt.push_back( 0x31 ); // Dst port: 54321
    // Seq = 0
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
    // Ack = 0
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
    pkt.push_back( 0x50 ); // Data offset = 5 (20 bytes), reserved
    pkt.push_back( 0x02 ); // Flags: SYN
    pkt.push_back( 0xFF );
    pkt.push_back( 0xFF ); // Window = 65535
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 ); // Checksum
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 ); // Urgent ptr

    return pkt;
}

} // anonymous namespace

SCENARIO( "Parsing a minimal pcap with a TCP SYN packet", "[pcap_parser]" )
{
    GIVEN( "a pcap buffer with global header + one TCP SYN packet" )
    {
        auto globalHdr = makeGlobalHeader();
        auto pktData = makeTcpSynPacket();
        auto pktHdr = makePacketHeader( 1000, 500000,
                                         static_cast<uint32_t>( pktData.size() ),
                                         static_cast<uint32_t>( pktData.size() ) );

        std::vector<uint8_t> buf;
        buf.insert( buf.end(), globalHdr.begin(), globalHdr.end() );
        buf.insert( buf.end(), pktHdr.begin(), pktHdr.end() );
        buf.insert( buf.end(), pktData.begin(), pktData.end() );

        WHEN( "parsing the buffer" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing succeeds" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.error.empty() );
            }

            THEN( "the global header is correct" )
            {
                REQUIRE( result.header.versionMajor == 2 );
                REQUIRE( result.header.versionMinor == 4 );
                REQUIRE( result.header.network == DltEthernet );
            }

            THEN( "exactly one packet is parsed" )
            {
                REQUIRE( result.packets.size() == 1 );
            }

            THEN( "the packet has correct IP addresses" )
            {
                const auto& pkt = result.packets[ 0 ];
                REQUIRE( pkt.srcIp == "192.168.1.100" );
                REQUIRE( pkt.dstIp == "10.0.0.1" );
            }

            THEN( "the packet has correct TCP ports" )
            {
                const auto& pkt = result.packets[ 0 ];
                REQUIRE( pkt.srcPort == 80 );
                REQUIRE( pkt.dstPort == 54321 );
            }

            THEN( "the protocol is HTTP (port 80 detected)" )
            {
                REQUIRE( result.packets[ 0 ].protocol == "HTTP" );
            }

            THEN( "TCP flags include SYN" )
            {
                REQUIRE( ( result.packets[ 0 ].tcpFlags & 0x02 ) != 0 );
            }

            THEN( "MAC addresses are parsed" )
            {
                const auto& pkt = result.packets[ 0 ];
                REQUIRE( pkt.dstMac == "00:11:22:33:44:55" );
                REQUIRE( pkt.srcMac == "66:77:88:99:aa:bb" );
            }

            THEN( "timestamps are correct" )
            {
                const auto& pkt = result.packets[ 0 ];
                REQUIRE( pkt.timestampSec == 1000 );
                REQUIRE( pkt.timestampUsec == 500000 );
            }
        }
    }
}

SCENARIO( "Parsing an empty or invalid buffer", "[pcap_parser]" )
{
    GIVEN( "a buffer that is too small" )
    {
        uint8_t tiny[] = { 0x01, 0x02, 0x03 };

        WHEN( "parsing" )
        {
            auto result = parsePcap( tiny, sizeof( tiny ) );

            THEN( "parsing fails with an error" )
            {
                REQUIRE_FALSE( result.ok );
                REQUIRE_FALSE( result.error.empty() );
            }
        }
    }

    GIVEN( "a buffer with invalid magic number" )
    {
        std::vector<uint8_t> buf( 24, 0xFF );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing fails" )
            {
                REQUIRE_FALSE( result.ok );
                REQUIRE( result.error.find( "magic" ) != std::string::npos );
            }
        }
    }
}

SCENARIO( "Parsing a pcap with no packets", "[pcap_parser]" )
{
    GIVEN( "a pcap with only a global header" )
    {
        auto globalHdr = makeGlobalHeader();

        WHEN( "parsing" )
        {
            auto result = parsePcap( globalHdr.data(), globalHdr.size() );

            THEN( "parsing succeeds with zero packets" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.empty() );
            }
        }
    }
}

// ── Helper: build an Ethernet + IPv4 + UDP packet ────────────────────────

namespace {

std::vector<uint8_t> makeUdpPacket( uint16_t srcPort, uint16_t dstPort,
                                     const std::vector<uint8_t>& payload )
{
    std::vector<uint8_t> pkt;

    // Ethernet header (14 bytes)
    pkt.insert( pkt.end(), { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF } ); // dst MAC
    pkt.insert( pkt.end(), { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } ); // src MAC
    pkt.push_back( 0x08 );
    pkt.push_back( 0x00 ); // IPv4

    // IPv4 header (20 bytes)
    uint16_t totalLen = static_cast<uint16_t>( 20 + 8 + payload.size() );
    pkt.push_back( 0x45 ); // v4, IHL=5
    pkt.push_back( 0x00 );
    pkt.push_back( static_cast<uint8_t>( totalLen >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( totalLen & 0xFF ) );
    pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } ); // ID, flags, frag
    pkt.push_back( 0x40 );                                // TTL=64
    pkt.push_back( 0x11 );                                // UDP
    pkt.insert( pkt.end(), { 0x00, 0x00 } );              // checksum
    pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x0A } );  // 192.168.1.10
    pkt.insert( pkt.end(), { 0x08, 0x08, 0x08, 0x08 } );  // 8.8.8.8

    // UDP header (8 bytes)
    uint16_t udpLen = static_cast<uint16_t>( 8 + payload.size() );
    pkt.push_back( static_cast<uint8_t>( srcPort >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( srcPort & 0xFF ) );
    pkt.push_back( static_cast<uint8_t>( dstPort >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( dstPort & 0xFF ) );
    pkt.push_back( static_cast<uint8_t>( udpLen >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( udpLen & 0xFF ) );
    pkt.insert( pkt.end(), { 0x00, 0x00 } ); // checksum

    pkt.insert( pkt.end(), payload.begin(), payload.end() );
    return pkt;
}

/// Build an Ethernet + IPv4 + ICMP Echo Request packet.
std::vector<uint8_t> makeIcmpEchoPacket()
{
    std::vector<uint8_t> pkt;

    // Ethernet header
    pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
    pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
    pkt.push_back( 0x08 );
    pkt.push_back( 0x00 ); // IPv4

    // IPv4 header (20 bytes), protocol = ICMP (1)
    pkt.push_back( 0x45 );
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 );
    pkt.push_back( 0x3C ); // total len = 60
    pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
    pkt.push_back( 0x40 ); // TTL=64
    pkt.push_back( 0x01 ); // ICMP
    pkt.insert( pkt.end(), { 0x00, 0x00 } );
    pkt.insert( pkt.end(), { 0x0A, 0x00, 0x00, 0x01 } ); // 10.0.0.1
    pkt.insert( pkt.end(), { 0x0A, 0x00, 0x00, 0x02 } ); // 10.0.0.2

    // ICMP Echo Request (type=8, code=0)
    pkt.push_back( 0x08 ); // type
    pkt.push_back( 0x00 ); // code
    pkt.insert( pkt.end(), { 0x00, 0x00 } ); // checksum
    pkt.insert( pkt.end(), { 0x00, 0x01 } ); // identifier
    pkt.insert( pkt.end(), { 0x00, 0x01 } ); // sequence
    // 32 bytes of padding
    for ( int i = 0; i < 32; ++i )
        pkt.push_back( static_cast<uint8_t>( i ) );

    return pkt;
}

/// Build an Ethernet + ARP Request packet.
std::vector<uint8_t> makeArpPacket()
{
    std::vector<uint8_t> pkt;

    // Ethernet header
    pkt.insert( pkt.end(), { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF } ); // broadcast
    pkt.insert( pkt.end(), { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } ); // sender
    pkt.push_back( 0x08 );
    pkt.push_back( 0x06 ); // ARP

    // ARP request (28 bytes)
    pkt.insert( pkt.end(), { 0x00, 0x01 } ); // HW type: Ethernet
    pkt.insert( pkt.end(), { 0x08, 0x00 } ); // Proto type: IPv4
    pkt.push_back( 0x06 );                   // HW size
    pkt.push_back( 0x04 );                   // Proto size
    pkt.insert( pkt.end(), { 0x00, 0x01 } ); // Opcode: Request

    // Sender MAC + IP
    pkt.insert( pkt.end(), { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 } );
    pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } ); // 192.168.1.1

    // Target MAC + IP
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } );
    pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x64 } ); // 192.168.1.100

    return pkt;
}

/// Build a complete pcap buffer from global header + N packets.
std::vector<uint8_t> buildPcap( uint32_t linkType,
                                 const std::vector<std::vector<uint8_t>>& packets )
{
    auto globalHdr = makeGlobalHeader( linkType );
    std::vector<uint8_t> buf( globalHdr.begin(), globalHdr.end() );

    uint32_t tsSec = 1000;
    for ( const auto& pktData : packets ) {
        auto pktHdr = makePacketHeader( tsSec, 0,
                                         static_cast<uint32_t>( pktData.size() ),
                                         static_cast<uint32_t>( pktData.size() ) );
        buf.insert( buf.end(), pktHdr.begin(), pktHdr.end() );
        buf.insert( buf.end(), pktData.begin(), pktData.end() );
        tsSec++;
    }
    return buf;
}

/// Build a Linux SLL2 wrapper (20 bytes) around a network-layer payload.
std::vector<uint8_t> wrapSll2( uint16_t etherType,
                                const std::vector<uint8_t>& payload )
{
    std::vector<uint8_t> pkt;
    // SLL2 header: ethertype at offset 0, rest is padding
    pkt.push_back( static_cast<uint8_t>( etherType >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( etherType & 0xFF ) );
    pkt.resize( 20, 0 ); // pad remaining 18 bytes
    pkt.insert( pkt.end(), payload.begin(), payload.end() );
    return pkt;
}

/// Build a minimal IPv4 + TCP SYN payload (no Ethernet header).
std::vector<uint8_t> makeRawIpv4Tcp( const uint8_t srcIp[ 4 ], const uint8_t dstIp[ 4 ],
                                      uint16_t srcPort, uint16_t dstPort )
{
    std::vector<uint8_t> pkt;

    // IPv4 header (20 bytes)
    pkt.push_back( 0x45 );
    pkt.push_back( 0x00 );
    pkt.push_back( 0x00 );
    pkt.push_back( 0x28 ); // total len = 40
    pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
    pkt.push_back( 0x40 ); // TTL
    pkt.push_back( 0x06 ); // TCP
    pkt.insert( pkt.end(), { 0x00, 0x00 } );
    pkt.insert( pkt.end(), srcIp, srcIp + 4 );
    pkt.insert( pkt.end(), dstIp, dstIp + 4 );

    // TCP header (20 bytes)
    pkt.push_back( static_cast<uint8_t>( srcPort >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( srcPort & 0xFF ) );
    pkt.push_back( static_cast<uint8_t>( dstPort >> 8 ) );
    pkt.push_back( static_cast<uint8_t>( dstPort & 0xFF ) );
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } ); // Seq
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } ); // Ack
    pkt.push_back( 0x50 );                                // data offset=5
    pkt.push_back( 0x02 );                                // SYN
    pkt.insert( pkt.end(), { 0xFF, 0xFF } );              // Window
    pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } ); // Checksum + Urgent

    return pkt;
}

} // anonymous namespace

// ── UDP Packet Tests ─────────────────────────────────────────────────────

SCENARIO( "Parsing a pcap with a UDP packet", "[pcap_parser]" )
{
    GIVEN( "a pcap containing one UDP packet on port 12345" )
    {
        auto pktData = makeUdpPacket( 12345, 9999, { 'H', 'e', 'l', 'l', 'o' } );
        auto buf = buildPcap( DltEthernet, { pktData } );

        WHEN( "parsing the buffer" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing succeeds with one UDP packet" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "UDP" );
                REQUIRE( result.packets[ 0 ].srcPort == 12345 );
                REQUIRE( result.packets[ 0 ].dstPort == 9999 );
                REQUIRE( result.packets[ 0 ].srcIp == "192.168.1.10" );
                REQUIRE( result.packets[ 0 ].dstIp == "8.8.8.8" );
                REQUIRE( result.packets[ 0 ].payloadLen == 5 );
            }
        }
    }
}

// ── DNS Detection Tests ──────────────────────────────────────────────────

SCENARIO( "DNS query is detected on port 53", "[pcap_parser]" )
{
    GIVEN( "a UDP packet to port 53 with a DNS query for example.com" )
    {
        // Minimal DNS query: header(12) + QNAME(13) + QTYPE(2) + QCLASS(2)
        std::vector<uint8_t> dns = {
            0x00, 0x01,  // Transaction ID
            0x01, 0x00,  // Flags: standard query
            0x00, 0x01,  // QDCOUNT = 1
            0x00, 0x00,  // ANCOUNT = 0
            0x00, 0x00,  // NSCOUNT = 0
            0x00, 0x00,  // ARCOUNT = 0
            // QNAME: example.com
            0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
            0x03, 'c', 'o', 'm',
            0x00,        // end of name
            0x00, 0x01,  // QTYPE: A
            0x00, 0x01   // QCLASS: IN
        };

        auto pktData = makeUdpPacket( 54321, 53, dns );
        auto buf = buildPcap( DltEthernet, { pktData } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "it is detected as DNS with the queried domain" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "DNS" );
                REQUIRE( result.packets[ 0 ].info.find( "Query" ) != std::string::npos );
                REQUIRE( result.packets[ 0 ].info.find( "example.com" )
                         != std::string::npos );
            }
        }
    }
}

// ── ICMP Tests ───────────────────────────────────────────────────────────

SCENARIO( "Parsing an ICMP Echo Request", "[pcap_parser]" )
{
    GIVEN( "a pcap with one ICMP echo request" )
    {
        auto pktData = makeIcmpEchoPacket();
        auto buf = buildPcap( DltEthernet, { pktData } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the protocol is ICMP and info shows Echo request" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "ICMP" );
                REQUIRE( result.packets[ 0 ].info.find( "Echo request" )
                         != std::string::npos );
                REQUIRE( result.packets[ 0 ].srcIp == "10.0.0.1" );
                REQUIRE( result.packets[ 0 ].dstIp == "10.0.0.2" );
            }
        }
    }
}

// ── ARP Tests ────────────────────────────────────────────────────────────

SCENARIO( "Parsing an ARP Request", "[pcap_parser]" )
{
    GIVEN( "a pcap with one ARP request" )
    {
        auto pktData = makeArpPacket();
        auto buf = buildPcap( DltEthernet, { pktData } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the protocol is ARP and info contains the target IP" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "ARP" );
                REQUIRE( result.packets[ 0 ].info.find( "Who has 192.168.1.100" )
                         != std::string::npos );
                REQUIRE( result.packets[ 0 ].info.find( "Tell 192.168.1.1" )
                         != std::string::npos );
            }
        }
    }
}

// ── Linux SLL2 Link Type Tests ───────────────────────────────────────────

SCENARIO( "Parsing a pcap with Linux SLL2 link type", "[pcap_parser]" )
{
    GIVEN( "a SLL2-encapsulated IPv4 TCP SYN packet" )
    {
        uint8_t src[] = { 0xAC, 0x10, 0xFA, 0xF8 }; // 172.16.250.248
        uint8_t dst[] = { 0xAC, 0x10, 0xFA, 0xC8 }; // 172.16.250.200
        auto ipTcp = makeRawIpv4Tcp( src, dst, 5555, 44321 );
        auto sll2Pkt = wrapSll2( EthertypeIpv4, ipTcp );
        auto buf = buildPcap( DltLinuxSll2, { sll2Pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing succeeds and extracts IP addresses" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].srcIp == "172.16.250.248" );
                REQUIRE( result.packets[ 0 ].dstIp == "172.16.250.200" );
                REQUIRE( result.packets[ 0 ].srcPort == 5555 );
            }

            THEN( "the link type is SLL2" )
            {
                REQUIRE( result.header.network == DltLinuxSll2 );
            }
        }
    }
}

// ── Text Preamble Scanning ───────────────────────────────────────────────

SCENARIO( "Parsing pcap with text preamble from adb/tcpdump", "[pcap_parser]" )
{
    GIVEN( "a pcap buffer preceded by tcpdump stderr text" )
    {
        std::string preamble = "tcpdump: listening on any, link-type LINUX_SLL2\n"
                               "tcpdump: verbose output suppressed\n";
        auto globalHdr = makeGlobalHeader( DltEthernet );
        auto pktData = makeTcpSynPacket();
        auto pktHdr = makePacketHeader( 1000, 0,
                                         static_cast<uint32_t>( pktData.size() ),
                                         static_cast<uint32_t>( pktData.size() ) );

        std::vector<uint8_t> buf( preamble.begin(), preamble.end() );
        buf.insert( buf.end(), globalHdr.begin(), globalHdr.end() );
        buf.insert( buf.end(), pktHdr.begin(), pktHdr.end() );
        buf.insert( buf.end(), pktData.begin(), pktData.end() );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing succeeds by scanning past the text" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].srcIp == "192.168.1.100" );
            }
        }
    }
}

// ── Big-Endian pcap Magic ────────────────────────────────────────────────

SCENARIO( "Parsing a big-endian pcap file", "[pcap_parser]" )
{
    GIVEN( "a pcap with swapped (big-endian) magic and global header" )
    {
        // Build a big-endian global header manually
        std::vector<uint8_t> hdr( 24, 0 );
        uint32_t magic = PcapMagicBE;
        std::memcpy( hdr.data(), &magic, 4 );

        // Version 2.4 (swapped)
        hdr[ 4 ] = 0x00;
        hdr[ 5 ] = 0x02;
        hdr[ 6 ] = 0x00;
        hdr[ 7 ] = 0x04;

        // snaplen 65535 (big-endian: MSB first)
        hdr[ 16 ] = 0x00;
        hdr[ 17 ] = 0x00;
        hdr[ 18 ] = 0xFF;
        hdr[ 19 ] = 0xFF;

        // network = 1 (Ethernet, big-endian)
        hdr[ 20 ] = 0x00;
        hdr[ 21 ] = 0x00;
        hdr[ 22 ] = 0x00;
        hdr[ 23 ] = 0x01;

        WHEN( "parsing just the header" )
        {
            auto result = parsePcap( hdr.data(), hdr.size() );

            THEN( "parsing succeeds and header fields are correctly swapped" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.header.versionMajor == 2 );
                REQUIRE( result.header.versionMinor == 4 );
                REQUIRE( result.header.network == DltEthernet );
            }
        }
    }
}

// ── pcap-ng Rejection ────────────────────────────────────────────────────

SCENARIO( "pcap-ng files are rejected with a clear error", "[pcap_parser]" )
{
    GIVEN( "a buffer starting with pcap-ng magic" )
    {
        std::vector<uint8_t> buf( 32, 0 );
        uint32_t magic = PcapNgMagic;
        std::memcpy( buf.data(), &magic, 4 );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "parsing fails with pcap-ng error message" )
            {
                REQUIRE_FALSE( result.ok );
                REQUIRE( result.error.find( "pcap-ng" ) != std::string::npos );
            }
        }
    }
}

// ── Raw IP Link Type ─────────────────────────────────────────────────────

SCENARIO( "Parsing a pcap with Raw IP (DLT 101) link type", "[pcap_parser]" )
{
    GIVEN( "a Raw IP pcap with a TCP SYN (no Ethernet header)" )
    {
        uint8_t src[] = { 0x0A, 0x00, 0x00, 0x01 };
        uint8_t dst[] = { 0x0A, 0x00, 0x00, 0x02 };
        auto rawPkt = makeRawIpv4Tcp( src, dst, 22, 50000 );
        auto buf = buildPcap( DltRaw, { rawPkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the packet is parsed correctly without MAC addresses" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].srcIp == "10.0.0.1" );
                REQUIRE( result.packets[ 0 ].dstIp == "10.0.0.2" );
                REQUIRE( result.packets[ 0 ].srcPort == 22 );
                REQUIRE( result.packets[ 0 ].srcMac.empty() );
            }
        }
    }
}

// ── VLAN Tagged Packet ───────────────────────────────────────────────────

SCENARIO( "Parsing a VLAN-tagged (802.1Q) packet", "[pcap_parser]" )
{
    GIVEN( "an Ethernet packet with a VLAN tag wrapping IPv4 TCP" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet header (14 bytes) with ethertype = 0x8100 (VLAN)
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x81 );
        pkt.push_back( 0x00 ); // VLAN

        // VLAN tag (4 bytes): VLAN ID + inner ethertype
        pkt.insert( pkt.end(), { 0x00, 0x64 } ); // VLAN ID 100
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 ); // inner ethertype: IPv4

        // IPv4 + TCP
        uint8_t src[] = { 0xC0, 0xA8, 0x01, 0x01 };
        uint8_t dst[] = { 0xC0, 0xA8, 0x01, 0x02 };
        auto ipTcp = makeRawIpv4Tcp( src, dst, 80, 50000 );
        pkt.insert( pkt.end(), ipTcp.begin(), ipTcp.end() );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the VLAN tag is stripped and IPv4 is parsed" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].srcIp == "192.168.1.1" );
                REQUIRE( result.packets[ 0 ].dstIp == "192.168.1.2" );
                REQUIRE( result.packets[ 0 ].srcPort == 80 );
                REQUIRE( result.packets[ 0 ].etherType == EthertypeIpv4 );
            }
        }
    }
}

// ── Multiple Packets ─────────────────────────────────────────────────────

SCENARIO( "Parsing a pcap with multiple different protocol packets", "[pcap_parser]" )
{
    GIVEN( "a pcap with TCP, UDP, ICMP, and ARP packets" )
    {
        auto tcp = makeTcpSynPacket();
        auto udp = makeUdpPacket( 12345, 9999, { 'H', 'e', 'l', 'l', 'o' } );
        auto icmp = makeIcmpEchoPacket();
        auto arp = makeArpPacket();

        auto buf = buildPcap( DltEthernet, { tcp, udp, icmp, arp } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "all four packets are parsed with correct protocols" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 4 );
                // TCP SYN on port 80 → HTTP
                REQUIRE( result.packets[ 0 ].protocol == "HTTP" );
                REQUIRE( result.packets[ 1 ].protocol == "UDP" );
                REQUIRE( result.packets[ 2 ].protocol == "ICMP" );
                REQUIRE( result.packets[ 3 ].protocol == "ARP" );
            }

            THEN( "packet numbers are sequential" )
            {
                REQUIRE( result.packets[ 0 ].number == 1 );
                REQUIRE( result.packets[ 1 ].number == 2 );
                REQUIRE( result.packets[ 2 ].number == 3 );
                REQUIRE( result.packets[ 3 ].number == 4 );
            }
        }
    }
}

// ── TLS Detection ────────────────────────────────────────────────────────

SCENARIO( "TLS ClientHello is detected in TCP payload", "[pcap_parser]" )
{
    GIVEN( "a TCP packet to port 443 with a TLS ClientHello" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet header
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4 header (20 bytes) — total_len will cover IP+TCP+payload
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 ); // placeholder total len
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 ); // TCP
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP header (20 bytes)
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 ); // src port 49152
        pkt.push_back( 0x01 );
        pkt.push_back( 0xBB ); // dst port 443
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 ); // data offset 5
        pkt.push_back( 0x18 ); // PSH, ACK
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // TLS record: ContentType=Handshake(0x16), Version=TLS1.2(0x0303)
        pkt.push_back( 0x16 ); // Handshake
        pkt.push_back( 0x03 );
        pkt.push_back( 0x03 ); // TLS 1.2
        pkt.push_back( 0x00 );
        pkt.push_back( 0x05 ); // length
        pkt.push_back( 0x01 ); // ClientHello

        // Fix IP total length
        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the protocol is TLS and info contains Client Hello" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "TLS" );
                REQUIRE( result.packets[ 0 ].info.find( "Client Hello" )
                         != std::string::npos );
            }
        }
    }
}

// ── HTTP Detection ───────────────────────────────────────────────────────

SCENARIO( "HTTP GET request is detected in TCP payload", "[pcap_parser]" )
{
    GIVEN( "a TCP packet to port 80 with an HTTP GET request" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 ); // placeholder
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP
        pkt.push_back( 0xD0 );
        pkt.push_back( 0x00 ); // src port 53248
        pkt.push_back( 0x00 );
        pkt.push_back( 0x50 ); // dst port 80
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 ); // PSH, ACK
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // HTTP payload
        std::string http = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        pkt.insert( pkt.end(), http.begin(), http.end() );

        // Fix IP total length
        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the protocol is HTTP and info contains the request line" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "HTTP" );
                REQUIRE( result.packets[ 0 ].info.find( "GET /index.html" )
                         != std::string::npos );
            }
        }
    }
}

// ── Truncated IPv4 Header ────────────────────────────────────────────────

SCENARIO( "Truncated IPv4 header is handled gracefully", "[pcap_parser]" )
{
    GIVEN( "an Ethernet frame with only 10 bytes of IPv4 data" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet header
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // Only 10 bytes of IPv4 (needs 20)
        pkt.insert( pkt.end(), { 0x45, 0x00, 0x00, 0x28, 0x00, 0x01,
                                  0x00, 0x00, 0x40, 0x06 } );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the packet is parsed but marked as truncated" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "IPv4" );
                REQUIRE( result.packets[ 0 ].info.find( "Truncated" )
                         != std::string::npos );
            }
        }
    }
}

// ── Port-based Protocol Hint Tests ───────────────────────────────────────

SCENARIO( "Port-based protocol names for well-known services", "[pcap_parser]" )
{
    GIVEN( "a TCP SYN to SSH port 22 (no payload)" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x28 ); // 40 bytes
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP to port 22, SYN
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 ); // src 49152
        pkt.push_back( 0x00 );
        pkt.push_back( 0x16 ); // dst 22
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x02 ); // SYN
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "protocol is identified as SSH" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets[ 0 ].protocol == "SSH" );
            }
        }
    }
}

// ── Payload Preview Tests ────────────────────────────────────────────────

SCENARIO( "Payload preview shows full text without truncation", "[pcap_parser]" )
{
    GIVEN( "a TCP packet with a long printable payload (> 80 chars)" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 ); // placeholder
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP header (20 bytes) on non-well-known ports
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 ); // src 49152
        pkt.push_back( 0xEA );
        pkt.push_back( 0x61 ); // dst 60001
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 ); // PSH, ACK
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // Long text payload (120 chars)
        std::string longText =
            "07-08 10:29:23.549  7182  7413 W HERE_CARLO: "
            "[carlo] /workspace/coresdk/carlo/location_engine.cpp:42 "
            "initializing module";
        pkt.insert( pkt.end(), longText.begin(), longText.end() );

        // Fix IP total length
        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the full payload text is shown without ellipsis" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                auto& info = result.packets[ 0 ].info;
                // Full text must be present, no truncation
                REQUIRE( info.find( "initializing module" ) != std::string::npos );
                // No ellipsis character
                REQUIRE( info.find( "\xe2\x80\xa6" ) == std::string::npos );
            }
        }
    }
}

SCENARIO( "Payload preview collapses binary runs to spaces", "[pcap_parser]" )
{
    GIVEN( "a TCP packet with mixed binary and text payload" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0xEA );
        pkt.push_back( 0x61 );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 );
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // Payload: text with binary bytes in between
        // "Hello" + 5 binary bytes + "World"
        std::string text1 = "Hello";
        std::string text2 = "World and more text here to meet threshold";
        pkt.insert( pkt.end(), text1.begin(), text1.end() );
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x02, 0x03, 0x04 } );
        pkt.insert( pkt.end(), text2.begin(), text2.end() );

        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "binary bytes are collapsed to a single space, not dots" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                auto& info = result.packets[ 0 ].info;
                // Both text parts visible
                REQUIRE( info.find( "Hello" ) != std::string::npos );
                REQUIRE( info.find( "World" ) != std::string::npos );
                // No runs of dots
                REQUIRE( info.find( "....." ) == std::string::npos );
            }
        }
    }
}

SCENARIO( "Predominantly binary payload is suppressed", "[pcap_parser]" )
{
    GIVEN( "a TCP packet with mostly binary payload" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0xEA );
        pkt.push_back( 0x61 );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 );
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // Payload: 3 printable chars then 50 binary bytes (< 40% printable)
        pkt.insert( pkt.end(), { 'A', 'B', 'C' } );
        for ( int i = 0; i < 50; ++i )
            pkt.push_back( static_cast<uint8_t>( i ) );

        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "the info line has no payload preview (binary suppressed)" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                // No " | " separator means no preview was appended
                REQUIRE( result.packets[ 0 ].info.find( " | " ) == std::string::npos );
            }
        }
    }
}

// ── NMEA Detection Tests ─────────────────────────────────────────────────

SCENARIO( "Valid NMEA sentence is detected in TCP payload", "[pcap_parser]" )
{
    GIVEN( "a TCP packet containing a $GAGSV NMEA sentence" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x01 } );
        pkt.insert( pkt.end(), { 0xC0, 0xA8, 0x01, 0x02 } );

        // TCP (non-well-known ports)
        pkt.push_back( 0xC0 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0xEA );
        pkt.push_back( 0x61 );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 );
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // NMEA sentence with mandatory comma
        std::string nmea = "$GAGSV,2,2,08,21,41,270,11*76\r\n";
        pkt.insert( pkt.end(), nmea.begin(), nmea.end() );

        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "protocol is NMEA and info contains the sentence" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol == "NMEA" );
                REQUIRE( result.packets[ 0 ].info.find( "$GAGSV" )
                         != std::string::npos );
            }
        }
    }
}

SCENARIO( "ADB $WRTE frames are not misidentified as NMEA", "[pcap_parser]" )
{
    GIVEN( "a TCP packet on ADB port 5555 with $WRTEJ payload (no comma)" )
    {
        std::vector<uint8_t> pkt;

        // Ethernet
        pkt.insert( pkt.end(), { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 } );
        pkt.insert( pkt.end(), { 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB } );
        pkt.push_back( 0x08 );
        pkt.push_back( 0x00 );

        // IPv4
        auto ipStart = pkt.size();
        pkt.push_back( 0x45 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.push_back( 0x00 );
        pkt.insert( pkt.end(), { 0x00, 0x01, 0x00, 0x00 } );
        pkt.push_back( 0x40 );
        pkt.push_back( 0x06 );
        pkt.insert( pkt.end(), { 0x00, 0x00 } );
        pkt.insert( pkt.end(), { 0xAC, 0x10, 0xFA, 0xF8 } ); // 172.16.250.248
        pkt.insert( pkt.end(), { 0xAC, 0x10, 0xFA, 0xC8 } ); // 172.16.250.200

        // TCP src=5555, dst=60217
        pkt.push_back( 0x15 );
        pkt.push_back( 0xB3 ); // 5555
        pkt.push_back( 0xEB );
        pkt.push_back( 0x39 ); // 60217
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x01 } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );
        pkt.push_back( 0x50 );
        pkt.push_back( 0x18 );
        pkt.insert( pkt.end(), { 0xFF, 0xFF } );
        pkt.insert( pkt.end(), { 0x00, 0x00, 0x00, 0x00 } );

        // ADB-like payload: "$WRTEJ" + binary (no comma → not NMEA)
        pkt.insert( pkt.end(), { '$', 'W', 'R', 'T', 'E', 'J', 0x00, 0x02,
                                  0x00, 0x80, 0x01, 0x00, 0x00, 0x00 } );
        // Add enough printable text after to pass the 40% threshold
        std::string logLine = "07-08 10:29:23.549  7182  7413 W TAG: some log message here";
        pkt.insert( pkt.end(), logLine.begin(), logLine.end() );

        uint16_t totalLen = static_cast<uint16_t>( pkt.size() - ipStart );
        pkt[ ipStart + 2 ] = static_cast<uint8_t>( totalLen >> 8 );
        pkt[ ipStart + 3 ] = static_cast<uint8_t>( totalLen & 0xFF );

        auto buf = buildPcap( DltEthernet, { pkt } );

        WHEN( "parsing" )
        {
            auto result = parsePcap( buf.data(), buf.size() );

            THEN( "protocol is ADB (port-based), NOT NMEA" )
            {
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].protocol != "NMEA" );
                REQUIRE( result.packets[ 0 ].protocol == "ADB" );
            }
        }
    }
}
