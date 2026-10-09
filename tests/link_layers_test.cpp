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
 * @file link_layers_test.cpp
 * @brief BDD tests for the 802.11 (with Radiotap), PPP, Cisco HDLC and PPPoE
 *        link layers.
 */

#include <catch2/catch.hpp>

#include "link_layers.h"
#include "pcapbuilder.h"

#include <random>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

// ── 802.11 frames ────────────────────────────────────────────────────────

const Bytes kStation{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const Bytes kAccessPoint{ 0x02, 0x00, 0x00, 0x00, 0x00, 0xAA };
const Bytes kServer{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const Bytes kBroadcast( 6, 0xFF );

/// Frame control flags (the second byte).
constexpr uint8_t kToDs = 0x01;
constexpr uint8_t kFromDs = 0x02;
constexpr uint8_t kMoreFragments = 0x04;
constexpr uint8_t kProtected = 0x40;
constexpr uint8_t kOrder = 0x80;

/// An 802.11 frame of @p type and @p subtype with three addresses and a
/// sequence control (sequence number @p sn, fragment 0); a fourth address
/// with both DS flags.
Bytes wifi( uint8_t type, uint8_t subtype, uint8_t flags, const Bytes& a1, const Bytes& a2,
            const Bytes& a3, uint16_t sn, const Bytes& rest = {}, const Bytes& a4 = kServer )
{
    Bytes b{ static_cast<uint8_t>( ( subtype << 4 ) | ( type << 2 ) ), flags };
    putLE16( b, 314 ); // duration
    b = b + a1 + a2 + a3;
    putLE16( b, static_cast<uint16_t>( sn << 4 ) );
    if ( ( flags & ( kToDs | kFromDs ) ) == ( kToDs | kFromDs ) ) {
        b = b + a4;
    }
    return b + rest;
}

/// A management frame from the access point to @p dst.
Bytes management( uint8_t subtype, const Bytes& body, const Bytes& dst = kBroadcast,
                  uint8_t flags = 0 )
{
    return wifi( 0, subtype, flags, dst, kAccessPoint, kAccessPoint, 100, body );
}

/// An information element.
Bytes element( uint8_t id, const Bytes& value )
{
    Bytes b{ id, static_cast<uint8_t>( value.size() ) };
    return b + value;
}

/// A beacon's or probe response's fixed fields: timestamp, interval 100 TU,
/// capabilities.
Bytes beaconFields()
{
    Bytes b( 8, 0 );
    putLE16( b, 100 );
    putLE16( b, 0x0431 );
    return b;
}

/// LLC/SNAP for @p etherType.
Bytes snap( uint16_t etherType, const Bytes& payload )
{
    Bytes b{ 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 };
    putBE16( b, etherType );
    return b + payload;
}

const Bytes kUdpPacket = ipv4( IpProtoUdp, udp( 5000, 53 ) );

/// A Radiotap header with TSFT, flags, rate, channel and signal fields,
/// @p extraPresent words more in the present bitmap.
Bytes radiotap( uint8_t flags, int extraPresent = 0 )
{
    Bytes b{ 0, 0, 0, 0 };              // version, pad, length (set below)
    const uint32_t fields = 0x0000002F; // TSFT, flags, rate, channel, signal
    putLE32( b, fields | ( extraPresent > 0 ? 0x80000000 : 0 ) );
    for ( int i = 0; i < extraPresent; ++i ) {
        putLE32( b, i + 1 < extraPresent ? 0x80000000 : 0 );
    }
    b.resize( ( b.size() + 7 ) / 8 * 8, 0 ); // TSFT is 8-aligned
    putLE32( b, 0x12345678 );
    putLE32( b, 0 );
    b.push_back( flags );
    b.push_back( 12 );  // rate: 6 Mb/s
    putLE16( b, 2437 ); // channel 6
    putLE16( b, 0x00A0 );
    b.push_back( 0xC4 ); // -60 dBm
    b[ 2 ] = static_cast<uint8_t>( b.size() );
    b[ 3 ] = static_cast<uint8_t>( b.size() >> 8 );
    return b;
}

PacketRecord only( const Bytes& frame, uint32_t linkType )
{
    auto result = parse( pcapOf( { frame }, linkType ) );
    REQUIRE( result.packets.size() == 1 );
    return result.packets[ 0 ];
}

// ── PPP and PPPoE ────────────────────────────────────────────────────────

/// A PPP frame of @p protocol in HDLC-like framing (address and control).
Bytes ppp( uint16_t protocol, const Bytes& payload )
{
    Bytes b{ 0xFF, 0x03 };
    putBE16( b, protocol );
    return b + payload;
}

/// A packet of a PPP control protocol (LCP, IPCP, PAP, …).
Bytes control( uint8_t code, const Bytes& data = {} )
{
    Bytes b{ code, 7 };
    putBE16( b, static_cast<uint16_t>( 4 + data.size() ) );
    return b + data;
}

/// A PPPoE header with @p code for session 0x1234 around @p payload.
Bytes pppoe( uint8_t code, const Bytes& payload, int length = -1 )
{
    Bytes b{ 0x11, code };
    putBE16( b, code == 0 ? 0x1234 : 0 );
    putBE16( b, static_cast<uint16_t>( length >= 0 ? length : payload.size() ) );
    return b + payload;
}

/// A PPPoE session frame carrying PPP @p protocol, without address and control.
Bytes pppoeSession( uint16_t protocol, const Bytes& payload )
{
    Bytes b;
    putBE16( b, protocol );
    return pppoe( 0x00, b + payload );
}

/// A PPPoE discovery tag.
Bytes tag( uint16_t type, const Bytes& value )
{
    Bytes b;
    putBE16( b, type );
    putBE16( b, static_cast<uint16_t>( value.size() ) );
    return b + value;
}

} // namespace

// ── Radiotap ─────────────────────────────────────────────────────────────

SCENARIO( "A Radiotap header is skipped by its length", "[link_layers]" )
{
    const auto data = wifi( 2, 0, kToDs, kAccessPoint, kStation, kServer, 7,
                            snap( EthertypeIpv4, kUdpPacket ) );

    for ( const int extra : { 0, 1, 2 } ) {
        GIVEN( "a data frame behind a Radiotap header with " + std::to_string( extra )
               + " extended present bitmaps" )
        {
            const auto pkt = only( radiotap( 0, extra ) + data, DltIeee80211Radio );

            THEN( "the frame's IP packet is dissected" )
            {
                REQUIRE( pkt.protocol == "DNS" );
                REQUIRE( pkt.srcIp == "192.168.1.1" );
                REQUIRE( pkt.dstPort == 53 );
            }
        }
    }

    GIVEN( "a frame whose Radiotap flags say it ends in a frame check sequence" )
    {
        Ipv4Options o;
        o.totalLength = 0; // TSO: the captured bytes are the packet
        const auto frame
            = radiotap( 0x10 )
              + wifi( 2, 0, kFromDs, kStation, kAccessPoint, kServer, 7,
                      snap( EthertypeIpv4,
                            ipv4( IpProtoTcp, tcp( 40000, 40001, text( "0123456789" ) ), o ) ) )
              + Bytes{ 0xDE, 0xAD, 0xBE, 0xEF };

        THEN( "the FCS is not taken for payload" )
        {
            const auto pkt = only( frame, DltIeee80211Radio );
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.payloadLen == 10 );
        }
    }

    GIVEN( "a QoS data frame whose Radiotap flags say its header is padded" )
    {
        Bytes qos{ 0x00, 0x00, 0x00, 0x00 }; // QoS control, then 2 bytes of padding to 28
        const auto frame = radiotap( 0x20 )
                           + wifi( 2, 8, kToDs, kAccessPoint, kStation, kServer, 7,
                                   qos + snap( EthertypeIpv4, kUdpPacket ) );

        THEN( "the padding is skipped" )
        {
            REQUIRE( only( frame, DltIeee80211Radio ).protocol == "DNS" );
        }
    }

    GIVEN( "Radiotap headers that are cut short or longer than the packet" )
    {
        auto tooLong = radiotap( 0 );
        tooLong[ 2 ] = 200;
        auto badVersion = radiotap( 0 );
        badVersion[ 0 ] = 1;
        // The present bitmap says another follows, past the header's 8 bytes.
        const Bytes endlessBitmap{ 0, 0, 8, 0, 0x02, 0, 0, 0x80, 0x80, 0, 0, 0 };

        THEN( "they are named as such" )
        {
            REQUIRE( only( Bytes{ 0, 0, 8 }, DltIeee80211Radio ).info
                     == "Truncated Radiotap header" );
            const auto pkt = only( tooLong, DltIeee80211Radio );
            REQUIRE( pkt.protocol == "Radiotap" );
            REQUIRE( pkt.info == "Invalid Radiotap header length 200" );
            REQUIRE( only( badVersion, DltIeee80211Radio ).info == "Radiotap version 1" );
            REQUIRE( only( endlessBitmap, DltIeee80211Radio ).protocol == "Radiotap" );
        }
    }
}

// ── 802.11 ───────────────────────────────────────────────────────────────

SCENARIO( "802.11 data frames reach their network layer", "[link_layers]" )
{
    GIVEN( "a data frame from a station to the distribution system" )
    {
        const auto pkt = only( wifi( 2, 0, kToDs, kAccessPoint, kStation, kServer, 7,
                                     snap( EthertypeIpv4, kUdpPacket ) ),
                               DltIeee80211 );

        THEN( "its IP packet is dissected, and the MACs are source and destination" )
        {
            REQUIRE( pkt.protocol == "DNS" );
            REQUIRE( pkt.etherType == EthertypeIpv4 );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:02" );
        }
    }

    GIVEN( "a QoS data frame from the distribution system carrying IPv6" )
    {
        const auto pkt
            = only( wifi( 2, 8, kFromDs, kStation, kAccessPoint, kServer, 7,
                          Bytes{ 0, 0 } + snap( EthertypeIpv6, ipv6( IpProtoUdp, udp( 1, 2 ) ) ) ),
                    DltIeee80211 );

        THEN( "it reaches IPv6, the source being the third address" )
        {
            REQUIRE( pkt.protocol == "UDP" );
            REQUIRE( pkt.srcIp == "fe80::1" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:02" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:01" );
        }
    }

    GIVEN( "a four-address data frame with an HT control field" )
    {
        const Bytes qosAndHtc{ 0, 0, 0, 0, 0, 0 };
        const auto pkt
            = only( wifi( 2, 8, kToDs | kFromDs | kOrder, kAccessPoint, kStation, kBroadcast, 7,
                          qosAndHtc + snap( EthertypeArp, Bytes( 28, 0 ) ), kServer ),
                    DltIeee80211 );

        THEN( "the fourth address is the source and ARP is reached" )
        {
            REQUIRE( pkt.protocol == "ARP" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:02" );
            REQUIRE( pkt.dstMac == "ff:ff:ff:ff:ff:ff" );
        }
    }

    GIVEN( "an EAPOL key frame" )
    {
        const auto pkt = only( wifi( 2, 8, kFromDs, kStation, kAccessPoint, kAccessPoint, 0,
                                     Bytes{ 0, 0 } + snap( 0x888E, Bytes( 8, 0 ) ) ),
                               DltIeee80211 );

        THEN( "it is named by its EtherType" )
        {
            REQUIRE( pkt.protocol == "EAPOL" );
        }
    }

    GIVEN( "data frames that are protected, fragmented, empty or not SNAP" )
    {
        THEN( "they are described as 802.11 or LLC frames" )
        {
            auto pkt = only( wifi( 2, 8, kToDs | kProtected, kAccessPoint, kStation, kServer, 42,
                                   Bytes( 40, 0x5A ) ),
                             DltIeee80211 );
            REQUIRE( pkt.protocol == "802.11" );
            REQUIRE( pkt.info == "QoS Data, SN=42, FN=0, Protected" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:02" );

            pkt = only( wifi( 2, 0, kToDs | kMoreFragments, kAccessPoint, kStation, kServer, 3,
                              snap( EthertypeIpv4, kUdpPacket ) ),
                        DltIeee80211 );
            REQUIRE( pkt.info == "Data, SN=3, FN=0, Fragmented" );

            pkt = only( wifi( 2, 4, kToDs, kAccessPoint, kStation, kAccessPoint, 9 ),
                        DltIeee80211 );
            REQUIRE( pkt.protocol == "802.11" );
            REQUIRE( pkt.info == "Null function (No data), SN=9, FN=0" );

            pkt = only( wifi( 2, 0, kToDs, kAccessPoint, kStation, kServer, 3,
                              Bytes{ 0x42, 0x42, 0x03, 0, 0, 0 } ),
                        DltIeee80211 );
            REQUIRE( pkt.protocol == "LLC" );
            REQUIRE( pkt.info == "Data, SN=3, FN=0, DSAP 0x42 SSAP 0x42" );
        }
    }
}

SCENARIO( "802.11 management and control frames are named", "[link_layers]" )
{
    GIVEN( "a beacon" )
    {
        const auto pkt = only( management( 8, beaconFields() + element( 0, text( "HomeNet" ) )
                                                  + element( 1, { 0x82, 0x84 } ) ),
                               DltIeee80211 );

        THEN( "Info names it with its sequence number, interval and SSID" )
        {
            REQUIRE( pkt.protocol == "802.11" );
            REQUIRE( pkt.info == "Beacon frame, SN=100, FN=0, BI=100, SSID=\"HomeNet\"" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:aa" );
            REQUIRE( pkt.dstMac == "ff:ff:ff:ff:ff:ff" );
            REQUIRE( pkt.srcIp.empty() );
        }
    }

    GIVEN( "the other management frames" )
    {
        THEN( "each is named as Wireshark names it" )
        {
            REQUIRE( only( management( 4, element( 0, {} ) ), DltIeee80211 ).info
                     == "Probe Request, SN=100, FN=0, SSID=Wildcard (Broadcast)" );
            REQUIRE( only( management( 5, beaconFields() + element( 0, text( "Cafe" ) ), kStation ),
                           DltIeee80211 )
                         .info
                     == "Probe Response, SN=100, FN=0, BI=100, SSID=\"Cafe\"" );
            REQUIRE( only( management( 0, Bytes{ 0x31, 0x04, 0x0A, 0x00 }
                                              + element( 0, text( "Cafe" ) ) ),
                           DltIeee80211 )
                         .info
                     == "Association Request, SN=100, FN=0, SSID=\"Cafe\"" );
            REQUIRE(
                only( management( 2, Bytes( 10, 0 ) + element( 0, text( "Cafe" ) ) ), DltIeee80211 )
                    .info
                == "Reassociation Request, SN=100, FN=0, SSID=\"Cafe\"" );
            REQUIRE( only( management( 1, Bytes( 6, 0 ) ), DltIeee80211 ).info
                     == "Association Response, SN=100, FN=0" );
            REQUIRE( only( management( 11, Bytes( 6, 0 ) ), DltIeee80211 ).info
                     == "Authentication, SN=100, FN=0" );
            REQUIRE( only( management( 12, { 3, 0 } ), DltIeee80211 ).info
                     == "Deauthentication, SN=100, FN=0" );
            REQUIRE( only( management( 10, { 8, 0 } ), DltIeee80211 ).info
                     == "Disassociate, SN=100, FN=0" );
            REQUIRE(
                only( management( 13, Bytes( 4, 0 ), kStation, kProtected ), DltIeee80211 ).info
                == "Action, SN=100, FN=0, Protected" );
        }
    }

    GIVEN( "SSIDs that need escaping, are too long or run past the frame" )
    {
        THEN( "the SSID is escaped, cut, or left out" )
        {
            REQUIRE( only( management( 8, beaconFields() + element( 0, text( "a\"b\nc" ) ) ),
                           DltIeee80211 )
                         .info
                     == "Beacon frame, SN=100, FN=0, BI=100, SSID=\"a\\\"b\\x0Ac\"" );
            const auto info
                = only( management( 8, beaconFields() + element( 0, Bytes( 200, 'x' ) ) ),
                        DltIeee80211 )
                      .info;
            REQUIRE( info.find( "SSID=\"xxx" ) != std::string::npos );
            REQUIRE( info.size() < 200 );
            REQUIRE( info.find( "\xe2\x80\xa6" ) != std::string::npos );
            REQUIRE(
                only( management( 8, beaconFields() + Bytes{ 0, 20, 'a' } ), DltIeee80211 ).info
                == "Beacon frame, SN=100, FN=0, BI=100" );
        }
    }

    GIVEN( "control frames" )
    {
        Bytes ack{ 0xD4, 0x00, 0x00, 0x00 };
        ack = ack + kStation;
        Bytes rts{ 0xB4, 0x00, 0x00, 0x00 };
        rts = rts + kAccessPoint + kStation;

        THEN( "they are named, with their receiver and transmitter" )
        {
            auto pkt = only( ack, DltIeee80211 );
            REQUIRE( pkt.protocol == "802.11" );
            REQUIRE( pkt.info == "Acknowledgement" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.srcMac.empty() );
            pkt = only( rts, DltIeee80211 );
            REQUIRE( pkt.info == "Request-to-send" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:aa" );
        }
    }

    GIVEN( "a frame cut inside its header" )
    {
        THEN( "it is named as such" )
        {
            const auto pkt = only( Bytes{ 0x80, 0x00, 0x00 }, DltIeee80211 );
            REQUIRE( pkt.protocol == "802.11" );
            REQUIRE( pkt.info == "Truncated 802.11 header" );
            REQUIRE( only( Bytes( 20, 0 ), DltIeee80211 ).info == "Truncated 802.11 header" );
        }
    }
}

// ── PPP ──────────────────────────────────────────────────────────────────

SCENARIO( "PPP frames reach IP and name their control protocols", "[link_layers]" )
{
    for ( const uint32_t linkType : { DltPpp, DltPppSerial } ) {
        GIVEN( "PPP frames of link-layer type " + std::to_string( linkType ) )
        {
            THEN( "IPv4 and IPv6 are dissected" )
            {
                auto pkt = only( ppp( 0x0021, kUdpPacket ), linkType );
                REQUIRE( pkt.protocol == "DNS" );
                REQUIRE( pkt.etherType == EthertypeIpv4 );
                REQUIRE( only( ppp( 0x0057, ipv6( IpProtoUdp, udp( 1, 2 ) ) ), linkType ).srcIp
                         == "fe80::1" );
            }

            THEN( "control protocols are named with their code" )
            {
                auto pkt = only( ppp( 0xC021, control( 1, { 1, 4, 0x05, 0xDC } ) ), linkType );
                REQUIRE( pkt.protocol == "LCP" );
                REQUIRE( pkt.info == "Configuration Request" );
                REQUIRE( only( ppp( 0xC021, control( 10, Bytes( 4, 0 ) ) ), linkType ).info
                         == "Echo Reply" );
                pkt = only( ppp( 0x8021, control( 2, { 3, 6, 10, 0, 0, 1 } ) ), linkType );
                REQUIRE( pkt.protocol == "IPCP" );
                REQUIRE( pkt.info == "Configuration Ack" );
                REQUIRE( only( ppp( 0x8057, control( 1 ) ), linkType ).protocol == "IPv6CP" );
                pkt = only( ppp( 0xC023, control( 1, { 4, 'u', 's', 'e', 'r' } ) ), linkType );
                REQUIRE( pkt.protocol == "PAP" );
                REQUIRE( pkt.info == "Authenticate-Request" );
                pkt = only( ppp( 0xC223, control( 1, Bytes( 17, 1 ) ) ), linkType );
                REQUIRE( pkt.protocol == "CHAP" );
                REQUIRE( pkt.info == "Challenge" );
                REQUIRE( only( ppp( 0xC021, control( 99 ) ), linkType ).info == "Code 99" );
                REQUIRE( only( ppp( 0xC021, { 1 } ), linkType ).info == "Truncated LCP packet" );
            }

            THEN( "another protocol keeps its number" )
            {
                const auto pkt = only( ppp( 0x0281, Bytes( 4, 0 ) ), linkType );
                REQUIRE( pkt.protocol == "PPP" );
                REQUIRE( pkt.info == "PPP protocol 0x0281" );
            }
        }
    }

    GIVEN( "PPP frames without address and control, and with a compressed protocol" )
    {
        Bytes noAddress{ 0x00, 0x21 };
        Bytes compressed{ 0x21 };

        THEN( "they reach IP too" )
        {
            REQUIRE( only( noAddress + kUdpPacket, DltPpp ).protocol == "DNS" );
            REQUIRE( only( compressed + kUdpPacket, DltPpp ).protocol == "DNS" );
        }
    }

    GIVEN( "Cisco HDLC frames" )
    {
        Bytes unicast{ 0x0F, 0x00 };
        putBE16( unicast, EthertypeIpv4 );
        Bytes multicast{ 0x8F, 0x00 };
        putBE16( multicast, EthertypeIpv6 );

        THEN( "they reach IP by their EtherType" )
        {
            REQUIRE( only( unicast + kUdpPacket, DltPppSerial ).protocol == "DNS" );
            REQUIRE( only( unicast + kUdpPacket, DltCiscoHdlc ).protocol == "DNS" );
            REQUIRE( only( multicast + ipv6( IpProtoUdp, udp( 1, 2 ) ), DltCiscoHdlc ).srcIp
                     == "fe80::1" );
        }
    }

    GIVEN( "PPP frames cut short" )
    {
        THEN( "they are named as such" )
        {
            REQUIRE( only( Bytes{ 0xFF }, DltPpp ).info == "Truncated PPP header" );
            REQUIRE( only( Bytes{ 0xFF, 0x03, 0x00 }, DltPppSerial ).info
                     == "Truncated PPP header" );
            REQUIRE( only( Bytes{ 0x0F, 0x00, 0x08 }, DltCiscoHdlc ).protocol == "CHDLC" );
        }
    }
}

// ── PPPoE ────────────────────────────────────────────────────────────────

SCENARIO( "PPPoE session frames reach IP, discovery messages are named", "[link_layers]" )
{
    GIVEN( "a PPPoE session frame carrying IPv4" )
    {
        const auto pkt
            = only( eth( EthertypePppoeSession, pppoeSession( 0x0021, kUdpPacket ) ), DltEthernet );

        THEN( "its IP packet is dissected, with the Ethernet MACs" )
        {
            REQUIRE( pkt.protocol == "DNS" );
            REQUIRE( pkt.srcIp == "192.168.1.1" );
            REQUIRE( pkt.srcMac == "66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a PPPoE session frame in a VLAN, as ISPs tag them" )
    {
        const auto pkt
            = only( eth( EthertypeVlan,
                         vlanTag( 7, EthertypePppoeSession,
                                  pppoeSession( 0x0057, ipv6( IpProtoUdp, udp( 1, 2 ) ) ) ) ),
                    DltEthernet );

        THEN( "it reaches IPv6" )
        {
            REQUIRE( pkt.protocol == "UDP" );
            REQUIRE( pkt.srcIp == "fe80::1" );
        }
    }

    GIVEN( "a session frame padded behind its PPPoE length" )
    {
        Ipv4Options o;
        o.totalLength = 0; // TSO: the captured bytes are the packet
        const auto frame
            = eth( EthertypePppoeSession,
                   pppoeSession( 0x0021, ipv4( IpProtoTcp, tcp( 80, 5000, text( "abc" ) ), o ) )
                       + Bytes( 6, 0 ) );

        THEN( "the padding is not taken for payload" )
        {
            REQUIRE( only( frame, DltEthernet ).payloadLen == 3 );
        }
    }

    GIVEN( "session frames carrying LCP and discovery messages" )
    {
        THEN( "they are named" )
        {
            auto pkt = only(
                eth( EthertypePppoeSession, pppoeSession( 0xC021, control( 9, Bytes( 4, 0 ) ) ) ),
                DltEthernet );
            REQUIRE( pkt.protocol == "LCP" );
            REQUIRE( pkt.info == "Echo Request" );

            pkt = only( eth( EthertypePppoeDiscovery, pppoe( 0x09, tag( 0x0101, {} ) ) ),
                        DltEthernet );
            REQUIRE( pkt.protocol == "PPPoED" );
            REQUIRE( pkt.info == "Active Discovery Initiation (PADI)" );
            REQUIRE( pkt.srcMac == "66:77:88:99:aa:bb" );

            pkt = only( eth( EthertypePppoeDiscovery,
                             pppoe( 0x07, tag( 0x0101, {} ) + tag( 0x0102, text( "isp-ac 1" ) ) ) ),
                        DltEthernet );
            REQUIRE( pkt.info == "Active Discovery Offer (PADO) AC-Name='isp-ac 1'" );

            REQUIRE( only( eth( EthertypePppoeDiscovery, pppoe( 0x19, {} ) ), DltEthernet ).info
                     == "Active Discovery Request (PADR)" );
            REQUIRE( only( eth( EthertypePppoeDiscovery, pppoe( 0x65, {} ) ), DltEthernet ).info
                     == "Active Discovery Session-confirmation (PADS)" );
            REQUIRE( only( eth( EthertypePppoeDiscovery, pppoe( 0xA7, {} ) ), DltEthernet ).info
                     == "Active Discovery Terminate (PADT)" );
            REQUIRE( only( eth( EthertypePppoeDiscovery, pppoe( 0x42, {} ) ), DltEthernet ).info
                     == "Code 0x42" );
        }
    }

    GIVEN( "PPPoE frames without the Ethernet header" )
    {
        THEN( "they are dissected the same" )
        {
            REQUIRE( only( pppoeSession( 0x0021, kUdpPacket ), DltPppEther ).protocol == "DNS" );
            REQUIRE( only( pppoe( 0x09, {} ), DltPppEther ).protocol == "PPPoED" );
        }
    }

    GIVEN( "PPPoE frames cut short" )
    {
        THEN( "they are named as such" )
        {
            const auto pkt
                = only( eth( EthertypePppoeSession, { 0x11, 0x00, 0x12 } ), DltEthernet );
            REQUIRE( pkt.protocol == "PPPoES" );
            REQUIRE( pkt.info == "Truncated PPPoE header" );
            const auto empty
                = only( eth( EthertypePppoeSession, pppoe( 0, { 0x00 } ) ), DltEthernet );
            REQUIRE( empty.protocol == "PPPoES" );
            REQUIRE( empty.info == "Truncated PPP header" );
        }
    }
}

// ── Names and robustness ─────────────────────────────────────────────────

SCENARIO( "The new link-layer types have names", "[link_layers]" )
{
    THEN( "each is named" )
    {
        REQUIRE( linkTypeName( DltIeee80211 ) == "802.11" );
        REQUIRE( linkTypeName( DltIeee80211Radio ) == "802.11 Radiotap" );
        REQUIRE( linkTypeName( DltPpp ) == "PPP" );
        REQUIRE( linkTypeName( DltPppSerial ) == "PPP HDLC" );
        REQUIRE( linkTypeName( DltPppEther ) == "PPPoE" );
        REQUIRE( linkTypeName( DltCiscoHdlc ) == "Cisco HDLC" );
    }
}

SCENARIO( "Mutated link-layer frames are dissected without fault", "[link_layers]" )
{
    const std::vector<std::pair<uint32_t, Bytes>> seeds{
        { DltIeee80211Radio,
          radiotap( 0x30, 1 )
              + wifi( 2, 8, kToDs, kAccessPoint, kStation, kServer, 7,
                      Bytes{ 0, 0, 0, 0 } + snap( EthertypeIpv4, kUdpPacket ) ) },
        { DltIeee80211Radio,
          radiotap( 0 ) + management( 8, beaconFields() + element( 0, text( "HomeNet" ) ) ) },
        { DltIeee80211,
          wifi( 2, 8, kToDs | kFromDs | kOrder, kAccessPoint, kStation, kBroadcast, 7,
                Bytes( 6, 0 ) + snap( EthertypeIpv6, ipv6( IpProtoUdp, udp( 1, 2 ) ) ) ) },
        { DltIeee80211,
          management( 0, Bytes{ 0x31, 0x04, 0x0A, 0x00 } + element( 0, text( "x" ) ) ) },
        { DltPpp, ppp( 0xC021, control( 1, { 1, 4, 0x05, 0xDC } ) ) },
        { DltPppSerial, ppp( 0x0021, kUdpPacket ) },
        { DltCiscoHdlc, Bytes{ 0x0F, 0x00, 0x08, 0x00 } + kUdpPacket },
        { DltPppEther, pppoeSession( 0x0021, kUdpPacket ) },
        { DltEthernet,
          eth( EthertypePppoeDiscovery, pppoe( 0x07, tag( 0x0102, text( "isp" ) ) ) ) },
        { DltEthernet, eth( EthertypePppoeSession, pppoeSession( 0x8021, control( 1 ) ) ) },
    };

    GIVEN( "frames of each link layer with random bytes changed, cut anywhere" )
    {
        THEN( "every one is dissected, its protocol one word and its Info one line" )
        {
            std::mt19937 random( 56 );
            for ( const auto& [ linkType, seed ] : seeds ) {
                for ( int round = 0; round < 3000; ++round ) {
                    auto mutated = seed;
                    const auto changes = random() % 8;
                    for ( unsigned c = 0; c < changes; ++c ) {
                        mutated[ random() % mutated.size() ] = static_cast<uint8_t>( random() );
                    }
                    mutated.resize( random() % ( mutated.size() + 1 ) );
                    PacketRecord pkt;
                    dissectPacket( pkt, linkType, false, mutated.data(), mutated.size() );
                    INFO( "link type " << linkType << ", round " << round );
                    REQUIRE_FALSE( pkt.protocol.empty() );
                    REQUIRE( pkt.protocol.find( ' ' ) == std::string::npos );
                    REQUIRE( pkt.info.find( '\n' ) == std::string::npos );
                }
            }
        }
    }
}
