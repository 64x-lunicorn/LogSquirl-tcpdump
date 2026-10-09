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
 * @file tunnels_test.cpp
 * @brief BDD tests for how the parser unwraps VXLAN, GRE and IP-in-IP tunnels.
 */

#include <catch2/catch.hpp>

#include "capture_stats.h"
#include "packet_formatter.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"

#include <random>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// The tunnel endpoints: 10.0.0.1 to 10.0.0.2.
Ipv4Options outerAddresses()
{
    Ipv4Options o;
    o.src[ 0 ] = 10, o.src[ 1 ] = 0, o.src[ 2 ] = 0, o.src[ 3 ] = 1;
    o.dst[ 0 ] = 10, o.dst[ 1 ] = 0, o.dst[ 2 ] = 0, o.dst[ 3 ] = 2;
    return o;
}

/// An IPv4 packet of @p protocol between the tunnel endpoints.
Bytes outerIpv4( uint8_t protocol, const Bytes& payload )
{
    return ipv4( protocol, payload, outerAddresses() );
}

/// The inner TCP segment, 192.168.1.1:40000 to 192.168.1.2:40001.
Bytes innerTcp()
{
    return ipv4( IpProtoTcp, tcp( 40000, 40001, Bytes{ 1, 2, 3 } ) );
}

/// An Ethernet frame from 02:00:00:00:00:01 to 02:00:00:00:00:02.
Bytes innerEth( uint16_t etherType, const Bytes& payload )
{
    Bytes b{ 0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01 };
    putBE16( b, etherType );
    return b + payload;
}

/// @p frame carried by VXLAN with VNI @p vni between the tunnel endpoints.
Bytes overVxlan( uint32_t vni, const Bytes& frame )
{
    return eth( EthertypeIpv4,
                outerIpv4( IpProtoUdp, udp( 54321, kVxlanPort, vxlan( vni, frame ) ) ) );
}

/// The only packet of an Ethernet capture of @p frame.
PacketRecord only( const Bytes& frame )
{
    auto result = parse( pcapOf( { frame } ) );
    REQUIRE( result.packets.size() == 1 );
    return result.packets[ 0 ];
}

/// The packet line of @p frame.
std::string lineOf( const Bytes& frame )
{
    const auto lines = formatAllPackets( { only( frame ) } );
    REQUIRE( lines.size() == 2 );
    return lines[ 1 ];
}

/// @p packet (an IPv4 one) wrapped in IPv4-in-IPv4 @p times times.
Bytes nestedIpip( Bytes packet, int times )
{
    for ( int i = 0; i < times; ++i ) {
        packet = outerIpv4( IpProtoIpip, packet );
    }
    return packet;
}

} // namespace

SCENARIO( "A packet in a VXLAN tunnel is shown by its inner packet", "[tunnels]" )
{
    GIVEN( "a TCP segment carried in VXLAN with VNI 100" )
    {
        const auto pkt = only( overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) ) );

        THEN( "addresses, ports and protocol are the inner packet's" )
        {
            REQUIRE( pkt.srcIp == "192.168.1.1" );
            REQUIRE( pkt.dstIp == "192.168.1.2" );
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.transport == Transport::Tcp );
            REQUIRE( pkt.srcPort == 40000 );
            REQUIRE( pkt.dstPort == 40001 );
            REQUIRE( pkt.payloadLen == 3 );
            REQUIRE( pkt.info.rfind( "40000 \xe2\x86\x92 40001 [ACK, PSH]", 0 ) == 0 );
        }

        THEN( "the MAC addresses are the inner frame's" )
        {
            REQUIRE( pkt.srcMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.dstMac == "02:00:00:00:00:02" );
        }

        THEN( "the tunnel keeps its VNI and the outer addresses" )
        {
            REQUIRE( pkt.tunnels.size() == 1 );
            REQUIRE( pkt.tunnels[ 0 ].name == "VXLAN VNI 100" );
            REQUIRE( pkt.tunnels[ 0 ].srcIp == "10.0.0.1" );
            REQUIRE( pkt.tunnels[ 0 ].dstIp == "10.0.0.2" );
        }

        THEN( "Info names the tunnel before the inner description" )
        {
            const auto line = lineOf( overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) ) );
            REQUIRE( line.find( "192.168.1.1" ) != std::string::npos );
            REQUIRE( line.find( "10.0.0.1" ) == std::string::npos );
            REQUIRE( line.find( "VXLAN VNI 100 | 40000 \xe2\x86\x92 40001 [ACK, PSH] Seq=" )
                     != std::string::npos );
        }
    }

    GIVEN( "a segment carried in VXLAN twice" )
    {
        const auto frame = overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) );

        THEN( "the TCP analysis marks the second after the tunnel's name" )
        {
            const auto lines = formatAllPackets( parse( pcapOf( { frame, frame } ) ).packets );
            REQUIRE( lines.size() == 3 );
            REQUIRE(
                lines[ 2 ].find( "VXLAN VNI 100 | [TCP Retransmission] 40000 \xe2\x86\x92 40001" )
                != std::string::npos );
        }
    }

    GIVEN( "an ARP request and an LLDP frame carried in VXLAN" )
    {
        Bytes arp{ 0, 1, 8, 0, 6, 4, 0, 1 };
        arp = arp + Bytes{ 2, 0, 0, 0, 0, 1, 192, 168, 1, 1 } + Bytes( 6, 0 )
              + Bytes{ 192, 168, 1, 2 };

        THEN( "they are dissected as on the wire, by the inner addresses" )
        {
            const auto request = only( overVxlan( 7, innerEth( EthertypeArp, arp ) ) );
            REQUIRE( request.protocol == "ARP" );
            REQUIRE( request.info == "Who has 192.168.1.2? Tell 192.168.1.1" );
            REQUIRE( request.tunnels.size() == 1 );

            const auto lldp = only( overVxlan( 7, innerEth( 0x88CC, Bytes( 20, 0 ) ) ) );
            REQUIRE( lldp.protocol == "LLDP" );
            REQUIRE( lldp.srcIp.empty() );
            REQUIRE( lldp.dstIp.empty() );
            REQUIRE( lineOf( overVxlan( 7, innerEth( 0x88CC, Bytes( 20, 0 ) ) ) )
                         .find( "02:00:00:00:00:01" )
                     != std::string::npos );
        }
    }

    GIVEN( "a VLAN-tagged frame carried in VXLAN" )
    {
        const auto pkt = only(
            overVxlan( 5, innerEth( EthertypeVlan, vlanTag( 10, EthertypeIpv4, innerTcp() ) ) ) );

        THEN( "the tag is stripped" )
        {
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcIp == "192.168.1.1" );
        }
    }

    GIVEN( "a VXLAN header without the I flag" )
    {
        const auto noVni = only(
            eth( EthertypeIpv4,
                 outerIpv4( IpProtoUdp,
                            udp( 54321, kVxlanPort,
                                 vxlan( 100, innerEth( EthertypeIpv4, innerTcp() ), 0 ) ) ) ) );

        THEN( "the tunnel is named without a VNI" )
        {
            REQUIRE( noVni.tunnels.size() == 1 );
            REQUIRE( noVni.tunnels[ 0 ].name == "VXLAN" );
            REQUIRE( noVni.protocol == "TCP" );
        }
    }

    GIVEN( "a VXLAN header cut short, and a frame cut inside its Ethernet header" )
    {
        const auto shortHeader = only( eth(
            EthertypeIpv4, outerIpv4( IpProtoUdp, udp( 54321, kVxlanPort, Bytes{ 8, 0, 0 } ) ) ) );
        const auto shortFrame = only( overVxlan( 9, Bytes{ 2, 0, 0, 0, 0, 2, 2 } ) );

        THEN( "the first is a UDP datagram, the second a truncated inner frame" )
        {
            REQUIRE( shortHeader.tunnels.empty() );
            REQUIRE( shortHeader.protocol == "VXLAN" );
            REQUIRE( shortHeader.srcIp == "10.0.0.1" );

            REQUIRE( shortFrame.tunnels.size() == 1 );
            REQUIRE( shortFrame.info == "Truncated Ethernet header" );
            REQUIRE( shortFrame.srcIp.empty() );
            REQUIRE_FALSE( shortFrame.transport.has_value() );
        }
    }

    GIVEN( "a datagram from port 4789 to another port" )
    {
        const auto pkt = only(
            eth( EthertypeIpv4,
                 outerIpv4( IpProtoUdp, udp( kVxlanPort, 54321, vxlan( 1, innerTcp() ) ) ) ) );

        THEN( "it is no VXLAN packet: VXLAN goes to port 4789" )
        {
            REQUIRE( pkt.tunnels.empty() );
            REQUIRE( pkt.srcIp == "10.0.0.1" );
        }
    }
}

SCENARIO( "A packet in a GRE tunnel is shown by its inner packet", "[tunnels]" )
{
    GIVEN( "an IPv4 packet in GRE without key and sequence number" )
    {
        const auto pkt = only(
            eth( EthertypeIpv4, outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp() ) ) ) );

        THEN( "it is unwrapped and the tunnel named GRE" )
        {
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcIp == "192.168.1.1" );
            REQUIRE( pkt.srcPort == 40000 );
            REQUIRE( pkt.tunnels.size() == 1 );
            REQUIRE( pkt.tunnels[ 0 ].name == "GRE" );
            REQUIRE( pkt.tunnels[ 0 ].srcIp == "10.0.0.1" );
        }
    }

    GIVEN( "GRE with checksum, key and sequence number" )
    {
        GreOptions o;
        o.checksum = true;
        o.key = true;
        o.sequence = true;
        const auto frame
            = eth( EthertypeIpv4, outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp(), o ) ) );

        THEN( "the optional fields are skipped and the key named" )
        {
            const auto pkt = only( frame );
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcPort == 40000 );
            REQUIRE( pkt.tunnels.size() == 1 );
            REQUIRE( pkt.tunnels[ 0 ].name == "GRE key=0x0000002A" );
            REQUIRE( lineOf( frame ).find( "GRE key=0x0000002A | 40000 \xe2\x86\x92 40001" )
                     != std::string::npos );
        }
    }

    GIVEN( "GRE with only a sequence number, carrying IPv6" )
    {
        GreOptions o;
        o.sequence = true;
        const auto pkt
            = only( eth( EthertypeIpv4,
                         outerIpv4( IpProtoGre, gre( EthertypeIpv6,
                                                     ipv6( IpProtoUdp, udp( 5000, 53 ) ), o ) ) ) );

        THEN( "the IPv6 packet is dissected" )
        {
            REQUIRE( pkt.srcIp == "fe80::1" );
            REQUIRE( pkt.dstPort == 53 );
            REQUIRE( pkt.transport == Transport::Udp );
            REQUIRE( pkt.tunnels[ 0 ].name == "GRE" );
        }
    }

    GIVEN( "an Ethernet frame in GRE (transparent Ethernet bridging, NVGRE)" )
    {
        GreOptions o;
        o.key = true;
        o.keyValue = 0x00012300;
        const auto pkt = only(
            eth( EthertypeIpv4,
                 outerIpv4( IpProtoGre, gre( EthertypeTransparentBridging,
                                             innerEth( EthertypeIpv4, innerTcp() ), o ) ) ) );

        THEN( "the frame is dissected from its Ethernet header" )
        {
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcMac == "02:00:00:00:00:01" );
            REQUIRE( pkt.tunnels[ 0 ].name == "GRE key=0x00012300" );
        }
    }

    GIVEN( "GRE carrying a protocol that is not dissected" )
    {
        const auto pkt
            = only( eth( EthertypeIpv4, outerIpv4( IpProtoGre, gre( 0x88BE, Bytes( 16, 0 ) ) ) ) );

        THEN( "the GRE packet itself is shown, with its protocol type" )
        {
            REQUIRE( pkt.tunnels.empty() );
            REQUIRE( pkt.protocol == "GRE" );
            REQUIRE( pkt.srcIp == "10.0.0.1" );
            REQUIRE( pkt.info == "GRE, protocol type 0x88BE" );
        }
    }

    GIVEN( "PPTP's enhanced GRE (version 1) and GRE with source routing" )
    {
        GreOptions pptp;
        pptp.version = 1;
        pptp.key = true;
        GreOptions routed;
        routed.routing = true;

        THEN( "neither is unwrapped" )
        {
            const auto v1 = only( eth(
                EthertypeIpv4, outerIpv4( IpProtoGre, gre( 0x880B, Bytes( 16, 0 ), pptp ) ) ) );
            REQUIRE( v1.tunnels.empty() );
            REQUIRE( v1.protocol == "GRE" );
            REQUIRE( v1.info == "GRE version 1, protocol type 0x880B" );

            const auto withRoute
                = only( eth( EthertypeIpv4,
                             outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp(), routed ) ) ) );
            REQUIRE( withRoute.tunnels.empty() );
            REQUIRE( withRoute.info == "GRE with source routing, protocol type 0x0800" );
        }
    }

    GIVEN( "GRE headers cut short" )
    {
        GreOptions o;
        o.key = true;
        o.sequence = true;
        const auto full = gre( EthertypeIpv4, innerTcp(), o );

        THEN( "they are described as truncated, never read beyond the packet" )
        {
            for ( size_t cut : { 0, 3, 4, 8, 11 } ) {
                const Bytes header( full.begin(), full.begin() + static_cast<long>( cut ) );
                const auto pkt = only( eth( EthertypeIpv4, outerIpv4( IpProtoGre, header ) ) );
                INFO( "cut at " << cut );
                REQUIRE( pkt.protocol == "GRE" );
                REQUIRE( pkt.info == "Truncated GRE header" );
                REQUIRE( pkt.tunnels.empty() );
            }
        }
    }
}

SCENARIO( "A packet in an IP-in-IP tunnel is shown by its inner packet", "[tunnels]" )
{
    GIVEN( "IPv4 in IPv4" )
    {
        const auto pkt = only( eth( EthertypeIpv4, outerIpv4( IpProtoIpip, innerTcp() ) ) );

        THEN( "it is unwrapped and the tunnel named after both versions" )
        {
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcIp == "192.168.1.1" );
            REQUIRE( pkt.tunnels.size() == 1 );
            REQUIRE( pkt.tunnels[ 0 ].name == "IPv4-in-IPv4" );
            REQUIRE( pkt.tunnels[ 0 ].dstIp == "10.0.0.2" );
        }
    }

    GIVEN( "IPv6 in IPv4 (6in4)" )
    {
        const auto pkt
            = only( eth( EthertypeIpv4,
                         outerIpv4( IpProtoIpv6Encap, ipv6( IpProtoTcp, tcp( 40000, 40443 ) ) ) ) );

        THEN( "it is unwrapped" )
        {
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.srcIp == "fe80::1" );
            REQUIRE( pkt.tunnels[ 0 ].name == "IPv6-in-IPv4" );
        }
    }

    GIVEN( "IPv4 and IPv6 in IPv6" )
    {
        const auto v4 = only( eth( EthertypeIpv6, ipv6( IpProtoIpip, innerTcp() ) ) );
        const auto v6 = only(
            eth( EthertypeIpv6, ipv6( IpProtoIpv6Encap, ipv6( IpProtoUdp, udp( 5000, 5001 ) ) ) ) );

        THEN( "both are unwrapped" )
        {
            REQUIRE( v4.protocol == "TCP" );
            REQUIRE( v4.tunnels[ 0 ].name == "IPv4-in-IPv6" );
            REQUIRE( v4.tunnels[ 0 ].srcIp == "fe80::1" );
            REQUIRE( v6.protocol == "UDP" );
            REQUIRE( v6.tunnels[ 0 ].name == "IPv6-in-IPv6" );
        }
    }

    GIVEN( "protocol 4 whose payload is no IPv4 header" )
    {
        const auto pkt = only(
            eth( EthertypeIpv4, outerIpv4( IpProtoIpip, ipv6( IpProtoUdp, udp( 1, 2 ) ) ) ) );

        THEN( "it is not unwrapped" )
        {
            REQUIRE( pkt.tunnels.empty() );
            REQUIRE( pkt.protocol == "IPIP" );
            REQUIRE( pkt.srcIp == "10.0.0.1" );
            REQUIRE( pkt.info == "Protocol 4" );
        }
    }

    GIVEN( "an inner IPv4 header cut short" )
    {
        const auto inner = innerTcp();
        const auto pkt = only( eth(
            EthertypeIpv4, outerIpv4( IpProtoIpip, Bytes( inner.begin(), inner.begin() + 12 ) ) ) );

        THEN( "the inner packet is described as truncated" )
        {
            REQUIRE( pkt.tunnels.size() == 1 );
            REQUIRE( pkt.info == "Truncated IPv4 header" );
            REQUIRE( pkt.srcIp.empty() );
        }
    }
}

SCENARIO( "Tunnels nest up to a bound", "[tunnels]" )
{
    GIVEN( "a GRE tunnel inside a VXLAN one" )
    {
        const auto frame = overVxlan(
            100,
            innerEth( EthertypeIpv4, outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp() ) ) ) );

        THEN( "both are named, outermost first" )
        {
            const auto pkt = only( frame );
            REQUIRE( pkt.protocol == "TCP" );
            REQUIRE( pkt.tunnels.size() == 2 );
            REQUIRE( pkt.tunnels[ 0 ].name == "VXLAN VNI 100" );
            REQUIRE( pkt.tunnels[ 1 ].name == "GRE" );
            REQUIRE( lineOf( frame ).find( "VXLAN VNI 100 | GRE | 40000 \xe2\x86\x92 40001" )
                     != std::string::npos );
        }
    }

    GIVEN( "a packet in exactly kMaxTunnels tunnels" )
    {
        const auto pkt = only( eth( EthertypeIpv4, nestedIpip( innerTcp(), kMaxTunnels ) ) );

        THEN( "it is unwrapped to the inner packet" )
        {
            REQUIRE( pkt.tunnels.size() == kMaxTunnels );
            REQUIRE( pkt.protocol == "TCP" );
        }
    }

    GIVEN( "a packet nested one tunnel deeper" )
    {
        const auto pkt = only( eth( EthertypeIpv4, nestedIpip( innerTcp(), kMaxTunnels + 1 ) ) );

        THEN( "the innermost tunnel is not unwrapped and described as such" )
        {
            REQUIRE( pkt.tunnels.size() == kMaxTunnels );
            REQUIRE( pkt.protocol == "IPIP" );
            REQUIRE( pkt.srcIp == "10.0.0.1" );
            REQUIRE( pkt.info == "IPv4-in-IPv4 not dissected: more than 4 nested tunnels" );
            REQUIRE_FALSE( pkt.transport.has_value() );
        }
    }

    GIVEN( "a VXLAN packet nested too deep" )
    {
        const auto pkt = only(
            eth( EthertypeIpv4,
                 nestedIpip( outerIpv4( IpProtoUdp,
                                        udp( 1, kVxlanPort,
                                             vxlan( 3, innerEth( EthertypeIpv4, innerTcp() ) ) ) ),
                             kMaxTunnels ) ) );

        THEN( "it stays the UDP datagram that carries it" )
        {
            REQUIRE( pkt.tunnels.size() == kMaxTunnels );
            REQUIRE( pkt.protocol == "VXLAN" );
            REQUIRE( pkt.transport == Transport::Udp );
            REQUIRE( pkt.info == "VXLAN VNI 3 not dissected: more than 4 nested tunnels" );
        }
    }
}

SCENARIO( "A quoted packet is not unwrapped", "[tunnels]" )
{
    GIVEN( "an ICMP error quoting a GRE packet" )
    {
        auto quote = outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp() ) );
        quote.resize( 28 );
        Bytes message{ 3, 1, 0, 0, 0, 0, 0, 0 };
        const auto pkt = only( eth( EthertypeIpv4, ipv4( IpProtoIcmp, message + quote ) ) );

        THEN( "the quote shows the tunnel's endpoints" )
        {
            REQUIRE( pkt.tunnels.empty() );
            REQUIRE( pkt.info
                     == "Destination unreachable (Host unreachable) for 10.0.0.1 "
                        "\xe2\x86\x92 10.0.0.2 GRE" );
        }
    }
}

SCENARIO( "Tunnelled streams are keyed by the inner addresses and ports", "[tunnels]" )
{
    GIVEN( "a segment in VXLAN, its reply in GRE, and the same segment untunnelled" )
    {
        const auto request = only( overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) ) );
        Ipv4Options back;
        back.src[ 3 ] = 2;
        back.dst[ 3 ] = 1;
        const auto reply = only(
            eth( EthertypeIpv4,
                 outerIpv4( IpProtoGre, gre( EthertypeIpv4,
                                             ipv4( IpProtoTcp, tcp( 40001, 40000 ), back ) ) ) ) );
        const auto plain = only( eth( EthertypeIpv4, innerTcp() ) );
        const auto other = only(
            overVxlan( 100, innerEth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40002, 40001 ) ) ) ) );

        THEN( "they share one stream, whatever the tunnel" )
        {
            StreamTracker tracker;
            const auto first = tracker.track( request );
            REQUIRE( first.id == 0 );
            const auto second = tracker.track( reply );
            REQUIRE( second.id == 0 );
            REQUIRE( second.direction != first.direction );
            REQUIRE( tracker.track( plain ).id == 0 );
            REQUIRE( tracker.track( other ).id == 1 );
        }
    }
}

SCENARIO( "The Capture Summary counts a tunnel's endpoints", "[tunnels]" )
{
    GIVEN( "a packet carried in VXLAN" )
    {
        const auto pkt = only( overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) ) );

        THEN( "the inner and the outer addresses are endpoints" )
        {
            CaptureStats stats;
            stats.add( pkt );
            REQUIRE( stats.endpointPackets.at( "192.168.1.1" ) == 1 );
            REQUIRE( stats.endpointPackets.at( "192.168.1.2" ) == 1 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.1" ) == 1 );
            REQUIRE( stats.endpointPackets.at( "10.0.0.2" ) == 1 );
            REQUIRE( stats.protocolPackets.at( "TCP" ) == 1 );
        }
    }
}

SCENARIO( "A malformed tunnel is never read beyond the packet", "[tunnels]" )
{
    GreOptions all;
    all.checksum = true;
    all.key = true;
    all.sequence = true;
    const std::vector<Bytes> samples{
        overVxlan( 100, innerEth( EthertypeIpv4, innerTcp() ) ),
        overVxlan( 100, innerEth( EthertypeIpv4,
                                  outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp() ) ) ) ),
        eth( EthertypeIpv4, outerIpv4( IpProtoGre, gre( EthertypeIpv4, innerTcp(), all ) ) ),
        eth( EthertypeIpv4,
             outerIpv4( IpProtoGre,
                        gre( EthertypeTransparentBridging,
                             innerEth( EthertypeIpv6, ipv6( IpProtoUdp, udp( 1, 53 ) ) ) ) ) ),
        eth( EthertypeIpv4, nestedIpip( innerTcp(), kMaxTunnels + 2 ) ),
        eth( EthertypeIpv6, ipv6( IpProtoIpv6Encap, ipv6( IpProtoIpip, innerTcp() ) ) ),
    };

    GIVEN( "tunnelled packets with random bytes changed, cut anywhere" )
    {
        THEN( "each is dissected to a bounded description and tunnel list" )
        {
            std::mt19937 random( 55 );
            std::vector<Bytes> frames;
            for ( int round = 0; round < 5000; ++round ) {
                auto mutated = samples[ random() % samples.size() ];
                const auto changes = random() % 8;
                for ( unsigned c = 0; c < changes; ++c ) {
                    // Past the outer Ethernet and IP headers, so that the tunnels are reached.
                    const auto at = 34 + random() % ( mutated.size() - 34 );
                    mutated[ at ] = static_cast<uint8_t>( random() );
                }
                mutated.resize( 34 + random() % ( mutated.size() - 33 ) );
                const auto pkt = only( mutated );
                REQUIRE( pkt.tunnels.size() <= kMaxTunnels );
                REQUIRE( pkt.info.find( '\n' ) == std::string::npos );
                REQUIRE( pkt.info.size() < 512 );
                frames.push_back( mutated );
            }
            const auto lines = formatAllPackets( parse( pcapOf( frames ) ).packets );
            REQUIRE( lines.size() == frames.size() + 1 );
        }
    }
}
