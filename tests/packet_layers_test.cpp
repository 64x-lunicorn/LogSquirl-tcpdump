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
 * @file packet_layers_test.cpp
 * @brief BDD tests for the layers the dissectors describe for the Packet Panel.
 */

#include <catch2/catch.hpp>

#include "packet_layers.h"
#include "pcapbuilder.h"

#include <algorithm>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// The layers of the one packet @p frame is, captured with @p linkType.
std::vector<PacketLayer> layersOf( const Bytes& frame, uint32_t linkType = DltEthernet )
{
    PacketRecord record;
    record.number = 7;
    record.capturedLen = static_cast<uint32_t>( frame.size() );
    record.originalLen = record.capturedLen;
    record.linkType = linkType;
    return dissectLayers( record, frame.data(), frame.size(), false );
}

std::vector<std::string> namesOf( const std::vector<PacketLayer>& layers )
{
    std::vector<std::string> names;
    for ( const auto& layer : layers ) {
        names.push_back( layer.name );
    }
    return names;
}

/// The field @p name of the layer called @p layerName; fails the test without it.
const LayerField& fieldOf( const std::vector<PacketLayer>& layers, const std::string& layerName,
                           const std::string& name )
{
    const auto layer = std::find_if( layers.begin(), layers.end(),
                                     [ & ]( const auto& l ) { return l.name == layerName; } );
    REQUIRE( layer != layers.end() );
    const auto field = std::find_if( layer->fields.begin(), layer->fields.end(),
                                     [ & ]( const auto& f ) { return f.name == name; } );
    INFO( layerName << " / " << name );
    REQUIRE( field != layer->fields.end() );
    return *field;
}

} // namespace

SCENARIO( "A packet's layers name every header the Parser reads", "[packet_layers]" )
{
    GIVEN( "an HTTP request over TCP over IPv4 in an Ethernet frame" )
    {
        const auto frame = eth(
            EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 80, text( "GET / HTTP/1.1\r\n" ) ) ) );
        const auto layers = layersOf( frame );

        THEN( "the frame, Ethernet, IPv4, TCP and HTTP follow each other" )
        {
            REQUIRE( namesOf( layers )
                     == std::vector<std::string>{ "Frame 7: 70 bytes on wire, 70 bytes captured",
                                                  "Ethernet II", "Internet Protocol Version 4",
                                                  "Transmission Control Protocol", "HTTP" } );
        }

        THEN( "each layer spans its header's bytes" )
        {
            REQUIRE( layers[ 0 ].offset == 0 );
            REQUIRE( layers[ 0 ].length == frame.size() );
            REQUIRE( layers[ 1 ].offset == 0 );
            REQUIRE( layers[ 1 ].length == 14 );
            REQUIRE( layers[ 2 ].offset == 14 );
            REQUIRE( layers[ 2 ].length == 20 );
            REQUIRE( layers[ 3 ].offset == 34 );
            REQUIRE( layers[ 3 ].length == 20 );
            REQUIRE( layers[ 4 ].offset == 54 );
            REQUIRE( layers[ 4 ].length == 16 );
        }

        THEN( "the fields are named, with their values and bytes" )
        {
            const auto& mac = fieldOf( layers, "Ethernet II", "Source" );
            REQUIRE( mac.value == "66:77:88:99:aa:bb" );
            REQUIRE( mac.offset == 6 );
            REQUIRE( mac.length == 6 );

            REQUIRE( fieldOf( layers, "Ethernet II", "Type" ).value == "IPv4 (0x0800)" );

            const auto& source = fieldOf( layers, "Internet Protocol Version 4", "Source Address" );
            REQUIRE( source.value == "192.168.1.1" );
            REQUIRE( source.offset == 26 );
            REQUIRE( source.length == 4 );
            REQUIRE( fieldOf( layers, "Internet Protocol Version 4", "Time to Live" ).value
                     == "64" );
            REQUIRE( fieldOf( layers, "Internet Protocol Version 4", "Protocol" ).value
                     == "TCP (6)" );

            const auto& port = fieldOf( layers, "Transmission Control Protocol", "Source Port" );
            REQUIRE( port.value == "40000" );
            REQUIRE( port.offset == 34 );
            REQUIRE( port.length == 2 );
            const auto& flags = fieldOf( layers, "Transmission Control Protocol", "Flags" );
            REQUIRE( flags.value == "0x018 [ACK, PSH]" );
            REQUIRE( flags.offset == 46 );
            REQUIRE( flags.length == 2 );

            REQUIRE( fieldOf( layers, "HTTP", "Description" ).value.rfind( "GET /", 0 ) == 0 );
        }

        THEN( "the frame layer tells the record" )
        {
            REQUIRE( fieldOf( layers, layers[ 0 ].name, "Frame Number" ).value == "7" );
            REQUIRE( fieldOf( layers, layers[ 0 ].name, "Link Type" ).value == "Ethernet (1)" );
        }
    }

    GIVEN( "a DNS query over UDP over IPv6" )
    {
        const auto frame
            = eth( EthertypeIpv6, ipv6( IpProtoUdp, udp( 5353, 53, Bytes( 12, 0 ) ) ) );
        const auto layers = layersOf( frame );

        THEN( "IPv6 and UDP are layers with their fields" )
        {
            const auto names = namesOf( layers );
            REQUIRE( names[ 2 ] == "Internet Protocol Version 6" );
            REQUIRE( names[ 3 ] == "User Datagram Protocol" );
            REQUIRE( fieldOf( layers, names[ 2 ], "Source Address" ).value == "fe80::1" );
            REQUIRE( fieldOf( layers, names[ 2 ], "Next Header" ).value == "UDP (17)" );
            REQUIRE( fieldOf( layers, names[ 3 ], "Destination Port" ).value == "53" );
            REQUIRE( fieldOf( layers, names[ 3 ], "Length" ).value == "20" );
        }
    }

    GIVEN( "a VLAN-tagged ARP request" )
    {
        Bytes arp;
        putBE16( arp, 1 );
        putBE16( arp, EthertypeIpv4 );
        arp.push_back( 6 );
        arp.push_back( 4 );
        putBE16( arp, 1 );
        arp = arp + Bytes{ 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 10, 0, 0, 1 } + Bytes( 6, 0 )
              + Bytes{ 10, 0, 0, 2 };
        const auto layers = layersOf( eth( EthertypeVlan, vlanTag( 42, EthertypeArp, arp ) ) );

        THEN( "the tag and ARP are layers of their own" )
        {
            REQUIRE( namesOf( layers )
                     == std::vector<std::string>{ layers[ 0 ].name, "Ethernet II",
                                                  "802.1Q Virtual LAN",
                                                  "Address Resolution Protocol" } );
            REQUIRE( fieldOf( layers, "802.1Q Virtual LAN", "ID" ).value == "42" );
            REQUIRE( fieldOf( layers, "Address Resolution Protocol", "Opcode" ).value
                     == "request (1)" );
            REQUIRE( fieldOf( layers, "Address Resolution Protocol", "Target IP Address" ).value
                     == "10.0.0.2" );
        }
    }

    GIVEN( "an ICMP echo request" )
    {
        Bytes icmp{ 8, 0, 0, 0, 0x12, 0x34, 0, 7 };
        const auto layers = layersOf( eth( EthertypeIpv4, ipv4( IpProtoIcmp, icmp ) ) );

        THEN( "ICMP's type and code are fields" )
        {
            const auto& type = fieldOf( layers, "Internet Control Message Protocol", "Type" );
            REQUIRE( type.value == "8" );
            REQUIRE( type.offset == 34 );
            REQUIRE( fieldOf( layers, "Internet Control Message Protocol", "Message" )
                         .value.rfind( "Echo (ping) request", 0 )
                     == 0 );
        }
    }

    GIVEN( "a TCP segment inside VXLAN" )
    {
        const auto inner = eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 1000, 2000 ) ) );
        const auto layers = layersOf( eth(
            EthertypeIpv4, ipv4( IpProtoUdp, udp( 50000, kVxlanPort, vxlan( 100, inner ) ) ) ) );

        THEN( "the outer and the inner layers are both shown, the tunnel between them" )
        {
            const auto names = namesOf( layers );
            REQUIRE( std::vector<std::string>( names.begin() + 1, names.end() )
                     == std::vector<std::string>{
                         "Ethernet II", "Internet Protocol Version 4", "User Datagram Protocol",
                         "Virtual eXtensible Local Area Network", "Ethernet II",
                         "Internet Protocol Version 4", "Transmission Control Protocol" } );
            REQUIRE( fieldOf( layers, "Virtual eXtensible Local Area Network", "VNI" ).value
                     == "100" );
            REQUIRE( layers.back().offset == 14 + 20 + 8 + 8 + 14 + 20 );
        }
    }

    GIVEN( "a Linux cooked capture v2 packet" )
    {
        Bytes sll2;
        putBE16( sll2, EthertypeIpv4 );
        sll2 = sll2 + Bytes( 18, 0 );
        const auto layers = layersOf( sll2 + ipv4( IpProtoUdp, udp( 1, 2 ) ), DltLinuxSll2 );

        THEN( "the cooked header is a layer" )
        {
            REQUIRE( layers[ 1 ].name == "Linux cooked capture v2" );
            REQUIRE( layers[ 1 ].length == 20 );
            REQUIRE( fieldOf( layers, layers[ 1 ].name, "Protocol" ).value == "IPv4 (0x0800)" );
        }
    }

    GIVEN( "an IPv4 header cut short by the snaplen" )
    {
        auto frame = eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 1, 2 ) ) );
        frame.resize( 14 + 30 );
        const auto layers = layersOf( frame );

        THEN( "no layer claims bytes past the captured ones" )
        {
            for ( const auto& layer : layers ) {
                REQUIRE( layer.offset + layer.length <= frame.size() );
                for ( const auto& field : layer.fields ) {
                    REQUIRE( field.offset + field.length <= frame.size() );
                }
            }
        }
    }
}
