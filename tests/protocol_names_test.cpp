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
 * @file protocol_names_test.cpp
 * @brief BDD tests for the name tables: IP protocol numbers, EtherTypes and
 *        well-known service ports.
 */

#include <catch2/catch.hpp>

#include "protocol_names.h"

#include <string>

using namespace tcpdump;

namespace {

/// A name as a string, "" for no name.
std::string nameOr( const char* name )
{
    return name ? name : "";
}

} // namespace

SCENARIO( "IP protocol numbers are named", "[names]" )
{
    THEN( "the protocols the Parser does not dissect have their IANA names" )
    {
        REQUIRE( nameOr( ipProtocolName( 2 ) ) == "IGMP" );
        REQUIRE( nameOr( ipProtocolName( 47 ) ) == "GRE" );
        REQUIRE( nameOr( ipProtocolName( 50 ) ) == "ESP" );
        REQUIRE( nameOr( ipProtocolName( 51 ) ) == "AH" );
        REQUIRE( nameOr( ipProtocolName( 89 ) ) == "OSPF" );
        REQUIRE( nameOr( ipProtocolName( 103 ) ) == "PIM" );
        REQUIRE( nameOr( ipProtocolName( 112 ) ) == "VRRP" );
        REQUIRE( nameOr( ipProtocolName( 115 ) ) == "L2TP" );
        REQUIRE( nameOr( ipProtocolName( 132 ) ) == "SCTP" );
    }

    THEN( "the ones it dissects are named too" )
    {
        REQUIRE( nameOr( ipProtocolName( IpProtoIcmp ) ) == "ICMP" );
        REQUIRE( nameOr( ipProtocolName( IpProtoTcp ) ) == "TCP" );
        REQUIRE( nameOr( ipProtocolName( IpProtoUdp ) ) == "UDP" );
        REQUIRE( nameOr( ipProtocolName( IpProtoIcmpv6 ) ) == "ICMPv6" );
    }

    THEN( "an unassigned number has no name" )
    {
        REQUIRE( ipProtocolName( 200 ) == nullptr );
        REQUIRE( ipProtocolName( 255 ) == nullptr );
    }
}

SCENARIO( "EtherTypes are named", "[names]" )
{
    THEN( "the link protocols the Parser does not dissect have their names" )
    {
        REQUIRE( nameOr( etherTypeName( 0x88CC ) ) == "LLDP" );
        REQUIRE( nameOr( etherTypeName( 0x8863 ) ) == "PPPoED" );
        REQUIRE( nameOr( etherTypeName( 0x8864 ) ) == "PPPoES" );
        REQUIRE( nameOr( etherTypeName( 0x8847 ) ) == "MPLS" );
        REQUIRE( nameOr( etherTypeName( 0x888E ) ) == "EAPOL" );
        REQUIRE( nameOr( etherTypeName( 0x88F7 ) ) == "PTP" );
        REQUIRE( nameOr( etherTypeName( 0x0842 ) ) == "WOL" );
    }

    THEN( "the tags the Parser strips are named" )
    {
        REQUIRE( nameOr( etherTypeName( EthertypeVlan ) ) == "VLAN" );
        REQUIRE( nameOr( etherTypeName( EthertypeQinQ ) ) == "QinQ" );
    }

    THEN( "an unassigned EtherType has no name" )
    {
        REQUIRE( etherTypeName( 0x1234 ) == nullptr );
    }
}

SCENARIO( "Well-known ports name their service, per transport", "[names]" )
{
    THEN( "UDP services are named on UDP" )
    {
        REQUIRE( nameOr( servicePortName( Transport::Udp, 161 ) ) == "SNMP" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 514 ) ) == "Syslog" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 69 ) ) == "TFTP" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 3478 ) ) == "STUN" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 51820 ) ) == "WireGuard" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 5355 ) ) == "LLMNR" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 137 ) ) == "NBNS" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 547 ) ) == "DHCPv6" );
    }

    THEN( "TCP services are named on TCP" )
    {
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 554 ) ) == "RTSP" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 389 ) ) == "LDAP" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 445 ) ) == "SMB" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 3389 ) ) == "RDP" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 5900 ) ) == "VNC" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 22 ) ) == "SSH" );
    }

    THEN( "services on both transports are named on both" )
    {
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 88 ) ) == "Kerberos" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 88 ) ) == "Kerberos" );
        REQUIRE( nameOr( servicePortName( Transport::Tcp, 53 ) ) == "DNS" );
        REQUIRE( nameOr( servicePortName( Transport::Udp, 53 ) ) == "DNS" );
    }

    THEN( "a service is not named on the transport it does not use" )
    {
        REQUIRE( servicePortName( Transport::Tcp, 69 ) == nullptr );   // TFTP
        REQUIRE( servicePortName( Transport::Udp, 3306 ) == nullptr ); // MySQL
    }

    THEN( "an unknown port has no name" )
    {
        REQUIRE( servicePortName( Transport::Tcp, 60001 ) == nullptr );
        REQUIRE( servicePortName( Transport::Udp, 60001 ) == nullptr );
    }
}
