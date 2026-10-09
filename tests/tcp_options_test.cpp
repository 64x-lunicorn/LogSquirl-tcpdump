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
 * @file tcp_options_test.cpp
 * @brief BDD tests for the TCP options: how they are read, and how Info
 *        shows them.
 */

#include <catch2/catch.hpp>

#include "pcapbuilder.h"

#include <algorithm>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// The options of a Linux SYN: MSS 1460, SACK permitted, timestamps, NOP,
/// window scale 7.
const Bytes kLinuxSyn{ 2, 4, 0x05, 0xB4, 4, 2, 8, 10, 0, 0, 0x30, 0x39, 0, 0, 0, 0, 1, 3, 3, 7 };

/// The options of an ACK: NOP, NOP, timestamps.
const Bytes kAckTimestamps{ 1, 1, 8, 10, 0, 0, 0x30, 0x3A, 0, 0, 0x01, 0x00 };

TcpOptions optionsOf( const Bytes& options )
{
    return parseTcpOptions( options.data(), options.size() );
}

/// The packet of a lone segment from 40000 to 80 with @p options.
PacketRecord packetOf( const Bytes& options, uint8_t flags, const Bytes& payload = {} )
{
    auto packets
        = tcpdump_test::parse(
              pcapOf( { eth( EthertypeIpv4,
                             ipv4( IpProtoTcp, tcpWithOptions( 40000, 80, options, flags, 1, 1,
                                                               64240, payload ) ) ) } ) )
              .packets;
    REQUIRE( packets.size() == 1 );
    return packets[ 0 ];
}

/// The Info of a lone segment from 40000 to 80 with @p options.
std::string infoOf( const Bytes& options, uint8_t flags )
{
    return packetOf( options, flags ).info;
}

} // namespace

SCENARIO( "The TCP options are read as Wireshark walks them", "[tcp_options]" )
{
    GIVEN( "the options of a Linux SYN" )
    {
        const auto options = optionsOf( kLinuxSyn );

        THEN( "each is read, and Info gets them in the order they come in" )
        {
            REQUIRE( options.mss == 1460 );
            REQUIRE( options.sackPermitted );
            REQUIRE( options.timestamps );
            REQUIRE( options.timestamps->value == 12345 );
            REQUIRE( options.timestamps->echoReply == 0 );
            REQUIRE( options.windowShift == 7 );
            REQUIRE( options.info == " MSS=1460 SACK_PERM TSval=12345 TSecr=0 WS=128" );
        }
    }

    GIVEN( "an unknown kind among them" )
    {
        // kind 30 (MPTCP), 6 bytes; then the MSS
        const auto options = optionsOf( { 30, 6, 1, 2, 3, 4, 2, 4, 0x05, 0x78 } );

        THEN( "it is skipped by its length" )
        {
            REQUIRE( options.mss == 1400 );
            REQUIRE( options.info == " MSS=1400" );
        }
    }

    GIVEN( "a window scale shift beyond 14" )
    {
        THEN( "WS shows the multiplier of 14, as Wireshark does; the shift is kept as sent" )
        {
            const auto options = optionsOf( { 3, 3, 15 } );
            REQUIRE( options.windowShift == 15 );
            REQUIRE( options.info == " WS=16384" );
        }
    }

    GIVEN( "known kinds with lengths other than theirs" )
    {
        const auto options
            = optionsOf( { 2, 3, 5, 3, 4, 7, 7, 8, 6, 0, 0, 0, 1, 4, 3, 2, 3, 3, 3 } );

        THEN( "they are skipped by the length they give; SACK_PERM is named whatever its "
              "length, as in Wireshark" )
        {
            REQUIRE_FALSE( options.mss );
            REQUIRE_FALSE( options.timestamps );
            REQUIRE( options.sackPermitted );
            REQUIRE( options.windowShift == 3 );
            REQUIRE( options.info == " SACK_PERM WS=8" );
        }
    }

    GIVEN( "an end of options" )
    {
        THEN( "what follows it is not read" )
        {
            const auto options = optionsOf( { 1, 0, 2, 4, 0x05, 0xB4 } );
            REQUIRE_FALSE( options.mss );
            REQUIRE( options.info.empty() );
        }
    }

    GIVEN( "a length below 2, or one that runs past the options" )
    {
        THEN( "the walk ends there" )
        {
            REQUIRE( optionsOf( { 2, 4, 0x05, 0xB4, 30, 1, 3, 3, 7 } ).info == " MSS=1460" );
            REQUIRE( optionsOf( { 2, 4, 0x05, 0xB4, 30, 0, 3, 3, 7 } ).info == " MSS=1460" );
            REQUIRE( optionsOf( { 2, 4, 0x05, 0xB4, 3, 4, 7 } ).info == " MSS=1460" );
            REQUIRE( optionsOf( { 2, 4, 0x05, 0xB4, 8 } ).info == " MSS=1460" );
        }
    }

    GIVEN( "every mutation of a length byte, and every cut of the options" )
    {
        THEN( "nothing past the options is read: bytes behind them change nothing" )
        {
            // Lengths at 1, 5, 7, 17: each set to every value; then each cut
            for ( const size_t at : { size_t( 1 ), size_t( 5 ), size_t( 7 ), size_t( 17 ) } ) {
                for ( int value = 0; value < 256; ++value ) {
                    auto mutated = kLinuxSyn;
                    mutated[ at ] = static_cast<uint8_t>( value );
                    for ( size_t len = 0; len <= mutated.size(); ++len ) {
                        // The same bytes, followed by two different tails
                        auto a
                            = Bytes( mutated.begin(), mutated.begin() + len ) + Bytes( 40, 0x08 );
                        auto b
                            = Bytes( mutated.begin(), mutated.begin() + len ) + Bytes( 40, 0x02 );
                        const auto fromA = parseTcpOptions( a.data(), len );
                        const auto fromB = parseTcpOptions( b.data(), len );
                        REQUIRE( fromA.info == fromB.info );
                        REQUIRE( fromA.mss == fromB.mss );
                        REQUIRE( fromA.windowShift == fromB.windowShift );
                        REQUIRE( fromA.sackPermitted == fromB.sackPermitted );
                        REQUIRE( bool( fromA.timestamps ) == bool( fromB.timestamps ) );
                    }
                }
            }
        }
    }
}

SCENARIO( "A SYN shows its options in Info, other segments their timestamps on request",
          "[tcp_options]" )
{
    GIVEN( "a SYN and a SYN-ACK with options" )
    {
        THEN( "the options follow the window, in their order" )
        {
            REQUIRE( infoOf( kLinuxSyn, 0x02 )
                     == "40000 \xe2\x86\x92 80 [SYN] Seq=1 Win=64240 MSS=1460 SACK_PERM "
                        "TSval=12345 TSecr=0 WS=128" );
            REQUIRE( infoOf( kLinuxSyn, 0x12 )
                     == "40000 \xe2\x86\x92 80 [SYN, ACK] Seq=1 Ack=1 Win=64240 MSS=1460 "
                        "SACK_PERM TSval=12345 TSecr=0 WS=128" );
        }
    }

    GIVEN( "a segment other than a SYN with the timestamps option" )
    {
        auto pkt = packetOf( kAckTimestamps, 0x18, text( "hello" ) );

        THEN( "Info leaves them out by default" )
        {
            REQUIRE( pkt.info.find( "TSval" ) == std::string::npos );
        }

        THEN( "on request they follow Len, before the payload's description" )
        {
            showTcpTimestamps( pkt );
            REQUIRE( pkt.info.rfind( "40000 \xe2\x86\x92 80 [ACK, PSH] Seq=1 Ack=1 Win=64240 Len=5 "
                                     "TSval=12346 TSecr=256 | ",
                                     0 )
                     == 0 );
        }
    }

    GIVEN( "a SYN, asked for its timestamps again" )
    {
        auto pkt = packetOf( kLinuxSyn, 0x02 );
        const auto info = pkt.info;
        showTcpTimestamps( pkt );

        THEN( "it shows them once, among its options" )
        {
            REQUIRE( pkt.info == info );
        }
    }

    GIVEN( "a segment without the option, asked for its timestamps" )
    {
        auto pkt = packetOf( { 1, 1, 1, 1 }, 0x10 );
        const auto info = pkt.info;
        showTcpTimestamps( pkt );

        THEN( "Info stays as it is" )
        {
            REQUIRE( pkt.info == info );
        }
    }
}
