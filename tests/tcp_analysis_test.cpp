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
 * @file tcp_analysis_test.cpp
 * @brief BDD tests for the TCP Analysis: relative sequence numbers and the
 *        analysis markers.
 */

#include <catch2/catch.hpp>

#include "packet_formatter.h"
#include "pcapbuilder.h"
#include "stream_tracker.h"
#include "tcp_analysis.h"

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kPshAck = 0x18;

constexpr uint16_t kClient = 40000;
constexpr uint16_t kServer = 80;

/// A segment from the client to the server, or back when @p fromServer;
/// with a window scale option of shift @p windowShift unless that is -1.
Bytes segment( bool fromServer, uint8_t flags, uint32_t seq, uint32_t ack,
               const Bytes& payload = {}, uint16_t window = 0xFFFF, int windowShift = -1 )
{
    auto addresses = Ipv4Options{};
    if ( fromServer ) {
        std::swap( addresses.src, addresses.dst );
    }
    const uint8_t words = windowShift < 0 ? 5 : 6;
    auto header = fromServer ? tcp( kServer, kClient, {}, words, flags, seq, ack, window )
                             : tcp( kClient, kServer, {}, words, flags, seq, ack, window );
    if ( windowShift >= 0 ) {
        // NOP, then the option: kind 3, length 3, the shift
        header[ 21 ] = 3;
        header[ 22 ] = 3;
        header[ 23 ] = static_cast<uint8_t>( windowShift );
    }
    return eth( EthertypeIpv4, ipv4( IpProtoTcp, header + payload, addresses ) );
}

/// The Info of each segment, after the TCP Analysis followed them in order.
std::vector<std::string> infoOf( const std::vector<Bytes>& segments,
                                 StreamTracker tracker = StreamTracker() )
{
    auto packets = parse( pcapOf( segments ) ).packets;
    REQUIRE( packets.size() == segments.size() );
    std::vector<std::string> infos;
    for ( auto& pkt : packets ) {
        analyseTcp( pkt, tracker.track( pkt ) );
        infos.push_back( pkt.info );
    }
    return infos;
}

/// The Info and the markers of each segment, captured @p gapUsec apart,
/// after the TCP Analysis followed them in order.
struct Analysed {
    std::vector<std::string> infos;
    std::vector<TcpMarkers> markers;
};

Analysed analyse( const std::vector<Bytes>& segments, uint32_t gapUsec = 1000000 )
{
    std::vector<Record> records;
    uint64_t usec = 0;
    for ( const auto& data : segments ) {
        records.push_back( { data, static_cast<uint32_t>( 1000 + usec / 1000000 ),
                             static_cast<uint32_t>( usec % 1000000 ), -1 } );
        usec += gapUsec;
    }
    auto packets = parse( pcapFile( records ) ).packets;
    REQUIRE( packets.size() == segments.size() );
    StreamTracker tracker;
    Analysed analysed;
    for ( auto& pkt : packets ) {
        analysed.markers.push_back( analyseTcp( pkt, tracker.track( pkt ) ) );
        analysed.infos.push_back( pkt.info );
    }
    return analysed;
}

/// Whether @p info starts with @p prefix.
bool startsWith( const std::string& info, const std::string& prefix )
{
    return info.compare( 0, prefix.size(), prefix ) == 0;
}

/// Whether @p info carries no marker: it starts with the ports.
bool unmarked( const std::string& info )
{
    return !info.empty() && info[ 0 ] != '[';
}

constexpr uint32_t kC = 1000; ///< The client's initial sequence number.
constexpr uint32_t kS = 5000; ///< The server's.

/// A handshake: the client's next sequence number is kC + 1, the server's kS + 1.
std::vector<Bytes> handshake()
{
    return {
        segment( false, kSyn, kC, 0 ),
        segment( true, kSyn | kAck, kS, kC + 1 ),
        segment( false, kAck, kC + 1, kS + 1 ),
    };
}

/// @p a followed by @p b.
std::vector<Bytes> operator+( std::vector<Bytes> a, const std::vector<Bytes>& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

/// Whether @p info shows @p fields ("Seq=1 Ack=1 Win=4000") right after
/// the flags, and nothing more of them.
bool showsWindow( const std::string& info, const std::string& fields )
{
    const auto at = info.find( "] " + fields );
    const auto end = at + 2 + fields.size();
    return at != std::string::npos && ( end == info.size() || info[ end ] == ' ' );
}

/// Whether @p info shows @p numbers ("Seq=1 Ack=1") right after the flags.
bool shows( const std::string& info, const std::string& numbers )
{
    return info.find( "] " + numbers + " Win=" ) != std::string::npos;
}

} // namespace

SCENARIO( "TCP sequence and acknowledgement numbers are shown relative per direction",
          "[tcp_analysis]" )
{
    GIVEN( "a handshake and an exchange of data with random initial sequence numbers" )
    {
        const uint32_t client = 3000000000u;
        const uint32_t server = 123456789u;
        const auto infos = infoOf( {
            segment( false, kSyn, client, 0 ),
            segment( true, kSyn | kAck, server, client + 1 ),
            segment( false, kAck, client + 1, server + 1 ),
            segment( false, kPshAck, client + 1, server + 1, text( "hello" ) ),
            segment( true, kPshAck, server + 1, client + 6, text( "hi" ) ),
            segment( false, kAck, client + 6, server + 3 ),
        } );

        THEN( "each direction counts from its SYN, which is Seq=0" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=0" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=0 Ack=1" ) );
            REQUIRE( shows( infos[ 2 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=1 Ack=6" ) );
            REQUIRE( shows( infos[ 5 ], "Seq=6 Ack=3" ) );
        }

        THEN( "the rest of Info is kept" )
        {
            REQUIRE( infos[ 3 ]
                     == "40000 \xe2\x86\x92 80 [ACK, PSH] Seq=1 Ack=1 Win=65535 Len=5 | hello" );
        }
    }

    GIVEN( "a SYN whose acknowledgement field is not zero" )
    {
        const auto infos = infoOf( { segment( false, kSyn, 1000, 777 ) } );

        THEN( "Ack is left out: without the ACK flag the field acknowledges nothing" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=0" ) );
        }
    }

    GIVEN( "a stream whose handshake was not captured" )
    {
        const auto infos = infoOf( {
            segment( true, kPshAck, 5000, 9000, text( "data" ) ),
            segment( false, kAck, 9000, 5004 ),
            segment( true, kPshAck, 5004, 9000, text( "more" ) ),
        } );

        THEN( "the first segment seen sets the base of both directions, as after a handshake" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=1 Ack=5" ) );
            REQUIRE( shows( infos[ 2 ], "Seq=5 Ack=1" ) );
        }
    }

    GIVEN( "a stream whose first segment carries no ACK" )
    {
        const auto infos = infoOf( {
            segment( false, 0x08, 5000, 0, text( "x" ) ),
            segment( true, kAck, 7000, 5001 ),
        } );

        THEN( "the other direction takes its base from its own first segment" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1" ) );
            REQUIRE( shows( infos[ 1 ], "Seq=1 Ack=2" ) );
        }
    }

    GIVEN( "sequence numbers that wrap past 2^32" )
    {
        const uint32_t client = 0xFFFFFFF0u;
        const auto infos = infoOf( {
            segment( false, kSyn, client, 0 ),
            segment( true, kSyn | kAck, 100, client + 1 ),
            segment( false, kPshAck, client + 1, 101, Bytes( 20, 'a' ) ),
            segment( false, kPshAck, client + 21, 101, Bytes( 20, 'a' ) ),
            segment( true, kAck, 101, client + 41 ),
        } );

        THEN( "the relative numbers go on counting" )
        {
            REQUIRE( shows( infos[ 2 ], "Seq=1 Ack=1" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=21 Ack=1" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=1 Ack=41" ) );
        }
    }

    GIVEN( "a new connection that reuses the addresses and ports of an earlier one" )
    {
        const auto infos = infoOf( {
            segment( false, kSyn, 1000, 0 ),
            segment( true, kSyn | kAck, 2000, 1001 ),
            segment( false, kAck, 1001, 2001 ),
            segment( false, kSyn, 50000, 0 ),
            segment( true, kSyn | kAck, 90000, 50001 ),
            segment( false, kAck, 50001, 90001 ),
        } );

        THEN( "its SYN starts counting afresh in both directions" )
        {
            REQUIRE( shows( infos[ 3 ], "Seq=0" ) );
            REQUIRE( shows( infos[ 4 ], "Seq=0 Ack=1" ) );
            REQUIRE( shows( infos[ 5 ], "Seq=1 Ack=1" ) );
        }
    }

    GIVEN( "a retransmitted SYN" )
    {
        const auto infos = infoOf( {
            segment( false, kSyn, 1000, 0 ),
            segment( true, kSyn | kAck, 2000, 1001 ),
            segment( false, kSyn, 1000, 0 ),
            segment( false, kAck, 1001, 2001 ),
        } );

        THEN( "it keeps the stream's bases" )
        {
            REQUIRE( shows( infos[ 2 ], "Seq=0" ) );
            REQUIRE( shows( infos[ 3 ], "Seq=1 Ack=1" ) );
        }
    }

    GIVEN( "a stream past the stream cap" )
    {
        const auto infos = infoOf(
            {
                segment( false, kSyn, 1000, 0 ),
            },
            StreamTracker( 0 ) );

        THEN( "its numbers are shown as they are, without a state to count from" )
        {
            REQUIRE( shows( infos[ 0 ], "Seq=1000" ) );
        }
    }
}

SCENARIO( "The whole-capture formatter shows relative numbers too", "[tcp_analysis]" )
{
    GIVEN( "a SYN with a random initial sequence number" )
    {
        const auto packets = parse( pcapOf( { segment( false, kSyn, 3000000000u, 0 ) } ) ).packets;

        THEN( "its line shows Seq=0" )
        {
            REQUIRE( shows( formatAllPackets( packets ).at( 1 ), "Seq=0" ) );
        }
    }
}

SCENARIO( "A segment sent again is marked a retransmission", "[tcp_analysis]" )
{
    GIVEN( "data the server did not acknowledge, sent again a second later" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( false, kPshAck, kC + 6, kS + 1, text( "more" ) ),
                                } );

        THEN( "the second copy is a retransmission, at the start of Info as in Wireshark" )
        {
            REQUIRE( unmarked( a.infos[ 3 ] ) );
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP Retransmission] 40000 \xe2\x86\x92 80 " ) );
            REQUIRE( a.markers[ 4 ] == TcpMarkers().set( TcpMarker::Retransmission ) );
        }

        THEN( "the data that follows it is not" )
        {
            REQUIRE( unmarked( a.infos[ 5 ] ) );
            REQUIRE( a.markers[ 5 ].none() );
        }
    }

    GIVEN( "a SYN sent again" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0 ),
            segment( false, kSyn, kC, 0 ),
        } );

        THEN( "it is a retransmission too, as it takes up a sequence number" )
        {
            REQUIRE( startsWith( a.infos[ 1 ], "[TCP Retransmission] " ) );
        }
    }

    GIVEN( "data the server has acknowledged already, sent again" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( true, kAck, kS + 1, kC + 6 ),
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                } );

        THEN( "it is a spurious retransmission" )
        {
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP Spurious Retransmission] 40000 " ) );
            REQUIRE( a.markers[ 5 ] == TcpMarkers().set( TcpMarker::SpuriousRetransmission ) );
        }
    }

    GIVEN( "a segment the receiver asked for with two duplicate ACKs, sent right away" )
    {
        const auto a = analyse( handshake()
                                    + std::vector<Bytes>{
                                        segment( false, kPshAck, kC + 1, kS + 1, Bytes( 10, 'a' ) ),
                                        segment( false, kPshAck, kC + 11, kS + 1, Bytes( 10, 'b' ) ),
                                        segment( false, kPshAck, kC + 21, kS + 1, Bytes( 10, 'c' ) ),
                                        segment( true, kAck, kS + 1, kC + 11 ),
                                        segment( true, kAck, kS + 1, kC + 11 ),
                                        segment( true, kAck, kS + 1, kC + 11 ),
                                        segment( false, kPshAck, kC + 11, kS + 1, Bytes( 10, 'b' ) ),
                                    },
                                1000 );

        THEN( "it is a fast retransmission" )
        {
            REQUIRE( startsWith( a.infos[ 9 ], "[TCP Fast Retransmission] 40000 " ) );
            REQUIRE( a.markers[ 9 ] == TcpMarkers().set( TcpMarker::FastRetransmission ) );
        }
    }
}

SCENARIO( "A segment that arrives shortly after a later one is out of order", "[tcp_analysis]" )
{
    const auto segments = handshake()
                          + std::vector<Bytes>{
                                segment( false, kPshAck, kC + 11, kS + 1, Bytes( 10, 'b' ) ),
                                segment( false, kPshAck, kC + 1, kS + 1, Bytes( 10, 'a' ) ),
                            };

    GIVEN( "the two half a millisecond apart, within Wireshark's 3 ms of the server's last "
           "segment" )
    {
        const auto a = analyse( segments, 500 );

        THEN( "the later data shows the gap, the earlier data is out of order" )
        {
            REQUIRE( startsWith( a.infos[ 3 ], "[TCP Previous segment not captured] 40000 " ) );
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP Out-Of-Order] 40000 " ) );
            REQUIRE( a.markers[ 4 ] == TcpMarkers().set( TcpMarker::OutOfOrder ) );
        }
    }

    GIVEN( "the two a second apart" )
    {
        const auto a = analyse( segments );

        THEN( "the earlier data is taken for a retransmission" )
        {
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP Retransmission] " ) );
        }
    }
}

SCENARIO( "An ACK that repeats the previous one is a duplicate ACK", "[tcp_analysis]" )
{
    GIVEN( "the client acknowledging the same data three times after the handshake" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kAck, kC + 1, kS + 1 ),
                                    segment( false, kAck, kC + 1, kS + 1 ),
                                } );

        THEN( "the repeats count from the last ACK that was not a duplicate, by its number" )
        {
            REQUIRE( unmarked( a.infos[ 2 ] ) );
            REQUIRE( startsWith( a.infos[ 3 ], "[TCP Dup ACK 3#1] 40000 " ) );
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP Dup ACK 3#2] 40000 " ) );
            REQUIRE( a.markers[ 4 ] == TcpMarkers().set( TcpMarker::DupAck ) );
        }
    }

    GIVEN( "a plain ACK that acknowledges new data" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( true, kPshAck, kS + 1, kC + 1, text( "hi" ) ),
                                    segment( false, kAck, kC + 1, kS + 3 ),
                                    segment( false, kAck, kC + 1, kS + 3 ),
                                } );

        THEN( "it is not a duplicate, and starts the count afresh" )
        {
            REQUIRE( unmarked( a.infos[ 4 ] ) );
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP Dup ACK 5#1] " ) );
        }
    }

    GIVEN( "the same ACK with another window, or with data" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "x" ), 1000 ),
                                } );

        THEN( "neither is a duplicate ACK: a window update, and data" )
        {
            REQUIRE( startsWith( a.infos[ 3 ], "[TCP Window Update] 40000 " ) );
            REQUIRE( a.markers[ 3 ] == TcpMarkers().set( TcpMarker::WindowUpdate ) );
            REQUIRE( unmarked( a.infos[ 4 ] ) );
        }
    }
}

SCENARIO( "A segment advertising no window is marked ZeroWindow", "[tcp_analysis]" )
{
    GIVEN( "the server's receive window running full" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( true, kAck, kS + 1, kC + 6, {}, 0 ),
                                    segment( false, kPshAck, kC + 6, kS + 1, text( "x" ) ),
                                    segment( true, kAck, kS + 1, kC + 6, {}, 0 ),
                                    segment( false, kPshAck, kC + 6, kS + 1, text( "x" ) ),
                                } );

        THEN( "its ACK shows ZeroWindow" )
        {
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP ZeroWindow] 80 \xe2\x86\x92 40000 " ) );
            REQUIRE( a.markers[ 4 ] == TcpMarkers().set( TcpMarker::ZeroWindow ) );
        }

        THEN( "a byte sent into the closed window is a probe, also when it is sent again" )
        {
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP ZeroWindowProbe] 40000 " ) );
            REQUIRE( startsWith( a.infos[ 7 ], "[TCP ZeroWindowProbe] 40000 " ) );
            REQUIRE( a.markers[ 7 ] == TcpMarkers().set( TcpMarker::ZeroWindowProbe ) );
        }

        THEN( "the ACK of a probe that keeps the window closed says so, Wireshark's last marker "
              "first" )
        {
            REQUIRE( startsWith( a.infos[ 6 ], "[TCP ZeroWindowProbeAck] [TCP ZeroWindow] 80 " ) );
            REQUIRE(
                a.markers[ 6 ]
                == TcpMarkers().set( TcpMarker::ZeroWindow ).set( TcpMarker::ZeroWindowProbeAck ) );
        }
    }

    GIVEN( "a SYN, FIN or RST with a window of zero" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 0 ),
            segment( true, kRst | kAck, 0, kC + 1, {}, 0 ),
            segment( false, kFin | kAck, kC + 1, 1, {}, 0 ),
        } );

        THEN( "none is marked: their window does not matter" )
        {
            REQUIRE( unmarked( a.infos[ 0 ] ) );
            REQUIRE( unmarked( a.infos[ 1 ] ) );
            REQUIRE( unmarked( a.infos[ 2 ] ) );
        }
    }
}

SCENARIO( "A segment one byte behind the next sequence number is a keep-alive", "[tcp_analysis]" )
{
    GIVEN( "an idle connection kept alive by the client, and the server's answer" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( true, kAck, kS + 1, kC + 6 ),
                                    segment( false, kAck, kC + 5, kS + 1 ),
                                    segment( true, kAck, kS + 1, kC + 6 ),
                                    segment( false, kAck, kC + 5, kS + 1, text( "?" ) ),
                                } );

        THEN( "the client's empty segment is a keep-alive, not a dup ACK" )
        {
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP Keep-Alive] 40000 " ) );
            REQUIRE( a.markers[ 5 ] == TcpMarkers().set( TcpMarker::KeepAlive ) );
        }

        THEN( "the server's repeated ACK answers it" )
        {
            REQUIRE( startsWith( a.infos[ 6 ], "[TCP Keep-Alive ACK] 80 " ) );
            REQUIRE( a.markers[ 6 ] == TcpMarkers().set( TcpMarker::KeepAliveAck ) );
        }

        THEN( "a keep-alive carrying the byte again is no retransmission" )
        {
            REQUIRE( startsWith( a.infos[ 7 ], "[TCP Keep-Alive] 40000 " ) );
            REQUIRE( a.markers[ 7 ] == TcpMarkers().set( TcpMarker::KeepAlive ) );
        }
    }

    GIVEN( "a repeated ACK that does not follow a keep-alive" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( true, kAck, kS + 1, kC + 6 ),
                                    segment( true, kAck, kS + 1, kC + 6 ),
                                } );

        THEN( "it is a dup ACK, not a keep-alive ACK" )
        {
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP Dup ACK 5#1] " ) );
        }
    }

    GIVEN( "a keep-alive with a closed window" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ) ),
                                    segment( false, kAck, kC + 5, kS + 1, {}, 0 ),
                                } );

        THEN( "it carries both markers, Wireshark's last first" )
        {
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP ZeroWindow] [TCP Keep-Alive] 40000 " ) );
        }
    }
}

SCENARIO( "The TCP Analysis marks nothing it cannot follow", "[tcp_analysis]" )
{
    GIVEN( "a stream past the stream cap, whose segments are repeated" )
    {
        auto packets = parse( pcapOf( { segment( false, kPshAck, kC, kS, text( "a" ) ),
                                        segment( false, kPshAck, kC, kS, text( "a" ) ) } ) )
                           .packets;
        StreamTracker tracker( 0 );

        THEN( "neither is marked" )
        {
            for ( auto& pkt : packets ) {
                REQUIRE( analyseTcp( pkt, tracker.track( pkt ) ).none() );
                REQUIRE( unmarked( pkt.info ) );
            }
        }
    }

    GIVEN( "a segment with a bogus header length, repeated" )
    {
        const auto bogus = eth( EthertypeIpv4,
                                ipv4( IpProtoTcp, tcp( kClient, kServer, {}, 2, kAck, kC, kS ) ) );
        const auto a = analyse( { bogus, bogus, bogus } );

        THEN( "none is analysed, as Wireshark leaves a malformed header alone" )
        {
            REQUIRE( unmarked( a.infos[ 2 ] ) );
            REQUIRE( a.markers[ 2 ].none() );
        }
    }

    GIVEN( "the first segments of a stream captured mid-way" )
    {
        const auto a = analyse( {
            segment( false, kAck, kC, kS ),
            segment( true, kAck, kS, kC ),
        } );

        THEN( "they are not marked" )
        {
            REQUIRE( unmarked( a.infos[ 0 ] ) );
            REQUIRE( unmarked( a.infos[ 1 ] ) );
        }
    }
}

SCENARIO( "Each marker kind has Wireshark's name", "[tcp_analysis]" )
{
    REQUIRE( std::string( tcpMarkerName( TcpMarker::Retransmission ) ) == "TCP Retransmission" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::FastRetransmission ) )
             == "TCP Fast Retransmission" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::SpuriousRetransmission ) )
             == "TCP Spurious Retransmission" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::OutOfOrder ) ) == "TCP Out-Of-Order" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::PreviousSegmentNotCaptured ) )
             == "TCP Previous segment not captured" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::WindowUpdate ) ) == "TCP Window Update" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::KeepAlive ) ) == "TCP Keep-Alive" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::KeepAliveAck ) ) == "TCP Keep-Alive ACK" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::DupAck ) ) == "TCP Dup ACK" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::ZeroWindowProbe ) ) == "TCP ZeroWindowProbe" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::ZeroWindow ) ) == "TCP ZeroWindow" );
    REQUIRE( std::string( tcpMarkerName( TcpMarker::ZeroWindowProbeAck ) )
             == "TCP ZeroWindowProbeAck" );
}

SCENARIO( "Data beyond the next sequence number shows a segment was not captured",
          "[tcp_analysis]" )
{
    GIVEN( "a gap in the client's data, and a reset beyond it" )
    {
        const auto a = analyse( handshake()
                                + std::vector<Bytes>{
                                    segment( false, kPshAck, kC + 11, kS + 1, Bytes( 10, 'b' ) ),
                                    segment( false, kPshAck, kC + 21, kS + 1, Bytes( 10, 'c' ) ),
                                    segment( false, kRst, kC + 100, 0 ),
                                } );

        THEN( "the segment after the gap says so, the next one and the reset do not" )
        {
            REQUIRE( startsWith( a.infos[ 3 ], "[TCP Previous segment not captured] 40000 " ) );
            REQUIRE( a.markers[ 3 ] == TcpMarkers().set( TcpMarker::PreviousSegmentNotCaptured ) );
            REQUIRE( unmarked( a.infos[ 4 ] ) );
            REQUIRE( unmarked( a.infos[ 5 ] ) );
        }
    }
}

SCENARIO( "The window is shown scaled once both sides agreed on window scaling", "[tcp_analysis]" )
{
    GIVEN( "a handshake in which both SYNs carry the window scale option" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 2 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000, 6 ),
            segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
            segment( true, kPshAck, kS + 1, kC + 1, text( "hi" ), 1000 ),
        } );

        THEN( "the SYNs show their window as sent" )
        {
            REQUIRE( showsWindow( a.infos[ 0 ], "Seq=0 Win=1000" ) );
            REQUIRE( showsWindow( a.infos[ 1 ], "Seq=0 Ack=1 Win=1000" ) );
        }

        THEN( "later segments show it shifted by their sender's scale" )
        {
            REQUIRE( showsWindow( a.infos[ 2 ], "Seq=1 Ack=1 Win=4000" ) );
            REQUIRE( showsWindow( a.infos[ 3 ], "Seq=1 Ack=1 Win=64000 Len=2" ) );
        }
    }

    GIVEN( "a shift beyond 14" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 15 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000, 0 ),
            segment( false, kAck, kC + 1, kS + 1, {}, 1 ),
            segment( true, kAck, kS + 1, kC + 1, {}, 1 ),
        } );

        THEN( "14 is used instead, as RFC 7323 says; a shift of 0 scales by 1" )
        {
            REQUIRE( showsWindow( a.infos[ 2 ], "Seq=1 Ack=1 Win=16384" ) );
            REQUIRE( showsWindow( a.infos[ 3 ], "Seq=1 Ack=1 Win=1" ) );
        }
    }

    GIVEN( "a handshake in which only the client's SYN carries the option" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 2 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000 ),
            segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
            segment( true, kAck, kS + 1, kC + 1, {}, 1000 ),
        } );

        THEN( "no window is scaled: the sides did not agree on scaling" )
        {
            REQUIRE( showsWindow( a.infos[ 2 ], "Seq=1 Ack=1 Win=1000" ) );
            REQUIRE( showsWindow( a.infos[ 3 ], "Seq=1 Ack=1 Win=1000" ) );
        }
    }

    GIVEN( "a stream captured mid-way, its handshake not seen" )
    {
        const auto a = analyse( {
            segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
            segment( true, kAck, kS + 1, kC + 1, {}, 1000 ),
        } );

        THEN( "the window is shown as sent, its scale unknown" )
        {
            REQUIRE( showsWindow( a.infos[ 0 ], "Seq=1 Ack=1 Win=1000" ) );
            REQUIRE( showsWindow( a.infos[ 1 ], "Seq=1 Ack=1 Win=1000" ) );
        }
    }

    GIVEN( "a new connection on the same ports whose SYNs carry no option" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 2 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000, 6 ),
            segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
            segment( false, kSyn, kC + 100000, 0, {}, 1000 ),
            segment( true, kSyn | kAck, kS + 100000, kC + 100001, {}, 1000 ),
            segment( false, kAck, kC + 100001, kS + 100001, {}, 1000 ),
        } );

        THEN( "it does not inherit the old connection's scaling" )
        {
            REQUIRE( showsWindow( a.infos[ 2 ], "Seq=1 Ack=1 Win=4000" ) );
            REQUIRE( showsWindow( a.infos[ 5 ], "Seq=1 Ack=1 Win=1000" ) );
        }
    }
}

SCENARIO( "The analysis markers look at the scaled window", "[tcp_analysis]" )
{
    GIVEN( "a server whose first ACK after its SYN-ACK repeats the SYN-ACK's window as sent" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 2 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000, 6 ),
            segment( true, kAck, kS + 1, kC + 1, {}, 1000 ),
            segment( true, kAck, kS + 1, kC + 1, {}, 1000 ),
        } );

        THEN( "the scaled window is a new one, a window update; the same again is a duplicate "
              "ACK" )
        {
            REQUIRE( startsWith( a.infos[ 2 ], "[TCP Window Update] 80 " ) );
            REQUIRE( showsWindow( a.infos[ 2 ], "Seq=1 Ack=1 Win=64000" ) );
            REQUIRE( startsWith( a.infos[ 3 ], "[TCP Dup ACK 2#1] 80 " ) );
        }
    }

    GIVEN( "a scaled window closing and opening again" )
    {
        const auto a = analyse( {
            segment( false, kSyn, kC, 0, {}, 1000, 2 ),
            segment( true, kSyn | kAck, kS, kC + 1, {}, 1000, 6 ),
            segment( false, kAck, kC + 1, kS + 1, {}, 1000 ),
            segment( false, kPshAck, kC + 1, kS + 1, text( "hello" ), 1000 ),
            segment( true, kAck, kS + 1, kC + 6, {}, 0 ),
            segment( true, kAck, kS + 1, kC + 6, {}, 2 ),
        } );

        THEN( "the closed window is a zero window, the opened one a window update" )
        {
            REQUIRE( startsWith( a.infos[ 4 ], "[TCP ZeroWindow] 80 " ) );
            REQUIRE( showsWindow( a.infos[ 4 ], "Seq=1 Ack=6 Win=0" ) );
            REQUIRE( startsWith( a.infos[ 5 ], "[TCP Window Update] 80 " ) );
            REQUIRE( showsWindow( a.infos[ 5 ], "Seq=1 Ack=6 Win=128" ) );
        }
    }
}
