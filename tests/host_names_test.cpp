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
 * @file host_names_test.cpp
 * @brief BDD tests for the host names: what DNS answers name
 *        (dnsResolvedNames()), the Host Names that keep them, and the
 *        Converter's lines and summary with host names shown, over
 *        tests/corpus/names.pcap.
 */

#include <catch2/catch.hpp>

#include "host_names.h"
#include "packet_formatter.h"
#include "payload_describer.h"
#include "pcap_converter.h"

#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QTemporaryDir>

#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

constexpr uint16_t kA = 1;
constexpr uint16_t kCname = 5;
constexpr uint16_t kPtr = 12;
constexpr uint16_t kMx = 15;
constexpr uint16_t kAaaa = 28;

constexpr uint16_t kQuery = 0x0100;
constexpr uint16_t kResponse = 0x8180;
constexpr uint16_t kNxDomain = 0x8183;
constexpr uint16_t kMdnsResponse = 0x8400;

Bytes operator+( Bytes a, const Bytes& b )
{
    a.insert( a.end(), b.begin(), b.end() );
    return a;
}

Bytes be16( size_t v )
{
    return { static_cast<uint8_t>( v >> 8 ), static_cast<uint8_t>( v ) };
}

/// A name as labels, uncompressed.
Bytes name( const std::string& dotted )
{
    Bytes out;
    std::istringstream labels( dotted );
    std::string label;
    while ( std::getline( labels, label, '.' ) ) {
        out.push_back( static_cast<uint8_t>( label.size() ) );
        out.insert( out.end(), label.begin(), label.end() );
    }
    out.push_back( 0 );
    return out;
}

Bytes record( const std::string& owner, uint16_t type, const Bytes& data, uint16_t ttl = 0x0E10 )
{
    return name( owner ) + be16( type ) + be16( 1 ) + be16( 0 ) + be16( ttl ) + be16( data.size() )
           + data;
}

Bytes ipv4( uint8_t a, uint8_t b, uint8_t c, uint8_t d )
{
    return { a, b, c, d };
}

Bytes ipv6Doc( uint8_t last )
{
    Bytes out{ 0x20, 0x01, 0x0d, 0xb8 };
    out.resize( 15, 0 );
    out.push_back( last );
    return out;
}

/// A response to a question for @p qname with @p count answers.
Bytes response( const std::string& qname, uint16_t type, size_t count, const Bytes& answers,
                uint16_t flags = kResponse )
{
    return be16( 0x1234 ) + be16( flags ) + be16( 1 ) + be16( count ) + be16( 0 ) + be16( 0 )
           + name( qname ) + be16( type ) + be16( 1 ) + answers;
}

std::vector<std::pair<std::string, std::string>> resolved( const Bytes& message )
{
    std::vector<std::pair<std::string, std::string>> out;
    for ( const auto& [ address, host ] : dnsResolvedNames( message.data(), message.size() ) ) {
        out.emplace_back( address, host );
    }
    return out;
}

using Names = std::vector<std::pair<std::string, std::string>>;

PacketRecord udpFrom( uint16_t srcPort )
{
    PacketRecord pkt;
    pkt.transport = Transport::Udp;
    pkt.srcPort = srcPort;
    pkt.dstPort = 50000;
    return pkt;
}

/// The packet lines of tests/corpus/names.pcap converted with @p options,
/// header excluded, and the summary.
std::pair<QStringList, CaptureSummary> convertNames( const ConversionOptions& options )
{
    static QTemporaryDir out;
    REQUIRE( out.isValid() );
    const auto result
        = convertPcap( QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( "names.pcap" ),
                       out.path(), nullptr, {}, options );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    QFile file( result.outputPath );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
    lines.removeFirst();
    return { lines, result.summary };
}

/// The Source and Destination of a packet line.
std::pair<QString, QString> addressesOf( const QString& line )
{
    const auto words = line.split( ' ', Qt::SkipEmptyParts );
    // No., Stream, UTC date and time, Time, Source, Destination
    return { words[ 5 ], words[ 6 ] };
}

} // namespace

SCENARIO( "DNS answers name the addresses they resolve", "[hostnames]" )
{
    GIVEN( "an A answer behind a CNAME" )
    {
        const auto message
            = response( "www.example.com", kA, 2,
                        record( "www.example.com", kCname, name( "example.com" ) )
                            + record( "example.com", kA, ipv4( 93, 184, 216, 34 ) ) );

        THEN( "the address gets the name that was asked for" )
        {
            REQUIRE( resolved( message ) == Names{ { "93.184.216.34", "www.example.com" } } );
        }
    }

    GIVEN( "a chain of CNAMEs in another case, and an AAAA answer" )
    {
        const auto message = response( "a.example", kAaaa, 3,
                                       record( "a.example", kCname, name( "B.example" ) )
                                           + record( "b.example", kCname, name( "c.example" ) )
                                           + record( "c.example", kAaaa, ipv6Doc( 1 ) ) );

        THEN( "the chain is followed back to its start, names compared without case" )
        {
            REQUIRE( resolved( message ) == Names{ { "2001:db8::1", "a.example" } } );
        }
    }

    GIVEN( "CNAMEs that loop" )
    {
        const auto message = response( "x.example", kA, 3,
                                       record( "x.example", kCname, name( "y.example" ) )
                                           + record( "y.example", kCname, name( "x.example" ) )
                                           + record( "x.example", kA, ipv4( 192, 0, 2, 1 ) ) );

        THEN( "following them back stops, and the address is named all the same" )
        {
            const auto names = resolved( message );
            REQUIRE( names.size() == 1 );
            REQUIRE( names[ 0 ].first == "192.0.2.1" );
        }
    }

    GIVEN( "PTR answers for IPv4 and IPv6 reverse names" )
    {
        // 2001:db8::1, its 32 nibbles from the last
        std::string v6 = "1.";
        for ( int i = 0; i < 23; ++i ) {
            v6 += "0.";
        }
        v6 += "8.b.d.0.1.0.0.2.ip6.arpa";
        const auto message
            = response( "7.100.51.198.in-addr.arpa", kPtr, 2,
                        record( "7.100.51.198.in-addr.arpa", kPtr, name( "ntp.example.net" ) )
                            + record( v6, kPtr, name( "host6.example.net" ) ) );

        THEN( "each names the address its owner spells" )
        {
            REQUIRE( resolved( message )
                     == Names{ { "198.51.100.7", "ntp.example.net" },
                               { "2001:db8::1", "host6.example.net" } } );
        }
    }

    GIVEN( "PTR answers whose owner spells no address" )
    {
        const auto message
            = response( "x", kPtr, 3,
                        record( "300.1.1.1.in-addr.arpa", kPtr, name( "a.example" ) )
                            + record( "1.1.1.in-addr.arpa", kPtr, name( "b.example" ) )
                            + record( "_http._tcp.local", kPtr, name( "c.example" ) ) );

        THEN( "they name nothing" )
        {
            REQUIRE( resolved( message ).empty() );
        }
    }

    GIVEN( "an mDNS response without questions" )
    {
        const auto message = be16( 0 ) + be16( kMdnsResponse ) + be16( 0 ) + be16( 1 ) + be16( 0 )
                             + be16( 0 ) + record( "printer.local", kA, ipv4( 192, 0, 2, 20 ) );

        THEN( "its answer names the address" )
        {
            REQUIRE( resolved( message ) == Names{ { "192.0.2.20", "printer.local" } } );
        }
    }

    GIVEN( "an mDNS response whose addresses are additional records" )
    {
        constexpr uint16_t kSrv = 33;
        const auto message
            = be16( 0 ) + be16( kMdnsResponse ) + be16( 0 ) + be16( 1 ) + be16( 0 ) + be16( 2 )
              + record( "_ipp._tcp.local", kPtr, name( "Printer._ipp._tcp.local" ) )
              + record( "Printer._ipp._tcp.local", kSrv,
                        be16( 0 ) + be16( 0 ) + be16( 631 ) + name( "printer.local" ) )
              + record( "printer.local", kA, ipv4( 192, 0, 2, 30 ) );

        THEN( "they name their addresses in mDNS, not in DNS, where they are unasked for" )
        {
            REQUIRE( dnsResolvedNames( message.data(), message.size(), true ).size() == 1 );
            REQUIRE( dnsResolvedNames( message.data(), message.size(), true )[ 0 ].name
                     == "printer.local" );
            REQUIRE( resolved( message ).empty() );
        }
    }

    GIVEN( "an mDNS goodbye: its records with TTL 0" )
    {
        const auto message = be16( 0 ) + be16( kMdnsResponse ) + be16( 0 ) + be16( 1 ) + be16( 0 )
                             + be16( 1 ) + record( "printer.local", kA, ipv4( 192, 0, 2, 20 ), 0 )
                             + record( "scanner.local", kA, ipv4( 192, 0, 2, 21 ), 0 );

        THEN( "it names nothing in mDNS; a DNS answer of TTL 0 still names" )
        {
            REQUIRE( dnsResolvedNames( message.data(), message.size(), true ).empty() );
            HostNames names;
            names.learn( udpFrom( 5353 ), { message.data(), message.size() }, {} );
            REQUIRE( names.size() == 0 );
            REQUIRE( resolved( message ) == Names{ { "192.0.2.20", "printer.local" } } );
        }
    }

    GIVEN( "messages that are no answer to learn from" )
    {
        const auto answer = record( "example.com", kA, ipv4( 192, 0, 2, 1 ) );

        THEN( "a query, an error response and other records name nothing" )
        {
            REQUIRE( resolved( response( "example.com", kA, 1, answer, kQuery ) ).empty() );
            REQUIRE( resolved( response( "example.com", kA, 1, answer, kNxDomain ) ).empty() );
            REQUIRE( resolved( response( "example.com", kMx, 1,
                                         record( "example.com", kMx,
                                                 be16( 10 ) + name( "mail.example.com" ) ) ) )
                         .empty() );
            REQUIRE( resolved( Bytes{ 0x12, 0x34, 0x81 } ).empty() );
        }

        THEN( "a name that no column could show names nothing" )
        {
            REQUIRE( resolved( response( "bad name", kA, 1,
                                         record( "bad name", kA, ipv4( 192, 0, 2, 1 ) ) ) )
                         .empty() );
            REQUIRE(
                resolved( response( "a(b)", kA, 1, record( "a(b)", kA, ipv4( 192, 0, 2, 1 ) ) ) )
                    .empty() );
        }
    }

    GIVEN( "a response cut short in its second answer" )
    {
        auto message = response( "example.com", kA, 2,
                                 record( "example.com", kA, ipv4( 192, 0, 2, 1 ) )
                                     + record( "example.com", kA, ipv4( 192, 0, 2, 2 ) ) );
        message.resize( message.size() - 2 );

        THEN( "the answers before the cut name their addresses" )
        {
            REQUIRE( resolved( message ) == Names{ { "192.0.2.1", "example.com" } } );
        }
    }

    GIVEN( "a response with more answers than are read" )
    {
        Bytes answers;
        for ( size_t i = 0; i < kMaxResolvedNames + 8; ++i ) {
            answers = answers
                      + record( "pool.example", kA, ipv4( 10, 0, 0, static_cast<uint8_t>( i ) ) );
        }
        const auto message = response( "pool.example", kA, kMaxResolvedNames + 8, answers );

        THEN( "the first kMaxResolvedNames name their addresses" )
        {
            REQUIRE( resolved( message ).size() == kMaxResolvedNames );
        }
    }
}

SCENARIO( "Only host names stand in a column", "[hostnames]" )
{
    THEN( "letters, digits, '-', '_' and '.' are" )
    {
        REQUIRE( isHostName( "www.example.com" ) );
        REQUIRE( isHostName( "_sip._udp.example.com" ) );
        REQUIRE( isHostName( "printer-2.local" ) );
        REQUIRE( isHostName( std::string( kMaxHostName, 'a' ) ) );
    }

    THEN( "anything else, an empty name, a leading dot or one too long is not" )
    {
        REQUIRE_FALSE( isHostName( "" ) );
        REQUIRE_FALSE( isHostName( ".example" ) );
        REQUIRE_FALSE( isHostName( "a b" ) );
        REQUIRE_FALSE( isHostName( "a(b)" ) );
        REQUIRE_FALSE( isHostName( "a\\x00b" ) );
        REQUIRE_FALSE( isHostName( "<Root>" ) );
        REQUIRE_FALSE( isHostName( "caf\xc3\xa9.example" ) );
        REQUIRE_FALSE( isHostName( std::string( kMaxHostName + 1, 'a' ) ) );
    }
}

SCENARIO( "The Host Names keep the names learned last, within their cap", "[hostnames]" )
{
    GIVEN( "Host Names for two addresses" )
    {
        HostNames names( 2 );
        names.add( "192.0.2.1", "one.example" );
        names.add( "192.0.2.2", "two.example" );

        THEN( "each address has its name, others none" )
        {
            REQUIRE( *names.find( "192.0.2.1" ) == "one.example" );
            REQUIRE( *names.find( "192.0.2.2" ) == "two.example" );
            REQUIRE( names.find( "192.0.2.3" ) == nullptr );
        }

        WHEN( "an address gets another name" )
        {
            names.add( "192.0.2.1", "spoofed.example" );

            THEN( "the later name replaces the earlier" )
            {
                REQUIRE( *names.find( "192.0.2.1" ) == "spoofed.example" );
                REQUIRE( names.size() == 2 );
            }

            AND_WHEN( "a third address is named" )
            {
                names.add( "192.0.2.3", "three.example" );

                THEN( "the name learned longest ago is let go" )
                {
                    REQUIRE( names.find( "192.0.2.2" ) == nullptr );
                    REQUIRE( *names.find( "192.0.2.1" ) == "spoofed.example" );
                    REQUIRE( *names.find( "192.0.2.3" ) == "three.example" );
                    REQUIRE( names.size() == 2 );
                }
            }
        }
    }

    GIVEN( "packets that carry a DNS response" )
    {
        const auto message
            = response( "example.com", kA, 1, record( "example.com", kA, ipv4( 192, 0, 2, 1 ) ) );
        const ByteView payload{ message.data(), message.size() };

        THEN( "a datagram from port 53 or 5353 teaches its names" )
        {
            for ( const uint16_t port : { 53, 5353 } ) {
                HostNames names;
                names.learn( udpFrom( port ), payload, {} );
                REQUIRE( names.find( "192.0.2.1" ) );
            }
        }

        THEN( "one to those ports, or from DNS over TLS, teaches nothing" )
        {
            HostNames names;
            auto toServer = udpFrom( 50000 );
            toServer.dstPort = 53;
            names.learn( toServer, payload, {} );
            names.learn( udpFrom( 853 ), payload, {} );
            auto tls = udpFrom( 853 );
            tls.transport = Transport::Tcp;
            const auto framed = be16( message.size() ) + message;
            names.learn( tls, {}, { framed.data(), framed.size() } );
            REQUIRE( names.size() == 0 );
        }

        THEN( "a TCP segment from port 53 teaches the whole messages it completed" )
        {
            const auto second = response( "example.org", kA, 1,
                                          record( "example.org", kA, ipv4( 192, 0, 2, 2 ) ) );
            auto messages = be16( message.size() ) + message + be16( second.size() ) + second;
            messages.resize( messages.size() + 1 ); // a byte of a next message
            auto pkt = udpFrom( 53 );
            pkt.transport = Transport::Tcp;
            HostNames names;
            names.learn( pkt, payload, { messages.data(), messages.size() } );
            REQUIRE( *names.find( "192.0.2.1" ) == "example.com" );
            REQUIRE( *names.find( "192.0.2.2" ) == "example.org" );
        }
    }
}

SCENARIO( "The Packet Formatter shows an address's name behind it", "[hostnames]" )
{
    PacketRecord pkt;
    pkt.number = 1;
    pkt.srcIp = "192.0.2.10";
    pkt.dstIp = "93.184.216.34";
    pkt.protocol = "TCP";
    HostNames names;
    names.add( "93.184.216.34", "www.example.com" );

    THEN( "with host names shown, a named address is one word with its name" )
    {
        LineLayout layout;
        layout.hostNames = true;
        const auto line
            = formatPacketLine( pkt, 0, 0, 0, TimePrecision::Microseconds, layout, &names );
        REQUIRE( line.find( " 192.0.2.10 " ) != std::string::npos );
        REQUIRE( line.find( " 93.184.216.34(www.example.com) " ) != std::string::npos );
    }

    THEN( "without, the line is as it ever was" )
    {
        REQUIRE( formatPacketLine( pkt, 0, 0, 0, TimePrecision::Microseconds, {}, &names )
                 == formatPacketLine( pkt, 0, 0, 0 ) );
    }
}

SCENARIO( "A capture converted with host names names its addresses from then on",
          "[hostnames][corpus]" )
{
    ConversionOptions options;
    options.layout.hostNames = true;
    const auto named = convertNames( options );
    const auto unnamed = convertNames( {} );
    const auto& lines = named.first;
    const auto& summary = named.second;
    const auto& plain = unnamed.first;
    const auto& plainSummary = unnamed.second;
    REQUIRE( lines.size() == 29 );
    REQUIRE( plain.size() == lines.size() );
    const auto addresses = [ &lines ]( int number ) {
        INFO( lines[ number - 1 ].toStdString() );
        return addressesOf( lines[ number - 1 ] );
    };
    using Pair = std::pair<QString, QString>;

    THEN( "packets before the answer show the address alone, those after it its name" )
    {
        REQUIRE( addresses( 1 ) == Pair{ "192.0.2.10", "93.184.216.34" } );
        REQUIRE( addresses( 2 ) == Pair{ "93.184.216.34", "192.0.2.10" } );
        REQUIRE( addresses( 5 ) == Pair{ "192.0.2.10", "93.184.216.34(www.example.com)" } );
        REQUIRE( addresses( 7 ) == Pair{ "93.184.216.34(www.example.com)", "192.0.2.10" } );
    }

    THEN( "AAAA, PTR, mDNS and DNS-over-TCP answers name their addresses" )
    {
        REQUIRE( addresses( 10 ) == Pair{ "2001:db8::10", "2001:db8::1(example.com)" } );
        REQUIRE( addresses( 14 ) == Pair{ "192.0.2.10", "198.51.100.7(ntp.example.net)" } );
        // The announcement's own line is written before its name is learned.
        REQUIRE( addresses( 15 ) == Pair{ "192.0.2.20", "224.0.0.251" } );
        REQUIRE( addresses( 16 ) == Pair{ "192.0.2.20(printer.local)", "192.0.2.10" } );
        REQUIRE( addresses( 22 ) == Pair{ "192.0.2.10", "192.0.2.80(example.org)" } );
    }

    THEN( "a name no column could show is not learned" )
    {
        REQUIRE( addresses( 25 ) == Pair{ "192.0.2.10", "203.0.113.5" } );
    }

    THEN( "a later answer renames the address, unchecked" )
    {
        REQUIRE( addresses( 28 ) == Pair{ "192.0.2.10", "93.184.216.34(other.example)" } );
        REQUIRE( addresses( 29 ) == Pair{ "93.184.216.34(other.example)", "192.0.2.10" } );
    }

    THEN( "only Source and Destination change, and nothing else of the lines" )
    {
        static const QRegularExpression named( R"(\([A-Za-z0-9_.-]+\))" );
        int changed = 0;
        for ( qsizetype i = 0; i < lines.size(); ++i ) {
            auto line = lines[ i ];
            line.replace( named, "" );
            // The columns are padded to their width; a name may overrun it.
            REQUIRE( line.simplified() == plain[ i ].simplified() );
            changed += lines[ i ] != plain[ i ];
        }
        REQUIRE( changed == 10 );
    }

    THEN( "the summary names its endpoints with the names learned last, and counts as ever" )
    {
        REQUIRE( summary.endpointPackets == plainSummary.endpointPackets );
        REQUIRE( summary.endpointNames
                 == std::map<std::string, std::string>{
                     { "198.51.100.7", "ntp.example.net" },
                     { "192.0.2.20", "printer.local" },
                     { "192.0.2.80", "example.org" },
                     { "2001:db8::1", "example.com" },
                     { "93.184.216.34", "other.example" },
                 } );
        REQUIRE( plainSummary.endpointNames.empty() );
    }

    THEN( "the conversations are the same as without names" )
    {
        const auto& with = *summary.conversations;
        const auto& without = *plainSummary.conversations;
        REQUIRE( with.size() == without.size() );
        for ( size_t i = 0; i < with.size(); ++i ) {
            REQUIRE( with[ i ].stream == without[ i ].stream );
            REQUIRE( with[ i ].addressA == without[ i ].addressA );
            REQUIRE( with[ i ].addressB == without[ i ].addressB );
            REQUIRE( with[ i ].packetsAToB + with[ i ].packetsBToA
                     == without[ i ].packetsAToB + without[ i ].packetsBToA );
        }
    }
}

SCENARIO( "A capture converted with a small cap of host names lets the oldest go",
          "[hostnames][corpus]" )
{
    ConversionOptions options;
    options.layout.hostNames = true;
    options.maxHostNames = 1;
    const auto converted = convertNames( options );
    const auto& lines = converted.first;
    const auto& summary = converted.second;

    THEN( "each address keeps its name until the next one is learned" )
    {
        REQUIRE( addressesOf( lines[ 6 ] ).first == "93.184.216.34(www.example.com)" );
        REQUIRE( addressesOf( lines[ 9 ] ).second == "2001:db8::1(example.com)" );
        REQUIRE( addressesOf( lines[ 21 ] ).second == "192.0.2.80(example.org)" );
        REQUIRE( addressesOf( lines[ 27 ] ).second == "93.184.216.34(other.example)" );
    }

    THEN( "at the end, only the name learned last is left" )
    {
        REQUIRE( summary.endpointNames
                 == std::map<std::string, std::string>{ { "93.184.216.34", "other.example" } } );
    }
}

SCENARIO( "Mutated DNS responses name only host names", "[hostnames]" )
{
    const auto original
        = response( "www.example.com", kA, 4,
                    record( "www.example.com", kCname, name( "example.com" ) )
                        + record( "example.com", kA, ipv4( 93, 184, 216, 34 ) )
                        + record( "example.com", kAaaa, ipv6Doc( 1 ) )
                        + record( "34.216.184.93.in-addr.arpa", kPtr, name( "example.com" ) ) );
    std::mt19937 random( 54 );
    std::uniform_int_distribution<size_t> position( 0, original.size() - 1 );
    std::uniform_int_distribution<int> byte( 0, 255 );

    THEN( "every name read is one a column can show, and none is read beyond the message" )
    {
        for ( int round = 0; round < 20000; ++round ) {
            auto message = original;
            const int changes = 1 + round % 4;
            for ( int i = 0; i < changes; ++i ) {
                message[ position( random ) ] = static_cast<uint8_t>( byte( random ) );
            }
            message.resize( position( random ) + 1 );
            for ( const auto& [ address, host ] :
                  dnsResolvedNames( message.data(), message.size() ) ) {
                REQUIRE( isHostName( host ) );
                REQUIRE_FALSE( address.empty() );
            }
        }
    }
}
