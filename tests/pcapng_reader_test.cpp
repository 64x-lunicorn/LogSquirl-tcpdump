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
 * @file pcapng_reader_test.cpp
 * @brief BDD tests for reading pcapng captures, block by block.
 */

#include <catch2/catch.hpp>

#include "packet_formatter.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "pcapng_reader.h"

#include <QFile>
#include <QTemporaryDir>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

Bytes udpFrame( uint16_t port )
{
    return eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, port, text( "hello" ) ) ) );
}

Bytes rawUdp( uint16_t port )
{
    return ipv4( IpProtoUdp, udp( 50000, port ) );
}

QString writeFile( const QTemporaryDir& dir, const QString& name, const Bytes& content )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    REQUIRE( file.write( reinterpret_cast<const char*>( content.data() ),
                         static_cast<qint64>( content.size() ) )
             == static_cast<qint64>( content.size() ) );
    return path;
}

QStringList readLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    if ( !lines.isEmpty() && lines.last().isEmpty() ) {
        lines.removeLast();
    }
    return lines;
}

/// The Time column of a converted line.
// The relative time follows the UTC date and time.
QString timeOf( const QString& line )
{
    return line.mid( 14 ).section( ' ', 2, 2, QString::SectionSkipEmpty );
}

const Pcapng le;
const Pcapng be{ true };

} // namespace

SCENARIO( "A pcapng capture is read in either byte order", "[pcapng]" )
{
    for ( const auto& order : { le, be } ) {
        GIVEN( std::string( order.bigEndian ? "a big" : "a little" )
               + "-endian section with one Ethernet interface and a packet" )
        {
            const auto file = order.shb() + order.idb( DltEthernet )
                              + order.epb( 0, 1000 * 1000000ULL + 250, udpFrame( 53 ) );

            WHEN( "it is parsed" )
            {
                const auto result = parse( file );

                THEN( "the packet is dissected with the interface's link type and precision" )
                {
                    REQUIRE( result.ok );
                    REQUIRE( result.packets.size() == 1 );
                    const auto& pkt = result.packets[ 0 ];
                    REQUIRE( pkt.number == 1 );
                    REQUIRE( pkt.linkType == DltEthernet );
                    REQUIRE( pkt.precision == TimePrecision::Microseconds );
                    REQUIRE( pkt.timestampSec == 1000 );
                    REQUIRE( pkt.timestampNsec == 250000 );
                    REQUIRE( pkt.srcMac == "66:77:88:99:aa:bb" );
                    REQUIRE( pkt.srcIp == "192.168.1.1" );
                    REQUIRE( pkt.dstPort == 53 );
                    REQUIRE( pkt.capturedLen == udpFrame( 53 ).size() );
                    REQUIRE( pkt.originalLen == udpFrame( 53 ).size() );
                    REQUIRE_FALSE( result.truncated );
                }

                THEN( "the reader announces the interface's link type and precision" )
                {
                    REQUIRE( result.linkTypes == std::vector<uint32_t>{ DltEthernet } );
                    REQUIRE( result.precision == TimePrecision::Microseconds );
                }
            }
        }
    }
}

SCENARIO( "if_tsresol gives an interface's timestamp unit", "[pcapng]" )
{
    struct Case {
        int tsresol;
        uint64_t timestamp;
        uint32_t sec;
        uint32_t nsec;
        TimePrecision precision;
    };
    const std::vector<Case> cases{
        { 6, 7000001ULL, 7, 1000, TimePrecision::Microseconds },
        { 9, 7000000001ULL, 7, 1, TimePrecision::Nanoseconds },
        { 3, 7005ULL, 7, 5000000, TimePrecision::Microseconds },
        { 12, 7000000000123ULL, 7, 0, TimePrecision::Nanoseconds },
        { 0x80 | 10, 7 * 1024ULL + 512, 7, 500000000, TimePrecision::Microseconds },
        { 0x80 | 30, ( 7ULL << 30 ) + ( 1ULL << 29 ), 7, 500000000, TimePrecision::Nanoseconds },
        { 0x80 | 40, ( 7ULL << 40 ) + ( 1ULL << 38 ), 7, 250000000, TimePrecision::Nanoseconds },
    };

    for ( const auto& c : cases ) {
        GIVEN( "an interface with if_tsresol " + std::to_string( c.tsresol ) )
        {
            const auto file = le.shb() + le.idb( DltEthernet, c.tsresol )
                              + le.epb( 0, c.timestamp, udpFrame( 1 ) );

            THEN( "the timestamp is converted to seconds and nanoseconds" )
            {
                const auto result = parse( file );
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.packets[ 0 ].timestampSec == c.sec );
                REQUIRE( result.packets[ 0 ].timestampNsec == c.nsec );
                REQUIRE( result.packets[ 0 ].precision == c.precision );
                REQUIRE( result.precision == c.precision );
            }
        }
    }

    GIVEN( "an interface with a unit too fine to count in 64 bits" )
    {
        const auto file = le.shb() + le.idb( DltEthernet, 20 ) + le.epb( 0, 1, udpFrame( 1 ) );

        THEN( "the capture ends there, as one that cannot be read on" )
        {
            const auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.packets.empty() );
            REQUIRE( result.truncated );
        }
    }
}

SCENARIO( "A pcapng time past 2106 keeps its date", "[pcapng]" )
{
    // A 64-bit timestamp in seconds: the second and third packets lie beyond
    // 32 bits of seconds, the third centuries after the first.
    GIVEN( "an interface counting in seconds, with packets in 1970, 2106 and 2286" )
    {
        const auto file = le.shb() + le.idb( DltEthernet, 0 ) + le.epb( 0, 1000, udpFrame( 1 ) )
                          + le.epb( 0, ( 1ULL << 32 ) + 5, udpFrame( 2 ) )
                          + le.epb( 0, 10000000000ULL, udpFrame( 3 ) );

        THEN( "each packet has its seconds in full" )
        {
            const auto result = parse( file );
            REQUIRE( result.packets.size() == 3 );
            REQUIRE( result.packets[ 1 ].timestampSec == 4294967301LL );
            REQUIRE( result.packets[ 2 ].timestampSec == 10000000000LL );
        }

        THEN( "the UTC Time, the relative Time and the Capture Summary show the real dates" )
        {
            QTemporaryDir dir;
            REQUIRE( dir.isValid() );
            const auto result = convertPcap( writeFile( dir, "future.pcapng", file ), dir.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            const auto lines = readLines( result.outputPath );
            REQUIRE( lines.size() == 4 );
            REQUIRE( lines[ 2 ].contains( "2106-02-07 06:28:21.000000Z" ) );
            REQUIRE( lines[ 3 ].contains( "2286-11-20 17:46:40.000000Z" ) );
            REQUIRE( timeOf( lines[ 2 ] ) == "4294966301.000000" );
            REQUIRE( timeOf( lines[ 3 ] ) == "9999999000.000000" );
            REQUIRE( result.summary.firstTimeUtc == "1970-01-01 00:16:40.000000Z" );
            REQUIRE( result.summary.lastTimeUtc == "2286-11-20 17:46:40.000000Z" );
            REQUIRE( result.summary.durationSeconds == Approx( 9999999000.0 ) );
        }
    }
}

SCENARIO( "Each packet is dissected with its own interface's link type", "[pcapng]" )
{
    GIVEN( "an Ethernet and a Raw IP interface, with a packet on each" )
    {
        const auto file = le.shb() + le.idb( DltEthernet ) + le.idb( DltRaw )
                          + le.epb( 1, 2000000, rawUdp( 7 ) ) + le.epb( 0, 3000000, udpFrame( 8 ) );

        WHEN( "it is parsed" )
        {
            const auto result = parse( file );

            THEN( "each packet has its interface's link type" )
            {
                REQUIRE( result.packets.size() == 2 );
                REQUIRE( result.packets[ 0 ].linkType == DltRaw );
                REQUIRE( result.packets[ 0 ].dstPort == 7 );
                REQUIRE( result.packets[ 0 ].srcMac.empty() );
                REQUIRE( result.packets[ 1 ].linkType == DltEthernet );
                REQUIRE( result.packets[ 1 ].dstPort == 8 );
                REQUIRE( result.linkTypes == std::vector<uint32_t>{ DltEthernet, DltRaw } );
            }
        }

        WHEN( "it is converted" )
        {
            QTemporaryDir dir;
            REQUIRE( dir.isValid() );
            const auto result = convertPcap( writeFile( dir, "two.pcapng", file ), dir.path() );

            THEN( "the Capture Summary lists both link types" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.packets == 2 );
                REQUIRE( result.summary.linkTypeNames
                         == std::vector<std::string>{ "Raw IP", "Ethernet" } );
            }
        }
    }

    GIVEN( "two interfaces of the same link type" )
    {
        const auto file = le.shb() + le.idb( DltEthernet ) + le.idb( DltEthernet );

        THEN( "it is announced once" )
        {
            REQUIRE( parse( file ).linkTypes == std::vector<uint32_t>{ DltEthernet } );
        }
    }
}

SCENARIO( "Microsecond and nanosecond interfaces in one capture", "[pcapng]" )
{
    GIVEN( "a microsecond and a nanosecond interface, with a packet on each" )
    {
        const auto file = le.shb() + le.idb( DltEthernet ) + le.idb( DltEthernet, 9 )
                          + le.epb( 0, 1000000000000000ULL, udpFrame( 1 ) )
                          + le.epb( 1, 1000000000123456789ULL, udpFrame( 2 ) )
                          + le.epb( 0, 1000000000000000ULL + 500, udpFrame( 3 ) );

        THEN( "each packet has its interface's precision, and the reader the finer one" )
        {
            const auto result = parse( file );
            REQUIRE( result.precision == TimePrecision::Nanoseconds );
            REQUIRE( result.packets.size() == 3 );
            REQUIRE( result.packets[ 0 ].precision == TimePrecision::Microseconds );
            REQUIRE( result.packets[ 1 ].precision == TimePrecision::Nanoseconds );
            REQUIRE( result.packets[ 1 ].timestampSec == 1000000000 );
            REQUIRE( result.packets[ 1 ].timestampNsec == 123456789 );
        }

        THEN( "the converted text shows both at nanosecond precision, none cut" )
        {
            QTemporaryDir dir;
            REQUIRE( dir.isValid() );
            const auto result = convertPcap( writeFile( dir, "mixed.pcapng", file ), dir.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            const auto lines = readLines( result.outputPath );
            REQUIRE( lines.size() == 4 );
            REQUIRE( timeOf( lines[ 1 ] ) == "0.000000000" );
            REQUIRE( timeOf( lines[ 2 ] ) == "0.123456789" );
            REQUIRE( timeOf( lines[ 3 ] ) == "0.000500000" );
        }
    }

    GIVEN( "a nanosecond interface declared only after the first packet" )
    {
        const auto file
            = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1000000000000000ULL, udpFrame( 1 ) )
              + le.idb( DltEthernet, 9 ) + le.epb( 1, 1000000000123456789ULL, udpFrame( 2 ) );

        THEN( "its packets are shown at the precision announced before the first packet" )
        {
            const auto result = parse( file );
            REQUIRE( result.precision == TimePrecision::Microseconds );
            REQUIRE( result.packets.size() == 2 );
            REQUIRE( result.packets[ 1 ].precision == TimePrecision::Microseconds );
            REQUIRE( result.packets[ 1 ].timestampNsec == 123456789 );
            REQUIRE( result.linkTypes == std::vector<uint32_t>{ DltEthernet } );
        }
    }
}

SCENARIO( "Simple Packet Blocks are read with the first interface's snaplen", "[pcapng]" )
{
    GIVEN( "an interface with a snaplen of 20 and a Simple Packet Block of a longer packet" )
    {
        const auto frame = udpFrame( 9 );
        const auto file = le.shb() + le.idb( DltEthernet, -1, 20 )
                          + le.spb( Bytes( frame.begin(), frame.begin() + 20 ),
                                    static_cast<uint32_t>( frame.size() ) );

        THEN( "only the snaplen's bytes are taken, and the packet has no timestamp" )
        {
            const auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].capturedLen == 20 );
            REQUIRE( result.packets[ 0 ].originalLen == frame.size() );
            REQUIRE( result.packets[ 0 ].timestampSec == 0 );
            REQUIRE( result.packets[ 0 ].linkType == DltEthernet );
            REQUIRE( result.packets[ 0 ].srcMac == "66:77:88:99:aa:bb" );
        }
    }

    GIVEN( "a Simple Packet Block of a packet shorter than the snaplen" )
    {
        const auto frame = udpFrame( 9 );
        const auto file = le.shb() + le.idb( DltEthernet )
                          + le.spb( frame, static_cast<uint32_t>( frame.size() ) );

        THEN( "the packet's own length is taken, not the block's padding" )
        {
            const auto result = parse( file );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.packets[ 0 ].capturedLen == frame.size() );
            REQUIRE( result.packets[ 0 ].dstPort == 9 );
        }
    }
}

SCENARIO( "Blocks other than packets and interfaces are skipped", "[pcapng]" )
{
    GIVEN( "name resolution, statistics, decryption secrets and custom blocks between packets" )
    {
        const auto file = le.shb() + le.block( kNrb, Bytes( 9, 0x11 ) ) + le.idb( DltEthernet )
                          + le.epb( 0, 1, udpFrame( 1 ) ) + le.block( kIsb, Bytes( 20, 0 ) )
                          + le.block( 0x0A, Bytes( 16, 0x22 ) ) + le.block( 0x40000BAD, {} )
                          + le.block( 0x2, Bytes( 3, 0 ) ) + le.epb( 0, 2, udpFrame( 2 ) );

        THEN( "both packets are read" )
        {
            const auto result = parse( file );
            REQUIRE( result.packets.size() == 2 );
            REQUIRE( result.packets[ 1 ].number == 2 );
            REQUIRE( result.packets[ 1 ].dstPort == 2 );
            REQUIRE_FALSE( result.truncated );
        }
    }
}

SCENARIO( "A pcapng file may hold several sections", "[pcapng]" )
{
    GIVEN( "a little-endian section followed by a big-endian one with its own interfaces" )
    {
        const auto file = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1000000, udpFrame( 1 ) )
                          + be.shb() + be.idb( DltRaw ) + be.idb( DltLinuxSll2 )
                          + be.epb( 0, 2000000, rawUdp( 2 ) );

        THEN( "the interface numbers start over in the second section" )
        {
            const auto result = parse( file );
            REQUIRE( result.packets.size() == 2 );
            REQUIRE( result.packets[ 1 ].linkType == DltRaw );
            REQUIRE( result.packets[ 1 ].dstPort == 2 );
            REQUIRE( result.packets[ 1 ].timestampSec == 2 );
            REQUIRE( result.linkTypes
                     == std::vector<uint32_t>{ DltEthernet, DltRaw, DltLinuxSll2 } );
        }
    }
}

SCENARIO( "A pcapng without packets converts to a header line", "[pcapng]" )
{
    GIVEN( "a section with an interface and no packet" )
    {
        QTemporaryDir dir;
        REQUIRE( dir.isValid() );
        const auto input
            = writeFile( dir, "empty.pcapng",
                         le.shb() + le.idb( DltLinuxSll2 ) + le.block( kIsb, Bytes( 20, 0 ) ) );

        THEN( "the text is the header line, and the summary has no packets but names the "
              "interface's link type, like an empty pcap's" )
        {
            const auto result = convertPcap( input, dir.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( readLines( result.outputPath ).size() == 1 );
            REQUIRE( result.summary.packets == 0 );
            REQUIRE( result.summary.protocolPackets.empty() );
            REQUIRE( result.summary.linkTypeNames == std::vector<std::string>{ "Linux SLL2" } );
            REQUIRE_FALSE( result.summary.endsInsideRecord );
        }
    }

    GIVEN( "a section header alone" )
    {
        THEN( "it is read, with no link type" )
        {
            const auto result = parse( le.shb() );
            REQUIRE( result.ok );
            REQUIRE( result.packets.empty() );
            REQUIRE( result.linkTypes.empty() );
            REQUIRE_FALSE( result.truncated );
        }
    }
}

SCENARIO( "A pcapng that is cut off is reported like a cut-off pcap", "[pcapng]" )
{
    const auto whole = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1, udpFrame( 1 ) )
                       + le.epb( 0, 2, udpFrame( 2 ) );

    GIVEN( "a capture cut in the middle of its last packet" )
    {
        const Bytes cut( whole.begin(), whole.end() - 20 );

        THEN( "the packets before are read and the capture ends inside a record" )
        {
            const auto result = parse( cut );
            REQUIRE( result.ok );
            REQUIRE( result.packets.size() == 1 );
            REQUIRE( result.truncated );
        }

        THEN( "the Converter's summary says so" )
        {
            QTemporaryDir dir;
            REQUIRE( dir.isValid() );
            const auto result = convertPcap( writeFile( dir, "cut.pcapng", cut ), dir.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == 1 );
            REQUIRE( result.summary.endsInsideRecord );
        }
    }

    GIVEN( "a capture cut in the middle of a block header" )
    {
        const auto file = le.shb() + le.idb( DltEthernet ) + Bytes{ 6, 0, 0 };

        THEN( "it ends inside a record" )
        {
            const auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.truncated );
        }
    }

    GIVEN( "a block whose length lies beyond the end of the file" )
    {
        auto file = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1, udpFrame( 1 ) );
        const auto lastBlock = file.size() - le.epb( 0, 1, udpFrame( 1 ) ).size();
        file[ lastBlock + 4 ] = 0x00;
        file[ lastBlock + 5 ] = 0x10; // 4096 bytes

        THEN( "the capture ends inside a record" )
        {
            const auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.packets.empty() );
            REQUIRE( result.truncated );
        }
    }

    GIVEN( "a capture cut inside its section header" )
    {
        const auto shb = le.shb();

        THEN( "it is not read, like a pcap cut inside its global header" )
        {
            const auto result = parse( Bytes( shb.begin(), shb.begin() + 26 ) );
            REQUIRE_FALSE( result.ok );
            REQUIRE_FALSE( result.error.empty() );
        }
    }
}

SCENARIO( "Blocks that contradict themselves end the capture", "[pcapng]" )
{
    const auto head = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1, udpFrame( 1 ) );

    const std::vector<std::pair<std::string, Bytes>> cases{
        { "a block shorter than a block header", le.block( kEpb, {}, 8 ) },
        { "a block length that is no multiple of 4", le.block( kNrb, Bytes( 8, 0 ), 21 ) },
        { "an Enhanced Packet Block too short for its fields", le.block( kEpb, Bytes( 8, 0 ) ) },
        { "a packet longer than its block", le.epb( 0, 2, udpFrame( 2 ), 4000 ) },
        { "a packet of an interface never declared", le.epb( 5, 2, udpFrame( 2 ) ) },
        { "trailing and leading block lengths that differ",
          [] {
              auto b = le.epb( 0, 2, udpFrame( 2 ) );
              b[ b.size() - 4 ] ^= 0x04;
              return b;
          }() },
        { "a section of another major version", le.shb( 2 ) },
        { "an interface block too short for its fields", le.block( kIdb, Bytes( 4, 0 ) ) },
    };

    for ( const auto& [ name, block ] : cases ) {
        GIVEN( "a packet, then " + name + ", then a packet" )
        {
            const auto file = head + block + le.epb( 0, 3, udpFrame( 3 ) );

            THEN( "the first packet is read and the capture ends inside a record" )
            {
                const auto result = parse( file );
                REQUIRE( result.ok );
                REQUIRE( result.packets.size() == 1 );
                REQUIRE( result.truncated );
            }
        }
    }
}

SCENARIO( "The capture format is detected from the first block", "[pcapng]" )
{
    GIVEN( "a pcapng behind a text preamble from tcpdump" )
    {
        const auto file = text( "tcpdump: listening on eth0\n" ) + le.shb() + le.idb( DltEthernet )
                          + le.epb( 0, 1, udpFrame( 1 ) );

        THEN( "it is read as a pcapng" )
        {
            const auto result = parse( file );
            REQUIRE( result.ok );
            REQUIRE( result.packets.size() == 1 );
        }

        THEN( "the factory hands the reader the start behind the preamble, counted as read" )
        {
            MemorySource memory( file.data(), file.size() );
            HeadSource source( memory );
            auto reader = makeCaptureReader( source );
            REQUIRE( dynamic_cast<PcapngReader*>( reader.get() ) != nullptr );
            REQUIRE( reader->open() );
            PacketRecord pkt;
            REQUIRE( reader->next( pkt ) );
            REQUIRE_FALSE( reader->next( pkt ) );
            REQUIRE( reader->bytesRead() == file.size() );
        }
    }

    GIVEN( "a section header block with an unknown byte-order magic" )
    {
        auto file = le.shb() + le.idb( DltEthernet );
        file[ 8 ] = 0x99;

        THEN( "it is rejected as a broken pcapng" )
        {
            const auto result = parse( file );
            REQUIRE_FALSE( result.ok );
            REQUIRE( result.error.find( "pcapng" ) != std::string::npos );
        }
    }

    GIVEN( "a first section of an unknown major version" )
    {
        const auto file = le.shb( 2 ) + le.idb( DltEthernet );

        THEN( "it is rejected with the version" )
        {
            const auto result = parse( file );
            REQUIRE_FALSE( result.ok );
            REQUIRE( result.error.find( "2.0" ) != std::string::npos );
        }
    }

    GIVEN( "a pcap" )
    {
        const auto file = pcapOf( { udpFrame( 1 ) } );

        THEN( "the factory picks the pcap reader" )
        {
            MemorySource memory( file.data(), file.size() );
            HeadSource source( memory );
            auto reader = makeCaptureReader( source );
            REQUIRE( dynamic_cast<PcapReader*>( reader.get() ) != nullptr );
            REQUIRE( reader->open() );
            PacketRecord pkt;
            REQUIRE( reader->next( pkt ) );
            REQUIRE( reader->bytesRead() == file.size() );
        }
    }
}

SCENARIO( "A pcapng is read one block at a time", "[pcapng]" )
{
    GIVEN( "a packet longer than what is dissected, then a small one" )
    {
        const auto big
            = eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 1, 2, Bytes( 300000, 'x' ) ) ) );
        const auto file = le.shb() + le.idb( DltEthernet ) + le.epb( 0, 1, big )
                          + le.epb( 0, 2, udpFrame( 3 ) );

        THEN( "both are read, the long one with its lengths, and every byte is consumed" )
        {
            MemorySource memory( file.data(), file.size() );
            PcapngReader reader( memory );
            REQUIRE( reader.open() );
            PacketRecord pkt;
            REQUIRE( reader.next( pkt ) );
            REQUIRE( pkt.capturedLen == big.size() );
            REQUIRE( pkt.originalLen == big.size() );
            REQUIRE( reader.next( pkt ) );
            REQUIRE( pkt.dstPort == 3 );
            REQUIRE_FALSE( reader.next( pkt ) );
            REQUIRE_FALSE( reader.truncated() );
            REQUIRE( reader.bytesRead() == file.size() );
        }
    }
}
