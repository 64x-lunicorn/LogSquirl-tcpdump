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
 * @file packet_recorder_test.cpp
 * @brief BDD tests for the Packet Recorder, through its interface: a host
 *        name labels the packets after its answer, not its own line, and the
 *        summary counts what was recorded, with what decryption and host
 *        names add, as a conversion's does.
 */

#include <catch2/catch.hpp>

#include "pcap_converter.h"
#include "pipeline_harness.h"

#include <QFile>
#include <QTemporaryDir>

#include <algorithm>
#include <map>
#include <string>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

Bytes corpusFile( const QString& name )
{
    QFile file( QStringLiteral( TCPDUMP_CORPUS_DIR ) + "/" + name );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto bytes = file.readAll();
    return Bytes( bytes.begin(), bytes.end() );
}

bool contains( const std::string& text, const std::string& part )
{
    return text.find( part ) != std::string::npos;
}

/// Options that show host names.
RecorderOptions withHostNames()
{
    RecorderOptions options;
    options.layout.hostNames = true;
    return options;
}

/// The summary of converting the corpus capture @p name with @p options.
CaptureSummary convertedSummary( const QString& name, const ConversionOptions& options = {} )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const auto result = convertPcap( QStringLiteral( TCPDUMP_CORPUS_DIR ) + "/" + name, out.path(),
                                     nullptr, {}, options );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    return result.summary;
}

} // namespace

SCENARIO( "The Packet Recorder names an address from the packet after its answer",
          "[packet_recorder][hostnames]" )
{
    GIVEN( "DNS and mDNS answers, recorded with host names shown" )
    {
        const auto recording = recorded( corpusFile( "names.pcap" ), {}, withHostNames() );
        const auto& packets = recording.packets;
        REQUIRE( packets.size() == 29 );

        THEN( "a packet before the answer shows the address alone, one after it its name" )
        {
            REQUIRE_FALSE( contains( packets[ 1 ].line, "(www.example.com)" ) );
            REQUIRE( contains( packets[ 4 ].line, "93.184.216.34(www.example.com)" ) );
        }
        THEN( "an announcement's own line shows its address alone, the next packet its name" )
        {
            REQUIRE( contains( packets[ 14 ].line, "mDNS" ) );
            REQUIRE_FALSE( contains( packets[ 14 ].line, "(printer.local)" ) );
            REQUIRE( contains( packets[ 15 ].line, "192.0.2.20(printer.local)" ) );
        }
        THEN( "the header is the layout's" )
        {
            REQUIRE( contains( recording.header, "Source" ) );
            REQUIRE( contains( recording.header, "Info" ) );
        }
    }
    GIVEN( "the same answers recorded without host names" )
    {
        const auto recording = recorded( corpusFile( "names.pcap" ) );

        THEN( "no line names an address, and the summary names no endpoint" )
        {
            REQUIRE( std::none_of( recording.packets.begin(), recording.packets.end(),
                                   []( const Piped& p ) { return contains( p.line, "(" ); } ) );
            REQUIRE( recording.summary.endpointNames.empty() );
        }
    }
}

SCENARIO( "The Packet Recorder makes the summary of what it recorded", "[packet_recorder]" )
{
    GIVEN( "a capture with names, recorded with host names shown" )
    {
        const auto recording = recorded( corpusFile( "names.pcap" ), {}, withHostNames() );
        const auto& summary = recording.summary;

        THEN( "it counts every packet and names its link-layer type" )
        {
            REQUIRE( summary.packets == 29 );
            REQUIRE( summary.linkTypeNames == std::vector<std::string>{ "Ethernet" } );
        }
        THEN( "it names the endpoints with the names learned last" )
        {
            REQUIRE( summary.endpointNames.at( "93.184.216.34" ) == "other.example" );
            REQUIRE( summary.endpointNames.at( "192.0.2.20" ) == "printer.local" );
        }
        THEN( "it is the summary a conversion of the capture makes" )
        {
            ConversionOptions options;
            options.layout.hostNames = true;
            REQUIRE( summary == convertedSummary( "names.pcap", options ) );
            REQUIRE( summary.conversations->list()
                     == convertedSummary( "names.pcap", options ).conversations->list() );
        }
        THEN( "the index holds each stream's first and last packet" )
        {
            const auto extent = recording.index->streamExtent( Transport::Tcp, 0 );
            REQUIRE( extent );
            REQUIRE( extent->first == 1 );
            REQUIRE( extent->last == 29 );
        }
    }
    GIVEN( "a TCP connection with every analysis marker" )
    {
        const auto summary = recorded( corpusFile( "tcp-analysis.pcap" ) ).summary;

        THEN( "the TCP Analysis of each packet is counted, as a conversion counts it" )
        {
            REQUIRE_FALSE( summary.tcpMarkers.empty() );
            REQUIRE( summary.handshakes > 0 );
            REQUIRE( summary == convertedSummary( "tcp-analysis.pcap" ) );
        }
    }
    GIVEN( "TLS sessions recorded with the secrets of their key log" )
    {
        const auto text = corpusFile( "tls-decrypt.keys" );
        tls::KeyLog keys;
        keys.addLines( reinterpret_cast<const char*>( text.data() ), text.size() );
        const auto summary
            = recorded( corpusFile( "tls-decrypt.pcap" ), withKeyLog( keys ) ).summary;

        THEN( "the summary counts the sessions decrypted" )
        {
            REQUIRE( summary.tlsSessionsDecrypted.value_or( 0 ) > 0 );
            REQUIRE( summary.keyLogError.empty() );
        }
    }
    GIVEN( "the same sessions without a key log" )
    {
        const auto summary = recorded( corpusFile( "tls-decrypt.pcap" ) ).summary;

        THEN( "the summary counts no sessions" )
        {
            REQUIRE_FALSE( summary.tlsSessionsDecrypted );
        }
    }
    GIVEN( "a pcap without packets" )
    {
        const auto summary = recorded( pcapOf( {} ) ).summary;

        THEN( "the summary still names the link-layer type the capture declares" )
        {
            REQUIRE( summary.packets == 0 );
            REQUIRE( summary.linkTypeNames == std::vector<std::string>{ "Ethernet" } );
        }
    }
}

SCENARIO( "The Packet Recorder's summary so far leaves the recording going on",
          "[packet_recorder]" )
{
    GIVEN( "a capture half recorded" )
    {
        const auto capture = corpusFile( "names.pcap" );
        MemorySource memory( capture.data(), capture.size() );
        HeadSource head( memory );
        const auto reader = makeCaptureReader( head );
        REQUIRE( reader->open() );
        PacketPipeline pipeline;
        PacketRecorder recorder( *reader, pipeline, withHostNames() );
        PacketRecord pkt;
        for ( int i = 0; i < 15 && reader->next( pkt ); ++i ) {
            const auto payload = reader->payloadOf( pkt );
            const auto outcome = pipeline.run( pkt, payload );
            recorder.record( pkt, payload, outcome );
        }

        WHEN( "the summary so far is made, and the rest recorded" )
        {
            const auto soFar = recorder.summary();
            while ( reader->next( pkt ) ) {
                const auto payload = reader->payloadOf( pkt );
                const auto outcome = pipeline.run( pkt, payload );
                recorder.record( pkt, payload, outcome );
            }
            const auto final = recorder.finalSummary();

            THEN( "the summary so far counts the packets so far" )
            {
                REQUIRE( soFar.packets == 15 );
                REQUIRE( recorder.packets() == 29 );
            }
            THEN( "the final summary counts them all, and names what was learned since" )
            {
                REQUIRE( final.packets == 29 );
                REQUIRE( soFar.endpointNames.count( "192.0.2.80" ) == 0 );
                REQUIRE( final.endpointNames.at( "192.0.2.80" ) == "example.org" );
            }
        }
    }
}
