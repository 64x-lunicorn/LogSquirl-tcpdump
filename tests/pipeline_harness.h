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
 * @file pipeline_harness.h
 * @brief A capture built in a test, taken through the Packet Pipeline as a
 *        conversion takes it, for the tests of the steps the pipeline runs.
 */

#pragma once

#include "capture_reader.h"
#include "packet_pipeline.h"
#include "pcapbuilder.h"
#include "tls_key_log.h"

#include <catch2/catch.hpp>

#include <utility>
#include <vector>

namespace tcpdump_test {

/// A packet as the Packet Pipeline left it, and what it found out.
struct Piped {
    tcpdump::PacketRecord pkt;
    /// Its stream; the state it points to is the pipeline's.
    tcpdump::Stream stream;
    tcpdump::TcpAnalysis analysis;
    Bytes completed;       ///< The messages it completed (PacketOutcome::messages)
    uint32_t segments = 0; ///< The segments they were put together from
};

/// The packets of @p capture, a pcap or pcapng file, each taken through
/// @p pipeline with its payload as the reader hands it out, as a conversion
/// takes them.
inline std::vector<Piped> piped( const Bytes& capture, tcpdump::PacketPipeline& pipeline )
{
    tcpdump::MemorySource memory( capture.data(), capture.size() );
    tcpdump::HeadSource head( memory );
    const auto reader = tcpdump::makeCaptureReader( head );
    REQUIRE( reader->open() );
    std::vector<Piped> out;
    tcpdump::PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto outcome = pipeline.run( pkt, reader->payloadOf( pkt ) );
        Piped one{ pkt, outcome.stream, outcome.analysis, {}, outcome.messages.segments };
        if ( outcome.messages.bytes.data ) {
            one.completed.assign( outcome.messages.bytes.data,
                                  outcome.messages.bytes.data + outcome.messages.bytes.size );
        }
        out.push_back( std::move( one ) );
    }
    return out;
}

/// The packets of @p capture through a Packet Pipeline of their own, with
/// @p options; the state their streams point to is gone with it.
inline std::vector<Piped> piped( const Bytes& capture,
                                 const tcpdump::PipelineOptions& options = {} )
{
    tcpdump::PacketPipeline pipeline( options );
    return piped( capture, pipeline );
}

/// A payload one end of a TCP connection sends, in a segment of its own.
struct Turn {
    bool fromClient = true;
    Bytes payload;
};

/// @p turns between the client's @p clientPort and the server's
/// @p serverPort, a second apart, as a pcap file: each end's sequence
/// numbers go on where its last segment ended, and acknowledge all the
/// other end sent.
inline Bytes tcpConversation( const std::vector<Turn>& turns, uint16_t clientPort,
                              uint16_t serverPort )
{
    std::vector<Record> records;
    uint32_t sec = 1000;
    uint32_t seq[ 2 ] = { 1000, 5000 }; // the client's, the server's
    for ( const auto& [ fromClient, payload ] : turns ) {
        Ipv4Options o;
        if ( !fromClient ) {
            std::swap( o.src, o.dst );
        }
        auto& next = seq[ fromClient ? 0 : 1 ];
        const auto ack = seq[ fromClient ? 1 : 0 ];
        const auto segment = fromClient
                                 ? tcp( clientPort, serverPort, payload, 5, 0x18, next, ack )
                                 : tcp( serverPort, clientPort, payload, 5, 0x18, next, ack );
        records.push_back(
            { eth( tcpdump::EthertypeIpv4, ipv4( tcpdump::IpProtoTcp, segment, o ) ), sec++ } );
        next += static_cast<uint32_t>( payload.size() );
    }
    return pcapFile( records );
}

/// Options that decrypt TLS with the secrets of @p keys, which must outlive
/// the pipeline.
inline tcpdump::PipelineOptions withKeyLog( const tcpdump::tls::KeyLog& keys )
{
    tcpdump::PipelineOptions options;
    options.tlsKeys
        = [ &keys ]( const uint8_t* clientRandom ) { return keys.find( clientRandom ); };
    return options;
}

} // namespace tcpdump_test
