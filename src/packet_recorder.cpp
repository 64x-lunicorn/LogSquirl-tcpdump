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
 * @file packet_recorder.cpp
 * @brief Implementation of the Packet Recorder.
 */

#include "packet_recorder.h"

#include "capture_reader.h"

#include <tuple>

namespace tcpdump {

PacketRecorder::PacketRecorder( const CaptureReader& reader, const PacketPipeline& pipeline,
                                const RecorderOptions& options )
    : reader_( reader )
    , pipeline_( pipeline )
    , keyLog_( options.keyLog )
    , formatter_( reader.precision(), options.layout )
    , index_( std::make_shared<CaptureIndex>( options.checkpointInterval ) )
{
    stats_.maxEndpoints = options.maxEndpoints;
    if ( options.layout.hostNames ) {
        names_.emplace( options.maxHostNames );
    }
}

std::string PacketRecorder::record( const PacketRecord& pkt, ByteView payload,
                                    const PacketOutcome& outcome )
{
    // The order, and why each step comes where it does, is the class's
    // (packet_recorder.h).
    const auto& stream = outcome.stream;
    stats_.addTcpAnalysis( outcome.analysis );
    conversations_.add( pkt, stream );
    stats_.add( pkt );
    auto line = formatter_.format( pkt, stream.id, names_ ? &*names_ : nullptr );
    // Behind its own line: a name labels the packets after its answer.
    if ( names_ ) {
        names_->learn( pkt, payload, outcome.messages.bytes );
    }
    if ( pkt.transport ) {
        index_->noteStream( *pkt.transport, stream.id, reader_.packetsRead() );
    }
    index_->note( reader_ );
    return line;
}

CaptureSummary PacketRecorder::summary() const
{
    return summarise( CaptureStats( stats_ ) );
}

CaptureSummary PacketRecorder::finalSummary()
{
    return summarise( std::move( stats_ ) );
}

CaptureSummary PacketRecorder::summarise( CaptureStats&& stats ) const
{
    // The packets' link-layer types first, then any the capture declares
    // without a packet of it, such as a pcap's when it holds none.
    for ( const auto linkType : reader_.linkTypes() ) {
        stats.addLinkType( linkType );
    }

    CaptureSummary summary;
    summary.packets = stats.packets;
    summary.bytes = stats.bytes;
    summary.cutPackets = stats.cutPackets;
    summary.durationSeconds = stats.durationSeconds();
    if ( stats.packets > 0 ) {
        summary.firstTimeUtc
            = formatUtcTime( stats.firstTimeSec, stats.firstTimeNsec, reader_.precision() );
        summary.lastTimeUtc
            = formatUtcTime( stats.lastTimeSec, stats.lastTimeNsec, reader_.precision() );
    }
    for ( const auto linkType : stats.linkTypes ) {
        summary.linkTypeNames.push_back( linkTypeName( linkType ) );
    }
    summary.protocolPackets = std::move( stats.protocolPackets );
    summary.protocolBytes = std::move( stats.protocolBytes );
    summary.endpointPackets = std::move( stats.endpointPackets );
    summary.tunnelEndpointPackets = std::move( stats.tunnelEndpointPackets );
    for ( size_t i = 0; i < kTcpMarkerKinds; ++i ) {
        if ( stats.tcpMarkers[ i ] > 0 ) {
            summary.tcpMarkers.emplace_back( tcpMarkerName( static_cast<TcpMarker>( i ) ),
                                             stats.tcpMarkers[ i ] );
        }
    }
    summary.handshakes = stats.initialRtts.count();
    summary.medianInitialRttNs = stats.medianInitialRttNs();
    // Rows of streams without a packet since the last summary are shared with it.
    summary.conversations = conversations_.rows( pipeline_.tracker(), pipeline_.labels(),
                                                 stats.firstTimeSec, stats.firstTimeNsec );
    summary.otherStreamPackets = conversations_.otherPackets();
    summary.otherStreamBytes = conversations_.otherBytes();
    summary.endsInsideRecord = reader_.truncated();
    if ( pipeline_.tracker().limitReached() ) {
        summary.streamCap = pipeline_.tracker().maxStreams();
    }
    if ( stats.endpointLimitReached() ) {
        summary.otherEndpointPackets = stats.otherEndpointPackets;
    }

    // What the decryption did, with TLS keys, and the endpoints' names.
    if ( const auto sessions = pipeline_.tlsSessionsDecrypted() ) {
        summary.tlsSessionsDecrypted = *sessions;
    }
    if ( keyLog_ ) {
        summary.keyLogError = keyLog_->error().toStdString();
    }
    if ( names_ ) {
        for ( const auto& [ address, packets ] : summary.endpointPackets ) {
            if ( const auto* name = names_->find( address ) ) {
                summary.endpointNames.emplace( address, *name );
            }
        }
    }
    return summary;
}

bool CaptureSummary::operator==( const CaptureSummary& other ) const
{
    auto fields = []( const CaptureSummary& s ) {
        return std::tie( s.packets, s.bytes, s.durationSeconds, s.firstTimeUtc, s.lastTimeUtc,
                         s.linkTypeNames, s.protocolPackets, s.protocolBytes, s.endpointPackets,
                         s.tunnelEndpointPackets, s.tcpMarkers, s.cutPackets, s.endsInsideRecord,
                         s.compressionProblem, s.packetNumbersUsedUp, s.streamCap,
                         s.otherEndpointPackets, s.tlsSessionsDecrypted, s.keyLogError,
                         s.endpointNames );
    };
    return fields( *this ) == fields( other );
}

std::vector<std::string> formatAllPackets( const std::vector<uint8_t>& capture,
                                           const PipelineOptions& options,
                                           const LineLayout& layout )
{
    MemorySource memory( capture.data(), capture.size() );
    HeadSource source( memory );
    const auto reader = makeCaptureReader( source );
    if ( !reader->open() ) {
        return {};
    }
    PacketPipeline pipeline( options );
    RecorderOptions recorderOptions;
    recorderOptions.layout = layout;
    PacketRecorder recorder( *reader, pipeline, recorderOptions );
    std::vector<std::string> lines{ recorder.header() };

    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto payload = reader->payloadOf( pkt );
        const auto outcome = pipeline.run( pkt, payload );
        lines.push_back( recorder.record( pkt, payload, outcome ) );
    }
    return lines;
}

} // namespace tcpdump
