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
 * @file packet_pipeline.cpp
 * @brief Implementation of the Packet Pipeline.
 */

#include "packet_pipeline.h"

namespace tcpdump {

PacketPipeline::PacketPipeline( const PipelineOptions& options )
    : previewChars_( options.previewChars )
    , tcpTimestamps_( options.tcpTimestamps )
    , tracker_( options.maxStreams )
    , reassembly_( options.reassemblyMemory, options.reassemblyStreamLimit )
{
    if ( options.tlsKeys ) {
        decryption_.emplace( options.tlsKeys, options.tlsKeyLogBytes );
    }
}

PacketOutcome PacketPipeline::run( PacketRecord& pkt, ByteView payload )
{
    // The order, and why each step comes where it does, is the class's
    // (packet_pipeline.h).
    limitPreview( pkt, previewChars_ ); // before anything else touches Info
    if ( tcpTimestamps_ ) {
        showTcpTimestamps( pkt );
    }
    PacketOutcome outcome;
    outcome.stream = tracker_.track( pkt );
    const auto& stream = outcome.stream;
    outcome.analysis = analyseTcp( pkt, stream );
    describeInStream( pkt, stream );
    outcome.messages = reassembly_.apply( pkt, stream, payload );
    rememberInStream( pkt, stream ); // after the reassembly, which completes NEWKEYS
    if ( decryption_ ) {
        decryption_->apply( pkt, stream, outcome.messages );
    }
    media_.apply( pkt ); // after the reassembly, which completes SDP bodies
    labels_.apply( pkt, stream );
    return outcome;
}

std::optional<size_t> PacketPipeline::tlsSessionsDecrypted() const
{
    if ( !decryption_ ) {
        return std::nullopt;
    }
    return decryption_->sessionsDecrypted();
}

} // namespace tcpdump
