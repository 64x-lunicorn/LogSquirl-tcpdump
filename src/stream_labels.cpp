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
 * @file stream_labels.cpp
 * @brief Implementation of the Stream Labels.
 */

#include "stream_labels.h"

#include <algorithm>

namespace tcpdump {

static_assert( sizeof( StreamState::label ) == 1, "A stream's label is paid once per stream" );

namespace {

/// The description of a packet that continues its stream's protocol.
constexpr const char* kContinuation = "Continuation";

} // namespace

void StreamLabels::apply( PacketRecord& pkt, const Stream& stream )
{
    if ( !stream.state ) {
        return;
    }
    auto& label = stream.state->label;

    if ( pkt.protocolRecognised ) {
        if ( label != 0 ) {
            return; // The first recognised label sticks
        }
        const auto known = std::find( labels_.begin(), labels_.end(), pkt.protocol );
        if ( known != labels_.end() ) {
            label = static_cast<uint8_t>( known - labels_.begin() + 1 );
        }
        else if ( labels_.size() < kMaxLabels ) {
            labels_.push_back( pkt.protocol );
            label = static_cast<uint8_t>( labels_.size() );
        }
        return;
    }

    if ( label == 0 ) {
        return;
    }
    pkt.protocol = labels_[ label - 1 ];
    if ( pkt.payloadLen == 0 ) {
        return; // Nothing continues: a bare ACK, a FIN, …
    }
    // The description is all after the separator: the parser puts none
    // before it, and the TCP Analysis only adds markers at the start.
    const auto at = pkt.info.find( kDescriptionSeparator );
    if ( at == std::string::npos ) {
        pkt.info += std::string( kDescriptionSeparator ) + kContinuation;
    }
    else {
        pkt.info.insert( at + std::char_traits<char>::length( kDescriptionSeparator ),
                         std::string( kContinuation ) + ": " );
    }
}

const std::string& StreamLabels::name( uint8_t label ) const
{
    static const std::string none;
    return label == 0 || label > labels_.size() ? none : labels_[ label - 1 ];
}

} // namespace tcpdump
