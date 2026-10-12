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
 * @file selected_packet_line.cpp
 * @brief Selected Packet Line: the selection read through the host.
 */

#include "selected_packet_line.h"

#include "plugin.h"
#include "stream_tracker.h"

namespace tcpdump {

namespace {

/// Why get_selected_log_lines() returned no line, @p result, for the user.
QString selectionFailure( int result )
{
    switch ( result ) {
    case LOGSQUIRL_LOG_LINES_NO_SELECTION:
        return selectPacketLineReason();
    case LOGSQUIRL_LOG_LINES_NO_LOG_FILE:
        return QStringLiteral( "The tab in front shows no capture." );
    default:
        return QStringLiteral( "LogSquirl did not tell the selected line (%1)." ).arg( result );
    }
}

} // namespace

QString selectPacketLineReason()
{
    return QStringLiteral( "Select a packet line to see its packet." );
}

SelectedLines readSelectedLines()
{
    const auto& st = g_state;
    const char* text = nullptr;
    size_t length = 0;
    size_t lineCount = 0;
    SelectedLines selection;
    selection.result = st.api->get_selected_log_lines( st.handle, &text, &length, &lineCount );
    if ( selection.result >= 0 && text ) {
        selection.text = QByteArray( text, static_cast<qsizetype>( length ) );
        selection.lineCount = lineCount;
    }
    else if ( selection.result >= 0 ) {
        // A success without text tells no line.
        selection.result = LOGSQUIRL_LOG_LINES_NO_SELECTION;
    }
    return selection;
}

SelectedPacketLine selectedPacketLine( const SelectedLines& selection )
{
    if ( selection.result < 0 ) {
        return { std::nullopt, selectionFailure( selection.result ) };
    }
    // The first selected line is the one read.
    const auto line = QString::fromUtf8( selection.text ).section( '\n', 0, 0 );
    auto packet = readPacketLine( line );
    if ( !packet ) {
        return { std::nullopt,
                 QStringLiteral( "The selected line is not a packet line of a capture." ) };
    }
    if ( packet->number == 0 ) {
        return { std::nullopt, QStringLiteral( "The selected line has no packet number." ) };
    }
    return { std::move( packet ), {} };
}

SelectedPacketLine readSelectedPacketLine()
{
    return selectedPacketLine( readSelectedLines() );
}

QString SelectedPacketLine::streamContentProblem() const
{
    if ( !packet ) {
        return reason;
    }
    if ( packet->stream == kNoStream ) {
        return QStringLiteral( "Packet %1 belongs to no stream: only TCP and UDP packets do." )
            .arg( packet->number );
    }
    return {};
}

QString SelectedPacketLine::streamLinesProblem() const
{
    if ( auto problem = streamContentProblem(); !problem.isEmpty() ) {
        return problem;
    }
    // Its content is read by its addresses, but no pattern picks its lines.
    if ( packet->stream == kUnnumbered ) {
        return QStringLiteral( "Packet %1 has no stream number: the capture has more "
                               "conversations than the plugin numbers." )
            .arg( packet->number );
    }
    return {};
}

} // namespace tcpdump
