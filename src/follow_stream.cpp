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
 * @file follow_stream.cpp
 * @brief Follow stream from the selected packet line.
 *
 * Reads the first Log Line the user selected through the host's
 * get_selected_log_lines, builds a pattern for its stream and opens it in
 * LogSquirl's Regex Lab, where the user sees the matches and applies it as
 * a filter.
 */

#include "follow_stream.h"
#include "plugin.h"
#include "regex_lab.h"

#include <QRegularExpression>
#include <QStringList>

namespace tcpdump {

namespace {

/// The arrow between the ports in the Info column.
const QString kArrow = QString::fromUtf8( " \xe2\x86\x92 " );

/// The ports at the start of a TCP or UDP packet's Info, "50000 → 80", which
/// markers in brackets and the MAC columns may precede.
const QRegularExpression& portsRegex()
{
    static const QRegularExpression regex(
        QStringLiteral( R"((?<![\w.])(\d{1,5})%1(\d{1,5})(?!\d))" ).arg( kArrow ) );
    return regex;
}

/// "a<sep>b" or "b<sep>a", or just one of them when both are the same.
QString eitherWay( const QString& a, const QString& b, const QString& separator )
{
    const auto forth = a + separator + b;
    const auto back = b + separator + a;
    return forth == back ? forth : QString( "(?:%1|%2)" ).arg( forth, back );
}

/// Why get_selected_log_lines() returned no line, for the user.
QString selectionFailure( int result )
{
    switch ( result ) {
    case LOGSQUIRL_LOG_LINES_NO_SELECTION:
        return "select a packet line first.";
    case LOGSQUIRL_LOG_LINES_NO_LOG_FILE:
        return "the tab in front shows no capture.";
    default:
        return QString( "LogSquirl did not tell the selected line (%1)." ).arg( result );
    }
}

} // namespace

FollowStream followStreamPattern( const QString& packetLine )
{
    const auto line = packetLine.section( '\n', 0, 0 );
    const auto match = packetLineRegex().match( line );
    if ( !match.hasMatch() ) {
        return { {}, "the selected line is not a packet line of a capture." };
    }
    const auto number = match.captured( "number" );
    const auto stream = match.captured( "stream" );
    if ( stream == "-" ) {
        return {
            {},
            QString( "packet %1 belongs to no stream: only TCP and UDP packets do." ).arg( number )
        };
    }
    if ( stream == "?" ) {
        return { {},
                 QString( "packet %1 has no stream number: the capture has more "
                          "conversations than the plugin numbers." )
                     .arg( number ) };
    }

    // Number and stream, then whatever time columns there are up to the
    // addresses; the Protocol column differs between the packets of one
    // stream, so it is skipped with the Length.
    auto pattern = QString( R"(%1%2 +\S+ +\d+ +)" )
                       .arg( upToSourcePattern( stream ),
                             eitherWay( literalPattern( match.captured( "source" ) ),
                                        literalPattern( match.captured( "destination" ) ), " +" ) );
    // The ports tell a TCP from a UDP stream of the same number between the
    // same hosts; a line without them still has the stream and addresses.
    // They are looked for anywhere in Info, after the MAC columns a Line
    // Layout may put at its start and the analysis markers.
    const auto ports = portsRegex().match( match.captured( "body" ) );
    if ( ports.hasMatch() ) {
        pattern += QString( R"(.*?(?<!\d)%1(?!\d))" )
                       .arg( eitherWay( ports.captured( 1 ), ports.captured( 2 ), kArrow ) );
    }
    return { pattern, {} };
}

void followSelectedStream()
{
    const auto& st = g_state;
    if ( !st.api || !st.handle || !st.hostCapabilities.regexLab
         || !st.hostCapabilities.selectedLogLines ) {
        return;
    }

    const char* text = nullptr;
    size_t length = 0;
    const int result = st.api->get_selected_log_lines( st.handle, &text, &length, nullptr );
    if ( result < 0 || !text ) {
        hostNotify( "Follow stream: " + selectionFailure( result ) );
        return;
    }

    // The first selected line is the one followed.
    const auto follow
        = followStreamPattern( QString::fromUtf8( text, static_cast<qsizetype>( length ) ) );
    if ( follow.pattern.isEmpty() ) {
        hostNotify( "Follow stream: " + follow.reason );
        return;
    }

    openRegexLab( "Follow stream", follow.pattern );
}

} // namespace tcpdump
