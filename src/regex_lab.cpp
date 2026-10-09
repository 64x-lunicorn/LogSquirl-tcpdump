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
 * @file regex_lab.cpp
 * @brief Patterns over the packet list, and the Regex Lab that opens them.
 */

#include "regex_lab.h"
#include "plugin.h"

namespace tcpdump {

namespace {

/// What the user did with the Lab: logged, for the record.
void regexLabClosed( void* user_data, int result, const char* pattern, int /* flags */ )
{
    const auto feature = QString::fromUtf8( static_cast<const char*>( user_data ) );
    if ( result == LOGSQUIRL_REGEX_LAB_APPLIED ) {
        hostLog( LOGSQUIRL_LOG_INFO,
                 feature + ": applied " + QString::fromUtf8( pattern ? pattern : "" ) );
    }
    else {
        hostLog( LOGSQUIRL_LOG_INFO, feature + ": cancelled" );
    }
}

} // namespace

const QRegularExpression& packetLineRegex()
{
    static const QRegularExpression regex(
        R"(^(?<number>\d++) ++(?<stream>\d++|[-?]) ++(?:(?<timestamp>[+-]?\d{4,}-\d{2}-\d{2} )"
        R"(\d{2}:\d{2}:\d{2}\.\d++Z) ++)?(?:(?<time>-?\d++\.\d++) ++)?(?<source>\S++) ++)"
        R"((?<destination>\S++) ++(?<protocol>\S++) ++(?<length>\d++) ++(?<body>.*)$)" );
    return regex;
}

QString upToSourcePattern( const QString& stream )
{
    // Either time column may be left out (LineLayout).  The columns cannot
    // slip when one is: an address never reads as a time, and a Protocol is
    // never all digits, as the Length is that each pattern requires after it.
    return QString( R"(^\d+ +%1 +(?:[+-]?\d{4,}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+Z +)?)"
                    R"((?:-?\d+\.\d+ +)?)" )
        .arg( stream );
}

QString literalPattern( const QString& text )
{
    QString escaped;
    for ( const auto c : text ) {
        if ( !c.isLetterOrNumber() && c != ':' ) {
            escaped += '\\';
        }
        escaped += c;
    }
    return escaped;
}

QString endpointPattern( const QString& address )
{
    // Source, then Destination; the Protocol and Length columns after them
    // pin the two in place.
    return QString( R"(%1(?:%2 +\S+|\S+ +%2) +\S+ +\d+ )" )
        .arg( upToSourcePattern(), literalPattern( address ) );
}

QString protocolPattern( const QString& protocol )
{
    // An empty protocol shows as "-", as any empty column does.
    return QString( R"(%1\S+ +\S+ +%2 +\d+ )" )
        .arg( upToSourcePattern(), literalPattern( protocol.isEmpty() ? "-" : protocol ) );
}

void openRegexLab( const char* feature, const QString& pattern )
{
    const auto& st = g_state;
    if ( !st.api || !st.handle || !st.hostCapabilities.regexLab ) {
        return;
    }
    const auto name = QString::fromUtf8( feature );
    hostLog( LOGSQUIRL_LOG_INFO, name + ": " + pattern );
    if ( st.api->open_regex_lab( st.handle, pattern.toUtf8().constData(),
                                 LOGSQUIRL_REGEX_LAB_MATCH_CASE, &regexLabClosed,
                                 const_cast<char*>( feature ) )
         != 0 ) {
        hostNotify( name + ": the Regex Lab did not open." );
    }
}

} // namespace tcpdump
