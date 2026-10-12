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
 * @brief Stream lines in Regex Lab, from the selected packet line.
 *
 * Builds a pattern for the stream of the packet line the Packet Panel read
 * from the selection (Selected Packet Line) and opens it in LogSquirl's
 * Regex Lab, where the user sees the matches and applies it as a filter.
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

/// The pattern of the lines of stream @p stream between @p source and
/// @p destination, either way, whether their columns show names or not,
/// and, unless they are empty, the ports @p sourcePort and
/// @p destinationPort.  @p source and @p destination may be columns, the
/// name of a host behind the address.
QString streamPattern( const QString& stream, const QString& source, const QString& destination,
                       const QString& sourcePort, const QString& destinationPort )
{
    // Number and stream, then whatever time columns there are up to the
    // addresses; the Protocol column differs between the packets of one
    // stream, so it is skipped with the Length.
    auto pattern = QString( R"(%1%2 +\S+ +\d+ +)" )
                       .arg( upToSourcePattern( stream ),
                             eitherWay( addressPattern( columnAddress( source ) ),
                                        addressPattern( columnAddress( destination ) ), " +" ) );
    // The ports tell a TCP from a UDP stream of the same number between the
    // same hosts; a line without them still has the stream and addresses.
    // They are looked for anywhere in Info, after the MAC columns a Line
    // Layout may put at its start and the analysis markers.
    if ( !sourcePort.isEmpty() ) {
        pattern += QString( R"(.*?(?<!\d)%1(?!\d))" )
                       .arg( eitherWay( sourcePort, destinationPort, kArrow ) );
    }
    return pattern;
}

} // namespace

QString followStreamPattern( const PacketLine& packet )
{
    if ( packet.stream < 0 ) {
        return {}; // kNoStream or kUnnumbered
    }
    const auto ports = portsRegex().match( packet.body );
    return streamPattern( QString::number( packet.stream ), packet.source, packet.destination,
                          ports.captured( 1 ), ports.captured( 2 ) );
}

QString conversationPattern( int stream, const QString& addressA, uint16_t portA,
                             const QString& addressB, uint16_t portB )
{
    return streamPattern( QString::number( stream ), addressA, addressB, QString::number( portA ),
                          QString::number( portB ) );
}

void followStream( const PacketLine& packet )
{
    const auto& st = g_state;
    if ( !st.api || !st.handle || !st.hostCapabilities.regexLab ) {
        return;
    }
    const auto pattern = followStreamPattern( packet );
    if ( !pattern.isEmpty() ) {
        openRegexLab( "Stream lines in Regex Lab", pattern );
    }
}

} // namespace tcpdump
