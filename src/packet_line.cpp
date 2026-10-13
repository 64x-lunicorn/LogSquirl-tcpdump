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
 * @file packet_line.cpp
 * @brief Reading a packet line back.
 */

#include "packet_line.h"

namespace tcpdump {

const QRegularExpression& packetLineRegex()
{
    static const QRegularExpression regex(
        R"(^(?<number>\d++) ++(?<stream>\d++|[-?]) ++(?:(?<timestamp>[+-]?\d{4,}-\d{2}-\d{2} )"
        R"(\d{2}:\d{2}:\d{2}\.\d++Z) ++)?(?:(?<time>-?\d++\.\d++) ++)?(?<source>\S++) ++)"
        R"((?<destination>\S++) ++(?<protocol>\S++) ++(?<length>\d++) ++(?<body>.*)$)" );
    return regex;
}

std::optional<PacketLine> readPacketLine( const QString& line )
{
    const auto match = packetLineRegex().match( line );
    if ( !match.hasMatch() ) {
        return std::nullopt;
    }
    PacketLine packet;
    bool ok = false;
    const auto number = match.captured( "number" ).toUInt( &ok );
    packet.number = ok ? number : 0;

    const auto stream = match.captured( "stream" );
    if ( stream == "-" ) {
        packet.stream = kNoStream;
    }
    else if ( stream == "?" ) {
        packet.stream = kUnnumbered;
    }
    else {
        // A number no stream can have is past the numbered ones, as a
        // packet number no packet can have is 0: the line is still a
        // packet line.
        packet.stream = stream.toInt( &ok );
        if ( !ok ) {
            packet.stream = kUnnumbered;
        }
    }

    packet.source = match.captured( "source" );
    packet.destination = match.captured( "destination" );
    packet.protocol = match.captured( "protocol" );
    packet.body = match.captured( "body" );

    // As the TCP Analysis writes it (tcp_analysis.cpp): after the TCP
    // fields, in seconds at the packet's precision.  The packet read back
    // alone has no stream to know it.
    static const QRegularExpression irtt( QStringLiteral( R"(\[iRTT=([0-9]+\.[0-9]+)\])" ) );
    packet.irtt = irtt.match( packet.body ).captured( 1 );
    return packet;
}

} // namespace tcpdump
