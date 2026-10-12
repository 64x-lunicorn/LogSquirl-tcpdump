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
 * @file selected_packet_line_test.cpp
 * @brief BDD tests for Selected Packet Line: what the host tells of the
 *        selection, and each kind of line, read into a packet or a reason.
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "selected_packet_line.h"

#include <QStringList>

#include <vector>

using namespace tcpdump;
using tcpdump_test::FakeHost;

namespace {

/// A packet line of number @p number and stream @p stream, between
/// 192.168.1.1 and 192.168.1.2, whose Info is @p info.
QString line( const char* number, const char* stream, const QString& info )
{
    return QString( "%1      %2       2023-11-14 22:13:20.000000Z  0.000000       192.168.1.1   "
                    "192.168.1.2   TCP       54     %3" )
        .arg( number, stream, info );
}

const QString kArrow = QString::fromUtf8( " \xe2\x86\x92 " );

/// A row of the table: what the host tells, and what is read of it.
struct Row {
    const char* what;
    int result;          ///< get_selected_log_lines()'s result.
    QStringList lines;   ///< The selected lines.
    uint32_t number;     ///< The packet read; 0: none, see reason.
    int stream;          ///< Its Stream column.
    QString irtt;        ///< Its iRTT.
    QString reason;      ///< Why there is no packet.
    QString content;     ///< Why Show stream content cannot show its stream.
    QString streamLines; ///< Why Stream lines in Regex Lab cannot pick its lines.
};

} // namespace

SCENARIO( "Selected Packet Line reads the first selected line as a packet, or says why not",
          "[selected_packet_line]" )
{
    const auto tcp = line( "1", "0", "50000" + kArrow + "80 [SYN] Seq=0 Win=65535" );
    const auto handshakeAck
        = line( "3", "0", "50000" + kArrow + "80 [ACK] Seq=1 Ack=1 Win=65535 [iRTT=0.012345]" );
    const auto udp = line( "5", "2", "40000" + kArrow + "53 Len=29 | Standard query" );
    const auto noStream = line( "7", "-", "Echo (ping) request id=0x0001, seq=1" );
    const auto unnumbered = line( "9", "?", "50000" + kArrow + "80 [SYN] Seq=0 Win=65535" );
    const auto noNumber = line( "99999999999", "0", "50000" + kArrow + "80 [SYN] Seq=0" );
    const QString header( "No.    Stream  UTC Time                     Time           Source   "
                          "Destination   Protocol  Length Info" );

    const QString notPacketLine( "The selected line is not a packet line of a capture." );
    const QString selectPacketLine( "Select a packet line to see its packet." );
    const QString belongsToNone( "Packet 7 belongs to no stream: only TCP and UDP packets do." );

    const std::vector<Row> rows{
        { "a TCP packet line", LOGSQUIRL_LOG_LINES_OK, { tcp }, 1, 0, {}, {}, {}, {} },
        { "the ACK that completes a handshake, before another line",
          LOGSQUIRL_LOG_LINES_OK,
          { handshakeAck, tcp },
          3,
          0,
          "0.012345",
          {},
          {},
          {} },
        { "a UDP packet line of more lines than the host tells",
          LOGSQUIRL_LOG_LINES_TRUNCATED,
          { udp, tcp },
          5,
          2,
          {},
          {},
          {},
          {} },
        { "a packet line of no stream",
          LOGSQUIRL_LOG_LINES_OK,
          { noStream },
          7,
          kNoStream,
          {},
          {},
          belongsToNone,
          belongsToNone },
        { "a packet line of a stream past the numbered ones",
          LOGSQUIRL_LOG_LINES_OK,
          { unnumbered },
          9,
          kUnnumbered,
          {},
          {},
          {},
          "Packet 9 has no stream number: the capture has more conversations than the plugin "
          "numbers." },
        { "a packet line whose number no packet has",
          LOGSQUIRL_LOG_LINES_OK,
          { noNumber },
          0,
          0,
          {},
          "The selected line has no packet number.",
          {},
          {} },
        { "the column header",
          LOGSQUIRL_LOG_LINES_OK,
          { header },
          0,
          0,
          {},
          notPacketLine,
          {},
          {} },
        { "a line of another log",
          LOGSQUIRL_LOG_LINES_OK,
          { "2026-10-09 12:00:00 INFO server started", tcp },
          0,
          0,
          {},
          notPacketLine,
          {},
          {} },
        { "an empty line", LOGSQUIRL_LOG_LINES_OK, { "" }, 0, 0, {}, notPacketLine, {}, {} },
        { "no line selected", LOGSQUIRL_LOG_LINES_OK, {}, 0, 0, {}, selectPacketLine, {}, {} },
        { "a tab that shows no Log File",
          LOGSQUIRL_LOG_LINES_NO_LOG_FILE,
          { tcp },
          0,
          0,
          {},
          "The tab in front shows no capture.",
          {},
          {} },
        { "a call off the UI thread",
          LOGSQUIRL_LOG_LINES_NOT_ON_UI_THREAD,
          { tcp },
          0,
          0,
          {},
          "LogSquirl did not tell the selected line (-1).",
          {},
          {} },
    };

    for ( const auto& row : rows ) {
        GIVEN( "a host whose selection is " << row.what )
        {
            FakeHost host;
            host.selectedLines = row.lines;
            host.selectionResult = row.result;

            WHEN( "the selected packet line is read" )
            {
                const auto selected = readSelectedPacketLine();

                THEN( "the host is asked once, and the packet or the reason is told" )
                {
                    REQUIRE( host.selectionCalls == 1 );
                    if ( row.number == 0 ) {
                        REQUIRE_FALSE( selected.packet );
                        REQUIRE( selected.reason == row.reason );
                        // Neither stream action works without a packet, for the same reason.
                        REQUIRE( selected.streamContentProblem() == row.reason );
                        REQUIRE( selected.streamLinesProblem() == row.reason );
                        return;
                    }
                    REQUIRE( selected.packet );
                    REQUIRE( selected.reason.isEmpty() );
                    REQUIRE( selected.packet->number == row.number );
                    REQUIRE( selected.packet->stream == row.stream );
                    REQUIRE( selected.packet->source == "192.168.1.1" );
                    REQUIRE( selected.packet->destination == "192.168.1.2" );
                    REQUIRE( selected.packet->irtt == row.irtt );
                    REQUIRE( selected.streamContentProblem() == row.content );
                    REQUIRE( selected.streamLinesProblem() == row.streamLines );
                }
            }
        }
    }
}

SCENARIO( "Selected Packet Line tells whether the selection changed", "[selected_packet_line]" )
{
    GIVEN( "a host with a packet line selected" )
    {
        FakeHost host;
        host.selectedLines = { line( "1", "0", "50000" + kArrow + "80 [SYN]" ) };
        const auto first = readSelectedLines();

        THEN( "the same selection read again is the same" )
        {
            REQUIRE( readSelectedLines() == first );
        }

        THEN( "another line, or another result, is another selection" )
        {
            host.selectedLines = { line( "2", "0", "80" + kArrow + "50000 [SYN, ACK]" ) };
            REQUIRE_FALSE( readSelectedLines() == first );
            host.selectedLines = { line( "1", "0", "50000" + kArrow + "80 [SYN]" ) };
            host.selectionResult = LOGSQUIRL_LOG_LINES_TRUNCATED;
            REQUIRE_FALSE( readSelectedLines() == first );
        }
    }
}
