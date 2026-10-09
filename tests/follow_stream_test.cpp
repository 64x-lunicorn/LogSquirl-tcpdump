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
 * @file follow_stream_test.cpp
 * @brief BDD tests for Follow stream: the pattern for a packet line's stream,
 *        and the menu entry and sidebar button that open it in the Regex Lab.
 */

#include <catch2/catch.hpp>

#include "corpus_layouts.h"
#include "fakehost.h"
#include "follow_stream.h"
#include "plugin.h"
#include "sidebarwidget.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QPushButton>
#include <QRegularExpression>
#include <QStringList>
#include <QTemporaryDir>

#include <set>

using tcpdump::followStreamPattern;
using tcpdump_test::FakeHost;

extern "C" int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );
extern "C" void logsquirl_plugin_shutdown( void );

namespace {

/// The packet lines of a corpus text, header excluded.
QStringList corpusLines( const QString& name )
{
    QFile file( QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( name ) );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
    REQUIRE_FALSE( lines.isEmpty() );
    lines.removeFirst();
    return lines;
}

/// The line of packet @p number.
QString packet( const QStringList& lines, int number )
{
    const auto prefix = QString::number( number ) + ' ';
    for ( const auto& line : lines ) {
        if ( line.startsWith( prefix ) ) {
            return line;
        }
    }
    FAIL( "no packet " << number );
    return {};
}

/// The numbers of the packets @p pattern matches, as the Regex Lab does with
/// Match case.
std::set<int> matched( const QString& pattern, const QStringList& lines )
{
    const QRegularExpression regex( pattern );
    INFO( pattern.toStdString() );
    REQUIRE( regex.isValid() );
    std::set<int> numbers;
    for ( const auto& line : lines ) {
        if ( regex.match( line ).hasMatch() ) {
            numbers.insert( line.section( ' ', 0, 0 ).toInt() );
        }
    }
    return numbers;
}

/// The packets the stream of packet @p number holds, by the pattern.
std::set<int> followed( const QStringList& lines, int number )
{
    const auto follow = followStreamPattern( packet( lines, number ) );
    INFO( follow.reason.toStdString() );
    REQUIRE_FALSE( follow.pattern.isEmpty() );
    return matched( follow.pattern, lines );
}

const QString kArrow = QString::fromUtf8( "\xe2\x86\x92" );

} // namespace

SCENARIO( "Follow stream matches exactly the lines of a packet's stream", "[followstream]" )
{
    GIVEN( "a capture with TCP and UDP streams of the same numbers between the same hosts" )
    {
        // Streams 0 and 1 are both a TCP and a UDP conversation of
        // 192.168.1.1 and 192.168.1.2.
        const auto lines = corpusLines( "mixed.txt" );

        THEN( "a TCP stream's line finds that TCP conversation, not the UDP one" )
        {
            REQUIRE( followed( lines, 1 ) == std::set<int>{ 1, 2 } );
            REQUIRE( followed( lines, 3 ) == std::set<int>{ 3 } );
        }

        THEN( "a UDP stream's line finds that UDP conversation, not the TCP one" )
        {
            REQUIRE( followed( lines, 5 ) == std::set<int>{ 5 } );
            REQUIRE( followed( lines, 6 ) == std::set<int>{ 6 } );
        }

        THEN( "a conversation is found in both directions" )
        {
            REQUIRE( followed( lines, 12 ) == std::set<int>{ 12, 14, 15 } );
            REQUIRE( followed( lines, 13 ) == std::set<int>{ 13, 16 } );
        }

        THEN( "a conversation between two equal ports is found" )
        {
            REQUIRE( followed( lines, 8 ) == std::set<int>{ 8 } );
        }
    }

    GIVEN( "tunnelled TCP and UDP streams of the same numbers between the same hosts" )
    {
        // Info starts with the tunnels, "VXLAN VNI 100 | 50000 → 8080 …":
        // the ports after them are the inner packet's.  Streams 0 and 1 are
        // both a TCP and a UDP conversation of 10.1.0.10 and 10.2.0.20,
        // stream 2 of 2001:db8:1::10 and 2001:db8:2::20.
        const auto lines = corpusLines( "tunnels.txt" );

        THEN( "each line finds its own conversation, in whichever tunnel" )
        {
            REQUIRE( followed( lines, 1 ) == std::set<int>{ 1, 2, 3, 4 } );
            REQUIRE( followed( lines, 2 ) == std::set<int>{ 1, 2, 3, 4 } );
            REQUIRE( followed( lines, 7 ) == std::set<int>{ 7 } );
            REQUIRE( followed( lines, 8 ) == std::set<int>{ 8 } );
            REQUIRE( followed( lines, 10 ) == std::set<int>{ 10 } );
            REQUIRE( followed( lines, 11 ) == std::set<int>{ 11 } );
            REQUIRE( followed( lines, 13 ) == std::set<int>{ 13 } );
        }
    }

    GIVEN( "every line of every corpus text" )
    {
        const QDir dir( QStringLiteral( TCPDUMP_CORPUS_DIR ) );
        for ( const auto& name : dir.entryList( { "*.txt" }, QDir::Files ) ) {
            const auto lines = corpusLines( name );
            for ( const auto& line : lines ) {
                INFO( name.toStdString() << ": " << line.toStdString() );
                const auto stream = line.section( ' ', 1, 1, QString::SectionSkipEmpty );
                const auto follow = followStreamPattern( line );

                if ( stream == "-" || stream == "?" ) {
                    // Each is a packet line, with a reason of its own.
                    REQUIRE( follow.pattern.isEmpty() );
                    REQUIRE( follow.reason.startsWith( "packet " ) );
                    continue;
                }
                // The line itself, and only lines of its stream number.
                REQUIRE( follow.reason.isEmpty() );
                const auto numbers = matched( follow.pattern, lines );
                REQUIRE( numbers.count( line.section( ' ', 0, 0 ).toInt() ) == 1 );
                for ( const auto number : numbers ) {
                    REQUIRE( packet( lines, number ).section( ' ', 1, 1, QString::SectionSkipEmpty )
                             == stream );
                }
            }
        }
    }

    GIVEN( "the corpus captures converted in every Line Layout" )
    {
        QTemporaryDir out;
        REQUIRE( out.isValid() );
        for ( const auto& capture : tcpdump_test::committedCaptures() ) {
            const auto layouts = tcpdump_test::allLineLayouts();
            const auto standard
                = tcpdump_test::convertedLines( capture, layouts.front(), out.path() );
            for ( const auto& layout : layouts ) {
                const auto lines = tcpdump_test::convertedLines( capture, layout, out.path() );
                REQUIRE( lines.size() == standard.size() );
                for ( qsizetype i = 0; i < lines.size(); ++i ) {
                    INFO( QFileInfo( capture ).fileName().toStdString()
                          << ", " << tcpdump_test::describeLayout( layout ) << ": "
                          << lines[ i ].toStdString() );
                    const auto follow = followStreamPattern( lines[ i ] );
                    const auto expected = followStreamPattern( standard[ i ] );
                    REQUIRE( follow.reason == expected.reason );
                    if ( !follow.pattern.isEmpty() ) {
                        // The same packets as in the default layout
                        REQUIRE( matched( follow.pattern, lines )
                                 == matched( expected.pattern, standard ) );
                    }
                }
            }
        }
    }

    GIVEN( "a TCP line whose Info starts with an analysis marker" )
    {
        const QStringList lines{
            "1      0       2023-11-14 22:13:20.000000Z  0.000000       192.168.1.1   "
            "192.168.1.2   HTTP      54     50000 "
                + kArrow + " 80 [SYN] Seq=0 Win=65535",
            "2      0       2023-11-14 22:13:21.000000Z  1.000000       192.168.1.1   "
            "192.168.1.2   HTTP      54     [TCP Retransmission] 50000 "
                + kArrow + " 80 [SYN] Seq=0 Win=65535",
            "3      0       2023-11-14 22:13:21.500000Z  1.500000       192.168.1.1   "
            "192.168.1.2   DNS       71     40000 "
                + kArrow + " 53 Len=29 | Query example.com",
        };

        THEN( "both lines of the stream are found from either" )
        {
            REQUIRE( followed( lines, 1 ) == std::set<int>{ 1, 2 } );
            REQUIRE( followed( lines, 2 ) == std::set<int>{ 1, 2 } );
        }
    }

    GIVEN( "lines that are no packet lines" )
    {
        const auto header = QString::fromUtf8(
            "No.    Stream  UTC Time                     Time           Source   Destination   "
            "Protocol  Length Info" );

        THEN( "they have no pattern, and the reason says so" )
        {
            for ( const auto& line :
                  { header, QString( "2026-10-09 ERROR something broke" ), QString() } ) {
                const auto follow = followStreamPattern( line );
                REQUIRE( follow.pattern.isEmpty() );
                REQUIRE( follow.reason.contains( "not a packet line" ) );
            }
        }
    }

    GIVEN( "a packet line without a stream" )
    {
        const auto line = packet( corpusLines( "mixed.txt" ), 7 );

        THEN( "the reason names the packet and why" )
        {
            const auto follow = followStreamPattern( line );
            REQUIRE( follow.pattern.isEmpty() );
            REQUIRE( follow.reason.contains( "packet 7" ) );
            REQUIRE( follow.reason.contains( "only TCP and UDP" ) );
        }
    }

    GIVEN( "a packet line past the stream cap" )
    {
        auto line = packet( corpusLines( "mixed.txt" ), 1 );
        line.replace( QRegularExpression( "^1      0  " ), "1      ?  " );

        THEN( "the reason says the stream was not numbered" )
        {
            const auto follow = followStreamPattern( line );
            REQUIRE( follow.pattern.isEmpty() );
            REQUIRE( follow.reason.contains( "no stream number" ) );
        }
    }

    GIVEN( "several selected lines" )
    {
        const auto lines = corpusLines( "mixed.txt" );

        THEN( "the first one is followed" )
        {
            const auto follow
                = followStreamPattern( packet( lines, 5 ) + '\n' + packet( lines, 1 ) );
            REQUIRE( matched( follow.pattern, lines ) == std::set<int>{ 5 } );
        }
    }
}

SCENARIO( "Follow stream opens the Regex Lab on the selected packet's stream", "[followstream]" )
{
    const auto lines = corpusLines( "mixed.txt" );

    GIVEN( "a plugin loaded by a host with the Regex Lab and the selected lines" )
    {
        FakeHost host;
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        auto* sidebar = tcpdump::g_state.sidebarWidget;
        auto* button = sidebar->findChild<QPushButton*>( "followStreamButton" );

        THEN( "Plugins > tcpdump > Follow stream and the sidebar button are offered" )
        {
            QStringList labels;
            for ( const auto& action : host.menuActions ) {
                labels << action.label;
            }
            REQUIRE( labels
                     == QStringList{ "Open pcap\xe2\x80\xa6", "Packet details",
                                     "Export packets\xe2\x80\xa6", "Display filter\xe2\x80\xa6",
                                     "Follow stream content", "Follow stream" } );
            REQUIRE( host.menuActions.last().menuPath == "tcpdump" );
            REQUIRE( button );
        }

        WHEN( "a TCP packet line is selected and the entry chosen" )
        {
            host.selectedLines = { packet( lines, 1 ) };
            host.menuActions.last().trigger();

            THEN( "the Regex Lab opens with the pattern of that stream, matching case" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                const auto& lab = host.regexLabs.first();
                REQUIRE( lab.pattern == followStreamPattern( packet( lines, 1 ) ).pattern );
                REQUIRE( lab.flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( matched( lab.pattern, lines ) == std::set<int>{ 1, 2 } );
                REQUIRE( host.notifications.isEmpty() );
            }

            AND_WHEN( "the user applies the pattern" )
            {
                host.regexLabs.first().apply( host.regexLabs.first().pattern,
                                              LOGSQUIRL_REGEX_LAB_MATCH_CASE );

                THEN( "the applied pattern is logged" )
                {
                    REQUIRE( host.logs.contains( "Follow stream: applied "
                                                 + host.regexLabs.first().pattern ) );
                }
            }

            AND_WHEN( "the user cancels the Lab" )
            {
                host.regexLabs.first().cancel();

                THEN( "the cancel is logged" )
                {
                    REQUIRE( host.logs.contains( "Follow stream: cancelled" ) );
                }
            }
        }

        WHEN( "a UDP packet line is selected and the sidebar button clicked" )
        {
            REQUIRE( button );
            host.selectedLines = { packet( lines, 5 ) };
            button->click();

            THEN( "the Regex Lab opens with the pattern of that UDP stream" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( matched( host.regexLabs.first().pattern, lines ) == std::set<int>{ 5 } );
            }
        }

        WHEN( "nothing is selected" )
        {
            host.menuActions.last().trigger();

            THEN( "no Lab opens, and a notification says to select a packet line" )
            {
                REQUIRE( host.regexLabs.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "select a packet line" ) );
            }
        }

        WHEN( "a packet line without a stream is selected" )
        {
            host.selectedLines = { packet( lines, 20 ) };
            host.menuActions.last().trigger();

            THEN( "no Lab opens, and a notification says the packet has no stream" )
            {
                REQUIRE( host.regexLabs.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "packet 20 belongs to no stream" ) );
            }
        }

        WHEN( "a line of another log is selected" )
        {
            host.selectedLines = { "2026-10-09 12:00:00 INFO server started" };
            host.menuActions.last().trigger();

            THEN( "no Lab opens, and a notification says it is no packet line" )
            {
                REQUIRE( host.regexLabs.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "not a packet line" ) );
            }
        }

        WHEN( "the tab in front shows no Log File" )
        {
            host.selectionResult = LOGSQUIRL_LOG_LINES_NO_LOG_FILE;
            host.menuActions.last().trigger();

            THEN( "no Lab opens, and a notification says the tab shows no capture" )
            {
                REQUIRE( host.regexLabs.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "shows no capture" ) );
            }
        }

        WHEN( "more lines are selected than the host tells" )
        {
            host.selectedLines = { packet( lines, 12 ), packet( lines, 13 ) };
            host.selectionResult = LOGSQUIRL_LOG_LINES_TRUNCATED;
            host.menuActions.last().trigger();

            THEN( "the first one is followed all the same" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( matched( host.regexLabs.first().pattern, lines )
                         == std::set<int>{ 12, 14, 15 } );
            }
        }

        logsquirl_plugin_shutdown();
    }

    GIVEN( "a plugin loaded by a host older than LogSquirl 26.11" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

        THEN( "neither the entry nor the button is offered" )
        {
            for ( const auto& action : host.menuActions ) {
                REQUIRE( action.label != "Follow stream" );
            }
            REQUIRE_FALSE(
                tcpdump::g_state.sidebarWidget->findChild<QPushButton*>( "followStreamButton" ) );
        }

        logsquirl_plugin_shutdown();
    }

    GIVEN( "a plugin loaded through the old init by a new host" )
    {
        FakeHost host;
        REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

        THEN( "neither the entry nor the button is offered" )
        {
            REQUIRE( host.menuActions.size() == 1 );
            REQUIRE_FALSE(
                tcpdump::g_state.sidebarWidget->findChild<QPushButton*>( "followStreamButton" ) );
        }

        logsquirl_plugin_shutdown();
    }
}
