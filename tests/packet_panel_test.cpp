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
 * @file packet_panel_test.cpp
 * @brief BDD tests for the Packet Panel: the selected line's packet, its
 *        layer tree and hex dump, and how the selection is polled.
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "packet_panel.h"
#include "sidebarwidget.h"

#include <QElapsedTimer>
#include <QFile>
#include <QPlainTextEdit>
#include <QTemporaryDir>
#include <QTreeWidget>

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );

using tcpdump::PacketPanel;
using tcpdump_test::FakeHost;
using tcpdump_test::waitFor;

namespace {

const QString kMixed = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );

/// The lines of the text file at @p path, the header first.
QStringList linesOf( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
}

/// Run the event loop for @p ms milliseconds.
void runFor( int ms )
{
    QElapsedTimer timer;
    timer.start();
    waitFor( [ & ] { return timer.elapsed() >= ms; } );
}

/// A loaded plugin whose sidebar converted @p capture and whose tab of it is in front.
struct LoadedCapture {
    explicit LoadedCapture( const QString& capture,
                            std::size_t apiSize = sizeof( LogSquirlHostApi ) )
        : host( apiSize )
    {
        REQUIRE( tempRoot.isValid() );
        tcpdump::g_state.tempRoot = tempRoot.path();
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        sidebar = tcpdump::g_state.sidebarWidget;
        panel = sidebar->packetPanel();
        sidebar->openPcapFile( capture );
        REQUIRE( waitFor( [ this ] { return !sidebar->isConverting(); } ) );
        REQUIRE( host.openedFiles.size() == 1 );
        text = host.openedFiles.first();
        lines = linesOf( text );
        host.activateFile( text );
    }

    ~LoadedCapture()
    {
        logsquirl_plugin_shutdown();
    }

    QTemporaryDir tempRoot;
    FakeHost host;
    tcpdump::SidebarWidget* sidebar = nullptr;
    PacketPanel* panel = nullptr;
    QString text;
    QStringList lines;
};

} // namespace

SCENARIO( "The hex dump shows each byte in hex and as ASCII", "[packet_panel]" )
{
    std::vector<uint8_t> bytes;
    for ( uint8_t i = 0; i < 20; ++i ) {
        bytes.push_back( static_cast<uint8_t>( 'A' + i ) );
    }
    bytes[ 0 ] = 0x00;
    const auto dump = tcpdump::hexDump( bytes );

    THEN( "16 bytes go on a line, after their offset, then as text" )
    {
        const auto lines = dump.split( '\n' );
        REQUIRE( lines.size() == 2 );
        REQUIRE( lines[ 0 ]
                 == "0000  00 42 43 44 45 46 47 48  49 4a 4b 4c 4d 4e 4f 50   .BCDEFGHIJKLMNOP" );
        REQUIRE( lines[ 1 ] == "0010  51 52 53 54" + QString( 40, ' ' ) + "QRST" );
    }

    THEN( "a byte range is found in the hex and the ASCII of each line it is on" )
    {
        const auto ranges = tcpdump::hexDumpRanges( bytes.size(), 14, 4 );
        REQUIRE( ranges.size() == 4 );
        QStringList shown;
        for ( const auto& [ start, length ] : ranges ) {
            shown << dump.mid( start, length );
        }
        REQUIRE( shown == QStringList{ "4f 50", "OP", "51 52", "QR" } );
    }

    THEN( "a range across the gap after 8 bytes covers it" )
    {
        const auto ranges = tcpdump::hexDumpRanges( bytes.size(), 7, 2 );
        REQUIRE( ranges.size() == 2 );
        REQUIRE( dump.mid( ranges[ 0 ].first, ranges[ 0 ].second ) == "48  49" );
    }

    THEN( "an empty range shows nothing" )
    {
        REQUIRE( tcpdump::hexDumpRanges( bytes.size(), 3, 0 ).empty() );
    }
}

SCENARIO( "The Packet Panel shows the packet of the selected line", "[packet_panel]" )
{
    GIVEN( "a converted capture in the tab in front, the sidebar in view" )
    {
        LoadedCapture loaded( kMixed );
        auto& host = loaded.host;
        auto* panel = loaded.panel;
        loaded.sidebar->show();
        REQUIRE( panel->isVisible() );

        WHEN( "a packet line is selected" )
        {
            host.selectedLines = { loaded.lines[ 3 ] };

            THEN( "the panel shows that packet, its layers and its bytes" )
            {
                REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
                REQUIRE( panel->statusText() == "Packet 3" );
                auto* tree = panel->findChild<QTreeWidget*>( "packetLayers" );
                REQUIRE( tree->topLevelItemCount() >= 3 );
                REQUIRE( tree->topLevelItem( 0 )->text( 0 ).startsWith( "Frame 3: " ) );
                REQUIRE( tree->topLevelItem( 1 )->text( 0 ) == "Ethernet II" );
                auto* dump = panel->findChild<QPlainTextEdit*>( "packetBytes" );
                REQUIRE( dump->toPlainText().startsWith( "0000  " ) );
            }

            AND_WHEN( "the selection moves to another line" )
            {
                REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
                host.selectedLines = { loaded.lines[ 5 ], loaded.lines[ 6 ] };

                THEN( "the panel follows it, to the first selected line's packet" )
                {
                    REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 5; } ) );
                }
            }

            AND_WHEN( "a field of the tree is selected" )
            {
                REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
                auto* tree = panel->findChild<QTreeWidget*>( "packetLayers" );
                auto* ethernet = tree->topLevelItem( 1 );
                QTreeWidgetItem* source = nullptr;
                for ( int i = 0; i < ethernet->childCount(); ++i ) {
                    if ( ethernet->child( i )->text( 0 ).startsWith( "Source: " ) ) {
                        source = ethernet->child( i );
                    }
                }
                REQUIRE( source );
                tree->setCurrentItem( source );

                THEN( "its bytes are highlighted in the hex dump, hex and ASCII" )
                {
                    auto* dump = panel->findChild<QPlainTextEdit*>( "packetBytes" );
                    const auto selections = dump->extraSelections();
                    REQUIRE( selections.size() == 2 );
                    const auto mac = source->text( 0 ).mid( 8 ).remove( ':' );
                    REQUIRE( selections[ 0 ].cursor.selectedText().remove( ' ' ) == mac );
                    REQUIRE( selections[ 1 ].cursor.selectedText().size() == 6 );
                }
            }
        }

        WHEN( "the selected line is the header, not a packet line" )
        {
            host.selectedLines = { loaded.lines[ 0 ] };

            THEN( "the panel says so" )
            {
                REQUIRE( waitFor(
                    [ panel ] { return panel->statusText().contains( "not a packet line" ); } ) );
                REQUIRE( panel->shownPacket() == 0 );
            }
        }

        WHEN( "nothing is selected" )
        {
            host.selectedLines.clear();

            THEN( "the panel asks for a selection" )
            {
                REQUIRE( waitFor( [ panel ] {
                    return panel->statusText() == "Select a packet line to see its packet.";
                } ) );
            }
        }

        WHEN( "a tab without a capture of the plugin comes to the front" )
        {
            host.selectedLines = { loaded.lines[ 3 ] };
            REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
            host.activateFile( "/some/other.log" );

            THEN( "the panel says the tab holds no capture" )
            {
                REQUIRE( panel->shownPacket() == 0 );
                REQUIRE( panel->statusText() == "No capture in this tab." );
            }

            AND_WHEN( "the capture's tab comes back" )
            {
                host.activateFile( loaded.text );

                THEN( "its packet is shown again" )
                {
                    REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
                }
            }
        }
    }
}

SCENARIO( "The Packet Panel polls the selection only while it is visible", "[packet_panel]" )
{
    GIVEN( "a converted capture in the tab in front and a selected line" )
    {
        LoadedCapture loaded( kMixed );
        auto& host = loaded.host;
        auto* panel = loaded.panel;
        host.selectedLines = { loaded.lines[ 2 ] };

        THEN( "nothing is asked while the sidebar is hidden" )
        {
            REQUIRE_FALSE( panel->isPolling() );
            const auto before = host.selectionCalls;
            runFor( 3 * PacketPanel::kPollIntervalMs );
            REQUIRE( host.selectionCalls == before );
        }

        WHEN( "the sidebar is shown" )
        {
            loaded.sidebar->show();
            REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 2; } ) );

            THEN( "the selection is asked for at most every interval" )
            {
                REQUIRE( panel->isPolling() );
                const auto before = host.selectionCalls;
                QElapsedTimer timer;
                timer.start();
                runFor( 4 * PacketPanel::kPollIntervalMs );
                const auto calls = host.selectionCalls - before;
                REQUIRE( calls >= 1 );
                REQUIRE( calls <= timer.elapsed() / PacketPanel::kPollIntervalMs + 1 );
            }

            THEN( "an unchanged selection leaves the panel as it is" )
            {
                auto* tree = panel->findChild<QTreeWidget*>( "packetLayers" );
                auto* first = tree->topLevelItem( 0 );
                const auto before = host.selectionCalls;
                REQUIRE( waitFor( [ & ] { return host.selectionCalls >= before + 2; } ) );
                REQUIRE( tree->topLevelItem( 0 ) == first );
            }

            AND_WHEN( "it is hidden again" )
            {
                loaded.sidebar->hide();

                THEN( "the polling stops" )
                {
                    REQUIRE_FALSE( panel->isPolling() );
                    const auto before = host.selectionCalls;
                    runFor( 3 * PacketPanel::kPollIntervalMs );
                    REQUIRE( host.selectionCalls == before );
                }
            }
        }
    }
}

SCENARIO( "A capture file changed since its conversion is reported", "[packet_panel]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    const auto capture = dir.filePath( "changing.pcap" );
    REQUIRE( QFile::copy( kMixed, capture ) );
    REQUIRE( QFile::setPermissions( capture, QFile::ReadOwner | QFile::WriteOwner ) );

    GIVEN( "a converted capture whose file is then cut short" )
    {
        LoadedCapture loaded( capture );
        QFile file( capture );
        REQUIRE( file.resize( file.size() / 2 ) );
        loaded.host.selectedLines = { loaded.lines.last() };

        WHEN( "a packet line is selected" )
        {
            loaded.sidebar->show();

            THEN( "the panel says the file changed and shows no packet" )
            {
                REQUIRE( waitFor( [ &loaded ] {
                    return loaded.panel->statusText().contains( "has changed" );
                } ) );
                REQUIRE( loaded.panel->shownPacket() == 0 );
            }
        }
    }
}

SCENARIO( "Packet details reads the selected line at once", "[packet_panel]" )
{
    GIVEN( "a host that tells the selected lines, the sidebar not in view" )
    {
        LoadedCapture loaded( kMixed );
        auto& host = loaded.host;
        const auto entry
            = std::find_if( host.menuActions.begin(), host.menuActions.end(),
                            []( const auto& a ) { return a.label == "Packet details"; } );
        REQUIRE( entry != host.menuActions.end() );

        WHEN( "a packet line is selected and Packet details chosen" )
        {
            host.selectedLines = { loaded.lines[ 1 ] };
            entry->trigger();

            THEN( "the panel shows the packet, and a notification names its layers" )
            {
                REQUIRE( loaded.panel->shownPacket() == 1 );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().startsWith( "Packet 1: Ethernet II / " ) );
            }
        }

        WHEN( "nothing is selected and Packet details chosen" )
        {
            entry->trigger();

            THEN( "the notification says why no packet is shown" )
            {
                REQUIRE(
                    host.notifications
                    == QStringList{ "Packet details: Select a packet line to see its packet." } );
            }
        }
    }

    GIVEN( "a host older than LogSquirl 26.11" )
    {
        LoadedCapture loaded( kMixed, LOGSQUIRL_HOST_API_BASE_SIZE );

        THEN( "there is no Packet details entry, and the panel says what it needs" )
        {
            for ( const auto& action : loaded.host.menuActions ) {
                REQUIRE( action.label != "Packet details" );
            }
            loaded.sidebar->show();
            REQUIRE( loaded.panel->statusText().contains( "26.11" ) );
            REQUIRE_FALSE( loaded.panel->isPolling() );
        }
    }
}
