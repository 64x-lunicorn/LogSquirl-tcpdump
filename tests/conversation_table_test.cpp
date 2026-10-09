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
 * @file conversation_table_test.cpp
 * @brief BDD tests for the Conversations table of the Packet Panel: its
 *        rows, sorting, filters and snapshot updates.
 */

#include <catch2/catch.hpp>

#include "conversation_table.h"
#include "fakehost.h"
#include "follow_stream.h"
#include "packet_panel.h"
#include "settings.h"
#include "sidebarwidget.h"

#include <QAction>
#include <QFile>
#include <QLabel>
#include <QRegularExpression>
#include <QTableView>
#include <QTemporaryDir>

#include <set>
#include <tuple>

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );
extern "C" void logsquirl_plugin_shutdown( void );

using tcpdump::Conversation;
using tcpdump::ConversationModel;
using tcpdump::ConversationTable;
using tcpdump::Transport;
using tcpdump_test::FakeHost;
using tcpdump_test::waitFor;

namespace {

const QString kMixed = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );

/// A loaded plugin whose sidebar converted @p capture with @p options and
/// whose tab of it is in front.
struct LoadedCapture {
    explicit LoadedCapture( const QString& capture, const tcpdump::ConversionOptions& options = {},
                            std::size_t apiSize = sizeof( LogSquirlHostApi ) )
        : host( apiSize )
    {
        REQUIRE( tempRoot.isValid() );
        tcpdump::g_state.tempRoot = tempRoot.path();
        REQUIRE( tcpdump::saveConversionOptions( host.configDir(), options ) );
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        sidebar = tcpdump::g_state.sidebarWidget;
        table = sidebar->packetPanel()->conversationTable();
        model = table->model();
        sidebar->openPcapFile( capture );
        REQUIRE( waitFor( [ this ] { return !sidebar->isConverting(); } ) );
        REQUIRE( host.openedFiles.size() == 1 );
        text = host.openedFiles.first();
        QFile file( text );
        REQUIRE( file.open( QIODevice::ReadOnly ) );
        lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
        lines.removeFirst();
        host.activateFile( text );
    }

    ~LoadedCapture()
    {
        logsquirl_plugin_shutdown();
    }

    /// The numbers of the packet lines @p pattern matches, matching case.
    std::set<int> matched( const QString& pattern ) const
    {
        const QRegularExpression regex( pattern );
        REQUIRE( regex.isValid() );
        std::set<int> numbers;
        for ( const auto& line : lines ) {
            if ( regex.match( line ).hasMatch() ) {
                numbers.insert( line.section( ' ', 0, 0 ).toInt() );
            }
        }
        return numbers;
    }

    QTemporaryDir tempRoot;
    FakeHost host;
    tcpdump::SidebarWidget* sidebar = nullptr;
    ConversationTable* table = nullptr;
    ConversationModel* model = nullptr;
    QString text;
    QStringList lines;
};

/// The text of @p column in table row @p row.
QVariant cellOf( const ConversationModel* model, int row, int column )
{
    return model->data( model->index( row, column ) );
}

/// Whether row @p a of @p model may come before row @p b, sorted by @p column ascending.
bool inOrder( const ConversationModel* model, int a, int b, int column )
{
    if ( column == ConversationModel::StreamColumn ) {
        const auto* x = model->conversationAt( a );
        const auto* y = model->conversationAt( b );
        return std::tie( x->transport, x->stream ) <= std::tie( y->transport, y->stream );
    }
    const auto x = cellOf( model, a, column );
    const auto y = cellOf( model, b, column );
    if ( column == ConversationModel::ProtocolColumn || column == ConversationModel::AddressAColumn
         || column == ConversationModel::AddressBColumn ) {
        return x.toString().toStdString() <= y.toString().toStdString();
    }
    return x.toDouble() <= y.toDouble();
}

} // namespace

SCENARIO( "The Conversations table lists the streams of the capture in front", "[conversations]" )
{
    GIVEN( "a converted capture in the tab in front" )
    {
        LoadedCapture loaded( kMixed );
        auto* model = loaded.model;

        THEN( "it has a row per numbered stream, TCP's first, with its counts" )
        {
            REQUIRE( model->rowCount() == 11 ); // TCP 0–7, UDP 0–2
            REQUIRE( cellOf( model, 0, ConversationModel::StreamColumn ) == "TCP 0" );
            REQUIRE( cellOf( model, 0, ConversationModel::ProtocolColumn ) == "HTTP" );
            REQUIRE( cellOf( model, 0, ConversationModel::AddressAColumn ) == "192.168.1.1" );
            REQUIRE( cellOf( model, 0, ConversationModel::PortBColumn ).toInt() == 80 );
            REQUIRE( cellOf( model, 0, ConversationModel::PacketsColumn ).toInt() == 2 );
            REQUIRE( cellOf( model, 0, ConversationModel::BytesAToBColumn ).toInt() == 155 );
            REQUIRE( cellOf( model, 0, ConversationModel::StartColumn ) == "0.938275" );
            REQUIRE( cellOf( model, 8, ConversationModel::StreamColumn ) == "UDP 0" );
            REQUIRE( loaded.table->findChild<QLabel*>()->text().contains( "(11)" ) );
        }

        THEN( "it sorts by every column, either way" )
        {
            for ( int column = 0; column < ConversationModel::ColumnCount; ++column ) {
                for ( const auto order : { Qt::AscendingOrder, Qt::DescendingOrder } ) {
                    INFO( "column " << column << ", order " << order );
                    loaded.table->view()->sortByColumn( column, order );
                    for ( int row = 1; row < model->rowCount(); ++row ) {
                        if ( order == Qt::AscendingOrder ) {
                            REQUIRE( inOrder( model, row - 1, row, column ) );
                        }
                        else {
                            REQUIRE( inOrder( model, row, row - 1, column ) );
                        }
                    }
                }
            }
        }

        WHEN( "the user clicks a conversation" )
        {
            loaded.table->view()->sortByColumn( ConversationModel::BytesColumn,
                                                Qt::DescendingOrder );
            // The SOCKS stream from 50003, the biggest after TCP 6.
            const auto* socks = model->conversationAt( 1 );
            REQUIRE( socks->stream == 4 );
            emit loaded.table->view()->clicked( model->index( 1, 3 ) );

            THEN( "the Regex Lab opens with the pattern of its lines, matching case" )
            {
                REQUIRE( loaded.host.regexLabs.size() == 1 );
                const auto& lab = loaded.host.regexLabs.first();
                REQUIRE( lab.pattern
                         == tcpdump::conversationPattern( 4, "192.168.1.1", 50003, "192.168.1.2",
                                                          1080 ) );
                REQUIRE( lab.flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( loaded.matched( lab.pattern ) == std::set<int>{ 12, 14, 15 } );
                REQUIRE( loaded.host.logs.contains( "Filter: " + lab.pattern ) );
            }
        }

        WHEN( "the user chooses Filter on this conversation for a UDP stream" )
        {
            const auto row = model->rowOf( Transport::Udp, 0 );
            loaded.table->view()->setCurrentIndex( model->index( row, 0 ) );
            auto* action = loaded.table->findChild<QAction*>( "filterOnConversation" );
            REQUIRE( action->isEnabled() );
            action->trigger();

            THEN( "the Regex Lab opens on that UDP stream, not the TCP stream 0" )
            {
                REQUIRE( loaded.host.regexLabs.size() == 1 );
                REQUIRE( loaded.matched( loaded.host.regexLabs.first().pattern )
                         == std::set<int>{ 5 } );
            }
        }

        WHEN( "a tab without a capture of the plugin comes to the front" )
        {
            loaded.host.activateFile( "/some/other.log" );

            THEN( "the table is empty" )
            {
                REQUIRE( model->rowCount() == 0 );
            }

            AND_WHEN( "the capture's tab comes back" )
            {
                loaded.host.activateFile( loaded.text );

                THEN( "its conversations are listed again" )
                {
                    REQUIRE( model->rowCount() == 11 );
                }
            }
        }

        WHEN( "a new summary snapshot arrives, as during a live capture" )
        {
            loaded.table->view()->sortByColumn( ConversationModel::PacketsColumn,
                                                Qt::DescendingOrder );
            const auto selected = model->rowOf( Transport::Udp, 1 );
            loaded.table->view()->setCurrentIndex( model->index( selected, 0 ) );

            auto rows = model->conversations()->list();
            Conversation added;
            added.transport = Transport::Tcp;
            added.stream = 8;
            added.protocol = "TCP";
            added.addressA = "192.168.1.1";
            added.addressB = "192.168.1.9";
            added.packetsAToB = 40;
            rows.push_back( added );
            tcpdump::CaptureSummary summary;
            summary.conversations = std::make_shared<const tcpdump::ConversationRows>( rows );
            loaded.sidebar->updateSummary( loaded.text, summary );

            THEN( "the table shows it, in the same sort, the same conversation selected" )
            {
                REQUIRE( model->rowCount() == 12 );
                REQUIRE( cellOf( model, 0, ConversationModel::StreamColumn ) == "TCP 8" );
                const auto* current
                    = model->conversationAt( loaded.table->view()->currentIndex().row() );
                REQUIRE( current );
                REQUIRE( current->transport == Transport::Udp );
                REQUIRE( current->stream == 1 );
            }
        }

        WHEN( "a snapshot arrives for a capture not in front" )
        {
            loaded.host.activateFile( "/some/other.log" );
            tcpdump::CaptureSummary summary;
            summary.conversations = std::make_shared<const tcpdump::ConversationRows>();
            loaded.sidebar->updateSummary( loaded.text, summary );

            THEN( "it is kept for when its tab comes back" )
            {
                REQUIRE( model->rowCount() == 0 );
                loaded.host.activateFile( loaded.text );
                REQUIRE( model->conversations()->empty() );
            }
        }
    }

    GIVEN( "a capture with more conversations than the stream cap" )
    {
        tcpdump::ConversionOptions options;
        options.maxStreams = 2;
        LoadedCapture loaded( kMixed, options );
        auto* model = loaded.model;

        THEN( "the numbered streams have their rows, the others one row together, last" )
        {
            REQUIRE( model->rowCount() == 3 );
            REQUIRE( model->conversationAt( 2 ) == nullptr );
            REQUIRE( cellOf( model, 2, ConversationModel::StreamColumn ) == "?" );
            REQUIRE( cellOf( model, 2, ConversationModel::ProtocolColumn ) == "Other streams" );
            REQUIRE( cellOf( model, 2, ConversationModel::PacketsColumn ).toInt() == 13 );
            loaded.table->view()->sortByColumn( ConversationModel::PacketsColumn,
                                                Qt::DescendingOrder );
            REQUIRE( model->conversationAt( 2 ) == nullptr );
        }

        WHEN( "the user clicks the other streams' row" )
        {
            emit loaded.table->view()->clicked( model->index( 2, 0 ) );

            THEN( "no Lab opens, and a notification says why" )
            {
                REQUIRE( loaded.host.regexLabs.isEmpty() );
                REQUIRE( loaded.host.notifications.size() == 1 );
                REQUIRE( loaded.host.notifications.first().contains( "stream cap" ) );
            }
        }
    }

    GIVEN( "a capture converted on a host without the Regex Lab" )
    {
        LoadedCapture loaded( kMixed, {}, LOGSQUIRL_HOST_API_BASE_SIZE );

        WHEN( "the user clicks a conversation" )
        {
            emit loaded.table->view()->clicked( loaded.model->index( 0, 0 ) );

            THEN( "nothing opens, and the context menu entry is disabled" )
            {
                REQUIRE( loaded.model->rowCount() == 11 );
                REQUIRE( loaded.host.regexLabs.isEmpty() );
                REQUIRE_FALSE(
                    loaded.table->findChild<QAction*>( "filterOnConversation" )->isEnabled() );
            }
        }
    }
}
