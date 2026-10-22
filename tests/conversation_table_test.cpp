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
#include <QApplication>
#include <QFile>
#include <QHeaderView>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QRegularExpression>
#include <QSettings>
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
        tcpdump::g_state.sessions->conversionSession().start( capture );
        REQUIRE( waitFor(
            [ this ] { return !tcpdump::g_state.sessions->conversionSession().isBusy(); } ) );
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

/// Click the left button on @p index of @p view, twice in a row if @p twice.
void clickOn( QTableView* view, const QModelIndex& index, bool twice = false )
{
    const QPointF at = view->visualRect( index ).center();
    const auto send = [ & ]( QEvent::Type type ) {
        QMouseEvent event( type, at, view->viewport()->mapToGlobal( at ), Qt::LeftButton,
                           type == QEvent::MouseButtonRelease ? Qt::NoButton : Qt::LeftButton,
                           Qt::NoModifier );
        QApplication::sendEvent( view->viewport(), &event );
    };
    send( QEvent::MouseButtonPress );
    send( QEvent::MouseButtonRelease );
    if ( twice ) {
        send( QEvent::MouseButtonDblClick );
        send( QEvent::MouseButtonRelease );
    }
}

/// Press @p key on @p view.
void press( QTableView* view, int key )
{
    QKeyEvent event( QEvent::KeyPress, key, Qt::NoModifier );
    QApplication::sendEvent( view, &event );
}

/// The header's context menu entry of the column headed @p header.
QAction* columnEntry( const ConversationTable* table, const QString& header )
{
    QAction* entry = nullptr;
    for ( auto* action : table->view()->horizontalHeader()->actions() ) {
        if ( action->text() == header ) {
            entry = action;
        }
    }
    INFO( header.toStdString() );
    REQUIRE( entry );
    return entry;
}

/// The columns @p table shows, by header.
QStringList shownColumns( const ConversationTable* table )
{
    QStringList headers;
    for ( int column = 0; column < ConversationModel::ColumnCount; ++column ) {
        if ( !table->view()->isColumnHidden( column ) ) {
            headers << table->model()->headerData( column, Qt::Horizontal ).toString();
        }
    }
    return headers;
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
            clickOn( loaded.table->view(), model->index( 1, 0 ) );

            THEN( "it is selected, and nothing opens; the tooltip says how to filter" )
            {
                REQUIRE( loaded.table->view()->toolTip().contains( "Double-click" ) );
                REQUIRE( loaded.table->view()->toolTip().contains( "Enter" ) );
                REQUIRE( loaded.table->view()->currentIndex().row() == 1 );
                REQUIRE( loaded.table->view()->selectionModel()->isRowSelected( 1 ) );
                REQUIRE( loaded.host.regexLabs.isEmpty() );
                REQUIRE( loaded.host.notifications.isEmpty() );
            }

            AND_WHEN( "presses Enter" )
            {
                press( loaded.table->view(), Qt::Key_Return );

                THEN( "the Regex Lab opens on the selected conversation" )
                {
                    REQUIRE( loaded.host.regexLabs.size() == 1 );
                    const auto* selected = model->conversationAt( 1 );
                    REQUIRE( loaded.host.regexLabs.first().pattern
                             == tcpdump::conversationPattern(
                                 selected->stream, QString::fromStdString( selected->addressA ),
                                 selected->portA, QString::fromStdString( selected->addressB ),
                                 selected->portB ) );
                }
            }
        }

        WHEN( "the user double-clicks a conversation" )
        {
            loaded.table->view()->sortByColumn( ConversationModel::BytesColumn,
                                                Qt::DescendingOrder );
            // The SOCKS stream from 50003, the biggest after TCP 6.
            const auto* socks = model->conversationAt( 1 );
            REQUIRE( socks->stream == 4 );
            clickOn( loaded.table->view(), model->index( 1, 3 ), true );

            THEN( "the Regex Lab opens with the pattern of its lines, matching case" )
            {
                REQUIRE( loaded.host.regexLabs.size() == 1 );
                const auto& lab = loaded.host.regexLabs.first();
                REQUIRE( lab.pattern
                         == tcpdump::conversationPattern( 4, "192.168.1.1", 50003, "192.168.1.2",
                                                          1080 ) );
                REQUIRE( lab.flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( loaded.matched( lab.pattern ) == std::set<int>{ 12, 14, 15 } );
                REQUIRE( loaded.host.logs.contains( "Filter conversation in Regex Lab: "
                                                    + lab.pattern ) );
            }
        }

        WHEN( "the user chooses Filter conversation in Regex Lab for a UDP stream" )
        {
            const auto row = model->rowOf( Transport::Udp, 0 );
            loaded.table->view()->setCurrentIndex( model->index( row, 0 ) );
            auto* action = loaded.table->findChild<QAction*>( "filterOnConversation" );
            REQUIRE( action->text() == "Filter conversation in Regex Lab" );
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
            tcpdump::g_state.sessions->catalog().updateSummary( loaded.text, summary );

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
            tcpdump::g_state.sessions->catalog().updateSummary( loaded.text, summary );

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
            clickOn( loaded.table->view(), model->index( 2, 0 ) );

            THEN( "it is selected, and nothing opens or notifies" )
            {
                REQUIRE( loaded.table->view()->currentIndex().row() == 2 );
                REQUIRE( loaded.host.regexLabs.isEmpty() );
                REQUIRE( loaded.host.notifications.isEmpty() );
            }
        }

        WHEN( "the user double-clicks the other streams' row" )
        {
            clickOn( loaded.table->view(), model->index( 2, 0 ), true );

            THEN( "no Lab opens, and a notification named as the entry says why" )
            {
                REQUIRE( loaded.host.regexLabs.isEmpty() );
                REQUIRE( loaded.host.notifications.size() == 1 );
                REQUIRE( loaded.host.notifications.first().startsWith(
                    "Filter conversation in Regex Lab: " ) );
                REQUIRE( loaded.host.notifications.first().contains( "stream cap" ) );
            }
        }
    }

    GIVEN( "a capture converted on a host without the Regex Lab" )
    {
        LoadedCapture loaded( kMixed, {}, LOGSQUIRL_HOST_API_BASE_SIZE );

        WHEN( "the user double-clicks a conversation" )
        {
            clickOn( loaded.table->view(), loaded.model->index( 0, 0 ), true );

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

SCENARIO( "The Conversations table shows the columns the user chose, also after a restart",
          "[conversations]" )
{
    GIVEN( "the plugin loaded with no column choice saved" )
    {
        QTemporaryDir tempRoot;
        REQUIRE( tempRoot.isValid() );
        tcpdump::g_state.tempRoot = tempRoot.path();
        FakeHost host;
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        const auto table
            = [] { return tcpdump::g_state.sidebarWidget->packetPanel()->conversationTable(); };
        const QStringList defaults{ "Stream", "Protocol", "Address A", "Port A",    "Address B",
                                    "Port B", "Packets",  "Bytes",     "Rel Start", "Duration" };

        THEN( "the per-direction columns are hidden, the others shown" )
        {
            REQUIRE( shownColumns( table() ) == defaults );
        }

        THEN( "the header's context menu lists every column, checked if shown" )
        {
            auto* header = table()->view()->horizontalHeader();
            REQUIRE( header->contextMenuPolicy() == Qt::ActionsContextMenu );
            REQUIRE( header->actions().size() == ConversationModel::ColumnCount );
            for ( int column = 0; column < ConversationModel::ColumnCount; ++column ) {
                const auto name = table()->model()->headerData( column, Qt::Horizontal ).toString();
                INFO( name.toStdString() );
                auto* entry = columnEntry( table(), name );
                REQUIRE( entry );
                REQUIRE( entry->isCheckable() );
                REQUIRE( entry->isChecked() == !table()->view()->isColumnHidden( column ) );
            }
        }

        WHEN( "the user shows Bytes A→B and hides Port A from the header's menu" )
        {
            columnEntry( table(), "Bytes A→B" )->trigger();
            columnEntry( table(), "Port A" )->trigger();
            auto chosen = defaults;
            chosen.removeOne( "Port A" );
            chosen.insert( chosen.indexOf( "Rel Start" ), "Bytes A→B" );

            THEN( "the table shows those columns, the entries checked to match" )
            {
                REQUIRE( shownColumns( table() ) == chosen );
                REQUIRE( columnEntry( table(), "Bytes A→B" )->isChecked() );
                REQUIRE_FALSE( columnEntry( table(), "Port A" )->isChecked() );
            }

            AND_WHEN( "LogSquirl is restarted" )
            {
                logsquirl_plugin_shutdown();
                REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

                THEN( "the table shows the columns chosen" )
                {
                    REQUIRE( shownColumns( table() ) == chosen );
                    REQUIRE_FALSE( columnEntry( table(), "Port A" )->isChecked() );
                }
            }
        }

        WHEN( "the user hides all columns but one" )
        {
            for ( const auto& name : defaults.mid( 1 ) ) {
                columnEntry( table(), name )->trigger();
            }

            THEN( "its entry is disabled, so that the header stays to bring the others back" )
            {
                REQUIRE( shownColumns( table() ) == QStringList{ "Stream" } );
                REQUIRE_FALSE( columnEntry( table(), "Stream" )->isEnabled() );
                REQUIRE( columnEntry( table(), "Port A" )->isEnabled() );
            }

            AND_WHEN( "shows another again" )
            {
                columnEntry( table(), "Port A" )->trigger();

                THEN( "the entry can be unchecked again" )
                {
                    REQUIRE( columnEntry( table(), "Stream" )->isEnabled() );
                }
            }
        }

        logsquirl_plugin_shutdown();
    }

    GIVEN( "a settings file with an unknown column among the hidden ones" )
    {
        QTemporaryDir tempRoot;
        REQUIRE( tempRoot.isValid() );
        tcpdump::g_state.tempRoot = tempRoot.path();
        FakeHost host;
        QSettings file( tcpdump::settingsFilePath( host.configDir() ), QSettings::IniFormat );
        file.setValue( "conversations/hiddenColumns", QStringList{ "duration", "nonsense" } );
        file.sync();

        WHEN( "the plugin is loaded" )
        {
            REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
            auto* loaded = tcpdump::g_state.sidebarWidget->packetPanel()->conversationTable();

            THEN( "the known columns are hidden, the unknown ignored, the others shown" )
            {
                REQUIRE( loaded->view()->isColumnHidden( ConversationModel::DurationColumn ) );
                REQUIRE_FALSE(
                    loaded->view()->isColumnHidden( ConversationModel::BytesAToBColumn ) );
                REQUIRE( shownColumns( loaded ).size() == ConversationModel::ColumnCount - 1 );
            }

            logsquirl_plugin_shutdown();
        }
    }
}
