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
 * @file conversation_table.cpp
 * @brief The Conversations table: its model, sorting and filters.
 */

#include "conversation_table.h"

#include "follow_stream.h"
#include "plugin.h"
#include "regex_lab.h"

#include <QAction>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QTableView>
#include <QVBoxLayout>

#include <algorithm>
#include <exception>
#include <tuple>

namespace tcpdump {

namespace {

const char* const kHeaders[ ConversationModel::ColumnCount ] = {
    "Stream", "Protocol",    "Address A", "Port A",      "Address B", "Port B",    "Packets",
    "Bytes",  "Packets A→B", "Bytes A→B", "Packets B→A", "Bytes B→A", "Rel Start", "Duration",
};

QString transportName( Transport transport )
{
    return transport == Transport::Tcp ? QStringLiteral( "TCP" ) : QStringLiteral( "UDP" );
}

/// Whether @p a comes before @p b by @p column, ascending; ties by stream.
bool before( const Conversation& a, const Conversation& b, int column )
{
    const auto byStream
        = [ & ] { return std::tie( a.transport, a.stream ) < std::tie( b.transport, b.stream ); };
    const auto compare = [ & ]( const auto& x, const auto& y ) {
        return x < y ? true : y < x ? false : byStream();
    };
    switch ( column ) {
    case ConversationModel::ProtocolColumn:
        return compare( a.protocol, b.protocol );
    case ConversationModel::AddressAColumn:
        return compare( a.addressA, b.addressA );
    case ConversationModel::PortAColumn:
        return compare( a.portA, b.portA );
    case ConversationModel::AddressBColumn:
        return compare( a.addressB, b.addressB );
    case ConversationModel::PortBColumn:
        return compare( a.portB, b.portB );
    case ConversationModel::PacketsColumn:
        return compare( a.packetsAToB + a.packetsBToA, b.packetsAToB + b.packetsBToA );
    case ConversationModel::BytesColumn:
        return compare( a.bytesAToB + a.bytesBToA, b.bytesAToB + b.bytesBToA );
    case ConversationModel::PacketsAToBColumn:
        return compare( a.packetsAToB, b.packetsAToB );
    case ConversationModel::BytesAToBColumn:
        return compare( a.bytesAToB, b.bytesAToB );
    case ConversationModel::PacketsBToAColumn:
        return compare( a.packetsBToA, b.packetsBToA );
    case ConversationModel::BytesBToAColumn:
        return compare( a.bytesBToA, b.bytesBToA );
    case ConversationModel::StartColumn:
        return compare( a.startSeconds, b.startSeconds );
    case ConversationModel::DurationColumn:
        return compare( a.durationSeconds, b.durationSeconds );
    default:
        return byStream();
    }
}

/// The text of @p column of @p row.
QVariant cell( const Conversation& row, int column )
{
    switch ( column ) {
    case ConversationModel::StreamColumn:
        return QStringLiteral( "%1 %2" ).arg( transportName( row.transport ) ).arg( row.stream );
    case ConversationModel::ProtocolColumn:
        return QString::fromStdString( row.protocol );
    case ConversationModel::AddressAColumn:
        return QString::fromStdString( row.addressA );
    case ConversationModel::PortAColumn:
        return row.portA;
    case ConversationModel::AddressBColumn:
        return QString::fromStdString( row.addressB );
    case ConversationModel::PortBColumn:
        return row.portB;
    case ConversationModel::PacketsColumn:
        return static_cast<qulonglong>( row.packetsAToB + row.packetsBToA );
    case ConversationModel::BytesColumn:
        return static_cast<qulonglong>( row.bytesAToB + row.bytesBToA );
    case ConversationModel::PacketsAToBColumn:
        return static_cast<qulonglong>( row.packetsAToB );
    case ConversationModel::BytesAToBColumn:
        return static_cast<qulonglong>( row.bytesAToB );
    case ConversationModel::PacketsBToAColumn:
        return static_cast<qulonglong>( row.packetsBToA );
    case ConversationModel::BytesBToAColumn:
        return static_cast<qulonglong>( row.bytesBToA );
    case ConversationModel::StartColumn:
        return QString::number( row.startSeconds, 'f', 6 );
    case ConversationModel::DurationColumn:
        return QString::number( row.durationSeconds, 'f', 6 );
    default:
        return {};
    }
}

bool isNumeric( int column )
{
    return column == ConversationModel::PortAColumn || column == ConversationModel::PortBColumn
           || column >= ConversationModel::PacketsColumn;
}

} // namespace

ConversationModel::ConversationModel( QObject* parent )
    : QAbstractTableModel( parent )
{
}

void ConversationModel::setConversations( std::shared_ptr<const ConversationRows> rows,
                                          uint64_t otherPackets, uint64_t otherBytes )
{
    beginResetModel();
    rows_ = std::move( rows );
    otherPackets_ = otherPackets;
    otherBytes_ = otherBytes;
    order_.clear();
    if ( rows_ ) {
        order_.reserve( rows_->size() );
        for ( const auto& chunk : rows_->chunks() ) {
            for ( const auto& row : *chunk ) {
                order_.push_back( &row );
            }
        }
        applySort();
    }
    endResetModel();
}

const Conversation* ConversationModel::conversationAt( int row ) const
{
    if ( row < 0 || static_cast<size_t>( row ) >= order_.size() ) {
        return nullptr;
    }
    return order_[ static_cast<size_t>( row ) ];
}

int ConversationModel::rowOf( Transport transport, int stream ) const
{
    for ( size_t row = 0; row < order_.size(); ++row ) {
        const auto& conversation = *order_[ row ];
        if ( conversation.transport == transport && conversation.stream == stream ) {
            return static_cast<int>( row );
        }
    }
    return -1;
}

int ConversationModel::rowCount( const QModelIndex& parent ) const
{
    if ( parent.isValid() ) {
        return 0;
    }
    return static_cast<int>( order_.size() ) + ( otherPackets_ > 0 ? 1 : 0 );
}

int ConversationModel::columnCount( const QModelIndex& parent ) const
{
    return parent.isValid() ? 0 : ColumnCount;
}

QVariant ConversationModel::data( const QModelIndex& index, int role ) const
{
    if ( !index.isValid() ) {
        return {};
    }
    const auto column = index.column();
    if ( role == Qt::TextAlignmentRole ) {
        return QVariant::fromValue( isNumeric( column ) ? Qt::AlignRight | Qt::AlignVCenter
                                                        : Qt::AlignLeft | Qt::AlignVCenter );
    }
    if ( role != Qt::DisplayRole && role != Qt::ToolTipRole ) {
        return {};
    }
    if ( const auto* conversation = conversationAt( index.row() ) ) {
        return cell( *conversation, column );
    }
    // The streams past the cap, which show stream "?" in the log.
    switch ( column ) {
    case StreamColumn:
        return QStringLiteral( "?" );
    case ProtocolColumn:
        return role == Qt::ToolTipRole
                   ? QStringLiteral( "The conversations past the stream cap, all together" )
                   : QStringLiteral( "Other streams" );
    case PacketsColumn:
        return static_cast<qulonglong>( otherPackets_ );
    case BytesColumn:
        return static_cast<qulonglong>( otherBytes_ );
    default:
        return {};
    }
}

QVariant ConversationModel::headerData( int section, Qt::Orientation orientation, int role ) const
{
    if ( orientation != Qt::Horizontal || role != Qt::DisplayRole || section < 0
         || section >= ColumnCount ) {
        return {};
    }
    return QString::fromUtf8( kHeaders[ section ] );
}

void ConversationModel::sort( int column, Qt::SortOrder order )
{
    if ( column < 0 || column >= ColumnCount ) {
        return;
    }
    emit layoutAboutToBeChanged( {}, QAbstractItemModel::VerticalSortHint );
    const auto before = persistentIndexList();
    std::vector<std::pair<const Conversation*, int>> kept;
    for ( const auto& index : before ) {
        kept.emplace_back( conversationAt( index.row() ), index.column() );
    }
    sortColumn_ = column;
    sortOrder_ = order;
    applySort();
    // Each persistent index (the selection, the current row) follows its row.
    QModelIndexList after;
    for ( size_t i = 0; i < kept.size(); ++i ) {
        const auto* conversation = kept[ i ].first;
        const auto row = conversation ? rowOf( conversation->transport, conversation->stream )
                                      : before[ static_cast<qsizetype>( i ) ].row();
        after << createIndex( row, kept[ i ].second );
    }
    changePersistentIndexList( before, after );
    emit layoutChanged( {}, QAbstractItemModel::VerticalSortHint );
}

void ConversationModel::applySort()
{
    if ( !rows_ ) {
        return;
    }
    const auto column = sortColumn_;
    if ( sortOrder_ == Qt::AscendingOrder ) {
        std::stable_sort( order_.begin(), order_.end(),
                          [ & ]( const Conversation* a, const Conversation* b ) {
                              return before( *a, *b, column );
                          } );
    }
    else {
        std::stable_sort( order_.begin(), order_.end(),
                          [ & ]( const Conversation* a, const Conversation* b ) {
                              return before( *b, *a, column );
                          } );
    }
}

ConversationTable::ConversationTable( QWidget* parent )
    : QWidget( parent )
{
    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    layout->setSpacing( 4 );

    title_ = new QLabel( "<b>Conversations</b>" );
    layout->addWidget( title_ );

    model_ = new ConversationModel( this );
    view_ = new QTableView;
    view_->setObjectName( "conversations" );
    view_->setModel( model_ );
    view_->setSortingEnabled( true );
    view_->sortByColumn( ConversationModel::StreamColumn, Qt::AscendingOrder );
    view_->setSelectionBehavior( QAbstractItemView::SelectRows );
    view_->setSelectionMode( QAbstractItemView::SingleSelection );
    view_->setEditTriggers( QAbstractItemView::NoEditTriggers );
    view_->verticalHeader()->hide();
    view_->horizontalHeader()->setStretchLastSection( true );
    view_->setWordWrap( false );
    layout->addWidget( view_, 1 );

    filterAction_ = new QAction( "Filter on this conversation", view_ );
    filterAction_->setObjectName( "filterOnConversation" );
    view_->addAction( filterAction_ );
    view_->setContextMenuPolicy( Qt::ActionsContextMenu );
    connect( filterAction_, &QAction::triggered, this,
             [ this ] { filterOn( view_->currentIndex().row() ); } );
    connect( view_, &QTableView::clicked, this,
             [ this ]( const QModelIndex& index ) { filterOn( index.row() ); } );

    setSummary( nullptr );
}

void ConversationTable::setSummary( const CaptureSummary* summary )
{
    const auto rows = summary ? summary->conversations : nullptr;
    const auto otherPackets = summary ? summary->otherStreamPackets : 0;
    const auto otherBytes = summary ? summary->otherStreamBytes : 0;
    if ( rows == model_->conversations() && rows ) {
        return; // the same snapshot: a tab that came back
    }

    // The conversation selected stays selected in the new snapshot.
    const auto* selected = model_->conversationAt( view_->currentIndex().row() );
    const auto keep = selected ? std::make_pair( selected->transport, selected->stream )
                               : std::make_pair( Transport::Tcp, -1 );
    model_->setConversations( rows, otherPackets, otherBytes );
    if ( keep.second >= 0 ) {
        const auto row = model_->rowOf( keep.first, keep.second );
        if ( row >= 0 ) {
            view_->setCurrentIndex( model_->index( row, 0 ) );
        }
    }

    const auto count = rows ? rows->size() : 0;
    title_->setText( summary ? QStringLiteral( "<b>Conversations</b> (%1)" ).arg( count )
                             : QStringLiteral( "<b>Conversations</b>" ) );
    const bool canFilter = g_state.hostCapabilities.regexLab;
    filterAction_->setEnabled( canFilter );
    view_->setToolTip( canFilter ? QStringLiteral( "Click a conversation to filter its lines in "
                                                   "the Regex Lab" )
                                 : QString() );
}

void ConversationTable::filterOn( int row )
{
    if ( row < 0 || row >= model_->rowCount() || !g_state.hostCapabilities.regexLab ) {
        return;
    }
    try {
        const auto* conversation = model_->conversationAt( row );
        if ( !conversation ) {
            hostNotify( "Filter: the streams past the stream cap show stream \"?\" and cannot "
                        "be told apart." );
            return;
        }
        openRegexLab( "Filter",
                      conversationPattern(
                          conversation->stream, QString::fromStdString( conversation->addressA ),
                          conversation->portA, QString::fromStdString( conversation->addressB ),
                          conversation->portB ) );
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog( LOGSQUIRL_LOG_ERROR,
                 "Filtering on a conversation failed: " + QString::fromUtf8( e.what() ) );
    }
}

} // namespace tcpdump
