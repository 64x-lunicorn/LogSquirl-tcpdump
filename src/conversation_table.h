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
 * @file conversation_table.h
 * @brief The Conversations table of the Packet Panel, as Wireshark's
 *        Statistics > Conversations shows it.
 *
 * A row per numbered TCP and UDP stream of the capture in front, from its
 * Capture Summary, sortable by every column.  A click on a row, or Filter
 * on this conversation in its context menu, opens the Regex Lab with the
 * pattern of the stream's lines, as the summary's endpoints do.  A summary
 * taken anew (a live capture's next snapshot) replaces the rows and keeps
 * the sort and the selected conversation.
 */

#pragma once

#include "conversations.h"
#include "pcap_converter.h"

#include <QAbstractTableModel>
#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

class QAction;
class QLabel;
class QTableView;

namespace tcpdump {

/// The rows of the Conversations table, sorted; the streams past the stream
/// cap, if any, as one last row, whatever the sort.
class ConversationModel : public QAbstractTableModel {
    Q_OBJECT

public:
    enum Column {
        StreamColumn, ///< "TCP 3": the transport and the Stream column.
        ProtocolColumn,
        AddressAColumn,
        PortAColumn,
        AddressBColumn,
        PortBColumn,
        PacketsColumn, ///< Both ways.
        BytesColumn,
        PacketsAToBColumn,
        BytesAToBColumn,
        PacketsBToAColumn,
        BytesBToAColumn,
        StartColumn, ///< Seconds after the capture's first packet.
        DurationColumn,
        ColumnCount
    };

    explicit ConversationModel( QObject* parent = nullptr );

    /// Show @p rows, and @p otherPackets and @p otherBytes of the streams
    /// past the cap as one more row unless there are none; sorted as before.
    void setConversations( std::shared_ptr<const std::vector<Conversation>> rows,
                           uint64_t otherPackets, uint64_t otherBytes );

    /// The rows shown.
    const std::shared_ptr<const std::vector<Conversation>>& conversations() const
    {
        return rows_;
    }

    /// The conversation of table row @p row; null for the other streams' row.
    const Conversation* conversationAt( int row ) const;

    /// The table row of the conversation of stream @p stream of
    /// @p transport, or -1.
    int rowOf( Transport transport, int stream ) const;

    int rowCount( const QModelIndex& parent = {} ) const override;
    int columnCount( const QModelIndex& parent = {} ) const override;
    QVariant data( const QModelIndex& index, int role = Qt::DisplayRole ) const override;
    QVariant headerData( int section, Qt::Orientation orientation,
                         int role = Qt::DisplayRole ) const override;
    void sort( int column, Qt::SortOrder order = Qt::AscendingOrder ) override;

private:
    /// Order order_ by sortColumn_ and sortOrder_.
    void applySort();

    std::shared_ptr<const std::vector<Conversation>> rows_;
    /// Indexes into rows_, in the order shown.
    std::vector<uint32_t> order_;
    uint64_t otherPackets_ = 0;
    uint64_t otherBytes_ = 0;
    int sortColumn_ = StreamColumn;
    Qt::SortOrder sortOrder_ = Qt::AscendingOrder;
};

/// The Conversations table and its title, in the Packet Panel.
class ConversationTable : public QWidget {
    Q_OBJECT

public:
    explicit ConversationTable( QWidget* parent = nullptr );

    /// Show the conversations of @p summary, the capture's in front; null
    /// for a tab that holds no capture of the plugin.  The same table again
    /// changes nothing; a new one keeps the sort and the selection.
    void setSummary( const CaptureSummary* summary );

    /// Open the Regex Lab with the pattern of table row @p row's lines.
    void filterOn( int row );

    ConversationModel* model() const
    {
        return model_;
    }

    QTableView* view() const
    {
        return view_;
    }

private:
    QLabel* title_ = nullptr;
    QTableView* view_ = nullptr;
    ConversationModel* model_ = nullptr;
    QAction* filterAction_ = nullptr;
};

} // namespace tcpdump
