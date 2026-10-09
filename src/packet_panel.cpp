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
 * @file packet_panel.cpp
 * @brief The Packet Panel: selection polling, layer tree and hex dump.
 */

#include "packet_panel.h"

#include "conversation_table.h"
#include "plugin.h"
#include "regex_lab.h"

#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QPlainTextEdit>
#include <QSplitter>
#include <QTextCursor>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <exception>

namespace tcpdump {

namespace {

constexpr size_t kBytesPerLine = 16;
/// Characters of a line's hex: 16 bytes of "xx ", one more space after 8, no trailing one.
constexpr int kHexWidth = 16 * 3;
constexpr int kOffsetGap = 2; ///< Between the offset and the hex.
constexpr int kAsciiGap = 3;  ///< Between the hex and the ASCII.

/// The tree item's roles holding the bytes of its layer or field.
constexpr int kOffsetRole = Qt::UserRole;
constexpr int kLengthRole = Qt::UserRole + 1;

/// Hex digits of the offset column for a dump of @p total bytes: 4 at least.
int offsetWidth( size_t total )
{
    int digits = 4;
    for ( size_t limit = 0x10000; total > limit && digits < 16; limit <<= 4 ) {
        ++digits;
    }
    return digits;
}

/// Where the hex of byte @p column (0–15) of a line starts on it.
int hexColumn( int width, size_t column )
{
    return width + kOffsetGap + static_cast<int>( column ) * 3 + ( column >= 8 ? 1 : 0 );
}

/// Where the ASCII of byte @p column of a line starts on it.
int asciiColumn( int width, size_t column )
{
    return width + kOffsetGap + kHexWidth + kAsciiGap + static_cast<int>( column );
}

/// The characters of a full line, its newline included.
int lineLength( int width )
{
    return asciiColumn( width, kBytesPerLine ) + 1;
}

/// What get_selected_log_lines()'s failure @p result means, for the user.
QString selectionProblem( int result )
{
    switch ( result ) {
    case LOGSQUIRL_LOG_LINES_NO_SELECTION:
        return QStringLiteral( "Select a packet line to see its packet." );
    case LOGSQUIRL_LOG_LINES_NO_LOG_FILE:
        return QStringLiteral( "The tab in front shows no capture." );
    default:
        return QStringLiteral( "LogSquirl did not tell the selected line (%1)." ).arg( result );
    }
}

} // namespace

QString hexDump( const std::vector<uint8_t>& bytes )
{
    static const char* const kDigits = "0123456789abcdef";
    const int width = offsetWidth( bytes.size() );
    QString dump;
    dump.reserve(
        static_cast<qsizetype>( ( bytes.size() / kBytesPerLine + 1 ) * lineLength( width ) ) );
    for ( size_t line = 0; line < bytes.size(); line += kBytesPerLine ) {
        const auto count = std::min( kBytesPerLine, bytes.size() - line );
        QString text( lineLength( width ) - 1, QLatin1Char( ' ' ) );
        const auto offset = QString::number( static_cast<qulonglong>( line ), 16 )
                                .rightJustified( width, QLatin1Char( '0' ) );
        text.replace( 0, width, offset );
        for ( size_t i = 0; i < count; ++i ) {
            const auto byte = bytes[ line + i ];
            text[ hexColumn( width, i ) ] = QLatin1Char( kDigits[ byte >> 4 ] );
            text[ hexColumn( width, i ) + 1 ] = QLatin1Char( kDigits[ byte & 0x0F ] );
            text[ asciiColumn( width, i ) ] = byte >= 0x20 && byte < 0x7F
                                                  ? QLatin1Char( static_cast<char>( byte ) )
                                                  : QLatin1Char( '.' );
        }
        text.truncate( asciiColumn( width, count ) );
        if ( !dump.isEmpty() ) {
            dump += QLatin1Char( '\n' );
        }
        dump += text;
    }
    return dump;
}

std::vector<std::pair<int, int>> hexDumpRanges( size_t total, size_t offset, size_t length )
{
    std::vector<std::pair<int, int>> ranges;
    const auto end = std::min( total, offset + length );
    const int width = offsetWidth( total );
    for ( size_t at = offset; at < end; ) {
        const auto line = at / kBytesPerLine;
        const auto first = at % kBytesPerLine;
        const auto last = std::min( kBytesPerLine, end - line * kBytesPerLine ) - 1;
        const int start = static_cast<int>( line ) * lineLength( width );
        ranges.emplace_back( start + hexColumn( width, first ),
                             hexColumn( width, last ) + 2 - hexColumn( width, first ) );
        ranges.emplace_back( start + asciiColumn( width, first ),
                             static_cast<int>( last - first + 1 ) );
        at = ( line + 1 ) * kBytesPerLine;
    }
    return ranges;
}

PacketPanel::PacketPanel( QWidget* parent )
    : QWidget( parent )
{
    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    layout->setSpacing( 4 );

    auto* title = new QLabel( "<b>Packet</b>" );
    layout->addWidget( title );

    status_ = new QLabel;
    status_->setObjectName( "packetStatus" );
    status_->setWordWrap( true );
    status_->setTextFormat( Qt::PlainText );
    layout->addWidget( status_ );

    auto* splitter = new QSplitter( Qt::Vertical );
    tree_ = new QTreeWidget;
    tree_->setObjectName( "packetLayers" );
    tree_->setHeaderHidden( true );
    tree_->setColumnCount( 1 );
    tree_->header()->setStretchLastSection( true );
    splitter->addWidget( tree_ );

    dump_ = new QPlainTextEdit;
    dump_->setObjectName( "packetBytes" );
    dump_->setReadOnly( true );
    dump_->setLineWrapMode( QPlainTextEdit::NoWrap );
    dump_->setFont( QFontDatabase::systemFont( QFontDatabase::FixedFont ) );
    splitter->addWidget( dump_ );

    conversations_ = new ConversationTable;
    conversations_->setObjectName( "conversationTable" );
    splitter->addWidget( conversations_ );
    layout->addWidget( splitter, 1 );

    connect( tree_, &QTreeWidget::currentItemChanged, this,
             [ this ]( QTreeWidgetItem* item ) { highlight( item ); } );

    timer_.setInterval( kPollIntervalMs );
    connect( &timer_, &QTimer::timeout, this, [ this ] {
        try {
            poll();
        } catch ( const std::exception& e ) {
            // An exception must not escape into Qt or the host.
            timer_.stop();
            hostLog( LOGSQUIRL_LOG_ERROR,
                     "The Packet Panel stopped: " + QString::fromUtf8( e.what() ) );
        }
    } );

    showReason( QStringLiteral( "No capture in this tab." ) );
}

PacketPanel::~PacketPanel() = default;

QString PacketPanel::statusText() const
{
    return status_->text();
}

void PacketPanel::setCapture( std::shared_ptr<const CaptureIndex> index )
{
    if ( index == index_ ) {
        return;
    }
    index_ = std::move( index );
    cursor_.reset();
    haveLast_ = false;
    if ( !index_ ) {
        showReason( QStringLiteral( "No capture in this tab." ) );
        return;
    }
    if ( isVisible() ) {
        poll();
    }
    else {
        showReason( QStringLiteral( "Select a packet line to see its packet." ) );
    }
}

void PacketPanel::refresh()
{
    poll( true );
}

void PacketPanel::showEvent( QShowEvent* event )
{
    QWidget::showEvent( event );
    // The selection may have changed while the panel was hidden.
    if ( g_state.hostCapabilities.selectedLogLines ) {
        timer_.start();
    }
    poll();
}

void PacketPanel::hideEvent( QHideEvent* event )
{
    QWidget::hideEvent( event );
    timer_.stop();
}

void PacketPanel::poll( bool force )
{
    const auto& st = g_state;
    if ( !index_ ) {
        showReason( QStringLiteral( "No capture in this tab." ) );
        return;
    }
    if ( !st.api || !st.handle || !st.hostCapabilities.selectedLogLines ) {
        showReason( QStringLiteral( "The Packet Panel needs LogSquirl 26.11 or later, which "
                                    "tells the selected line." ) );
        return;
    }

    const char* text = nullptr;
    size_t length = 0;
    const int result = st.api->get_selected_log_lines( st.handle, &text, &length, nullptr );
    const QByteArray selection
        = result >= 0 && text ? QByteArray( text, static_cast<qsizetype>( length ) ) : QByteArray();
    if ( !force && haveLast_ && result == lastResult_ && selection == lastSelection_ ) {
        return; // nothing changed
    }
    haveLast_ = true;
    lastResult_ = result;
    lastSelection_ = selection;

    if ( result < 0 || !text ) {
        showReason( selectionProblem( result ) );
        return;
    }
    showSelection( QString::fromUtf8( selection ) );
}

void PacketPanel::showSelection( const QString& selection )
{
    // The first selected line is the one shown.
    const auto line = selection.section( '\n', 0, 0 );
    const auto match = packetLineRegex().match( line );
    if ( !match.hasMatch() ) {
        showReason( QStringLiteral( "The selected line is not a packet line of a capture." ) );
        return;
    }
    bool ok = false;
    const auto number = match.captured( "number" ).toUInt( &ok );
    if ( !ok || number == 0 ) {
        showReason( QStringLiteral( "The selected line has no packet number." ) );
        return;
    }
    showPacket( number );
}

void PacketPanel::showPacket( uint32_t number )
{
    if ( !cursor_ ) {
        cursor_ = std::make_unique<CaptureCursor>( index_ );
    }
    CapturedPacket packet;
    if ( !cursor_->read( number, packet ) ) {
        showReason( QStringLiteral( "Packet %1: %2" ).arg( number ).arg( cursor_->error() ) );
        return;
    }

    layers_ = dissectLayers( packet.record, packet.bytes.data(), packet.bytes.size(),
                             packet.byteSwapped );
    shownPacket_ = number;
    shownBytes_ = packet.bytes.size();
    auto status = QStringLiteral( "Packet %1" ).arg( number );
    if ( packet.record.capturedLen > packet.bytes.size() ) {
        status += QStringLiteral( " (the first %1 bytes)" ).arg( packet.bytes.size() );
    }
    status_->setText( status );

    tree_->clear();
    for ( const auto& layer : layers_ ) {
        auto* layerItem = new QTreeWidgetItem( tree_, { QString::fromStdString( layer.name ) } );
        layerItem->setData( 0, kOffsetRole, static_cast<qulonglong>( layer.offset ) );
        layerItem->setData( 0, kLengthRole, static_cast<qulonglong>( layer.length ) );
        for ( const auto& field : layer.fields ) {
            auto* fieldItem = new QTreeWidgetItem(
                layerItem, { QString::fromStdString( field.name + ": " + field.value ) } );
            fieldItem->setData( 0, kOffsetRole, static_cast<qulonglong>( field.offset ) );
            fieldItem->setData( 0, kLengthRole, static_cast<qulonglong>( field.length ) );
        }
    }
    // The frame stays collapsed, the headers in it open.
    for ( int i = 1; i < tree_->topLevelItemCount(); ++i ) {
        tree_->topLevelItem( i )->setExpanded( true );
    }
    dump_->setPlainText( hexDump( packet.bytes ) );
    highlight( nullptr );
}

void PacketPanel::showReason( const QString& reason )
{
    shownPacket_ = 0;
    shownBytes_ = 0;
    layers_.clear();
    status_->setText( reason );
    tree_->clear();
    dump_->clear();
}

void PacketPanel::highlight( QTreeWidgetItem* item )
{
    QList<QTextEdit::ExtraSelection> selections;
    if ( item ) {
        const auto offset = static_cast<size_t>( item->data( 0, kOffsetRole ).toULongLong() );
        const auto length = static_cast<size_t>( item->data( 0, kLengthRole ).toULongLong() );
        QTextCharFormat format;
        format.setBackground( palette().highlight() );
        format.setForeground( palette().highlightedText() );
        bool first = true;
        for ( const auto& [ start, count ] : hexDumpRanges( shownBytes_, offset, length ) ) {
            QTextEdit::ExtraSelection selection;
            selection.cursor = QTextCursor( dump_->document() );
            selection.cursor.setPosition( start );
            selection.cursor.setPosition( start + count, QTextCursor::KeepAnchor );
            selection.format = format;
            selections << selection;
            if ( first ) {
                // Bring the first highlighted line into view.
                auto cursor = dump_->textCursor();
                cursor.setPosition( start );
                dump_->setTextCursor( cursor );
                dump_->ensureCursorVisible();
                first = false;
            }
        }
    }
    dump_->setExtraSelections( selections );
}

} // namespace tcpdump
