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
 * @file export_dialog.cpp
 * @brief Implementation of the Export packets dialog.
 */

#include "export_dialog.h"

#include "logsquirl_plugin_api.h"

#include <QDialogButtonBox>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>

namespace tcpdump {

ExportDialog::ExportDialog( const ExportRequest& request, QWidget* parent )
    : QDialog( parent )
    , packets_( request.packets )
{
    setWindowTitle( QStringLiteral( "Export Packets" ) );
    auto* layout = new QVBoxLayout( this );

    auto* intro = new QLabel(
        QStringLiteral( "Packets of %1 to export, as they are in it, to a new %2 file: numbers "
                        "and ranges, or packet lines copied in LogSquirl and pasted here." )
            .arg( request.captureName, request.format == CaptureFormat::Pcapng
                                           ? QStringLiteral( "pcapng" )
                                           : QStringLiteral( "pcap" ) ) );
    intro->setTextFormat( Qt::PlainText );
    intro->setWordWrap( true );
    layout->addWidget( intro );

    if ( request.truncated ) {
        auto* truncated = new QLabel(
            QStringLiteral( "<b>LogSquirl told only the first %1 selected lines</b> (at most %2 "
                            "lines or 1 MiB). To export more, such as all lines of a Filtered "
                            "View, copy them there and paste them here." )
                .arg( request.selectedLines )
                .arg( LOGSQUIRL_SELECTED_LOG_LINES_MAX_LINES ) );
        truncated->setObjectName( "truncatedNote" );
        truncated->setWordWrap( true );
        layout->addWidget( truncated );
    }

    text_ = new QPlainTextEdit( formatPacketRanges( request.numbers ) );
    text_->setObjectName( "packets" );
    layout->addWidget( text_, 1 );

    count_ = new QLabel;
    count_->setObjectName( "packetCount" );
    layout->addWidget( count_ );

    auto* buttons = new QDialogButtonBox( QDialogButtonBox::Cancel );
    exportButton_ = buttons->addButton( QStringLiteral( "Export\xe2\x80\xa6" ),
                                        QDialogButtonBox::AcceptRole );
    exportButton_->setObjectName( "exportButton" );
    layout->addWidget( buttons );
    connect( buttons, &QDialogButtonBox::accepted, this, &QDialog::accept );
    connect( buttons, &QDialogButtonBox::rejected, this, &QDialog::reject );
    updateTimer_ = new QTimer( this );
    updateTimer_->setSingleShot( true );
    updateTimer_->setInterval( kUpdateDelayMs );
    connect( updateTimer_, &QTimer::timeout, this, &ExportDialog::update );
    connect( text_, &QPlainTextEdit::textChanged, this, [ this ] {
        exportButton_->setEnabled( false ); // until the text is read again
        updateTimer_->start();
    } );

    update();
}

void ExportDialog::setText( const QString& text )
{
    text_->setPlainText( text );
    update();
}

const PacketSet& ExportDialog::packetSet()
{
    if ( updateTimer_->isActive() ) {
        update();
    }
    return set_;
}

void ExportDialog::update()
{
    updateTimer_->stop();
    set_ = parsePacketSet( text_->toPlainText(), packets_ );
    const auto packets = set_.numbers.count();
    auto count = packets == 1 ? QStringLiteral( "1 packet" )
                              : QStringLiteral( "%1 packets" ).arg( packets );
    if ( set_.skipped > 0 ) {
        count += QStringLiteral( "; %1 skipped that name no packet of the capture" )
                     .arg( set_.skipped );
    }
    count_->setText( count );
    exportButton_->setEnabled( !set_.numbers.empty() );
}

} // namespace tcpdump
