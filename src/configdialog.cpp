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
 * @file configdialog.cpp
 * @brief Implementation of the configuration dialog.
 */

#include "configdialog.h"

#include "settings.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QVBoxLayout>

namespace tcpdump {

namespace {

/// A spin box for a count from @p min to @p max.
QSpinBox* countBox( const char* name, size_t min, size_t max )
{
    auto* box = new QSpinBox;
    box->setObjectName( name );
    box->setRange( static_cast<int>( min ), static_cast<int>( max ) );
    box->setGroupSeparatorShown( true );
    return box;
}

} // namespace

ConfigDialog::ConfigDialog( const ConversionOptions& options, QWidget* parent )
    : QDialog( parent )
{
    setWindowTitle( QStringLiteral( "tcpdump / pcap Viewer Options" ) );

    // Columns
    timeColumns_ = new QComboBox;
    timeColumns_->setObjectName( "timeColumns" );
    timeColumns_->addItem( QStringLiteral( "UTC time and time since the first packet" ),
                           static_cast<int>( TimeColumns::Both ) );
    timeColumns_->addItem( QStringLiteral( "UTC time only" ),
                           static_cast<int>( TimeColumns::AbsoluteOnly ) );
    timeColumns_->addItem( QStringLiteral( "Time since the first packet only" ),
                           static_cast<int>( TimeColumns::RelativeOnly ) );
    macColumns_ = new QCheckBox( QStringLiteral( "Show MAC addresses as columns" ) );
    macColumns_->setObjectName( "macColumns" );

    auto* columns = new QGroupBox( QStringLiteral( "Columns" ) );
    auto* columnsLayout = new QFormLayout( columns );
    columnsLayout->addRow( QStringLiteral( "Time:" ), timeColumns_ );
    columnsLayout->addRow( macColumns_ );
    auto* layoutNote = new QLabel( QStringLiteral(
        "<small>Other columns than the defaults change the line layout: highlighters and "
        "filters written for the default one may no longer match.</small>" ) );
    layoutNote->setWordWrap( true );
    columnsLayout->addRow( layoutNote );

    // Payload preview
    preview_ = new QCheckBox( QStringLiteral( "Preview payloads no protocol is recognised in" ) );
    preview_->setObjectName( "preview" );
    previewChars_ = countBox( "previewChars", 1, kMaxPreviewChars );
    previewChars_->setSuffix( QStringLiteral( " characters" ) );
    connect( preview_, &QCheckBox::toggled, previewChars_, &QSpinBox::setEnabled );
    tcpTimestamps_ = new QCheckBox(
        QStringLiteral( "Show TCP timestamps (TSval, TSecr) on every segment, not only on SYNs" ) );
    tcpTimestamps_->setObjectName( "tcpTimestamps" );

    auto* previewBox = new QGroupBox( QStringLiteral( "Info" ) );
    auto* previewLayout = new QFormLayout( previewBox );
    previewLayout->addRow( preview_ );
    previewLayout->addRow( QStringLiteral( "At most:" ), previewChars_ );
    previewLayout->addRow( tcpTimestamps_ );

    // TLS decryption
    keyLogPath_ = new QLineEdit;
    keyLogPath_->setObjectName( "keyLogPath" );
    keyLogPath_->setPlaceholderText( QStringLiteral( "No key log: TLS stays encrypted" ) );
    keyLogPath_->setClearButtonEnabled( true );
    auto* keyLogBrowse = new QPushButton( QStringLiteral( "Browse\u2026" ) );
    keyLogBrowse->setObjectName( "keyLogBrowse" );
    connect( keyLogBrowse, &QPushButton::clicked, this, [ this ] {
        const auto path = QFileDialog::getOpenFileName(
            this, QStringLiteral( "TLS Key Log File" ), keyLogPath_->text(),
            QStringLiteral( "Key log files (*.log *.txt *.keys *.keylog);;All files (*)" ) );
        if ( !path.isEmpty() ) {
            keyLogPath_->setText( path );
        }
    } );
    auto* keyLogRow = new QHBoxLayout;
    keyLogRow->addWidget( keyLogPath_ );
    keyLogRow->addWidget( keyLogBrowse );
    auto* tls = new QGroupBox( QStringLiteral( "TLS decryption" ) );
    auto* tlsLayout = new QFormLayout( tls );
    tlsLayout->addRow( QStringLiteral( "Key log file:" ), keyLogRow );
    auto* tlsNote = new QLabel( QStringLiteral(
        "<small>The file SSLKEYLOGFILE makes browsers, curl and OpenSSL write. Its secrets "
        "decrypt every session they belong to: keep it as private as the traffic itself. The "
        "plugin only reads it, while converting, and never shows or stores a secret.</small>" ) );
    tlsNote->setWordWrap( true );
    tlsLayout->addRow( tlsNote );

    // Memory caps
    maxStreams_ = countBox( "maxStreams", kMinCap, kMaxStreamCap );
    maxEndpoints_ = countBox( "maxEndpoints", kMinCap, kMaxEndpointCap );
    reassemblyMegabytes_ = countBox( "reassemblyMegabytes", kMinCap, kMaxReassemblyMegabytes );
    reassemblyMegabytes_->setSuffix( QStringLiteral( " MB" ) );
    auto* advanced = new QGroupBox( QStringLiteral( "Advanced" ) );
    auto* advancedLayout = new QFormLayout( advanced );
    advancedLayout->addRow( QStringLiteral( "Streams numbered at most:" ), maxStreams_ );
    advancedLayout->addRow( QStringLiteral( "Endpoints counted at most:" ), maxEndpoints_ );
    advancedLayout->addRow( QStringLiteral( "TCP reassembly memory at most:" ),
                            reassemblyMegabytes_ );
    auto* capsNote = new QLabel( QStringLiteral(
        "<small>The caps bound the memory a conversion takes; later streams show stream ?, "
        "later endpoints are counted together, and a message reassembly cannot hold is marked "
        "[reassembly limit].</small>" ) );
    capsNote->setWordWrap( true );
    advancedLayout->addRow( capsNote );

    // SOME/IP
    someIpPorts_ = new QLineEdit;
    someIpPorts_->setObjectName( "someIpPorts" );
    someIpPorts_->setPlaceholderText( QStringLiteral( "30501, 30502" ) );
    someIpNamesFile_ = new QLineEdit;
    someIpNamesFile_->setObjectName( "someIpNamesFile" );
    someIpNamesFile_->setPlaceholderText( QStringLiteral( "None" ) );
    auto* browse = new QPushButton( QStringLiteral( "Browse\u2026" ) );
    browse->setObjectName( "someIpNamesBrowse" );
    connect( browse, &QPushButton::clicked, this, [ this ] {
        const auto path = QFileDialog::getOpenFileName(
            this, QStringLiteral( "SOME/IP Name Table" ), someIpNamesFile_->text() );
        if ( !path.isEmpty() ) {
            someIpNamesFile_->setText( path );
        }
    } );
    auto* namesRow = new QHBoxLayout;
    namesRow->addWidget( someIpNamesFile_ );
    namesRow->addWidget( browse );
    auto* someIp = new QGroupBox( QStringLiteral( "SOME/IP" ) );
    auto* someIpLayout = new QFormLayout( someIp );
    someIpLayout->addRow( QStringLiteral( "Also on ports:" ), someIpPorts_ );
    someIpLayout->addRow( QStringLiteral( "Name table:" ), namesRow );
    auto* someIpNote = new QLabel( QStringLiteral(
        "<small>SOME/IP is read on port 30490, on these ports, and on any other where its "
        "header fits. The name table names services, methods and eventgroups, one per line: "
        "<tt>service 0x1234 Navigation</tt>, <tt>method 0x1234 0x0001 GetRoute</tt>, "
        "<tt>eventgroup 0x1234 0x0010 Route</tt>.</small>" ) );
    someIpNote->setWordWrap( true );
    someIpLayout->addRow( someIpNote );

    auto* note = new QLabel( QStringLiteral(
        "The options apply to the next capture you open: an open capture keeps the options "
        "it was converted with." ) );
    note->setObjectName( "note" );
    note->setWordWrap( true );

    auto* buttons = new QDialogButtonBox( QDialogButtonBox::Ok | QDialogButtonBox::Cancel
                                          | QDialogButtonBox::RestoreDefaults );
    buttons->setObjectName( "buttons" );
    connect( buttons, &QDialogButtonBox::accepted, this, &QDialog::accept );
    connect( buttons, &QDialogButtonBox::rejected, this, &QDialog::reject );
    connect( buttons->button( QDialogButtonBox::RestoreDefaults ), &QPushButton::clicked, this,
             [ this ] { showOptions( ConversionOptions{} ); } );

    auto* layout = new QVBoxLayout( this );
    layout->addWidget( columns );
    layout->addWidget( previewBox );
    layout->addWidget( someIp );
    layout->addWidget( tls );
    layout->addWidget( advanced );
    layout->addWidget( note );
    layout->addWidget( buttons );

    showOptions( options );
}

void ConfigDialog::showOptions( const ConversionOptions& options )
{
    timeColumns_->setCurrentIndex(
        timeColumns_->findData( static_cast<int>( options.layout.timeColumns ) ) );
    macColumns_->setChecked( options.layout.macColumns );
    preview_->setChecked( options.preview );
    previewChars_->setEnabled( options.preview );
    previewChars_->setValue( static_cast<int>( options.previewChars ) );
    tcpTimestamps_->setChecked( options.tcpTimestamps );
    maxStreams_->setValue( static_cast<int>( options.maxStreams ) );
    maxEndpoints_->setValue( static_cast<int>( options.maxEndpoints ) );
    reassemblyMegabytes_->setValue( static_cast<int>( options.reassemblyMegabytes ) );
    someIpPorts_->setText( QString::fromStdString( someIpPortsText( options.someIpPorts ) ) );
    someIpNamesFile_->setText( options.someIpNamesFile );
    keyLogPath_->setText( options.keyLogPath );
}

ConversionOptions ConfigDialog::options() const
{
    ConversionOptions options;
    options.layout.timeColumns = static_cast<TimeColumns>( timeColumns_->currentData().toInt() );
    options.layout.macColumns = macColumns_->isChecked();
    options.preview = preview_->isChecked();
    options.previewChars = static_cast<size_t>( previewChars_->value() );
    options.tcpTimestamps = tcpTimestamps_->isChecked();
    options.maxStreams = static_cast<size_t>( maxStreams_->value() );
    options.maxEndpoints = static_cast<size_t>( maxEndpoints_->value() );
    options.reassemblyMegabytes = static_cast<size_t>( reassemblyMegabytes_->value() );
    options.someIpPorts = parseSomeIpPorts( someIpPorts_->text().toStdString() );
    options.someIpNamesFile = someIpNamesFile_->text().trimmed();
    options.keyLogPath = keyLogPath_->text().trimmed();
    return options;
}

} // namespace tcpdump
