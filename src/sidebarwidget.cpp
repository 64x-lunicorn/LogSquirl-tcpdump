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
 * @file sidebarwidget.cpp
 * @brief Implementation of the tcpdump sidebar panel.
 *
 * When the user clicks "Open pcap…", the widget:
 *   1. Opens a file dialog for .pcap / .cap / .dmp files
 *   2. Converts the pcap packet by packet with pcap_converter: parses each
 *      packet, formats it into a human-readable line, and writes the line
 *      to a temporary .log file
 *   3. Opens the .log file in LogSquirl's main viewer
 */

#include "sidebarwidget.h"
#include "pcap_converter.h"
#include "plugin.h"

#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QLocale>
#include <QMessageBox>
#include <QPointer>
#include <QPromise>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <exception>
#include <map>
#include <new>
#include <vector>

namespace tcpdump {

SidebarWidget::SidebarWidget( QWidget* parent )
    : QWidget( parent )
    , tempRoot_( QDir::tempPath() )
{
    pool_.setMaxThreadCount( 1 );

    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 8, 8, 8, 8 );
    layout->setSpacing( 6 );

    // Title
    auto* title = new QLabel( "<b>tcpdump / pcap Viewer</b>" );
    layout->addWidget( title );

    // Open button
    openButton_ = new QPushButton( "Open pcap\xe2\x80\xa6" );
    openButton_->setObjectName( "openButton" );
    openButton_->setToolTip( "Open a pcap capture file and display it as text" );
    layout->addWidget( openButton_ );

    connect( openButton_, &QPushButton::clicked, this, &SidebarWidget::onOpenClicked );

    // Progress of a running conversion, and a way to stop it
    progressBar_ = new QProgressBar;
    progressBar_->setObjectName( "progress" );
    progressBar_->setRange( 0, 1000 );
    progressBar_->setTextVisible( false );
    layout->addWidget( progressBar_ );

    cancelButton_ = new QPushButton( "Cancel" );
    cancelButton_->setObjectName( "cancelButton" );
    cancelButton_->setToolTip( "Stop reading the capture" );
    layout->addWidget( cancelButton_ );
    connect( cancelButton_, &QPushButton::clicked, this, &SidebarWidget::cancel );

    // Summary label
    summaryLabel_ = new QLabel( "No capture loaded." );
    summaryLabel_->setObjectName( "summary" );
    summaryLabel_->setTextFormat( Qt::RichText );
    summaryLabel_->setWordWrap( true );
    layout->addWidget( summaryLabel_ );

    // Push everything up
    layout->addStretch();

    setConverting( false );
}

SidebarWidget::~SidebarWidget()
{
    // The host unloads the library right after the plugin is shut down:
    // the worker must be done with it before.
    if ( cancelRunning_ ) {
        cancelRunning_->store( true );
    }
    pool_.waitForDone();

    // A running conversion's file never reached a tab.
    if ( !runningDir_.isEmpty() ) {
        QDir( runningDir_ ).removeRecursively();
    }
}

void SidebarWidget::removeTempFiles()
{
    for ( const auto& dir : std::as_const( tabDirs_ ) ) {
        QDir( dir ).removeRecursively();
    }
    tabDirs_.clear();
}

void SidebarWidget::onOpenClicked()
{
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }

    // The dialog runs its own event loop, in which the plugin may be shut
    // down and this widget deleted.
    const QPointer<SidebarWidget> self( this );
    const auto filePath
        = QFileDialog::getOpenFileName( this, "Open pcap Capture File", lastDir_,
                                        "pcap files (*.pcap *.cap *.dmp);;All files (*)" );
    if ( !self ) {
        return;
    }

    if ( filePath.isEmpty() ) {
        return;
    }

    lastDir_ = QFileInfo( filePath ).absolutePath();
    try {
        openPcapFile( filePath );
    } catch ( const std::exception& e ) {
        // An exception must not escape a Qt slot.
        hostLog(
            LOGSQUIRL_LOG_ERROR,
            QString( "Opening %1 failed: %2" ).arg( filePath, QString::fromUtf8( e.what() ) ) );
    }
}

void SidebarWidget::openPcapFile( const QString& filePath )
{
    if ( converting_ ) {
        return;
    }
    hostLog( LOGSQUIRL_LOG_INFO, "Opening pcap file: " + filePath );

    // Write to a new file in a new directory that only the user can enter,
    // so that no other user can read the capture's text or plant a file or
    // link in its place, and no earlier tab's file is overwritten.  It is
    // kept for its tab until LogSquirl quits.
    QTemporaryDir tempDir( tempRoot_ + "/logsquirl-tcpdump-XXXXXX" );
    if ( !tempDir.isValid() ) {
        ConversionResult result;
        result.error = "Cannot create a temporary directory: " + tempDir.errorString();
        finishConversion( filePath, {}, {}, std::move( result ) );
        return;
    }
    tempDir.setAutoRemove( false );
    const auto outDir = tempDir.path();
    auto baseName = QFileInfo( filePath ).completeBaseName();
    if ( baseName.isEmpty() ) {
        baseName = "capture";
    }
    const auto outPath = tempDir.filePath( baseName + ".log" );

    const auto generation = ++generation_;
    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancelRunning_ = cancelled;
    runningDir_ = outDir;
    setConverting( true );
    summaryLabel_->setText( QString( "Reading %1\xe2\x80\xa6" )
                                .arg( QFileInfo( filePath ).fileName().toHtmlEscaped() ) );

    // The watcher lives on this thread, so its signals are delivered here.
    auto* watcher = new QFutureWatcher<ConversionResult>( this );
    connect( watcher, &QFutureWatcher<ConversionResult>::progressValueChanged, this,
             [ this, generation ]( int permille ) {
                 if ( generation == generation_ ) {
                     progressBar_->setValue( permille );
                 }
             } );
    connect( watcher, &QFutureWatcher<ConversionResult>::finished, this,
             [ this, watcher, generation, cancelled, filePath, outDir, outPath ] {
                 watcher->deleteLater();
                 ConversionResult result;
                 if ( watcher->future().resultCount() > 0 ) {
                     result = watcher->result();
                 }
                 else {
                     result.error = "The conversion ended without a result";
                 }
                 // Cancel wins even over a conversion that had just finished.
                 if ( cancelled->load() ) {
                     result.status = ConversionResult::Status::Cancelled;
                 }
                 if ( result.status != ConversionResult::Status::Converted ) {
                     QDir( outDir ).removeRecursively();
                 }
                 if ( generation == generation_ ) {
                     finishConversion( filePath, outDir, outPath, std::move( result ) );
                 }
                 else if ( result.status == ConversionResult::Status::Converted ) {
                     QDir( outDir ).removeRecursively(); // outdated: never shown
                 }
             } );

    watcher->setFuture( QtConcurrent::run( &pool_, [ filePath, outPath, cancelled ](
                                                       QPromise<ConversionResult>& promise ) {
        promise.setProgressRange( 0, 1000 );
        ConversionResult result;
        try {
            result = convertPcap( filePath, outPath, cancelled.get(), [ &promise ]( int permille ) {
                promise.setProgressValue( permille );
            } );
        } catch ( const std::bad_alloc& ) {
            result = ConversionResult();
            result.error = "Not enough memory to read the capture";
        } catch ( const std::exception& e ) {
            result = ConversionResult();
            result.error = QString::fromUtf8( e.what() );
        } catch ( ... ) {
            result = ConversionResult();
            result.error = "Unknown error";
        }
        promise.addResult( std::move( result ) );
    } ) );
}

void SidebarWidget::cancel()
{
    if ( !converting_ || !cancelRunning_ ) {
        return;
    }
    cancelRunning_->store( true );
    cancelButton_->setEnabled( false );
    summaryLabel_->setText( "Cancelling\xe2\x80\xa6" );
}

void SidebarWidget::setConverting( bool converting )
{
    converting_ = converting;
    openButton_->setEnabled( !converting );
    cancelButton_->setEnabled( converting );
    cancelButton_->setHidden( !converting );
    progressBar_->setHidden( !converting );
    progressBar_->setValue( 0 );
}

void SidebarWidget::finishConversion( const QString& filePath, const QString& outDir,
                                      const QString& outPath, ConversionResult result )
{
    cancelRunning_.reset();
    runningDir_.clear();
    setConverting( false );

    switch ( result.status ) {
    case ConversionResult::Status::Cancelled:
        summaryLabel_->setText( "Cancelled." );
        hostLog( LOGSQUIRL_LOG_INFO, "Cancelled opening " + filePath );
        return;

    case ConversionResult::Status::Failed: {
        const auto& msg = result.error;
        summaryLabel_->setText( "Error: " + msg.toHtmlEscaped() );
        hostLog( LOGSQUIRL_LOG_ERROR, "pcap parse error: " + msg );
        hostNotify( "Failed to open pcap: " + msg );
        return;
    }

    case ConversionResult::Status::Converted:
        break;
    }

    // Open in LogSquirl viewer
    tabDirs_.append( outDir );
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, outPath.toUtf8().constData(), 0 );
    }

    summaryLabel_->setText(
        summaryHtml( QFileInfo( filePath ).fileName(), QFileInfo( filePath ).size(), result ) );

    hostLog( LOGSQUIRL_LOG_INFO,
             QString( "Opened %1 packets from %2" ).arg( result.stats.packets ).arg( filePath ) );
}

namespace {

QString formatBytes( uint64_t bytes )
{
    if ( bytes >= 1024 * 1024 ) {
        return QString::number( static_cast<double>( bytes ) / ( 1024.0 * 1024.0 ), 'f', 1 )
               + " MB";
    }
    if ( bytes >= 1024 ) {
        return QString::number( static_cast<double>( bytes ) / 1024.0, 'f', 1 ) + " KB";
    }
    return QString::number( bytes ) + " B";
}

/// Entries of @p counts by count, highest first.
std::vector<std::pair<std::string, uint64_t>>
byCount( const std::map<std::string, uint64_t>& counts )
{
    std::vector<std::pair<std::string, uint64_t>> sorted( counts.begin(), counts.end() );
    std::stable_sort( sorted.begin(), sorted.end(),
                      []( const auto& a, const auto& b ) { return a.second > b.second; } );
    return sorted;
}

} // namespace

QString summaryHtml( const QString& fileName, qint64 fileSize, const ConversionResult& result )
{
    const auto& stats = result.stats;
    const double duration = stats.durationSeconds();

    // Link type name
    QString linkName;
    switch ( result.header.network ) {
    case 0:
        linkName = "BSD Loopback";
        break;
    case 1:
        linkName = "Ethernet";
        break;
    case 101:
        linkName = "Raw IP";
        break;
    case 113:
        linkName = "Linux SLL";
        break;
    case 276:
        linkName = "Linux SLL2";
        break;
    default:
        linkName = QString::number( result.header.network );
        break;
    }

    // Packets per second
    QString ppsStr = "-";
    if ( duration > 0.0 ) {
        auto pps = static_cast<double>( stats.packets ) / duration;
        ppsStr = QString::number( pps, 'f', 0 );
    }

    // Build summary HTML; anything from the file or its name is escaped,
    // since the label renders markup
    QString html;
    html += QString( "<b>%1</b><br>" ).arg( fileName.toHtmlEscaped() );
    html += QString( "<hr>" );

    // General stats
    html += QString( "<b>Overview</b><br>" );
    html += QString( "Packets: <b>%1</b><br>" )
                .arg( QLocale().toString( static_cast<qulonglong>( stats.packets ) ) );
    html += QString( "File size: %1<br>" ).arg( formatBytes( static_cast<uint64_t>( fileSize ) ) );
    html += QString( "Duration: <b>%1 s</b><br>" ).arg( duration, 0, 'f', 3 );
    html += QString( "Packets/s: %1<br>" ).arg( ppsStr );
    html += QString( "Link type: %1<br>" ).arg( linkName );
    if ( result.truncated ) {
        html += "<i>The capture was cut off in the middle of a packet.</i><br>";
    }
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : byCount( stats.protocolPackets ) ) {
        const auto bytes = stats.protocolBytes.at( proto );
        const auto pct
            = static_cast<double>( count ) / static_cast<double>( stats.packets ) * 100.0;
        html += QString( "%1: %2 (%3%, %4)<br>" )
                    .arg( QString::fromStdString( proto ).toHtmlEscaped() )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) )
                    .arg( pct, 0, 'f', 1 )
                    .arg( formatBytes( bytes ) );
    }
    html += "<br>";

    // Top IPs
    html += QString( "<b>Endpoints</b> (%1 unique)<br>" ).arg( stats.endpointPackets.size() );
    int shown = 0;
    for ( const auto& [ ip, count ] : byCount( stats.endpointPackets ) ) {
        if ( shown >= 8 )
            break;
        html += QString( "%1: %2 pkts<br>" )
                    .arg( QString::fromStdString( ip ).toHtmlEscaped() )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        shown++;
    }

    return html;
}

} // namespace tcpdump
