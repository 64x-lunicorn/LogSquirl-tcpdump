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
#include "tempdirs.h"

#include <QFileDialog>
#include <QFileInfo>
#include <QLocale>
#include <QPointer>
#include <QPromise>
#include <QStandardPaths>
#include <QStringList>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <exception>
#include <map>
#include <vector>

namespace tcpdump {

namespace {

/// The README section on installing the Log Format and what it unlocks.
const char* const kLogFormatHelpUrl
    = "https://github.com/64x-lunicorn/LogSquirl-tcpdump#log-format";

} // namespace

SidebarWidget::SidebarWidget( QWidget* parent )
    : QWidget( parent )
    , chooseFile_( []( QWidget* parent, const QString& dir ) {
        return QFileDialog::getOpenFileName( parent, "Open pcap Capture File", dir,
                                             "pcap files (*.pcap *.cap *.dmp);;All files (*)" );
    } )
    , tempRoot_( tcpdump::tempRoot() )
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

    connect( openButton_, &QPushButton::clicked, this, &SidebarWidget::chooseAndOpen );

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
    summaryLabel_->setOpenExternalLinks( true );
    layout->addWidget( summaryLabel_ );

    // Push everything up
    layout->addStretch();

    setConverting( false );
}

SidebarWidget::~SidebarWidget()
{
    // The host unloads the library right after the plugin is shut down:
    // the worker must be done with it before.  It checks the cancel flag
    // between packets, and convertPcap() reads regular files only, so it
    // cannot block on a FIFO or device; a regular file on a network share
    // that stalls can still hold it up until the system gives up on it.
    if ( cancelRunning_ ) {
        cancelRunning_->store( true );
    }
    pool_.waitForDone();

    // A conversion that finished before the cancel reached it wrote a file
    // no tab will show: the cancel wins, and the file goes.
    if ( watcher_ && watcher_->future().resultCount() > 0 ) {
        applyCancelRequest( watcher_->result(), cancelRunning_.get() );
    }
}

void SidebarWidget::chooseAndOpen()
{
    // The Open button is disabled meanwhile, but the menu entry is not.
    if ( converting_ ) {
        hostNotify( "A capture is still being read: wait for it, or cancel it first." );
        return;
    }
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }

    // The dialog runs its own event loop, in which this widget may be
    // deleted, e.g. with a parent that is closed meanwhile: then there is
    // nothing left to open the file for.  This does not help if the plugin
    // is unloaded while the dialog is open: the code this call returns into
    // is gone then, and only the host can prevent that.
    const QPointer<SidebarWidget> self( this );
    const auto filePath = chooseFile_( this, lastDir_ );
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
        // An exception must not escape into Qt or the host.
        hostLog(
            LOGSQUIRL_LOG_ERROR,
            QString( "Opening %1 failed: %2" ).arg( filePath, QString::fromUtf8( e.what() ) ) );
    }
}

void SidebarWidget::openPcapFile( const QString& filePath )
{
    // One conversion at a time (Open is disabled meanwhile), so the outcome
    // that arrives is always that of the running one.
    if ( converting_ ) {
        return;
    }
    hostLog( LOGSQUIRL_LOG_INFO, "Opening pcap file: " + filePath );

    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancelRunning_ = cancelled;
    setConverting( true );
    summaryLabel_->setText( QString( "Reading %1\xe2\x80\xa6" )
                                .arg( QFileInfo( filePath ).fileName().toHtmlEscaped() ) );

    // The watcher lives on this thread, so its signals are delivered here.
    watcher_ = new QFutureWatcher<ConversionResult>( this );
    connect( watcher_, &QFutureWatcher<ConversionResult>::progressValueChanged, progressBar_,
             &QProgressBar::setValue );
    connect( watcher_, &QFutureWatcher<ConversionResult>::finished, this,
             [ this, cancelled, filePath ] {
                 ConversionResult result;
                 if ( watcher_->future().resultCount() > 0 ) {
                     result = watcher_->result();
                 }
                 else {
                     result.error = "The conversion ended without a result";
                 }
                 finishConversion( filePath,
                                   applyCancelRequest( std::move( result ), cancelled.get() ) );
             } );

    // The Converter writes into a new private directory below the temporary
    // root, kept for its tab until LogSquirl quits, and reports every
    // failure as a result: nothing is caught here.
    const auto tempRoot = tempRoot_;
    watcher_->setFuture( QtConcurrent::run(
        &pool_, [ filePath, tempRoot, cancelled ]( QPromise<ConversionResult>& promise ) {
            promise.setProgressRange( 0, 1000 );
            promise.addResult(
                convertPcap( filePath, tempRoot, cancelled.get(), [ &promise ]( int permille ) {
                    promise.setProgressValue( permille );
                } ) );
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

void SidebarWidget::finishConversion( const QString& filePath, ConversionResult result )
{
    cancelRunning_.reset();
    watcher_->deleteLater();
    watcher_ = nullptr;
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

    // Open in LogSquirl viewer; the file stays until LogSquirl quits
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, result.outputPath.toUtf8().constData(), 0 );
    }

    auto html = summaryHtml( QFileInfo( filePath ).fileName(), QFileInfo( filePath ).size(),
                             result.summary );
    // Whether LogSquirl has the Log Format installed is not known to the
    // plugin, so the hint is shown regardless, but only once per load.
    if ( !formatHintShown_ ) {
        formatHintShown_ = true;
        html += QString( "<br><i>Table view, \xce\x94t and Go to timestamp need the plugin's "
                         "Log Format: <a href=\"%1\">install it once</a>.</i>" )
                    .arg( kLogFormatHelpUrl );
    }
    summaryLabel_->setText( html );

    hostLog( LOGSQUIRL_LOG_INFO,
             QString( "Opened %1 packets from %2" ).arg( result.summary.packets ).arg( filePath ) );
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

QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary )
{
    const double duration = summary.durationSeconds;

    // Packets per second
    QString ppsStr = "-";
    if ( duration > 0.0 ) {
        auto pps = static_cast<double>( summary.packets ) / duration;
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
                .arg( QLocale().toString( static_cast<qulonglong>( summary.packets ) ) );
    if ( summary.cutPackets > 0 ) {
        html += QString( "Cut packets: <b>%1</b> (captured shorter than on the wire)<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( summary.cutPackets ) ) );
    }
    html += QString( "File size: %1<br>" ).arg( formatBytes( static_cast<uint64_t>( fileSize ) ) );
    if ( !summary.firstTimeUtc.empty() ) {
        html += QString( "First packet: %1<br>" )
                    .arg( QString::fromStdString( summary.firstTimeUtc ) );
        html += QString( "Last packet: %1<br>" )
                    .arg( QString::fromStdString( summary.lastTimeUtc ) );
    }
    html += QString( "Duration: <b>%1 s</b><br>" ).arg( duration, 0, 'f', 3 );
    html += QString( "Packets/s: %1<br>" ).arg( ppsStr );
    QStringList linkTypes;
    for ( const auto& name : summary.linkTypeNames ) {
        linkTypes << QString::fromStdString( name ).toHtmlEscaped();
    }
    html += QString( "%1: %2<br>" )
                .arg( linkTypes.size() > 1 ? "Link types" : "Link type" )
                .arg( linkTypes.join( ", " ) );
    if ( summary.endsInsideRecord ) {
        html += "<i>The capture was cut off in the middle of a packet.</i><br>";
    }
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : byCount( summary.protocolPackets ) ) {
        const auto bytes = summary.protocolBytes.at( proto );
        const auto pct
            = static_cast<double>( count ) / static_cast<double>( summary.packets ) * 100.0;
        html += QString( "%1: %2 (%3%, %4)<br>" )
                    .arg( QString::fromStdString( proto ).toHtmlEscaped() )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) )
                    .arg( pct, 0, 'f', 1 )
                    .arg( formatBytes( bytes ) );
    }
    html += "<br>";

    // Top IPs
    html += QString( "<b>Endpoints</b> (%1%2 unique)<br>" )
                .arg( summary.otherEndpointPackets ? "more than " : "" )
                .arg( summary.endpointPackets.size() );
    int shown = 0;
    for ( const auto& [ ip, count ] : byCount( summary.endpointPackets ) ) {
        if ( shown >= 8 )
            break;
        html += QString( "%1: %2 pkts<br>" )
                    .arg( QString::fromStdString( ip ).toHtmlEscaped() )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        shown++;
    }
    if ( summary.otherEndpointPackets ) {
        html += QString( "Other endpoints: %1 pkts<br>" )
                    .arg( QLocale().toString(
                        static_cast<qulonglong>( *summary.otherEndpointPackets ) ) );
    }
    if ( summary.streamCap ) {
        html += QString( "<br><i>More than %1 conversations: later ones show stream ? in the "
                         "log.</i><br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( *summary.streamCap ) ) );
    }

    return html;
}

} // namespace tcpdump
