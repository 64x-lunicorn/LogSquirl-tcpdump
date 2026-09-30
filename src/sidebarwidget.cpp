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
#include <QFileDialog>
#include <QFileInfo>
#include <QLocale>
#include <QMessageBox>
#include <QStandardPaths>

#include <algorithm>
#include <map>
#include <vector>

namespace tcpdump {

SidebarWidget::SidebarWidget( QWidget* parent )
    : QWidget( parent )
{
    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 8, 8, 8, 8 );
    layout->setSpacing( 6 );

    // Title
    auto* title = new QLabel( "<b>tcpdump / pcap Viewer</b>" );
    layout->addWidget( title );

    // Open button
    openButton_ = new QPushButton( "Open pcap\xe2\x80\xa6" );
    openButton_->setToolTip( "Open a pcap capture file and display it as text" );
    layout->addWidget( openButton_ );

    connect( openButton_, &QPushButton::clicked, this, &SidebarWidget::onOpenClicked );

    // Summary label
    summaryLabel_ = new QLabel( "No capture loaded." );
    summaryLabel_->setWordWrap( true );
    layout->addWidget( summaryLabel_ );

    // Push everything up
    layout->addStretch();
}

void SidebarWidget::onOpenClicked()
{
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }

    const auto filePath
        = QFileDialog::getOpenFileName( this, "Open pcap Capture File", lastDir_,
                                        "pcap files (*.pcap *.cap *.dmp);;All files (*)" );

    if ( filePath.isEmpty() ) {
        return;
    }

    lastDir_ = QFileInfo( filePath ).absolutePath();
    openPcapFile( filePath );
}

void SidebarWidget::openPcapFile( const QString& filePath )
{
    hostLog( LOGSQUIRL_LOG_INFO, "Opening pcap file: " + filePath );

    // Write to a temporary file that persists after the plugin is done
    // (LogSquirl will display it; user can save it if they want)
    const auto baseName = QFileInfo( filePath ).completeBaseName();
    const auto tempDir = QStandardPaths::writableLocation( QStandardPaths::TempLocation );
    const auto outPath = tempDir + "/logsquirl_tcpdump_" + baseName + ".log";

    // Parse the capture and write it out packet by packet
    const auto result = convertPcap( filePath, outPath );
    if ( result.status != ConversionResult::Status::Converted ) {
        const auto& msg = result.error;
        summaryLabel_->setText( "Error: " + msg );
        hostLog( LOGSQUIRL_LOG_ERROR, "pcap parse error: " + msg );
        hostNotify( "Failed to open pcap: " + msg );
        return;
    }

    // Open in LogSquirl viewer
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

    // Build summary HTML
    QString html;
    html += QString( "<b>%1</b><br>" ).arg( fileName );
    html += QString( "<hr>" );

    // General stats
    html += QString( "<b>Overview</b><br>" );
    html += QString( "Packets: <b>%1</b><br>" )
                .arg( QLocale().toString( static_cast<qulonglong>( stats.packets ) ) );
    html += QString( "File size: %1<br>" ).arg( formatBytes( static_cast<uint64_t>( fileSize ) ) );
    html += QString( "Duration: <b>%1 s</b><br>" ).arg( duration, 0, 'f', 3 );
    html += QString( "Packets/s: %1<br>" ).arg( ppsStr );
    html += QString( "Link type: %1<br>" ).arg( linkName );
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : byCount( stats.protocolPackets ) ) {
        const auto bytes = stats.protocolBytes.at( proto );
        const auto pct
            = static_cast<double>( count ) / static_cast<double>( stats.packets ) * 100.0;
        html += QString( "%1: %2 (%3%, %4)<br>" )
                    .arg( QString::fromStdString( proto ) )
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
                    .arg( QString::fromStdString( ip ) )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        shown++;
    }

    return html;
}

} // namespace tcpdump
