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
 *   2. Parses the pcap with pcap_parser
 *   3. Formats packets into human-readable lines with packet_formatter
 *   4. Writes the result to a temporary .log file
 *   5. Opens the .log file in LogSquirl's main viewer
 */

#include "sidebarwidget.h"
#include "packet_formatter.h"
#include "pcap_parser.h"
#include "plugin.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QLocale>
#include <QMessageBox>
#include <QStandardPaths>
#include <QTemporaryFile>
#include <QTextStream>

#include <algorithm>
#include <map>
#include <set>

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

    const auto filePath = QFileDialog::getOpenFileName(
        this, "Open pcap Capture File", lastDir_,
        "pcap files (*.pcap *.cap *.dmp);;All files (*)" );

    if ( filePath.isEmpty() ) {
        return;
    }

    lastDir_ = QFileInfo( filePath ).absolutePath();
    openPcapFile( filePath );
}

void SidebarWidget::openPcapFile( const QString& filePath )
{
    hostLog( LOGSQUIRL_LOG_INFO,
             qPrintable( "Opening pcap file: " + filePath ) );

    // Parse the pcap file
    auto result = parsePcapFile( filePath.toStdString() );
    if ( !result.ok ) {
        const auto msg = QString::fromStdString( result.error );
        summaryLabel_->setText( "Error: " + msg );
        hostLog( LOGSQUIRL_LOG_ERROR, qPrintable( "pcap parse error: " + msg ) );
        if ( g_state.api && g_state.handle ) {
            g_state.api->show_notification(
                g_state.handle,
                qPrintable( "Failed to open pcap: " + msg ) );
        }
        return;
    }

    // Format packets to text lines
    auto lines = formatAllPackets( result.packets );

    // Write to a temporary file that persists after the plugin is done
    // (LogSquirl will display it; user can save it if they want)
    const auto baseName = QFileInfo( filePath ).completeBaseName();
    const auto tempDir
        = QStandardPaths::writableLocation( QStandardPaths::TempLocation );
    const auto outPath = tempDir + "/logsquirl_tcpdump_" + baseName + ".log";

    QFile outFile( outPath );
    if ( !outFile.open( QIODevice::WriteOnly | QIODevice::Text ) ) {
        summaryLabel_->setText( "Error: Cannot write temp file" );
        hostLog( LOGSQUIRL_LOG_ERROR, "Failed to create temp output file" );
        return;
    }

    QTextStream stream( &outFile );
    for ( const auto& line : lines ) {
        stream << QString::fromStdString( line ) << "\n";
    }
    outFile.close();

    // Open in LogSquirl viewer
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, qPrintable( outPath ), 0 );
    }

    // Update summary with detailed capture info
    double duration = 0.0;
    if ( result.packets.size() >= 2 ) {
        const auto& first = result.packets.front();
        const auto& last = result.packets.back();
        duration = static_cast<double>( last.timestampSec - first.timestampSec )
                   + ( static_cast<double>( last.timestampUsec )
                       - static_cast<double>( first.timestampUsec ) )
                         / 1000000.0;
    }

    // Protocol breakdown
    std::map<std::string, int> protoCounts;
    std::map<std::string, uint64_t> protoBytes;
    std::set<std::string> uniqueIps;
    std::map<std::string, int> ipPacketCounts;
    uint64_t totalBytes = 0;

    for ( const auto& pkt : result.packets ) {
        protoCounts[ pkt.protocol ]++;
        protoBytes[ pkt.protocol ] += pkt.capturedLen;
        totalBytes += pkt.capturedLen;
        if ( !pkt.srcIp.empty() ) {
            uniqueIps.insert( pkt.srcIp );
            ipPacketCounts[ pkt.srcIp ]++;
        }
        if ( !pkt.dstIp.empty() ) {
            uniqueIps.insert( pkt.dstIp );
            ipPacketCounts[ pkt.dstIp ]++;
        }
    }

    // Sort protocols by count (descending)
    std::vector<std::pair<std::string, int>> sortedProtos( protoCounts.begin(),
                                                           protoCounts.end() );
    std::sort( sortedProtos.begin(), sortedProtos.end(),
               []( const auto& a, const auto& b ) { return a.second > b.second; } );

    // Sort IPs by packet count (descending), show top 6
    std::vector<std::pair<std::string, int>> sortedIps( ipPacketCounts.begin(),
                                                        ipPacketCounts.end() );
    std::sort( sortedIps.begin(), sortedIps.end(),
               []( const auto& a, const auto& b ) { return a.second > b.second; } );

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

    // Format file size
    auto fileSize = QFileInfo( filePath ).size();
    QString sizeStr;
    if ( fileSize >= 1024 * 1024 ) {
        sizeStr = QString::number( fileSize / ( 1024.0 * 1024.0 ), 'f', 1 ) + " MB";
    }
    else if ( fileSize >= 1024 ) {
        sizeStr = QString::number( fileSize / 1024.0, 'f', 1 ) + " KB";
    }
    else {
        sizeStr = QString::number( fileSize ) + " B";
    }

    // Packets per second
    QString ppsStr = "-";
    if ( duration > 0.0 ) {
        auto pps = static_cast<double>( result.packets.size() ) / duration;
        ppsStr = QString::number( pps, 'f', 0 );
    }

    // Build summary HTML
    QString html;
    html += QString( "<b>%1</b><br>" ).arg( QFileInfo( filePath ).fileName() );
    html += QString( "<hr>" );

    // General stats
    html += QString( "<b>Overview</b><br>" );
    html += QString( "Packets: <b>%1</b><br>" )
                .arg( QLocale().toString( static_cast<qlonglong>( result.packets.size() ) ) );
    html += QString( "File size: %1<br>" ).arg( sizeStr );
    html += QString( "Duration: <b>%1 s</b><br>" ).arg( duration, 0, 'f', 3 );
    html += QString( "Packets/s: %1<br>" ).arg( ppsStr );
    html += QString( "Link type: %1<br>" ).arg( linkName );
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : sortedProtos ) {
        auto bytes = protoBytes[ proto ];
        QString bytesStr;
        if ( bytes >= 1024 * 1024 ) {
            bytesStr = QString::number( bytes / ( 1024.0 * 1024.0 ), 'f', 1 ) + " MB";
        }
        else if ( bytes >= 1024 ) {
            bytesStr = QString::number( bytes / 1024.0, 'f', 1 ) + " KB";
        }
        else {
            bytesStr = QString::number( bytes ) + " B";
        }

        auto pct = ( result.packets.size() > 0 )
                       ? static_cast<double>( count ) / result.packets.size() * 100.0
                       : 0.0;
        html += QString( "%1: %2 (%3%, %4)<br>" )
                    .arg( QString::fromStdString( proto ) )
                    .arg( QLocale().toString( count ) )
                    .arg( pct, 0, 'f', 1 )
                    .arg( bytesStr );
    }
    html += "<br>";

    // Top IPs
    html += QString( "<b>Endpoints</b> (%1 unique)<br>" )
                .arg( uniqueIps.size() );
    int shown = 0;
    for ( const auto& [ ip, count ] : sortedIps ) {
        if ( shown >= 8 )
            break;
        html += QString( "%1: %2 pkts<br>" )
                    .arg( QString::fromStdString( ip ) )
                    .arg( QLocale().toString( count ) );
        shown++;
    }

    summaryLabel_->setText( html );

    hostLog( LOGSQUIRL_LOG_INFO,
             qPrintable( QString( "Opened %1 packets from %2" )
                             .arg( result.packets.size() )
                             .arg( filePath ) ) );
}

} // namespace tcpdump
