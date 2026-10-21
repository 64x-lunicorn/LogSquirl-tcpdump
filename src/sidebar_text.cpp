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
 * @file sidebar_text.cpp
 * @brief What the sidebar says, decided without a widget.
 *
 * The endpoints and protocols a summary lists are links, with filter links:
 * a click opens the Regex Lab with the pattern of their lines (see
 * regex_lab.h).  The tunnel endpoints are not: the addresses of the packets
 * that carried a tunnelled one show in no column, so no pattern could pick
 * their lines.
 */

#include "sidebar_text.h"

#include "capture_sessions.h"
#include "live_capture_form.h"
#include "regex_lab.h"

#include <QByteArray>
#include <QColor>
#include <QLocale>
#include <QStringList>
#include <QUrl>

#include <algorithm>
#include <map>
#include <vector>

namespace tcpdump {

const char* const kLogFormatHelpUrl
    = "https://github.com/64x-lunicorn/LogSquirl-tcpdump#log-format";

namespace {

/// What the summary says for a tab that shows no capture of the plugin.
const char* const kNoCaptureText = "No capture in this tab.";

/// The links of the summary that open a filter: this, then "endpoint/" or
/// "protocol/" and the percent-encoded name.
const char* const kFilterScheme = "tcpdump-filter:";
const char* const kEndpointFilter = "endpoint/";
const char* const kProtocolFilter = "protocol/";

} // namespace

QString summaryLinkPattern( const QString& link )
{
    if ( !link.startsWith( kFilterScheme ) ) {
        return {};
    }
    const auto filter = link.mid( static_cast<qsizetype>( qstrlen( kFilterScheme ) ) );
    const auto nameOf = []( const QString& rest, const char* kind ) {
        return QString::fromUtf8(
            QByteArray::fromPercentEncoding( rest.mid( qstrlen( kind ) ).toUtf8() ) );
    };
    if ( filter.startsWith( kEndpointFilter ) ) {
        return endpointPattern( nameOf( filter, kEndpointFilter ) );
    }
    if ( filter.startsWith( kProtocolFilter ) ) {
        return protocolPattern( nameOf( filter, kProtocolFilter ) );
    }
    return {};
}

namespace {

/// How far the line under the capture's name is from the window's colour
/// to the text's: one part in this many.
constexpr int kSeparatorShare = 3;

/// The line under the capture's name.  A rule is drawn in the text's
/// colour, stark on a dark window: this one a third of the way from the
/// window's colour to the text's.
QString separatorHtml( const QPalette& palette )
{
    const auto window = palette.color( QPalette::Window );
    const auto text = palette.color( QPalette::WindowText );
    const auto mix = []( int from, int to ) { return from + ( to - from ) / kSeparatorShare; };
    const QColor line( mix( window.red(), text.red() ), mix( window.green(), text.green() ),
                       mix( window.blue(), text.blue() ) );
    return QString( "<hr style=\"background-color:%1\">" ).arg( line.name() );
}

} // namespace

QString summaryLabelText( SummaryStatus status, const CaptureSessions& sessions, bool filterLinks,
                          const QPalette& palette )
{
    const auto& conversion = sessions.conversionSession();
    const auto& live = sessions.liveSession();
    const auto& catalog = sessions.catalog();
    // The capture being read is shown in a tab of its own when it is done:
    // until then, whatever comes to the front, the label says it is read.
    if ( conversion.isBusy() ) {
        return conversion.label();
    }
    switch ( status ) {
    case SummaryStatus::NothingLoaded:
        return "No capture loaded.";
    case SummaryStatus::Front:
        break;
    case SummaryStatus::Conversion:
        // Its outcome's label, "Cancelled." or the error; a capture opened
        // is in front.
        if ( const auto label = conversion.label(); !label.isEmpty() ) {
            return label;
        }
        break;
    case SummaryStatus::LiveStarted:
        return QString( "Capturing %1\xe2\x80\xa6 waiting for the first packet." )
            .arg( live.name().toHtmlEscaped() );
    case SummaryStatus::LiveFile:
        // The host may have brought its tab to the front at once, showing
        // its summary; otherwise the label says the capture goes on.
        if ( !live.files().isEmpty() && catalog.isFront( live.files().last() ) ) {
            break;
        }
        return QString( "Capturing %1\xe2\x80\xa6" ).arg( live.name().toHtmlEscaped() );
    case SummaryStatus::LiveOutcome: {
        // Its tab in front shows its final summary: the catalog announced it.
        const auto& outcome = live.outcome();
        if ( !outcome || ( !outcome->files.isEmpty() && catalog.isLive( catalog.frontFile() ) ) ) {
            break;
        }
        switch ( outcome->status ) {
        case LiveOutcome::Status::Stopped:
        case LiveOutcome::Status::Empty:
            return liveOutcomeText( *outcome ).toHtmlEscaped();
        case LiveOutcome::Status::Failed:
            if ( outcome->files.isEmpty() ) {
                return "Error: " + outcome->error.toHtmlEscaped();
            }
            break;
        case LiveOutcome::Status::Captured:
            break;
        }
        // Its tabs show the final summary; another tab is in front, or none.
        return QString( "The capture %1 has ended: its tab shows its summary." )
            .arg( outcome->name.toHtmlEscaped() );
    }
    }
    return frontSummaryHtml( catalog, filterLinks, palette );
}

QString frontSummaryHtml( const CaptureCatalog& catalog, bool filterLinks, const QPalette& palette )
{
    const auto* front = catalog.front();
    if ( !front ) {
        return kNoCaptureText;
    }
    const auto& capture = *front;
    QString html;
    if ( catalog.isCapturing( catalog.frontFile() ) ) {
        html += "<i>Capturing\xe2\x80\xa6 the summary so far:</i><br>";
    }
    if ( !capture.error.isEmpty() ) {
        html += QString( "<b>Error:</b> %1<br>The capture so far is kept.<br>" )
                    .arg( capture.error.toHtmlEscaped() );
    }
    html
        += summaryHtml( capture.fileName, capture.fileSize, capture.summary, filterLinks, palette );
    if ( capture.withFormatHint ) {
        html += QString( "<br><i>Table view, \xce\x94t and Go to timestamp need the plugin's "
                         "Log Format: <a href=\"%1\">install it once</a>.</i>" )
                    .arg( kLogFormatHelpUrl );
    }
    return html;
}

QString liveStateText( const LiveCaptureSession& live )
{
    switch ( live.state() ) {
    case LiveCaptureSession::State::Idle:
        return {};
    case LiveCaptureSession::State::Checking:
        return "Asking the source about the choice before it starts\xe2\x80\xa6";
    case LiveCaptureSession::State::Capturing:
        return liveProgressText( live.progress(), live.elapsedMs(), live.limits() );
    case LiveCaptureSession::State::Stopping:
        return liveProgressText( live.progress(), live.elapsedMs(), live.limits() )
               + " \xe2\x80\x94 stopping\xe2\x80\xa6";
    }
    return {};
}

QString liveErrorHtml( const LiveOutcome& outcome )
{
    auto text = "Error: " + guidanceHtml( outcome.error );
    if ( !outcome.guidance.isEmpty() ) {
        text += "<br>" + guidanceHtml( outcome.guidance );
    }
    return text;
}

namespace {

/// @p name as text, or, with @p link, as a link to the filter of @p kind.
QString filterName( const std::string& name, const char* kind, bool link )
{
    const auto text = QString::fromStdString( name ).toHtmlEscaped();
    if ( !link ) {
        return text;
    }
    return QString( "<a href=\"%1%2%3\">%4</a>" )
        .arg( QString( kFilterScheme ), QString( kind ),
              QString::fromUtf8( QUrl::toPercentEncoding( QString::fromStdString( name ) ) ),
              text );
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

QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks, const QPalette& palette )
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
    html += separatorHtml( palette );

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
    if ( !summary.compressionProblem.empty() ) {
        html += QString( "<i>The capture was cut off: %1.</i><br>" )
                    .arg( QString::fromStdString( summary.compressionProblem ).toHtmlEscaped() );
    }
    else if ( summary.endsInsideRecord ) {
        html += "<i>The capture was cut off in the middle of a packet.</i><br>";
    }
    if ( summary.packetNumbersUsedUp ) {
        html += QString( "<i>Stopped at packet %1, the last one the No. column can number; the "
                         "rest was not converted.</i><br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( summary.packets ) ) );
    }
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : byCount( summary.protocolPackets ) ) {
        const auto bytes = summary.protocolBytes.at( proto );
        const auto pct
            = static_cast<double>( count ) / static_cast<double>( summary.packets ) * 100.0;
        // The name is not put in with arg(), which would read a '%' in it.
        html += filterName( proto, kProtocolFilter, filterLinks );
        html += QString( ": %1 (%2%, %3)<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) )
                    .arg( pct, 0, 'f', 1 )
                    .arg( formatBytes( bytes ) );
    }
    html += "<br>";

    // TCP analysis markers, and the handshakes' round-trip time
    if ( !summary.tcpMarkers.empty() || summary.medianInitialRttNs ) {
        html += "<b>Analysis</b><br>";
        if ( summary.medianInitialRttNs ) {
            html += QString( "Median iRTT: %1 ms (%2 %3)<br>" )
                        .arg( static_cast<double>( *summary.medianInitialRttNs ) / 1e6, 0, 'f', 3 )
                        .arg( QLocale().toString( static_cast<qulonglong>( summary.handshakes ) ) )
                        .arg( summary.handshakes == 1 ? "handshake" : "handshakes" );
        }
        for ( const auto& [ marker, count ] : summary.tcpMarkers ) {
            html += QString( "%1: %2<br>" )
                        .arg( QString::fromStdString( marker ).toHtmlEscaped() )
                        .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        }
        html += "<br>";
    }

    // TLS decryption, with a key log: what it decrypted, or why it could not
    if ( summary.tlsSessionsDecrypted ) {
        html += "<b>TLS decryption</b><br>";
        if ( !summary.keyLogError.empty() ) {
            html += QString( "<i>%1</i><br>" )
                        .arg( QString::fromStdString( summary.keyLogError ).toHtmlEscaped() );
        }
        html += QString( "Sessions decrypted: %1<br><br>" )
                    .arg( QLocale().toString(
                        static_cast<qulonglong>( *summary.tlsSessionsDecrypted ) ) );
    }

    // Top IPs
    html += QString( "<b>Endpoints</b> (%1%2 unique)<br>" )
                .arg( summary.otherEndpointPackets ? "more than " : "" )
                .arg( summary.endpointPackets.size() );
    int shown = 0;
    for ( const auto& [ ip, count ] : byCount( summary.endpointPackets ) ) {
        if ( shown >= 8 )
            break;
        html += filterName( ip, kEndpointFilter, filterLinks );
        // The name a DNS answer gave it, with host names shown: plain
        // text, the filter is the address's.
        const auto name = summary.endpointNames.find( ip );
        if ( name != summary.endpointNames.end() ) {
            html += " (" + QString::fromStdString( name->second ).toHtmlEscaped() + ")";
        }
        html += QString( ": %1 pkts<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        shown++;
    }
    if ( summary.otherEndpointPackets ) {
        html += QString( "Other endpoints: %1 pkts<br>" )
                    .arg( QLocale().toString(
                        static_cast<qulonglong>( *summary.otherEndpointPackets ) ) );
    }

    // The tunnels' endpoints, which no line shows: plain text, no filter
    if ( !summary.tunnelEndpointPackets.empty() ) {
        html += QString( "<br><b>Tunnel endpoints</b> (%1 unique)<br>" )
                    .arg( summary.tunnelEndpointPackets.size() );
        int shownTunnel = 0;
        for ( const auto& [ ip, count ] : byCount( summary.tunnelEndpointPackets ) ) {
            if ( shownTunnel >= 8 )
                break;
            html += QString::fromStdString( ip ).toHtmlEscaped();
            html += QString( ": %1 pkts<br>" )
                        .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
            shownTunnel++;
        }
    }
    if ( summary.streamCap ) {
        html += QString( "<br><i>More than %1 conversations: later ones show stream ? in the "
                         "log.</i><br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( *summary.streamCap ) ) );
    }

    return html;
}

namespace {

/// How far @p done is to @p limit, in percent, at most 100.
int percentOf( uint64_t done, uint64_t limit )
{
    return static_cast<int>(
        std::min<uint64_t>( done * 100 / std::max<uint64_t>( limit, 1 ), 100 ) );
}

} // namespace

QString liveProgressText( const LiveSnapshot& snapshot, qint64 elapsedMs, const LiveLimits& limits )
{
    const auto packets = snapshot.summary.packets;
    QString rate = "-";
    if ( snapshot.elapsed.count() > 0 ) {
        rate = QString::number( static_cast<double>( packets ) * 1000.0
                                    / static_cast<double>( snapshot.elapsed.count() ),
                                'f', 1 );
    }
    const auto seconds = std::max<qint64>( elapsedMs, 0 ) / 1000;
    auto text
        = QString( "Packets: %1 \xc2\xb7 Bytes: %2 \xc2\xb7 %3 packets/s \xc2\xb7 Elapsed %4" )
              .arg( QLocale().toString( static_cast<qulonglong>( packets ) ),
                    formatBytes( snapshot.summary.bytes ), rate, clockTime( seconds ) );

    // Each stop condition, and how far the capture is to it: the one
    // furthest on stops it first, unless the traffic changes.
    QStringList stops;
    if ( limits.duration.count() > 0 ) {
        stops << QString( "after %1 (%2%)" )
                     .arg( clockTime( limits.duration.count() ) )
                     .arg( percentOf( static_cast<uint64_t>( seconds ),
                                      static_cast<uint64_t>( limits.duration.count() ) ) );
    }
    if ( limits.packets > 0 ) {
        stops << QString( "at %1 packets (%2%)" )
                     .arg( QLocale().toString( static_cast<qulonglong>( limits.packets ) ) )
                     .arg( percentOf( packets, limits.packets ) );
    }
    if ( limits.bytes > 0 ) {
        stops << QString( "at %1 (%2%)" )
                     .arg( formatBytes( limits.bytes ) )
                     .arg( percentOf( snapshot.rawBytes, limits.bytes ) );
    }
    if ( !stops.isEmpty() ) {
        text += "\nStops " + stops.join( ", or " );
    }
    if ( limits.ringBuffer() ) {
        text += QString( "\nRing buffer: file %1, keeping the last %2" )
                    .arg( snapshot.rawFile )
                    .arg( limits.ringFiles );
    }
    return text;
}

} // namespace tcpdump
