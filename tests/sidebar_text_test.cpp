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
 * @file sidebar_text_test.cpp
 * @brief BDD tests for what the sidebar says, without a widget: the summary
 *        label's text of each status, from the plugin's sessions; a
 *        capture's summary; the filters its links open; a live capture's
 *        progress and error.
 */

#include <catch2/catch.hpp>

#include "capture_sessions.h"
#include "fake_live_session.h"
#include "fakehost.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "regex_lab.h"
#include "sidebar_text.h"

#include <QDir>
#include <QFile>
#include <QImage>
#include <QLabel>
#include <QLocale>
#include <QPalette>
#include <QPixmap>
#include <QRegularExpression>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <cmath>
#include <functional>
#include <set>
#include <thread>

using namespace tcpdump_test;
using tcpdump::CaptureSessions;
using tcpdump::SummaryStatus;

namespace {

QString writeCapture( const QTemporaryDir& dir, const QString& name, const Bytes& content )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( content.data() ),
                static_cast<qint64>( content.size() ) );
    return path;
}

/** A capture of @p count UDP packets. */
Bytes captureOf( int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back(
            eth( tcpdump::EthertypeIpv4,
                 ipv4( tcpdump::IpProtoUdp, udp( 40000, static_cast<uint16_t>( 1000 + i % 50 ),
                                                 text( "payload" ) ) ) ) );
    }
    return pcapOf( packets );
}

/** The target of the link that reads @p text in @p html; empty without one. */
QString linkTarget( const QString& html, const QString& text )
{
    const QRegularExpression link( "<a href=\"([^\"]*)\">"
                                   + QRegularExpression::escape( text.toHtmlEscaped() ) + "</a>" );
    return link.match( html ).captured( 1 );
}

/** The numbers of the lines of @p path that @p pattern matches, from 1. */
std::set<int> matchedLines( const QString& path, const QString& pattern )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    const auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    const QRegularExpression regex( pattern );
    REQUIRE( regex.isValid() );
    std::set<int> numbers;
    for ( int i = 0; i < lines.size(); ++i ) {
        if ( regex.match( lines[ i ] ).hasMatch() ) {
            numbers.insert( i + 1 );
        }
    }
    return numbers;
}

/** A light palette, and a dark one. */
QPalette lightPalette()
{
    QPalette light;
    light.setColor( QPalette::Window, QColor( 0xf0, 0xf0, 0xf0 ) );
    light.setColor( QPalette::WindowText, QColor( 0x10, 0x10, 0x10 ) );
    return light;
}
QPalette darkPalette()
{
    QPalette dark;
    dark.setColor( QPalette::Window, QColor( 0x20, 0x20, 0x20 ) );
    dark.setColor( QPalette::WindowText, QColor( 0xf0, 0xf0, 0xf0 ) );
    return dark;
}

/** A converter that converts, then holds its result until cancelled. */
tcpdump::FileConversionSession::Converter heldConverter()
{
    return []( const QString& filePath, const QString& outputRoot, const std::atomic_bool* cancel,
               const std::function<void( int )>&, const tcpdump::ConversionOptions& options ) {
        auto result = tcpdump::convertPcap( filePath, outputRoot, nullptr, {}, options );
        while ( !cancel->load() ) {
            std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
        }
        return result;
    };
}

} // namespace

SCENARIO( "the summary label says what opening a capture file comes to", "[sidebar_text]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    auto& conversion = sessions.conversionSession();
    const auto label = [ & ]( SummaryStatus status, const QPalette& palette = lightPalette() ) {
        return tcpdump::summaryLabelText( status, sessions, false, palette );
    };
    const QString readmeSection = tcpdump::kLogFormatHelpUrl;

    THEN( "with nothing loaded, it says so; a tab in front says it holds no capture" )
    {
        REQUIRE( readmeSection == "https://github.com/64x-lunicorn/LogSquirl-tcpdump#log-format" );
        REQUIRE( label( SummaryStatus::NothingLoaded ) == "No capture loaded." );
        REQUIRE( label( SummaryStatus::Front ) == "No capture in this tab." );
    }

    WHEN( "a capture is being read" )
    {
        conversion.setConverter( heldConverter() );
        REQUIRE( conversion.start( writeCapture( dir, "small.pcap", captureOf( 3 ) ) ) );

        THEN( "it says so, whatever claims the label, in any palette" )
        {
            for ( const auto status : { SummaryStatus::Conversion, SummaryStatus::Front,
                                        SummaryStatus::LiveOutcome } ) {
                REQUIRE( label( status ) == "Reading small.pcap\xe2\x80\xa6" );
                REQUIRE( label( status, darkPalette() ) == "Reading small.pcap\xe2\x80\xa6" );
            }
        }

        AND_WHEN( "it is cancelled" )
        {
            conversion.cancel();

            THEN( "it says it is cancelling, then that it was cancelled" )
            {
                REQUIRE( label( SummaryStatus::Conversion ) == "Cancelling\xe2\x80\xa6" );
                REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
                REQUIRE( label( SummaryStatus::Conversion ) == "Cancelled." );
                REQUIRE( label( SummaryStatus::Conversion, darkPalette() ) == "Cancelled." );
            }
        }
    }

    WHEN( "a file that is not a capture is opened" )
    {
        REQUIRE( conversion.start( writeCapture( dir, "junk.pcap", Bytes( 64, 0xEE ) ) ) );
        REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

        THEN( "it says the outcome's label" )
        {
            REQUIRE( conversion.outcome() );
            REQUIRE( label( SummaryStatus::Conversion ) == conversion.outcome()->label );
            REQUIRE( label( SummaryStatus::Conversion ).contains( "magic" ) );
        }

        AND_WHEN( "a capture is opened next" )
        {
            REQUIRE( conversion.start( writeCapture( dir, "good.pcap", captureOf( 1 ) ) ) );
            REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

            THEN( "its summary, in front, is the first to link to the Log Format" )
            {
                const auto text = label( SummaryStatus::Front );
                REQUIRE( text.startsWith( "<b>good.pcap</b>" ) );
                REQUIRE( text.contains( "href=\"" + readmeSection + "\"" ) );
                REQUIRE( linkTarget( text, "install it once" ) == readmeSection );
            }
        }
    }

    WHEN( "two captures are opened, and a tab of neither comes to the front" )
    {
        REQUIRE( conversion.start( writeCapture( dir, "first.pcap", captureOf( 1 ) ) ) );
        REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
        REQUIRE( conversion.start( writeCapture( dir, "second.pcap", captureOf( 2 ) ) ) );
        REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
        REQUIRE( host.openedFiles.size() == 2 );
        sessions.catalog().setFront( dir.filePath( "server.log" ) );

        THEN( "it says the tab holds no capture, and names none" )
        {
            REQUIRE( label( SummaryStatus::Front ) == "No capture in this tab." );
        }

        AND_WHEN( "the first capture's tab comes to the front" )
        {
            sessions.catalog().setFront( host.openedFiles.at( 0 ) );

            THEN( "its summary is shown, as it was, the hint with it" )
            {
                const auto text = label( SummaryStatus::Front );
                REQUIRE( text.startsWith( "<b>first.pcap</b>" ) );
                REQUIRE_FALSE( text.contains( "second.pcap" ) );
                REQUIRE( text.contains( readmeSection ) );
            }
        }

        AND_WHEN( "the second capture's tab comes to the front" )
        {
            sessions.catalog().setFront( host.openedFiles.at( 1 ) );

            THEN( "its summary is shown, without the hint" )
            {
                const auto text = label( SummaryStatus::Front );
                REQUIRE( text.startsWith( "<b>second.pcap</b>" ) );
                REQUIRE_FALSE( text.contains( readmeSection ) );
            }
        }
    }
}

// What a live capture does is the Live Capture Session's, tested in
// live_capture_session_test.cpp; here, what the summary label says of it,
// with captures the test scripts.
SCENARIO( "the summary label says what a live capture comes to", "[sidebar_text]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( dir.path() );
    ScriptedRuns runs;
    sessions.liveSession().setRunFactory( runs.factory() );
    const auto logPath = dir.filePath( "eth0.log" );
    const auto rawPath = dir.filePath( "eth0.pcap" );
    const auto otherTab = dir.filePath( "server.log" );
    tcpdump::LiveSnapshot snapshot;
    snapshot.summary.packets = 1;
    tcpdump::ConversionResult captured;
    captured.status = tcpdump::ConversionResult::Status::Converted;
    captured.outputPath = logPath;
    captured.summary.packets = 2;
    const auto label = [ & ]( SummaryStatus status ) {
        return tcpdump::summaryLabelText( status, sessions, false, lightPalette() );
    };
    // A switch of the colour scheme says the same, but for a summary's line.
    const auto paletteKeeps = [ & ]( SummaryStatus status ) {
        return tcpdump::summaryLabelText( status, sessions, false, darkPalette() )
               == label( status );
    };

    WHEN( "a capture starts" )
    {
        REQUIRE( sessions.liveSession().start( "eth0", {} ) );

        THEN( "the label says it waits for the first packet" )
        {
            REQUIRE( label( SummaryStatus::LiveStarted )
                     == "Capturing eth0\xe2\x80\xa6 waiting for the first packet." );
            REQUIRE( paletteKeeps( SummaryStatus::LiveStarted ) );
        }

        AND_WHEN( "its tab opens behind another" )
        {
            sessions.catalog().setFront( otherTab );
            runs.last().open( logPath, rawPath );

            THEN( "the label says the capture goes on" )
            {
                REQUIRE( label( SummaryStatus::LiveFile ) == "Capturing eth0\xe2\x80\xa6" );
                REQUIRE( paletteKeeps( SummaryStatus::LiveFile ) );
            }

            AND_WHEN( "it ends with packets" )
            {
                runs.last().finish( captured );

                THEN( "the label says its tab shows its summary" )
                {
                    REQUIRE( label( SummaryStatus::LiveOutcome )
                             == "The capture eth0 has ended: its tab shows its summary." );
                    REQUIRE( paletteKeeps( SummaryStatus::LiveOutcome ) );
                }

                AND_WHEN( "its tab comes to the front" )
                {
                    sessions.catalog().setFront( logPath );

                    THEN( "the label shows its final summary" )
                    {
                        REQUIRE(
                            label( SummaryStatus::LiveOutcome ).contains( "Packets: <b>2</b>" ) );
                        REQUIRE_FALSE(
                            label( SummaryStatus::LiveOutcome ).contains( "Capturing" ) );
                    }
                }
            }
        }

        AND_WHEN( "its tab opens and comes to the front, and a snapshot comes" )
        {
            runs.last().open( logPath, rawPath );
            sessions.catalog().setFront( logPath );
            runs.last().snapshot( snapshot );

            THEN( "the label shows the summary so far, also of its file" )
            {
                for ( const auto status : { SummaryStatus::Front, SummaryStatus::LiveFile } ) {
                    REQUIRE( label( status ).startsWith(
                        "<i>Capturing\xe2\x80\xa6 the summary so far:</i><br><b>eth0.pcap</b>" ) );
                    REQUIRE( label( status ).contains( "Packets: <b>1</b>" ) );
                }
            }

            AND_WHEN( "it ends with packets" )
            {
                runs.last().finish( captured );

                THEN( "the label shows its final summary" )
                {
                    REQUIRE( label( SummaryStatus::LiveOutcome ).startsWith( "<b>eth0.pcap</b>" ) );
                    REQUIRE( label( SummaryStatus::LiveOutcome ).contains( "Packets: <b>2</b>" ) );
                }
            }

            AND_WHEN( "it fails" )
            {
                auto failed = captured;
                failed.status = tcpdump::ConversionResult::Status::Failed;
                failed.error = "tcpdump exited with code 1";
                runs.last().finish( failed );

                THEN( "the label shows the error above the summary" )
                {
                    REQUIRE( label( SummaryStatus::LiveOutcome )
                                 .startsWith( "<b>Error:</b> tcpdump exited with code 1<br>The "
                                              "capture so far is kept.<br><b>eth0.pcap</b>" ) );
                }
            }
        }

        AND_WHEN( "it is stopped before anything came" )
        {
            tcpdump::ConversionResult stopped;
            stopped.status = tcpdump::ConversionResult::Status::Stopped;
            runs.last().finish( stopped );

            THEN( "the label says so" )
            {
                REQUIRE( label( SummaryStatus::LiveOutcome )
                         == "The capture eth0 was stopped before anything was captured." );
                REQUIRE( paletteKeeps( SummaryStatus::LiveOutcome ) );
            }
        }

        AND_WHEN( "it fails before a packet came" )
        {
            tcpdump::ConversionResult failed;
            failed.status = tcpdump::ConversionResult::Status::Failed;
            failed.error = "no <such> device";
            runs.last().finish( failed );

            THEN( "the label says it ended without a file, not the error the Live capture "
                  "section shows" )
            {
                REQUIRE( label( SummaryStatus::LiveOutcome )
                         == "The capture eth0 failed before anything was captured." );
                REQUIRE( paletteKeeps( SummaryStatus::LiveOutcome ) );
            }
        }
    }
}

SCENARIO( "the Live capture section says how the capture goes", "[sidebar_text]" )
{
    QTemporaryDir dir;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( dir.path() );
    ScriptedRuns runs;
    auto& live = sessions.liveSession();
    live.setRunFactory( runs.factory() );

    THEN( "it says nothing while no capture runs" )
    {
        REQUIRE( tcpdump::liveStateText( live ).isEmpty() );
    }

    WHEN( "a capture runs" )
    {
        REQUIRE( live.start( "eth0", {} ) );
        tcpdump::LiveSnapshot snapshot;
        snapshot.summary.packets = 3;
        runs.last().snapshot( snapshot );

        THEN( "it shows its progress" )
        {
            REQUIRE( tcpdump::liveStateText( live ).startsWith( "Packets: 3 \xc2\xb7" ) );
        }

        AND_WHEN( "it is stopped" )
        {
            live.stop();

            THEN( "it says it is stopping" )
            {
                REQUIRE( tcpdump::liveStateText( live ).startsWith( "Packets: 3 \xc2\xb7" ) );
                REQUIRE( tcpdump::liveStateText( live ).endsWith(
                    " \xe2\x80\x94 stopping\xe2\x80\xa6" ) );
            }
        }
    }

    WHEN( "a capture failed, its error and Guidance like markup" )
    {
        tcpdump::LiveOutcome outcome;
        outcome.status = tcpdump::LiveOutcome::Status::Failed;
        outcome.error = "fakecap exited with code 1:\nfakecap: <eth0> permission denied";
        outcome.guidance = "Run: setcap cap_net_raw=eip <fakecap> && log in again.";

        THEN( "its error and Guidance are shown as text, line by line" )
        {
            REQUIRE( tcpdump::liveErrorHtml( outcome )
                     == "Error: fakecap exited with code 1:<br>fakecap: &lt;eth0&gt; permission "
                        "denied<br>Run: setcap cap_net_raw=eip &lt;fakecap&gt; &amp;&amp; log in "
                        "again." );
            outcome.guidance.clear();
            REQUIRE_FALSE( tcpdump::liveErrorHtml( outcome ).contains( "setcap" ) );
        }
    }
}

SCENARIO( "endpoints and protocols in the summary are links to their lines' filters",
          "[sidebar_text]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    const auto capture = QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( "mixed.pcap" );
    const auto converted = tcpdump::convertPcap( capture, tempRoot.path() );
    REQUIRE( converted.status == tcpdump::ConversionResult::Status::Converted );
    const auto text = converted.outputPath;
    const auto html = tcpdump::summaryHtml( "mixed.pcap", 100, converted.summary, true );
    const auto patternOf = [ & ]( const QString& name ) {
        return tcpdump::summaryLinkPattern( linkTarget( html, name ) );
    };

    THEN( "each endpoint and protocol listed is a link" )
    {
        for ( const auto& name :
              { "192.168.1.1", "192.168.1.100", "fe80::1", "HTTP", "ICMPv6", "SOCKS" } ) {
            INFO( name );
            REQUIRE_FALSE( linkTarget( html, name ).isEmpty() );
        }
    }

    THEN( "an IPv6 endpoint's is the pattern of that address" )
    {
        REQUIRE( patternOf( "fe80::1" ) == tcpdump::endpointPattern( "fe80::1" ) );
        REQUIRE( matchedLines( text, patternOf( "fe80::1" ) ) == std::set<int>{ 8, 9, 10 } );
    }

    THEN( "an IPv4 endpoint that starts another matches its lines, not the other's" )
    {
        REQUIRE( patternOf( "192.168.1.1" ) == tcpdump::endpointPattern( "192.168.1.1" ) );
        std::set<int> expected;
        for ( int line = 2; line <= 22; ++line ) {
            if ( line < 8 || line > 10 ) {
                expected.insert( line );
            }
        }
        REQUIRE( matchedLines( text, patternOf( "192.168.1.1" ) ) == expected );
        REQUIRE( matchedLines( text, patternOf( "192.168.1.100" ) ) == std::set<int>{ 22 } );
    }

    THEN( "a protocol's is the pattern of that Protocol column" )
    {
        REQUIRE( patternOf( "HTTP" ) == tcpdump::protocolPattern( "HTTP" ) );
        REQUIRE( matchedLines( text, patternOf( "HTTP" ) ) == std::set<int>{ 2, 3, 4 } );
    }

    THEN( "any other link opens no filter" )
    {
        REQUIRE( tcpdump::summaryLinkPattern( tcpdump::kLogFormatHelpUrl ).isEmpty() );
    }

    THEN( "without filter links, as on a host older than LogSquirl 26.11, they are plain text" )
    {
        const auto plain = tcpdump::summaryHtml( "mixed.pcap", 100, converted.summary, false );
        REQUIRE( plain.contains( "<b>Endpoints</b>" ) );
        REQUIRE( plain.contains( "192.168.1.1: " ) );
        REQUIRE( plain.contains( "HTTP: " ) );
        REQUIRE_FALSE( plain.contains( "tcpdump-filter:" ) );
    }
}

SCENARIO( "the line under the capture's name takes the palette's colours", "[sidebar_text]" )
{
    GIVEN( "a light and a dark palette" )
    {
        // Which palette, not the palette: of named values Catch2 v2's
        // generator keeps a reference, to a copy gone by the time it is read.
        const bool isDark = GENERATE( false, true );
        const auto palette = isDark ? darkPalette() : lightPalette();

        WHEN( "a summary is shown in a label of that palette" )
        {
            QLabel label;
            label.setPalette( palette );
            label.setAutoFillBackground( true );
            label.setTextFormat( Qt::RichText );
            label.setText(
                tcpdump::summaryHtml( "a.pcap", 100, tcpdump::CaptureSummary(), false, palette ) );
            label.resize( 300, label.sizeHint().height() );
            const auto image = label.grab().toImage();

            THEN( "the line is drawn between the window's and the text's colour" )
            {
                // The line is the one row mostly of one colour other than
                // the window's.
                const auto window = palette.color( QPalette::Window ).rgb();
                const auto text = palette.color( QPalette::WindowText );
                bool found = false;
                for ( int y = 0; y < image.height() && !found; ++y ) {
                    const QColor middle = image.pixelColor( image.width() / 2, y );
                    if ( middle.rgb() == window ) {
                        continue;
                    }
                    int same = 0;
                    for ( int x = 0; x < image.width(); ++x ) {
                        same += image.pixelColor( x, y ) == middle;
                    }
                    if ( same > image.width() / 2 ) {
                        found = true;
                        REQUIRE( std::abs( middle.lightness() - text.lightness() ) > 60 );
                    }
                }
                REQUIRE( found );
            }
        }
    }
}

SCENARIO( "the summary shows names as text, not markup", "[sidebar_text]" )
{
    GIVEN( "a capture whose file name, protocol and endpoint contain markup" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 1;
        summary.protocolPackets[ "<i>P</i>" ] = 1;
        summary.protocolBytes[ "<i>P</i>" ] = 60;
        summary.endpointPackets[ "<img src=x>" ] = 1;

        WHEN( "the summary is built" )
        {
            const auto html = tcpdump::summaryHtml( "<b>a&b</b>.pcap", 100, summary );

            THEN( "each is escaped" )
            {
                REQUIRE( html.contains( "&lt;b&gt;a&amp;b&lt;/b&gt;.pcap" ) );
                REQUIRE( html.contains( "&lt;i&gt;P&lt;/i&gt;" ) );
                REQUIRE( html.contains( "&lt;img src=x&gt;" ) );
                REQUIRE_FALSE( html.contains( "<img" ) );
                REQUIRE_FALSE( html.contains( "<i>" ) );
            }
        }
    }
}

SCENARIO( "the summary's filter links keep any name intact", "[sidebar_text]" )
{
    GIVEN( "a protocol and an endpoint whose names hold ':', '%' and markup" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 2;
        summary.protocolPackets[ "A:B%1<i>" ] = 2;
        summary.protocolBytes[ "A:B%1<i>" ] = 120;
        summary.endpointPackets[ "fe80::1%2" ] = 2;

        WHEN( "the summary is built with filter links" )
        {
            const auto html = tcpdump::summaryHtml( "a.pcap", 100, summary, true );

            THEN( "each is a link, followed by its counts" )
            {
                REQUIRE_FALSE( linkTarget( html, "A:B%1<i>" ).isEmpty() );
                REQUIRE_FALSE( linkTarget( html, "fe80::1%2" ).isEmpty() );
                REQUIRE( html.contains( "A:B%1&lt;i&gt;</a>: 2 (100.0%, 120 B)<br>" ) );
                REQUIRE( html.contains( "fe80::1%2</a>: 2 pkts<br>" ) );
                REQUIRE_FALSE( html.contains( "<i>" ) );
            }
        }
    }
}

SCENARIO( "the summary lists the capture's link-layer types", "[sidebar_text]" )
{
    GIVEN( "a capture of one link-layer type" )
    {
        tcpdump::CaptureSummary summary;
        summary.linkTypeNames = { "Ethernet" };

        THEN( "it is named" )
        {
            REQUIRE( tcpdump::summaryHtml( "a.pcap", 100, summary )
                         .contains( "Link type: Ethernet<br>" ) );
        }
    }

    GIVEN( "a capture of several link-layer types" )
    {
        tcpdump::CaptureSummary summary;
        summary.linkTypeNames = { "Linux SLL2", "Ethernet", "<147>" };

        THEN( "they are listed comma-separated, as text" )
        {
            REQUIRE( tcpdump::summaryHtml( "a.pcap", 100, summary )
                         .contains( "Link types: Linux SLL2, Ethernet, &lt;147&gt;<br>" ) );
        }
    }
}

SCENARIO( "the summary tells what the TLS decryption did", "[sidebar_text]" )
{
    GIVEN( "a capture converted with a key log" )
    {
        tcpdump::CaptureSummary summary;
        summary.tlsSessionsDecrypted = 3;

        THEN( "the sessions decrypted are counted" )
        {
            const auto html = tcpdump::summaryHtml( "a.pcap", 100, summary );
            REQUIRE( html.contains( "<b>TLS decryption</b><br>Sessions decrypted: 3<br>" ) );
        }
    }

    GIVEN( "a key log that could not be read" )
    {
        tcpdump::CaptureSummary summary;
        summary.tlsSessionsDecrypted = 0;
        summary.keyLogError = "Cannot read the TLS key log: <No such file>";

        THEN( "it says why, as text" )
        {
            const auto html = tcpdump::summaryHtml( "a.pcap", 100, summary );
            REQUIRE( html.contains( "<i>Cannot read the TLS key log: &lt;No such "
                                    "file&gt;</i><br>Sessions decrypted: 0" ) );
        }
    }

    GIVEN( "a capture converted without a key log" )
    {
        THEN( "nothing is said about TLS decryption" )
        {
            REQUIRE_FALSE( tcpdump::summaryHtml( "a.pcap", 100, tcpdump::CaptureSummary() )
                               .contains( "TLS decryption" ) );
        }
    }
}

SCENARIO( "the summary shows the earliest and latest packet time", "[sidebar_text]" )
{
    GIVEN( "a capture with packets" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 2;
        summary.firstTimeUtc = "2026-10-09 08:41:10.123456Z";
        summary.lastTimeUtc = "2026-10-09 08:41:40.000000Z";

        THEN( "both are shown in UTC, as the log's UTC Time column has them" )
        {
            const auto html = tcpdump::summaryHtml( "a.pcap", 100, summary );
            REQUIRE( html.contains( "First packet: 2026-10-09 08:41:10.123456Z<br>" ) );
            REQUIRE( html.contains( "Last packet: 2026-10-09 08:41:40.000000Z<br>" ) );
        }
    }

    GIVEN( "a capture without packets" )
    {
        THEN( "neither is shown" )
        {
            const auto html = tcpdump::summaryHtml( "a.pcap", 100, tcpdump::CaptureSummary() );
            REQUIRE_FALSE( html.contains( "First packet" ) );
            REQUIRE_FALSE( html.contains( "Last packet" ) );
        }
    }
}

SCENARIO( "the summary lists the busiest endpoints", "[sidebar_text]" )
{
    GIVEN( "a capture with ten endpoints" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 55;
        for ( int i = 1; i <= 10; ++i ) {
            summary.endpointPackets[ "10.0.0." + std::to_string( i ) ] = static_cast<uint64_t>( i );
        }

        THEN( "the eight busiest are listed, busiest first, and all are counted" )
        {
            const auto html = tcpdump::summaryHtml( "ten.pcap", 100, summary );
            REQUIRE( html.contains( "<b>Endpoints</b> (10 unique)" ) );
            REQUIRE( html.contains( "10.0.0.10: 10 pkts" ) );
            REQUIRE( html.contains( "10.0.0.3: 3 pkts" ) );
            REQUIRE_FALSE( html.contains( "10.0.0.2: 2 pkts" ) );
            REQUIRE( html.indexOf( "10.0.0.10:" ) < html.indexOf( "10.0.0.9:" ) );
        }
    }
}

SCENARIO( "the summary names the endpoints DNS answers named", "[sidebar_text]" )
{
    GIVEN( "a capture converted with host names, one endpoint named" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 5;
        summary.endpointPackets[ "93.184.216.34" ] = 3;
        summary.endpointPackets[ "192.0.2.10" ] = 2;
        summary.endpointNames[ "93.184.216.34" ] = "www.example.com";

        THEN( "its name follows the address, the filter link is the address's" )
        {
            const auto html = tcpdump::summaryHtml( "names.pcap", 100, summary, true );
            REQUIRE( html.contains( "93.184.216.34</a> (www.example.com): 3 pkts" ) );
            REQUIRE( html.contains( "endpoint/93.184.216.34\"" ) );
            REQUIRE( html.contains( "192.0.2.10</a>: 2 pkts" ) );
        }
    }
}

SCENARIO( "the summary lists a tunnel's endpoints apart, without a filter", "[sidebar_text]" )
{
    GIVEN( "a capture whose packets were carried through tunnels" )
    {
        tcpdump::CaptureSummary summary;
        summary.endpointPackets[ "10.1.0.10" ] = 4;
        summary.tunnelEndpointPackets[ "192.0.2.1" ] = 4;
        summary.tunnelEndpointPackets[ "<img src=x>" ] = 1;

        THEN( "they are listed under Tunnel endpoints, after the endpoints, as plain text" )
        {
            const auto html = tcpdump::summaryHtml( "tunnels.pcap", 100, summary, true );
            REQUIRE( html.contains( "<b>Endpoints</b> (1 unique)" ) );
            REQUIRE( html.contains( "<b>Tunnel endpoints</b> (2 unique)<br>192.0.2.1: 4 pkts" ) );
            REQUIRE( html.contains( "&lt;img src=x&gt;: 1 pkts" ) );
            REQUIRE( html.indexOf( "<b>Endpoints</b>" ) < html.indexOf( "<b>Tunnel endpoints" ) );
            REQUIRE( html.contains( "endpoint/10.1.0.10" ) );
            REQUIRE_FALSE( html.contains( "192.0.2.1\"" ) );
            REQUIRE_FALSE( html.contains( "endpoint/192.0.2.1" ) );
        }
    }

    GIVEN( "a capture without tunnels" )
    {
        tcpdump::CaptureSummary summary;
        summary.endpointPackets[ "10.1.0.10" ] = 4;

        THEN( "there is no such group" )
        {
            REQUIRE_FALSE( tcpdump::summaryHtml( "plain.pcap", 100, summary, true )
                               .contains( "Tunnel endpoints" ) );
        }
    }
}

SCENARIO( "the summary says what was cut", "[sidebar_text]" )
{
    GIVEN( "a capture that was cut off" )
    {
        tcpdump::CaptureSummary summary;
        summary.endsInsideRecord = true;

        THEN( "the summary says so" )
        {
            REQUIRE( tcpdump::summaryHtml( "cut.pcap", 100, summary ).contains( "cut off" ) );
        }
    }

    GIVEN( "a capture with more packets than the No. column can number" )
    {
        tcpdump::CaptureSummary summary;
        summary.packetNumbersUsedUp = true;

        THEN( "the summary says the rest was not converted" )
        {
            REQUIRE( tcpdump::summaryHtml( "huge.pcap", 100, summary )
                         .contains( "the last one the No. column can number; the rest was not "
                                    "converted" ) );
        }
    }

    GIVEN( "a capture with more conversations than were numbered" )
    {
        tcpdump::CaptureSummary summary;
        summary.streamCap = 5;

        THEN( "the summary names the cap and the ? stream" )
        {
            const auto html = tcpdump::summaryHtml( "many.pcap", 100, summary );
            REQUIRE( html.contains( "More than 5 conversations" ) );
            REQUIRE( html.contains( "stream ?" ) );
        }
    }

    GIVEN( "a capture with more addresses than were counted" )
    {
        tcpdump::CaptureSummary summary;
        summary.endpointPackets[ "10.0.0.1" ] = 3;
        summary.otherEndpointPackets = 7;

        THEN( "the summary counts the rest as other endpoints" )
        {
            const auto html = tcpdump::summaryHtml( "many.pcap", 100, summary );
            REQUIRE( html.contains( "(more than 1 unique)" ) );
            REQUIRE( html.contains( "Other endpoints: 7 pkts" ) );
        }
    }

    GIVEN( "a capture with packets cut at the snaplen" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 1500;
        summary.cutPackets = 1200;

        THEN( "the summary counts them" )
        {
            const auto html = tcpdump::summaryHtml( "snaplen.pcap", 100, summary );
            REQUIRE( html.contains(
                QString( "Cut packets: <b>%1</b>" ).arg( QLocale().toString( 1200 ) ) ) );
        }
    }

    GIVEN( "a capture with nothing cut" )
    {
        THEN( "none of the messages shows" )
        {
            const auto html = tcpdump::summaryHtml( "whole.pcap", 100, tcpdump::CaptureSummary() );
            REQUIRE_FALSE( html.contains( "Cut packets" ) );
            REQUIRE_FALSE( html.contains( "cut off" ) );
            REQUIRE_FALSE( html.contains( "stream ?" ) );
            REQUIRE_FALSE( html.contains( "Other endpoints" ) );
        }
    }
}

SCENARIO( "the summary lists the TCP analysis markers", "[sidebar_text]" )
{
    GIVEN( "a capture with retransmissions and duplicate ACKs" )
    {
        tcpdump::CaptureSummary summary;
        summary.packets = 5000;
        summary.tcpMarkers = { { "TCP Retransmission", 1200 }, { "TCP Dup ACK", 3 } };

        THEN( "they are counted under Analysis, in the summary's order" )
        {
            const auto html = tcpdump::summaryHtml( "lossy.pcap", 100, summary );
            REQUIRE( html.contains( "<b>Analysis</b><br>" ) );
            REQUIRE( html.contains(
                QString( "TCP Retransmission: %1<br>" ).arg( QLocale().toString( 1200 ) ) ) );
            REQUIRE( html.contains( "TCP Dup ACK: 3<br>" ) );
            REQUIRE( html.indexOf( "TCP Retransmission" ) < html.indexOf( "TCP Dup ACK" ) );
        }
    }

    GIVEN( "a capture with handshakes and no marker" )
    {
        tcpdump::CaptureSummary summary;
        summary.handshakes = 1200;
        summary.medianInitialRttNs = 12345678;

        THEN( "the median initial round-trip time is under Analysis, in milliseconds" )
        {
            const auto html = tcpdump::summaryHtml( "clean.pcap", 100, summary );
            REQUIRE( html.contains( "<b>Analysis</b><br>" ) );
            REQUIRE( html.contains( QString( "Median iRTT: 12.346 ms (%1 handshakes)<br>" )
                                        .arg( QLocale().toString( 1200 ) ) ) );
        }
    }

    GIVEN( "a capture without any" )
    {
        THEN( "there is no Analysis heading" )
        {
            const auto html = tcpdump::summaryHtml( "clean.pcap", 100, tcpdump::CaptureSummary() );
            REQUIRE_FALSE( html.contains( "Analysis" ) );
        }
    }
}
