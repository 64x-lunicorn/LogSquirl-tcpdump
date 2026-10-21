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
 * @file sidebarwidget_test.cpp
 * @brief Smoke tests of the sidebar, a view of the plugin's sessions: its
 *        layout and scrolling, and that its buttons, labels and links are
 *        wired to the sessions, the catalog and the host.
 *
 * What the sessions do is tested at the sessions (capture_sessions_test.cpp,
 * file_conversion_session_test.cpp, live_capture_session_test.cpp,
 * export_session_test.cpp), what the Activity rule allows in
 * activity_test.cpp, what the catalog says is in front in
 * capture_catalog_test.cpp, and what the labels say of all of them in
 * sidebar_text_test.cpp; here, only that the sidebar shows it.
 */

#include <catch2/catch.hpp>

#include "conversation_table.h"
#include "fake_live_session.h"
#include "fakehost.h"
#include "packet_panel.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "regex_lab.h"
#include "sidebarwidget.h"

#include <QCoreApplication>
#include <QDesktopServices>
#include <QFile>
#include <QLabel>
#include <QPalette>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QUrl>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <thread>

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );

using tcpdump::CaptureSessions;
using tcpdump::SidebarWidget;
using tcpdump::SummaryStatus;
using tcpdump_test::FakeHost;
using tcpdump_test::waitFor;
using namespace tcpdump_test;

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

/** Records the URLs QDesktopServices::openUrl() is asked to open. */
class UrlRecorder : public QObject {
    Q_OBJECT

public:
    QList<QUrl> opened;

public slots:
    void open( const QUrl& url )
    {
        opened << url;
    }
};

template <typename T>
T* child( const SidebarWidget& widget, const char* name )
{
    auto* found = widget.findChild<T*>( name );
    REQUIRE( found );
    return found;
}

/// Scroll each scroll area @p widget is in so that @p rect of it is in view,
/// innermost first, as a user would; true if then the widgets it is in clip
/// none of it.
bool scrollIntoView( QWidget* widget, const QRect& rect )
{
    for ( auto* parent = widget->parentWidget(); parent; parent = parent->parentWidget() ) {
        if ( auto* area = qobject_cast<QScrollArea*>( parent ) ) {
            const auto top = widget->mapTo( area->widget(), rect.topLeft() );
            // ensureVisible() takes a point and margins around it.
            const auto half = rect.height() / 2;
            area->ensureVisible( top.x() + rect.width() / 2, top.y() + half, rect.width() / 2,
                                 rect.height() - half );
            QCoreApplication::processEvents();
        }
    }
    auto shown = rect;
    for ( auto* parent = widget->parentWidget(); parent; parent = parent->parentWidget() ) {
        shown &= QRect( widget->mapFrom( parent, QPoint( 0, 0 ) ), parent->size() );
    }
    return shown == rect;
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

SCENARIO( "a sidebar with nothing loaded says so once", "[sidebar]" )
{
    FakeHost host;
    CaptureSessions sessions;
    SidebarWidget widget( sessions );

    THEN( "the summary says no capture is loaded, the Packet section not again, and the "
          "controls are idle" )
    {
        REQUIRE( child<QLabel>( widget, "summary" )->text() == "No capture loaded." );
        REQUIRE( child<QLabel>( widget, "packetStatus" )->isHidden() );
        REQUIRE( child<QPushButton>( widget, "openButton" )->isEnabled() );
        REQUIRE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
        REQUIRE( child<QProgressBar>( widget, "progress" )->isHidden() );
        REQUIRE( child<QPushButton>( widget, "liveCaptureButton" )->isEnabled() );
        REQUIRE( child<QPushButton>( widget, "stopButton" )->isHidden() );
        REQUIRE( child<QPushButton>( widget, "saveCaptureButton" )->isHidden() );
    }

    THEN( "it is the sessions' dialog parent, until it goes" )
    {
        REQUIRE( sessions.dialogParent() == &widget );
    }
}

SCENARIO( "the Open and Cancel buttons reach the File Conversion session, and the sidebar shows "
          "it",
          "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    FakeHost host;
    CaptureSessions sessions;
    SidebarWidget widget( sessions );
    sessions.setTempRoot( dir.path() );
    auto& conversion = sessions.conversionSession();
    conversion.setConverter( heldConverter() );
    const auto capture = writeCapture( dir, "small.pcap", captureOf( 3 ) );
    QWidget* dialogParent = nullptr;
    sessions.setFileChooser( [ & ]( QWidget* parent, const QString& ) {
        dialogParent = parent;
        return capture;
    } );
    auto* summary = child<QLabel>( widget, "summary" );

    WHEN( "the Open button is clicked" )
    {
        child<QPushButton>( widget, "openButton" )->click();

        THEN( "the dialog is shown over the sidebar, and its controls show the conversion" )
        {
            REQUIRE( dialogParent == &widget );
            REQUIRE( conversion.isBusy() );
            REQUIRE_FALSE( child<QPushButton>( widget, "openButton" )->isEnabled() );
            REQUIRE_FALSE( child<QPushButton>( widget, "liveCaptureButton" )->isEnabled() );
            REQUIRE_FALSE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
            REQUIRE( child<QPushButton>( widget, "cancelButton" )->isEnabled() );
            REQUIRE_FALSE( child<QProgressBar>( widget, "progress" )->isHidden() );
            REQUIRE( summary->text()
                     == tcpdump::summaryLabelText( SummaryStatus::Conversion, sessions, false,
                                                   widget.palette() ) );
        }

        AND_WHEN( "Cancel is clicked" )
        {
            child<QPushButton>( widget, "cancelButton" )->click();

            THEN( "the session cancels; Cancel is disabled and the label says so" )
            {
                REQUIRE( conversion.state() == tcpdump::FileConversionSession::State::Cancelling );
                REQUIRE_FALSE( child<QPushButton>( widget, "cancelButton" )->isEnabled() );
                REQUIRE( summary->text() == "Cancelling\xe2\x80\xa6" );
                REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
            }

            AND_WHEN( "the conversion has ended" )
            {
                REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

                THEN( "the sidebar shows its outcome, and is idle" )
                {
                    REQUIRE( summary->text() == "Cancelled." );
                    REQUIRE( child<QPushButton>( widget, "openButton" )->isEnabled() );
                    REQUIRE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
                    REQUIRE( child<QProgressBar>( widget, "progress" )->isHidden() );
                }
            }
        }
    }

    WHEN( "a capture is converted" )
    {
        conversion.setConverter( []( const QString& filePath, const QString& outputRoot,
                                     const std::atomic_bool*, const std::function<void( int )>&,
                                     const tcpdump::ConversionOptions& options ) {
            return tcpdump::convertPcap( filePath, outputRoot, nullptr, {}, options );
        } );
        child<QPushButton>( widget, "openButton" )->click();
        REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

        THEN( "the sidebar is idle and shows its summary, its tab in front" )
        {
            REQUIRE( child<QPushButton>( widget, "openButton" )->isEnabled() );
            REQUIRE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
            REQUIRE( summary->text().startsWith( "<b>small.pcap</b>" ) );
        }
    }
}

SCENARIO( "the sidebar follows the tab in front", "[sidebar]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    REQUIRE( dir.isValid() );
    REQUIRE( tempRoot.isValid() );
    FakeHost host;
    tcpdump::g_state.tempRoot = tempRoot.path();
    REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
    REQUIRE( host.hasActiveFileCallback() );
    auto* widget = tcpdump::g_state.sidebarWidget;
    auto* sessions = tcpdump::g_state.sessions;
    auto* summary = child<QLabel>( *widget, "summary" );
    auto* conversations = widget->packetPanel()->conversationTable()->model();
    auto& conversion = sessions->conversionSession();
    REQUIRE( conversion.start( writeCapture( dir, "first.pcap", captureOf( 1 ) ) ) );
    REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
    REQUIRE( host.openedFiles.size() == 1 );

    WHEN( "a tab with a file the plugin did not write comes to the front" )
    {
        host.activateFile( dir.filePath( "server.log" ) );

        THEN( "the catalog is told, and the sidebar shows no capture" )
        {
            REQUIRE( sessions->catalog().front() == nullptr );
            REQUIRE( summary->text() == "No capture in this tab." );
            REQUIRE( conversations->rowCount() == 0 );
        }

        AND_WHEN( "the capture's tab comes back" )
        {
            host.activateFile( host.openedFiles.first() );

            THEN( "its summary and its conversations are shown again" )
            {
                REQUIRE( summary->text().startsWith( "<b>first.pcap</b>" ) );
                REQUIRE( conversations->rowCount() == 1 );
            }
        }
    }

    logsquirl_plugin_shutdown();
}

SCENARIO( "the sidebar shows the Live Capture Session, and its Stop reaches it", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    FakeHost host;
    CaptureSessions sessions;
    SidebarWidget widget( sessions );
    sessions.setTempRoot( dir.path() );
    ScriptedRuns runs;
    auto& live = sessions.liveSession();
    live.setRunFactory( runs.factory() );
    auto* start = child<QPushButton>( widget, "liveCaptureButton" );
    auto* stop = child<QPushButton>( widget, "stopButton" );
    auto* progress = child<QLabel>( widget, "liveProgress" );
    auto* stderrView = child<QPlainTextEdit>( widget, "liveStderr" );
    auto* error = child<QLabel>( widget, "liveError" );
    auto* summary = child<QLabel>( widget, "summary" );

    WHEN( "a capture starts, and its program writes to stderr" )
    {
        REQUIRE( live.start( "eth0", {} ) );
        runs.last().stderrLine( "eth0: listening" );

        THEN( "Start is gone, and Stop, the progress, stderr and the label show" )
        {
            REQUIRE( start->isHidden() );
            REQUIRE_FALSE( stop->isHidden() );
            REQUIRE( stop->isEnabled() );
            REQUIRE_FALSE( progress->isHidden() );
            REQUIRE( progress->text() == tcpdump::liveStateText( live ) );
            REQUIRE_FALSE( stderrView->isHidden() );
            REQUIRE( stderrView->toPlainText() == "eth0: listening" );
            REQUIRE_FALSE( child<QPushButton>( widget, "openButton" )->isEnabled() );
            REQUIRE( summary->text()
                     == tcpdump::summaryLabelText( SummaryStatus::LiveStarted, sessions, false,
                                                   widget.palette() ) );
        }

        AND_WHEN( "Stop is clicked" )
        {
            stop->click();

            THEN( "the session stops it, telling nothing, and Stop is disabled" )
            {
                REQUIRE( runs.last().stopped );
                REQUIRE( host.notifications.isEmpty() );
                REQUIRE( live.state() == tcpdump::LiveCaptureSession::State::Stopping );
                REQUIRE_FALSE( stop->isEnabled() );
                REQUIRE( progress->text() == tcpdump::liveStateText( live ) );
            }
        }

        AND_WHEN( "it fails" )
        {
            tcpdump::ConversionResult failed;
            failed.status = tcpdump::ConversionResult::Status::Failed;
            failed.error = "no such device";
            runs.last().finish( failed );

            THEN( "the section shows its error, and Start is back" )
            {
                REQUIRE( live.outcome() );
                REQUIRE_FALSE( error->isHidden() );
                REQUIRE( error->text() == tcpdump::liveErrorHtml( *live.outcome() ) );
                REQUIRE_FALSE( start->isHidden() );
                REQUIRE( stop->isHidden() );
                REQUIRE( summary->text()
                         == tcpdump::summaryLabelText( SummaryStatus::LiveOutcome, sessions, false,
                                                       widget.palette() ) );
            }

            AND_WHEN( "the next capture starts" )
            {
                REQUIRE( live.start( "eth1", {} ) );

                THEN( "the error and the stderr lines go" )
                {
                    REQUIRE( error->isHidden() );
                    REQUIRE( stderrView->isHidden() );
                }
            }
        }
    }
}

SCENARIO( "the summary's links open the README in the browser and filters in the Regex Lab",
          "[sidebar]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    FakeHost host;
    CaptureSessions sessions;
    SidebarWidget widget( sessions );
    sessions.setTempRoot( tempRoot.path() );
    auto* summary = child<QLabel>( widget, "summary" );
    auto& conversion = sessions.conversionSession();
    REQUIRE( conversion.start( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ) ) );
    REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

    WHEN( "the user clicks the Log Format hint's link" )
    {
        UrlRecorder browser;
        QDesktopServices::setUrlHandler( "https", &browser, "open" );
        emit summary->linkActivated( linkTarget( summary->text(), "install it once" ) );
        QDesktopServices::unsetUrlHandler( "https" );

        THEN( "the README section opens in the browser" )
        {
            REQUIRE( browser.opened == QList<QUrl>{ QUrl( tcpdump::kLogFormatHelpUrl ) } );
            REQUIRE( host.regexLabs.isEmpty() );
        }
    }

    WHEN( "the user clicks an endpoint" )
    {
        const auto link = linkTarget( summary->text(), "fe80::1" );
        emit summary->linkActivated( link );

        THEN( "the Regex Lab opens with its filter's pattern, matching case, and logs it" )
        {
            REQUIRE( host.regexLabs.size() == 1 );
            const auto& lab = host.regexLabs.first();
            REQUIRE( lab.pattern == tcpdump::summaryLinkPattern( link ) );
            REQUIRE( lab.flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
            REQUIRE( host.logs.contains( "Filter: " + lab.pattern ) );
        }

        AND_WHEN( "the user applies it" )
        {
            host.regexLabs.first().apply( host.regexLabs.first().pattern,
                                          LOGSQUIRL_REGEX_LAB_MATCH_CASE );

            THEN( "the applied pattern is logged" )
            {
                REQUIRE(
                    host.logs.contains( "Filter: applied " + host.regexLabs.first().pattern ) );
            }
        }
    }
}

SCENARIO( "on a host older than LogSquirl 26.11 the summary has no filter links", "[sidebar]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );
    CaptureSessions sessions;
    SidebarWidget widget( sessions );
    sessions.setTempRoot( tempRoot.path() );
    auto& conversion = sessions.conversionSession();
    REQUIRE( conversion.start( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ) ) );
    REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );

    const auto text = child<QLabel>( widget, "summary" )->text();
    REQUIRE( text.contains( "<b>Endpoints</b>" ) );
    REQUIRE_FALSE( text.contains( "tcpdump-filter:" ) );
}

SCENARIO( "a sidebar that goes leaves the sessions running", "[sidebar]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    auto widget = std::make_unique<SidebarWidget>( sessions );
    auto& conversion = sessions.conversionSession();
    REQUIRE( conversion.start( writeCapture( dir, "small.pcap", captureOf( 3 ) ) ) );

    WHEN( "it goes while a capture is being read" )
    {
        widget.reset();

        THEN( "the capture is opened all the same, and the dialogs are shown over no window" )
        {
            REQUIRE( sessions.dialogParent() == nullptr );
            REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
            REQUIRE( host.openedFiles.size() == 1 );
        }
    }

    WHEN( "it goes, and another sidebar is made over the sessions" )
    {
        const auto observers = sessions.catalog().frontObserverCount();
        widget.reset();
        const auto afterGone = sessions.catalog().frontObserverCount();
        widget = std::make_unique<SidebarWidget>( sessions );

        THEN( "the catalog no longer tells the one that went, only the new one" )
        {
            REQUIRE( afterGone == observers - 1 );
            REQUIRE( sessions.catalog().frontObserverCount() == observers );
            REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
            REQUIRE(
                child<QLabel>( *widget, "summary" )->text().startsWith( "<b>small.pcap</b>" ) );
        }
    }
}

SCENARIO( "a long summary in a short sidebar can be scrolled to its end", "[sidebar]" )
{
    GIVEN( "a sidebar in a host's sidebar tabs of a given height, showing a long summary" )
    {
        FakeHost host;
        // As the host's sidebar holds it: a page of a QTabWidget, which a
        // splitter may make shorter than the sidebar's minimum.  The sessions
        // come first, so that they outlive the sidebar the tabs delete.
        CaptureSessions sessions;
        QTabWidget tabs;
        auto* widget = new SidebarWidget( sessions );
        tabs.addTab( widget, "tcpdump" );
        const auto height = GENERATE( 250, 400, 600, 900 );
        tabs.setFixedSize( 380, height );
        tabs.show();
        QCoreApplication::processEvents();
        auto* summary = child<QLabel>( *widget, "summary" );
        auto* area = child<QScrollArea>( *widget, "summaryArea" );
        auto* panel = child<QWidget>( *widget, "packetPanel" );
        auto* conversations = child<QWidget>( *widget, "conversationTable" );
        const auto line = widget->fontMetrics().lineSpacing();

        // The summary comes after the sidebar is shown, as a capture's does,
        // and takes the room the Packet panel leaves, up to 24 lines.
        QStringList lines;
        for ( int i = 1; i < 80; ++i ) {
            lines << QString( "Endpoint line %1" ).arg( i );
        }
        lines << "The last line";
        summary->setText( lines.join( "<br>" ) );
        REQUIRE( waitFor( [ & ] {
            const auto fitted = area->height() == SidebarWidget::kSummaryMaxLines * line
                                || panel->height() == panel->minimumHeight();
            return area->verticalScrollBar()->maximum() > 0 && fitted;
        } ) );

        THEN( "the summary ends above the Packet panel, and both keep a usable height" )
        {
            const auto areaBottom = area->mapTo( widget, QPoint( 0, area->height() ) ).y();
            const auto panelTop = panel->mapTo( widget, QPoint( 0, 0 ) ).y();
            REQUIRE( areaBottom <= panelTop );
            REQUIRE( area->height() >= SidebarWidget::kSummaryMinLines * line );
            REQUIRE( panel->height() >= SidebarWidget::kPacketPanelMinLines * line );
            REQUIRE( conversations->height()
                     >= tcpdump::PacketPanel::kConversationsMinLines * line );
        }

        THEN( "the summary's last line can be scrolled into view, whole" )
        {
            // The label is as tall as its text: none of it is cut off.
            REQUIRE( summary->height() >= summary->heightForWidth( summary->width() ) );
            REQUIRE( scrollIntoView(
                summary, QRect( 0, summary->height() - line, summary->width(), line ) ) );
        }

        THEN( "the bottom of the Conversations can be scrolled into view" )
        {
            REQUIRE( scrollIntoView( conversations, QRect( 0, conversations->height() - line,
                                                           conversations->width(), line ) ) );
        }

        if ( height >= 900 ) {
            THEN( "a sidebar taller than its minimum does not scroll as a whole" )
            {
                REQUIRE(
                    child<QScrollArea>( *widget, "sidebarScroll" )->verticalScrollBar()->maximum()
                    == 0 );
            }
        }
    }
}
SCENARIO( "the summary's line follows a switch of the colour scheme", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar showing a capture's summary in a light palette" )
    {
        FakeHost host;
        CaptureSessions sessions;
        SidebarWidget widget( sessions );
        sessions.setTempRoot( dir.path() );
        QPalette light;
        light.setColor( QPalette::Window, QColor( 0xf0, 0xf0, 0xf0 ) );
        light.setColor( QPalette::WindowText, QColor( 0x10, 0x10, 0x10 ) );
        widget.setPalette( light );
        auto* summary = child<QLabel>( widget, "summary" );
        sessions.conversionSession().start( writeCapture( dir, "first.pcap", captureOf( 1 ) ) );
        REQUIRE( waitFor( [ &sessions ] { return !sessions.conversionSession().isBusy(); } ) );
        const auto before = summary->text();
        REQUIRE( before.contains( "<hr style=\"background-color:#a6a6a6\">" ) );

        WHEN( "the palette turns dark" )
        {
            QPalette dark;
            dark.setColor( QPalette::Window, QColor( 0x20, 0x20, 0x20 ) );
            dark.setColor( QPalette::WindowText, QColor( 0xf0, 0xf0, 0xf0 ) );
            widget.setPalette( dark );

            THEN( "the line takes the dark palette's colours, the rest as it was" )
            {
                auto expected = before;
                expected.replace( "#a6a6a6", "#656565" );
                REQUIRE( summary->text() == expected );
            }
        }
    }
}

#include "sidebarwidget_test.moc"
