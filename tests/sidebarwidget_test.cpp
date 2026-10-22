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
#include "settings.h"
#include "sidebarwidget.h"

#include <QCoreApplication>
#include <QDesktopServices>
#include <QFile>
#include <QLabel>
#include <QLocale>
#include <QMouseEvent>
#include <QPalette>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollArea>
#include <QScrollBar>
#include <QSplitter>
#include <QTabWidget>
#include <QTemporaryDir>
#include <QTextDocument>
#include <QUrl>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
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

/// Drag the handle before pane @p index of @p splitter by @p dy pixels, as a
/// user would with the mouse.
void dragHandle( QSplitter* splitter, int index, int dy )
{
    auto* handle = splitter->handle( index );
    const QPoint start( handle->width() / 2, handle->height() / 2 );
    const auto end = start + QPoint( 0, dy );
    // The handle moves as it is dragged: where the mouse is, on the screen.
    const auto startGlobal = handle->mapToGlobal( start );
    const auto endGlobal = handle->mapToGlobal( end );
    const auto send = [ handle ]( QEvent::Type type, QPoint local, QPoint global,
                                  Qt::MouseButton button, Qt::MouseButtons buttons ) {
        QMouseEvent event( type, QPointF( local ), QPointF( global ), button, buttons,
                           Qt::NoModifier );
        QCoreApplication::sendEvent( handle, &event );
    };
    send( QEvent::MouseButtonPress, start, startGlobal, Qt::LeftButton, Qt::LeftButton );
    send( QEvent::MouseMove, end, endGlobal, Qt::NoButton, Qt::LeftButton );
    send( QEvent::MouseButtonRelease, end, endGlobal, Qt::LeftButton, Qt::NoButton );
    QCoreApplication::processEvents();
}

/// The lines of the text file at @p path.
QStringList linesOf( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
}

/// The summary @p html up to the end of its Protocols section, without the
/// empty line after it.
QString upToSectionAfterProtocols( const QString& html )
{
    const QString heading = "<b>Protocols</b>";
    const auto protocols = html.indexOf( heading );
    REQUIRE( protocols >= 0 );
    const auto next = html.indexOf( QRegularExpression( "<br><br><b>[A-Z][a-zA-Z ]*</b>" ),
                                    protocols + heading.size() );
    return next < 0 ? html : html.left( next );
}

/// The height of rich text @p html in @p label, as the label lays it out at
/// its width.
int textHeight( const QString& html, const QLabel* label )
{
    QTextDocument document;
    document.setDefaultFont( label->font() );
    document.setDocumentMargin( 0 );
    document.setHtml( html );
    document.setTextWidth( label->width() );
    return static_cast<int>( std::ceil( document.size().height() ) );
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

SCENARIO( "a capture program's stderr flood keeps the last lines shown and the host log bounded",
          "[sidebar]" )
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
    auto* stderrView = child<QPlainTextEdit>( widget, "liveStderr" );
    auto* dropped = child<QLabel>( widget, "liveStderrDropped" );
    const auto shown = stderrView->maximumBlockCount();
    REQUIRE( shown > 0 );
    const auto logged = [ &host ] {
        return static_cast<int>(
            std::count_if( host.logs.begin(), host.logs.end(),
                           []( const QString& line ) { return line.startsWith( "eth0: " ); } ) );
    };

    WHEN( "a capture's program writes a few lines" )
    {
        REQUIRE( live.start( "eth0", {} ) );
        runs.last().stderrLines( { "eth0: listening", "second" }, 0 );

        THEN( "they are shown and logged, and nothing is said to be dropped" )
        {
            REQUIRE( stderrView->toPlainText() == "eth0: listening\nsecond" );
            REQUIRE( dropped->isHidden() );
            REQUIRE( logged() == 2 );
        }
    }

    WHEN( "a capture's program writes more lines than are logged, none dropped" )
    {
        REQUIRE( live.start( "eth0", {} ) );
        QStringList lines;
        for ( int i = 0; i < 150; ++i ) {
            lines << QString( "line %1" ).arg( i );
        }
        runs.last().stderrLines( lines, 0 );

        THEN( "the host log took the first ones, and says so" )
        {
            REQUIRE( logged()
                     == static_cast<int>( tcpdump::LiveCaptureSession::kStderrLogged ) + 1 );
            REQUIRE( host.logs.contains( "eth0: line 0" ) );
            REQUIRE( host.logs.last().contains( "only its first 100 lines are" ) );
        }
    }

    WHEN( "a capture's program writes far more lines than are shown, some dropped on the way" )
    {
        REQUIRE( live.start( "eth0", {} ) );
        int next = 0;
        quint64 sent = 0;
        QStringList handedOn;
        for ( int batch = 0; batch < 20; ++batch ) {
            QStringList lines;
            next += 7; // dropped before they were handed on
            for ( int i = 0; i < 100; ++i ) {
                lines << QString( "line %1" ).arg( next++ );
            }
            runs.last().stderrLines( lines, 7 );
            handedOn << lines;
            sent += 107;
        }

        THEN( "the view keeps the last lines and says how many earlier ones were dropped" )
        {
            const auto text = stderrView->toPlainText().split( '\n' );
            REQUIRE( text == handedOn.mid( handedOn.size() - shown ) );
            REQUIRE_FALSE( dropped->isHidden() );
            REQUIRE( dropped->text()
                     == QString( "%1 earlier lines dropped" )
                            .arg( QLocale().toString( static_cast<qulonglong>( sent - shown ) ) ) );
        }

        THEN(
            "the host log took a bounded number of them, then one line that more were not logged" )
        {
            REQUIRE( logged()
                     == static_cast<int>( tcpdump::LiveCaptureSession::kStderrLogged ) + 1 );
            REQUIRE( host.logs.last().startsWith( "eth0: " ) );
            REQUIRE( host.logs.last().contains( "not logged" ) );
        }

        THEN( "that line does not claim the first lines were logged, as some were dropped" )
        {
            // 7 dropped before each batch of 100: the first batch and the
            // second's 7 before the notice.
            REQUIRE_FALSE( host.logs.last().contains( "its first" ) );
            REQUIRE( host.logs.last().contains( "not the first: 14 were dropped" ) );
        }

        AND_WHEN( "the next capture starts and writes a line" )
        {
            runs.last().finish( {} );
            runs.last().end();
            REQUIRE( live.start( "eth0", {} ) );
            runs.last().stderrLines( { "again" }, 0 );

            THEN( "the view starts afresh, and the host log takes its lines again" )
            {
                REQUIRE( stderrView->toPlainText() == "again" );
                REQUIRE( dropped->isHidden() );
                REQUIRE( host.logs.last() == "eth0: again" );
            }
        }
    }

    logsquirl_plugin_shutdown();
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
        // and takes the room the Packet panel leaves, up to kSummaryMaxLines.
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

        if ( height <= 250 ) {
            THEN( "a sidebar shorter than the summary's and the Packet panel's minimums scrolls "
                  "as a whole, the splitter between them at its minimum" )
            {
                REQUIRE(
                    child<QScrollArea>( *widget, "sidebarScroll" )->verticalScrollBar()->maximum()
                    > 0 );
                auto* splitter = child<QSplitter>( *widget, "summarySplitter" );
                REQUIRE( splitter->height() == splitter->minimumSizeHint().height() );
            }
        }
    }
}

SCENARIO( "at the default split, a selected packet leaves the summary's Overview and Protocols "
          "in view",
          "[sidebar]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    FakeHost host;
    tcpdump::g_state.tempRoot = tempRoot.path();
    REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
    auto* widget = tcpdump::g_state.sidebarWidget;
    widget->resize( 360, 1000 );
    widget->show();
    auto& conversion = tcpdump::g_state.sessions->conversionSession();
    REQUIRE( conversion.start( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ) ) );
    REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
    REQUIRE( host.openedFiles.size() == 1 );
    host.activateFile( host.openedFiles.first() );

    WHEN( "a packet line is selected" )
    {
        auto* panel = widget->packetPanel();
        host.selectedLines = { linesOf( host.openedFiles.first() )[ 3 ] };
        REQUIRE( waitFor( [ panel ] { return panel->shownPacket() == 3; } ) );
        QCoreApplication::processEvents();

        THEN( "the summary shows its Overview and Protocols without scrolling" )
        {
            auto* summary = child<QLabel>( *widget, "summary" );
            auto* area = child<QScrollArea>( *widget, "summaryArea" );
            const auto html = summary->text();
            REQUIRE( html.contains( "<b>Overview</b>" ) );
            REQUIRE( html.contains( "<b>Protocols</b>" ) );
            REQUIRE( area->verticalScrollBar()->value() == 0 );
            REQUIRE( textHeight( upToSectionAfterProtocols( html ), summary )
                     <= area->viewport()->height() );
        }

        THEN( "the Packet panel keeps at least its minimum" )
        {
            REQUIRE( panel->height() >= panel->minimumHeight() );
        }
    }

    logsquirl_plugin_shutdown();
}

SCENARIO( "the handle between the summary and the Packet panel moves their share", "[sidebar]" )
{
    GIVEN( "a sidebar showing a long summary, at the default split" )
    {
        QTemporaryDir tempRoot;
        REQUIRE( tempRoot.isValid() );
        FakeHost host;
        CaptureSessions sessions;
        SidebarWidget widget( sessions );
        sessions.setTempRoot( tempRoot.path() );
        // Tall enough that the Packet panel is above its minimum.
        widget.resize( 360, 1200 );
        widget.show();
        auto& conversion = sessions.conversionSession();
        REQUIRE( conversion.start( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ) ) );
        REQUIRE( waitFor( [ & ] { return !conversion.isBusy(); } ) );
        QCoreApplication::processEvents();
        auto* splitter = child<QSplitter>( widget, "summarySplitter" );
        auto* summaryPane = splitter->widget( 0 );
        auto* panel = child<QWidget>( widget, "packetPanel" );
        REQUIRE( splitter->widget( 1 ) == panel );
        const auto paneBefore = summaryPane->height();
        const auto panelBefore = panel->height();
        REQUIRE( panelBefore > panel->minimumHeight() );

        WHEN( "the user drags the handle up" )
        {
            dragHandle( splitter, 1, -60 );

            THEN( "the summary is shorter, and the Packet panel taller by as much" )
            {
                REQUIRE( summaryPane->height() == paneBefore - 60 );
                REQUIRE( panel->height() == panelBefore + 60 );
            }
        }

        WHEN( "the user drags the handle far down" )
        {
            dragHandle( splitter, 1, 5000 );

            THEN( "the Packet panel stops at its minimum" )
            {
                REQUIRE( panel->height() == panel->minimumHeight() );
                REQUIRE( summaryPane->height() > paneBefore );
            }
        }

        WHEN( "the user drags the handle far up" )
        {
            dragHandle( splitter, 1, -5000 );

            THEN( "the summary stops at its minimum" )
            {
                REQUIRE( summaryPane->height() == summaryPane->minimumSizeHint().height() );
                REQUIRE( child<QScrollArea>( widget, "summaryArea" )->height()
                         >= SidebarWidget::kSummaryMinLines * widget.fontMetrics().lineSpacing() );
            }
        }
    }
}

SCENARIO( "the sidebar's splitter positions are kept in settings.ini across a restart",
          "[sidebar]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    FakeHost host;
    CaptureSessions sessions;
    sessions.setTempRoot( tempRoot.path() );
    const auto makeSidebar = [ &sessions ] {
        auto widget = std::make_unique<SidebarWidget>( sessions );
        widget->resize( 360, 1200 );
        widget->show();
        QCoreApplication::processEvents();
        return widget;
    };
    const auto splitters = []( const SidebarWidget& widget ) {
        return std::vector<QSplitter*>{ child<QSplitter>( widget, "summarySplitter" ),
                                        child<QSplitter>( widget, "layersSplitter" ),
                                        child<QSplitter>( widget, "conversationsSplitter" ) };
    };
    const auto sizesOf = [ & ]( const SidebarWidget& widget ) {
        std::vector<QList<int>> sizes;
        for ( auto* splitter : splitters( widget ) ) {
            sizes.push_back( splitter->sizes() );
        }
        return sizes;
    };

    GIVEN( "a settings file without them" )
    {
        auto widget = makeSidebar();

        THEN( "the split is the default: the summary as tall as it asks, the Packet panel the "
              "rest" )
        {
            auto* splitter = child<QSplitter>( *widget, "summarySplitter" );
            REQUIRE( splitter->widget( 0 )->height()
                     == splitter->widget( 0 )->sizeHint().height() );
            REQUIRE( tcpdump::loadSplitterSizes( host.configDir(), "summarySplit" ).isEmpty() );
        }
    }

    GIVEN( "a settings file with sizes of another number of panes" )
    {
        REQUIRE( tcpdump::saveSplitterSizes( host.configDir(), "summarySplit", { 300 } ) );
        auto widget = makeSidebar();

        THEN( "the split is the default" )
        {
            auto* splitter = child<QSplitter>( *widget, "summarySplitter" );
            REQUIRE( splitter->widget( 0 )->height()
                     == splitter->widget( 0 )->sizeHint().height() );
        }
    }

    GIVEN( "a sidebar whose three handles the user dragged" )
    {
        auto widget = makeSidebar();
        auto all = splitters( *widget );
        const auto before = sizesOf( *widget );
        dragHandle( all[ 0 ], 1, 120 );
        dragHandle( all[ 1 ], 1, 30 );
        dragHandle( all[ 2 ], 1, -40 );
        const auto dragged = sizesOf( *widget );
        for ( size_t i = 0; i < dragged.size(); ++i ) {
            REQUIRE( dragged[ i ] != before[ i ] );
        }

        THEN( "settings.ini holds their sizes" )
        {
            REQUIRE( waitFor( [ & ] {
                return tcpdump::loadSplitterSizes( host.configDir(), "summarySplit" )
                           == dragged[ 0 ]
                       && tcpdump::loadSplitterSizes( host.configDir(), "layersSplit" )
                              == dragged[ 1 ]
                       && tcpdump::loadSplitterSizes( host.configDir(), "conversationsSplit" )
                              == dragged[ 2 ];
            } ) );
        }

        WHEN( "LogSquirl restarts, its sidebar made anew" )
        {
            widget.reset();
            widget = makeSidebar();

            THEN( "the splitters are where the user left them" )
            {
                REQUIRE( sizesOf( *widget ) == dragged );
            }
        }

        WHEN( "LogSquirl restarts with a shorter sidebar" )
        {
            widget.reset();
            widget = makeSidebar();
            widget->resize( 360, 1000 );
            QCoreApplication::processEvents();

            THEN( "the summary keeps its height, and the Packet panel is shorter" )
            {
                const auto sizes = child<QSplitter>( *widget, "summarySplitter" )->sizes();
                REQUIRE( sizes[ 0 ] == dragged[ 0 ][ 0 ] );
                REQUIRE( sizes[ 1 ] < dragged[ 0 ][ 1 ] );
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
