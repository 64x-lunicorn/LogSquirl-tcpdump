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
 * @file live_capture_ui_test.cpp
 * @brief BDD tests for the live capture UI: the sidebar's Live capture
 *        section, Plugins > tcpdump > Start live capture… and its dialog,
 *        with a fake Live Source Kind.
 */

#include <catch2/catch.hpp>

#include "activity.h"
#include "adb_source.h"
#include "fake_live_source.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "local_source.h"
#include "settings.h"
#include "sidebarwidget.h"
#include "stream_capture.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFontDatabase>
#include <QFontInfo>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTextBlock>
#include <QTextDocument>
#include <QTextLayout>
#include <QTimer>

#include <cstdlib>
#include <memory>

extern "C" int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
extern "C" void logsquirl_plugin_shutdown( void );

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A UDP datagram of conversation @p i.
Bytes datagram( int i )
{
    return eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( static_cast<uint16_t>( 40000 + i ), 9999,
                                                      text( "live" ) ) ) );
}

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( const std::shared_ptr<FakeSourceKind>& kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( kind );
    return registry;
}

/// The form's fields.
struct Fields {
    explicit Fields( QWidget* in )
        : source( in->findChild<QComboBox*>( "liveSource" ) )
        , status( in->findChild<QLabel*>( "liveSourceStatus" ) )
        , networkInterface( in->findChild<QComboBox*>( "liveInterface" ) )
        , refresh( in->findChild<QPushButton*>( "liveRefresh" ) )
        , filter( in->findChild<QLineEdit*>( "liveFilter" ) )
        , filterHint( in->findChild<QLabel*>( "liveFilterHint" ) )
        , snaplen( in->findChild<QSpinBox*>( "liveSnaplen" ) )
        , start( in->findChild<QPushButton*>( "liveStartButton" ) )
    {
        REQUIRE( source );
        REQUIRE( status );
        REQUIRE( networkInterface );
        REQUIRE( refresh );
        REQUIRE( filter );
        REQUIRE( filterHint );
        REQUIRE( snaplen );
        REQUIRE( start );
    }

    QComboBox* source;
    QLabel* status;
    QComboBox* networkInterface;
    QPushButton* refresh;
    QLineEdit* filter;
    QLabel* filterHint;
    QSpinBox* snaplen;
    QPushButton* start;
};

/// Press Start live capture… in @p sidebar, a view of @p sessions, and start
/// what @p dialog shows, as if the dialog it opens were filled so and its
/// Start pressed.
void startFrom( CaptureSessions& sessions, SidebarWidget& sidebar, const LiveCaptureDialog& dialog )
{
    sessions.setLiveChoiceAsker( [ &dialog ]( QWidget*, LiveChoice& choice ) {
        choice = dialog.choice();
        return true;
    } );
    auto* button = sidebar.findChild<QPushButton*>( "liveCaptureButton" );
    REQUIRE( button );
    button->click();
}

/// The fixed-width font found for the system's.
QString fixedFamily()
{
    return fixedFontFamily();
}

/// How guidanceHtml() shows a command, @p html, on a line of its own.
QString commandHtml( const QString& html )
{
    return QString( "<p style=\"white-space:pre-wrap\"><code style=\"font-family:'%1'\">%2</code>"
                    "</p>" )
        .arg( fixedFamily(), html );
}

/// Whether @p label, shown in @p window, shows all of its text: its lines,
/// wrapped at its own width, are no wider than it and no more than it is
/// tall, and it ends before the window's right edge.  Where the platform's
/// font makes a word wider than the label (the Windows runner's offscreen
/// fallback font, twice as wide as a real one), no wrapping at words can
/// fit it: only the right edge is checked, with a warning.
bool fitsWidth( const QLabel* label, const QWidget* window )
{
    const auto right = label->mapTo( window, QPoint( label->width(), 0 ) ).x();
    QTextDocument words;
    words.setDefaultFont( label->font() );
    words.setHtml( label->text() );
    words.setDocumentMargin( 0 );
    auto wordWrap = words.defaultTextOption();
    wordWrap.setWrapMode( QTextOption::WordWrap ); // not anywhere, as a document would
    words.setDefaultTextOption( wordWrap );
    words.setTextWidth( 0 ); // its ideal width is then its widest word's
    if ( words.idealWidth() > label->contentsRect().width() ) {
        WARN( "a word is " << words.idealWidth() << " px wide in this platform's font, "
                           << label->contentsRect().width() << " px fit the label" );
        return right <= window->width();
    }

    QTextDocument document;
    document.setDefaultFont( label->font() );
    document.setHtml( label->text() );
    document.setDocumentMargin( 0 );
    // As a word-wrapped label wraps: at word boundaries alone.
    auto option = document.defaultTextOption();
    option.setWrapMode( QTextOption::WordWrap );
    document.setDefaultTextOption( option );
    document.setTextWidth( label->contentsRect().width() );
    UNSCOPED_INFO( "text " << document.idealWidth() << " x " << document.size().height() << " in "
                           << label->contentsRect().width() << " x "
                           << label->contentsRect().height() << ", right edge " << right << " of "
                           << window->width() << ", font "
                           << label->font().family().toStdString() );
    return document.idealWidth() <= label->contentsRect().width() && right <= window->width()
           && document.size().height() <= label->contentsRect().height();
}

/// Wait until @p form has listed the fake's two interfaces.
bool listed( const LiveCaptureForm* form, const Fields& fields )
{
    return waitFor( [ & ] { return !form->isListing() && fields.networkInterface->count() == 2; } );
}

} // namespace

SCENARIO( "Start live capture… captures what its dialog is given, and Stop finalises it",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->capture = pcapOf( { datagram( 0 ), datagram( 1 ), datagram( 2 ) } );

    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sessions.setTempRoot( root.path() );
    sessions.setLiveSources( registryOf( fake ) );
    auto* button = sidebar.findChild<QPushButton*>( "liveCaptureButton" );
    auto* stop = sidebar.findChild<QPushButton*>( "stopButton" );
    auto* stderrView = sidebar.findChild<QPlainTextEdit*>( "liveStderr" );
    REQUIRE( sidebar.findChild<QWidget*>( "liveSection" ) );

    THEN( "the sidebar has no form of its own, and lists nothing until the dialog opens" )
    {
        REQUIRE_FALSE( sidebar.findChild<LiveCaptureForm*>() );
        REQUIRE( fake->interfaceListings == 0 );
        REQUIRE( button->isEnabled() );
        REQUIRE_FALSE( button->isHidden() );
    }

    const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
    auto* form = dialog->form();
    const Fields fields( dialog.get() );

    GIVEN( "the fake source chosen and its two interfaces listed" )
    {
        REQUIRE( fields.source->currentText() == "Fake" );
        REQUIRE( listed( form, fields ) );
        REQUIRE( fields.networkInterface->itemText( 0 ) == "fake0 \xe2\x80\x94 Fake Ethernet" );
        REQUIRE( fields.networkInterface->itemData( 1 ).toString() == "fake1" );
        REQUIRE( fields.snaplen->value() == 262144 );
        REQUIRE( fields.start->isEnabled() );

        WHEN( "the second interface, a filter and a snaplen are chosen and Start is pressed" )
        {
            fields.networkInterface->setCurrentIndex( 1 );
            fields.filter->setText( "udp port 9999 and host 10.0.0.1" );
            fields.snaplen->setValue( 1500 );
            startFrom( sessions, sidebar, *dialog );

            THEN( "the source is asked for exactly that, and the tab opens following the file" )
            {
                REQUIRE( sessions.liveSession().isBusy() );
                REQUIRE( fake->started().size() == 1 );
                const auto choice = fake->started().front();
                REQUIRE(
                    choice
                    == LiveChoice{ "fake", "", "fake1", "udp port 9999 and host 10.0.0.1", 1500 } );
                REQUIRE( fake->command( choice ).arguments
                         == QStringList{ "-i", "fake1", "-s", "1500",
                                         "udp port 9999 and host 10.0.0.1" } );
                REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
                REQUIRE( QFileInfo( host.openedFiles.first() ).fileName() == "fake1.log" );
                REQUIRE( host.openedFollowing == QList<bool>{ true } );
            }

            THEN( "Start live capture… is gone while it runs; Stop, the counters and stderr show" )
            {
                REQUIRE( button->isHidden() );
                REQUIRE_FALSE( stop->isHidden() );
                auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
                REQUIRE( waitFor( [ & ] { return live->text().contains( "Packets: 3" ); } ) );
                REQUIRE( live->text().contains( "packets/s" ) );
                REQUIRE( live->text().contains( "Elapsed" ) );
                REQUIRE( waitFor( [ & ] { return !stderrView->isHidden(); } ) );
                REQUIRE( stderrView->toPlainText() == "fakecap: listening" );
            }

            THEN( "Open pcap… is disabled, and opening a file is refused with the Activity rule's "
                  "reason" )
            {
                REQUIRE_FALSE( sidebar.findChild<QPushButton*>( "openButton" )->isEnabled() );
                sessions.chooseAndOpen();
                REQUIRE( host.notifications
                         == QStringList{ refusalMessage( ActivityRefusal::Capturing ) } );
            }

            AND_WHEN( "Stop is pressed" )
            {
                REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
                const auto logPath = host.openedFiles.first();
                sessions.catalog().setFront( logPath );
                REQUIRE( waitFor( [ & ] { return readLines( logPath ).size() == 4; } ) );
                stop->click();
                REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

                THEN( "the capture is final, and Start live capture… is back" )
                {
                    REQUIRE( sidebar.findChild<QLabel*>( "summary" )
                                 ->text()
                                 .contains( "Packets: <b>3</b>" ) );
                    REQUIRE_FALSE( button->isHidden() );
                    REQUIRE( button->isEnabled() );
                    REQUIRE( host.notifications.isEmpty() );
                }

                THEN( "the dialog shows the choice again after a restart" )
                {
                    CaptureSessions restarted;
                    restarted.setLiveSources( registryOf( fake ) );
                    const auto shown = restarted.makeLiveCaptureDialog( nullptr );
                    const Fields again( shown.get() );
                    REQUIRE( listed( shown->form(), again ) );
                    REQUIRE( shown->choice()
                             == LiveChoice{ "fake", "", "fake1", "udp port 9999 and host 10.0.0.1",
                                            1500 } );
                    REQUIRE( again.networkInterface->currentIndex() == 1 );
                }
            }
        }

        WHEN( "an interface the source does not list is typed" )
        {
            fields.networkInterface->setEditText( "any" );

            THEN( "it is the choice" )
            {
                REQUIRE( form->choice().networkInterface == "any" );
                REQUIRE( fields.start->isEnabled() );
            }
        }

        WHEN( "Refresh is pressed" )
        {
            fields.networkInterface->setCurrentIndex( 1 );
            const int before = fake->interfaceListings;
            fields.refresh->click();
            REQUIRE( form->isListing() );
            REQUIRE( listed( form, fields ) );

            THEN( "the interfaces are listed anew, and the one chosen stays chosen" )
            {
                REQUIRE( fake->interfaceListings == before + 1 );
                REQUIRE( form->choice().networkInterface == "fake1" );
            }
        }

        WHEN( "a display filter is typed as the capture filter" )
        {
            fields.filter->setText( "ip.addr == 10.0.0.1" );

            THEN( "the hint below says so, and Start is disabled with the reason" )
            {
                REQUIRE_FALSE( fields.filterHint->isHidden() );
                REQUIRE( fields.filterHint->text().contains( "display filter" ) );
                REQUIRE_FALSE( fields.start->isEnabled() );
                REQUIRE( fields.start->toolTip().contains( "display filter" ) );
                REQUIRE_FALSE( sessions.liveSession().start( form->choice() ) );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( fake->started().empty() );
            }
        }

        WHEN( "a capture file is being read" )
        {
            sessions.conversionSession().start(
                QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( "mixed.pcap" ) );

            THEN( "Start live capture… is disabled until it is done" )
            {
                REQUIRE_FALSE( button->isEnabled() );
                REQUIRE( button->toolTip().contains( "being read" ) );
                REQUIRE( waitFor( [ & ] { return !sessions.conversionSession().isBusy(); } ) );
                REQUIRE( button->isEnabled() );
            }
        }
    }
}

SCENARIO( "The stop conditions and the ring buffer are fields of the form, for every source",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->capture = pcapOf( { datagram( 0 ), datagram( 1 ), datagram( 2 ) } );

    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sessions.setTempRoot( root.path() );
    sessions.setLiveSources( registryOf( fake ) );
    const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
    auto* form = dialog->form();
    const Fields fields( dialog.get() );
    auto spin = [ & ]( const char* name ) {
        auto* box = dialog->findChild<QSpinBox*>( name );
        REQUIRE( box );
        return box;
    };
    auto* stopSeconds = spin( "liveStopSeconds" );
    auto* stopPackets = spin( "liveStopPackets" );
    auto* stopMegabytes = spin( "liveStopMegabytes" );
    auto* ringFiles = spin( "liveRingFiles" );
    auto* ringMegabytes = spin( "liveRingMegabytes" );
    auto* ringSeconds = spin( "liveRingSeconds" );
    REQUIRE( listed( form, fields ) );

    THEN( "none is set at first: the capture runs until Stop, into one file" )
    {
        REQUIRE( form->choice().limits == LiveLimits{} );
        REQUIRE( stopSeconds->text() == "no limit" );
        REQUIRE( ringFiles->text() == "off" );
        REQUIRE_FALSE( ringMegabytes->isEnabled() );
        REQUIRE_FALSE( ringSeconds->isEnabled() );
    }

    WHEN( "they are set" )
    {
        stopSeconds->setValue( 3600 );
        stopPackets->setValue( 1000 );
        stopMegabytes->setValue( 50 );
        ringFiles->setValue( 4 );
        ringMegabytes->setValue( 10 );
        ringSeconds->setValue( 300 );

        THEN( "they are the choice's limits, the sizes in bytes" )
        {
            const auto limits = form->choice().limits;
            REQUIRE( limits.duration == std::chrono::seconds( 3600 ) );
            REQUIRE( limits.packets == 1000 );
            REQUIRE( limits.bytes == 50 * kMegabyte );
            REQUIRE( limits.ringFiles == 4 );
            REQUIRE( limits.fileBytes == 10 * kMegabyte );
            REQUIRE( limits.fileDuration == std::chrono::seconds( 300 ) );
            REQUIRE( ringMegabytes->isEnabled() );
            REQUIRE( fields.start->isEnabled() );
        }

        AND_WHEN( "the dialog is opened by new sessions after a capture" )
        {
            REQUIRE( saveLiveChoice( host.configDir(), form->choice() ) );
            CaptureSessions restarted;
            restarted.setLiveSources( registryOf( fake ) );

            THEN( "the fields are restored" )
            {
                REQUIRE( restarted.makeLiveCaptureDialog( nullptr )->choice().limits
                         == form->choice().limits );
            }
        }
    }

    WHEN( "a ring buffer keeps files but has no size or duration to start a new one at" )
    {
        ringFiles->setValue( 3 );

        THEN( "Start is disabled with the reason" )
        {
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( fields.start->toolTip().contains( "ring buffer needs a file size" ) );
            REQUIRE_FALSE( sessions.liveSession().start( form->choice() ) );
            REQUIRE( fake->started().empty() );
        }
    }

    WHEN( "the capture is to stop after two packets, and three come" )
    {
        stopPackets->setValue( 2 );
        startFrom( sessions, sidebar, *dialog );
        REQUIRE( sessions.liveSession().isBusy() );
        auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
        const auto progress = live->text();
        REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

        THEN( "the counters showed the condition, and the capture ended by itself with two" )
        {
            REQUIRE( progress.contains( "Stops at 2 packets" ) );
            REQUIRE( fake->started().front().limits.packets == 2 );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().contains( "stopped after 2 packets" ) );
            REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
            REQUIRE( readLines( host.openedFiles.first() ).size() == 3 );
        }
    }
}

SCENARIO( "An unavailable source says why in the dialog, and a failed capture shows its error in "
          "the section",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();

    GIVEN( "a source that is unavailable" )
    {
        fake->unavailableReason = "fakecap not found: install the Fake Capture Tools";
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        sessions.setLiveSources( registryOf( fake ) );
        const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
        const Fields fields( dialog.get() );

        THEN( "the dialog shows the reason, lists nothing, and Start is disabled" )
        {
            REQUIRE_FALSE( fields.status->isHidden() );
            REQUIRE( fields.status->text() == fake->unavailableReason );
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( fields.start->toolTip() == fake->unavailableReason );
            REQUIRE( fake->interfaceListings == 0 );
            REQUIRE_FALSE( fields.networkInterface->isEnabled() );
        }

        THEN( "starting it anyway is refused with the reason" )
        {
            REQUIRE_FALSE(
                sessions.liveSession().start( LiveChoice{ "fake", "", "fake0", "", 100 } ) );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().contains( "fakecap not found" ) );
            REQUIRE( fake->started().empty() );
        }
    }

    GIVEN( "a source whose capture fails with a permission error" )
    {
        fake->capture = pcapOf( { datagram( 0 ) } );
        fake->failure = "fakecap exited with code 1:\nfakecap: permission denied";
        fake->hint = "Give fakecap the capture permission.";
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        sessions.setLiveSources( registryOf( fake ) );
        const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
        const Fields fields( dialog.get() );
        REQUIRE( listed( dialog->form(), fields ) );
        startFrom( sessions, sidebar, *dialog );
        REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

        THEN( "the section shows the error and what the source says to do" )
        {
            auto* error = sidebar.findChild<QLabel*>( "liveError" );
            REQUIRE_FALSE( error->isHidden() );
            REQUIRE( error->text().contains( "fakecap: permission denied" ) );
            REQUIRE( error->text().contains( "Give fakecap the capture permission." ) );
            REQUIRE( host.notifications.size() == 1 );
        }

        AND_WHEN( "the next capture starts" )
        {
            fake->failure.clear();
            startFrom( sessions, sidebar, *dialog );

            THEN( "the error goes" )
            {
                REQUIRE( sidebar.findChild<QLabel*>( "liveError" )->isHidden() );
                sessions.liveSession().stop();
                REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
            }
        }
    }

    GIVEN( "a source whose capture fails before a packet, its Guidance like markup" )
    {
        fake->failure = "fakecap exited with code 1:\nfakecap: <eth0> permission denied";
        fake->hint = "Run: setcap cap_net_raw=eip <fakecap> && log in again.";
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        sessions.setLiveSources( registryOf( fake ) );
        const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
        const Fields fields( dialog.get() );
        REQUIRE( listed( dialog->form(), fields ) );
        startFrom( sessions, sidebar, *dialog );
        REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

        THEN( "the section shows the error's lines and the Guidance as text, the summary not the "
              "error again" )
        {
            const auto outcome = sessions.liveSession().outcome();
            REQUIRE( outcome );
            REQUIRE( outcome->status == LiveOutcome::Status::Failed );
            REQUIRE( outcome->files.isEmpty() );
            auto* error = sidebar.findChild<QLabel*>( "liveError" );
            REQUIRE_FALSE( error->isHidden() );
            REQUIRE( error->text()
                     == "Error: Cannot read the capture: fakecap exited with code 1:<br>fakecap: "
                        "&lt;eth0&gt; permission denied<br>Run: setcap cap_net_raw=eip "
                        "&lt;fakecap&gt; &amp;&amp; log in again." );
            REQUIRE( sidebar.findChild<QLabel*>( "summary" )->text()
                     == "The capture fake0 failed before anything was captured." );
            REQUIRE( host.openedFiles.isEmpty() );
        }

        THEN( "the error is in the sidebar once" )
        {
            int shown = 0;
            for ( const auto* label : sidebar.findChildren<QLabel*>() ) {
                if ( !label->isHidden() && label->text().contains( "permission denied" ) ) {
                    ++shown;
                }
            }
            REQUIRE( shown == 1 );
        }
    }
}

SCENARIO( "A failure's commands and links wrap in a narrow sidebar, nothing cut off", "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->failure = "fakecap exited with code 1:\nfakecap: permission denied";
    const auto [ os, command ] = GENERATE( table<CaptureOs, QString>(
        { { CaptureOs::MacOS, "sudo dseditgroup -o edit -a \"$USER\" -t user access_bpf" },
          { CaptureOs::Linux,
            "sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/lib/wireshark/dumpcap" } } ) );
    fake->hint = capturePermissionGuidance( os, "/usr/local/lib/wireshark/dumpcap" );
    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sidebar.resize( 300, 900 );
    sidebar.show();
    sessions.setTempRoot( root.path() );
    sessions.setLiveSources( registryOf( fake ) );
    const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
    const Fields fields( dialog.get() );
    REQUIRE( listed( dialog->form(), fields ) );
    startFrom( sessions, sidebar, *dialog );
    REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
    QApplication::processEvents();

    THEN( "the section shows every word of the command and the whole link within its width" )
    {
        auto* error = sidebar.findChild<QLabel*>( "liveError" );
        REQUIRE_FALSE( error->isHidden() );
        REQUIRE( fitsWidth( error, &sidebar ) );
        QTextDocument document;
        document.setHtml( error->text() );
        REQUIRE( document.toPlainText().contains( command ) );
        if ( os == CaptureOs::MacOS ) {
            REQUIRE( error->text().contains( "<a href=\"https://www.wireshark.org/download.html\">"
                                             "https://www.wireshark.org/download.html</a>" ) );
        }
        REQUIRE( error->openExternalLinks() );
        REQUIRE( error->textInteractionFlags().testFlag( Qt::TextSelectableByMouse ) );
        REQUIRE( error->textInteractionFlags().testFlag( Qt::LinksAccessibleByMouse ) );
    }
}

SCENARIO( "A source with devices lists them, and the interfaces of the one chosen", "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->deviceMode = LiveSourceKind::Devices::Listed;
    fake->capture = pcapOf( { datagram( 0 ) } );
    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sessions.setTempRoot( root.path() );
    sessions.setLiveSources( registryOf( fake ) );
    const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
    const Fields fields( dialog.get() );
    auto* device = dialog->findChild<QComboBox*>( "liveDevice" );
    REQUIRE( listed( dialog->form(), fields ) );

    THEN( "the unauthorized device is listed with its problem but not chosen" )
    {
        REQUIRE_FALSE( device->isHidden() );
        REQUIRE( device->count() == 2 );
        REQUIRE( device->itemText( 0 ).contains( "unauthorized" ) );
        REQUIRE( device->currentIndex() == 1 );
        REQUIRE( fake->listedDevices() == QStringList{ "phoneA" } );
    }

    WHEN( "it is started" )
    {
        startFrom( sessions, sidebar, *dialog );
        REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );

        THEN( "the device is part of the choice and of the capture's name" )
        {
            REQUIRE( fake->started().front().device == "phoneA" );
            REQUIRE( QFileInfo( host.openedFiles.first() ).fileName() == "phoneA-fake0.log" );
        }
        sessions.liveSession().stop();
        REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
    }
}

SCENARIO( "A long interface name does not widen the Start live capture dialog", "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->firstDescription = QString( 200, 'w' );
    LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
    const Fields fields( &dialog );
    REQUIRE( listed( dialog.form(), fields ) );

    THEN( "the dialog stays narrow, the field shows the start of the entry, the list it whole" )
    {
        const int longest = dialog.fontMetrics().horizontalAdvance( fake->firstDescription );
        REQUIRE( dialog.minimumSizeHint().width() < longest / 2 );
        REQUIRE( dialog.sizeHint().width() < longest / 2 );
        REQUIRE( fields.networkInterface->currentIndex() == 0 );
        REQUIRE( fields.networkInterface->itemText( 0 ).contains( fake->firstDescription ) );
        REQUIRE( fields.networkInterface->lineEdit()->cursorPosition() == 0 );
    }
}

SCENARIO( "A source's descriptions show in the dialog's lists as typed, and cut when long",
          "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();

    GIVEN( "an interface whose description is markup" )
    {
        const QString markup = "<b>Fake</b> <img src=\"file:///etc/logo.png\"> & co";
        fake->firstDescription = markup;
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );
        REQUIRE( listed( dialog.form(), fields ) );

        THEN( "the entry and its tooltip show the description's characters" )
        {
            REQUIRE( fields.networkInterface->itemText( 0 ).contains( markup ) );
            REQUIRE( asShown( fields.networkInterface->itemData( 0, Qt::ToolTipRole ).toString() )
                     == markup );
        }
    }

    GIVEN( "an interface whose description is a megabyte long" )
    {
        fake->firstDescription = QString( 1024 * 1024, 'w' );
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );
        REQUIRE( listed( dialog.form(), fields ) );

        THEN( "the entry and its tooltip show its start, cut off" )
        {
            const auto tip
                = asShown( fields.networkInterface->itemData( 0, Qt::ToolTipRole ).toString() );
            REQUIRE( tip == QString( kMaxShownTextChars, 'w' ) + QChar( 0x2026 ) );
            REQUIRE( fields.networkInterface->itemText( 0 ).endsWith( tip ) );
        }
    }
}

SCENARIO( "A source of typed devices that lists none says where they come from, and how to type "
          "one",
          "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->deviceMode = LiveSourceKind::Devices::Typed;
    fake->listsNoDevices = true;
    LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
    const Fields fields( &dialog );
    auto* device = dialog.findChild<QComboBox*>( "liveDevice" );
    REQUIRE( waitFor( [ & ] { return !dialog.form()->isListing(); } ) );

    THEN( "the status says the source's text, and the empty field shows the form to type" )
    {
        REQUIRE_FALSE( fields.status->isHidden() );
        REQUIRE( fields.status->text() == "No phone is plugged in: type its serial." );
        REQUIRE( device->isEditable() );
        REQUIRE( device->lineEdit()->placeholderText() == "serial" );
        REQUIRE( fake->interfaceListings == 0 );
    }
}

SCENARIO( "A source's own options show in the dialog, are part of the choice, and are kept",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->withOptions = true;
    fake->capture = pcapOf( { datagram( 0 ) } );
    auto plain = std::make_shared<FakeSourceKind>( "plain", "Plain" );
    auto registry = registryOf( fake );
    registry->add( plain );

    auto sessions = std::make_unique<CaptureSessions>();
    auto sidebar = std::make_unique<SidebarWidget>( *sessions );
    sessions->setTempRoot( root.path() );
    sessions->setLiveSources( registry );
    auto dialog = sessions->makeLiveCaptureDialog( nullptr );
    auto* form = dialog->form();
    const Fields fields( dialog.get() );
    REQUIRE( listed( form, fields ) );
    auto* note = dialog->findChild<QLineEdit*>( "fakeNote" );
    REQUIRE( note );

    WHEN( "an option is set" )
    {
        int changes = 0;
        QObject::connect( form, &LiveCaptureForm::changed, [ & ] { ++changes; } );
        note->setText( "hello" );

        THEN( "it is part of the choice, and the form says it changed" )
        {
            REQUIRE( changes > 0 );
            REQUIRE( form->choice().options == LiveOptions{ { "note", "hello" } } );
            REQUIRE( fields.start->isEnabled() );
        }

        AND_WHEN( "another source is chosen, and then this one again" )
        {
            fields.source->setCurrentIndex( 1 );
            emit fields.source->activated( 1 );

            THEN( "the other source has no options widget, and this one's options stay" )
            {
                REQUIRE_FALSE( dialog->findChild<QLineEdit*>( "fakeNote" ) );
                REQUIRE( form->choice().options.isEmpty() );
                fields.source->setCurrentIndex( 0 );
                emit fields.source->activated( 0 );
                auto* again = dialog->findChild<QLineEdit*>( "fakeNote" );
                REQUIRE( again );
                REQUIRE( again->text() == "hello" );
                REQUIRE( form->choice().options == LiveOptions{ { "note", "hello" } } );
            }
        }

        AND_WHEN( "the capture is started and the plugin restarts" )
        {
            startFrom( *sessions, *sidebar, *dialog );
            REQUIRE( fake->started().size() == 1 );
            REQUIRE( fake->started().front().options == LiveOptions{ { "note", "hello" } } );
            sessions->liveSession().stop();
            REQUIRE( waitFor( [ & ] { return !sessions->liveSession().isBusy(); } ) );
            // The dialog lists on the sessions' pool: it goes first.
            dialog.reset();
            sidebar.reset();
            sessions.reset();
            CaptureSessions restarted;
            restarted.setLiveSources( registry );
            const auto shown = restarted.makeLiveCaptureDialog( nullptr );

            THEN( "the option is shown again" )
            {
                auto* again = shown->findChild<QLineEdit*>( "fakeNote" );
                REQUIRE( again );
                REQUIRE( again->text() == "hello" );
                REQUIRE( shown->choice().options == LiveOptions{ { "note", "hello" } } );
            }
        }
    }

    WHEN( "an option the source does not accept is set" )
    {
        note->setText( "bad" );

        THEN( "Start is disabled with the source's reason" )
        {
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( fields.start->toolTip() == "The note is bad." );
        }
    }

    WHEN( "a choice with options is set" )
    {
        form->setChoice( LiveChoice{ "fake", "", "fake0", "", 100, { { "note", "given" } } } );

        THEN( "the widget shows them" )
        {
            REQUIRE( dialog->findChild<QLineEdit*>( "fakeNote" )->text() == "given" );
        }
    }
}

SCENARIO( "A source's text shows its commands on lines of their own and its links as links",
          "[live_ui]" )
{
    THEN( "a command in backticks is a block, without the punctuation that ended it" )
    {
        REQUIRE( guidanceHtml( "If not, run `sudo x -a \"$USER\"`, then log in again." )
                 == "If not, run" + commandHtml( "sudo x -a &quot;$USER&quot;" )
                        + "then log in again." );
        REQUIRE( guidanceHtml( "Restart adb: `adb kill-server`." )
                 == "Restart adb:" + commandHtml( "adb kill-server" ) );
    }

    THEN( "a command wraps at the width it gets, in a fixed-width font, and is copied whole" )
    {
        const QString command = "sudo dseditgroup -o edit -a \"$USER\" -t user access_bpf";
        QTextDocument document;
        document.setHtml( guidanceHtml( "If not, run `" + command + "`, then log in again." ) );
        const auto oneLine = document.idealWidth();
        document.setTextWidth( 120 );
        REQUIRE( document.idealWidth() <= 120 );
        REQUIRE( document.size().height() > 0 );
        REQUIRE( document.toPlainText().contains( command ) );
        const auto at = document.toPlainText().indexOf( command );
        const auto block = document.findBlock( static_cast<int>( at ) );
        REQUIRE( block.text() == command );
        REQUIRE( block.layout()->lineCount() > 1 );
        // In the system's fixed-width font, which the offscreen platform of
        // the tests may not have.
        const bool fixedFound = QFontInfo( QFont( fixedFamily() ) ).fixedPitch();
        for ( auto fragment = block.begin(); !fragment.atEnd(); ++fragment ) {
            const auto format = fragment.fragment().charFormat();
            REQUIRE( format.fontFamilies().toStringList() == QStringList{ fixedFamily() } );
            REQUIRE( QFontInfo( format.font() ).fixedPitch() == fixedFound );
        }
        REQUIRE( oneLine > 120 );
        const auto prose = document.findBlock( 0 ).begin().fragment().charFormat();
        REQUIRE_FALSE( prose.fontFamilies().toStringList().contains( fixedFamily() ) );
    }

    THEN( "a URL of the plugin's own guidance is a link, without the punctuation after it" )
    {
        REQUIRE( guidanceHtml( "Get it (https://www.wireshark.org/download.html, \"pkg\")." )
                 == "Get it (<a href=\"https://www.wireshark.org/download.html\">"
                    "https://www.wireshark.org/download.html</a>, &quot;pkg&quot;)." );
        REQUIRE(
            guidanceHtml( "From https://npcap.com/#download." )
            == "From <a href=\"https://npcap.com/#download\">https://npcap.com/#download</a>." );
    }

    THEN( "any other URL is text, to be read but not clicked" )
    {
        REQUIRE( guidanceHtml( "Sign in at https://example.org/login." )
                 == "Sign in at https://example.org/login." );
        REQUIRE( guidanceHtml( "See https://npcap.com/#download.example.org now" )
                 == "See https://npcap.com/#download.example.org now" );
    }

    THEN( "the install hints keep their links" )
    {
        REQUIRE( guidanceHtml( adbInstallHint() )
                     .contains( "<a href=\"https://developer.android.com/tools/releases/"
                                "platform-tools\">" ) );
        REQUIRE( guidanceHtml( capturePermissionGuidance( CaptureOs::Windows, {} ) )
                     .contains( "<a href=\"https://npcap.com/#download\">" ) );
    }

    THEN( "line breaks are kept, markup is escaped, and a lone backtick is shown as it is" )
    {
        REQUIRE( guidanceHtml( "a <b>\n1. & `c" ) == "a &lt;b&gt;<br>1. &amp; `c" );
    }

    THEN( "the macOS permission guidance shows its command and its download link so" )
    {
        const auto html = guidanceHtml( capturePermissionGuidance( CaptureOs::MacOS, {} ) );
        REQUIRE( html.contains(
            commandHtml( "sudo dseditgroup -o edit -a &quot;$USER&quot; -t user access_bpf" ) ) );
        REQUIRE( html.contains( "<a href=\"https://www.wireshark.org/download.html\">" ) );
    }

    GIVEN( "a source unavailable for a reason with a command" )
    {
        FakeHost host;
        auto fake = std::make_shared<FakeSourceKind>();
        fake->unavailableReason = "fakecap cannot capture: run `fakecap --allow`.";
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );

        THEN( "the dialog's status shows it so, its links open" )
        {
            REQUIRE( fields.status->text()
                     == "fakecap cannot capture: run" + commandHtml( "fakecap --allow" ) );
            REQUIRE( fields.status->openExternalLinks() );
        }
    }

    GIVEN( "a source unavailable for a reason with a long command" )
    {
        FakeHost host;
        auto plain = std::make_shared<FakeSourceKind>();
        plain->unavailableReason = "fakecap cannot capture.";
        LiveCaptureDialog plainDialog( registryOf( plain ), LiveChoice{ "fake", "", "", "", 100 } );
        auto fake = std::make_shared<FakeSourceKind>();
        fake->unavailableReason = "fakecap cannot capture: run `sudo fakecap --allow-capture "
                                  "--on-every-interface --for-the-group fakecap-users --and-keep-"
                                  "it-so-after-a-restart --without-asking-again "
                                  "/usr/local/lib/fakecap/bin/fakecap-helper`.";
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );

        THEN( "the dialog is no wider than with a short reason, and shows all of the command" )
        {
            REQUIRE( dialog.sizeHint().width() <= plainDialog.sizeHint().width() );
            dialog.show();
            QApplication::processEvents();
            REQUIRE( fitsWidth( fields.status, &dialog ) );
        }
    }
}

SCENARIO( "A URL a program wrote is text in the dialog's status and the section's error, but the "
          "plugin's own are links",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    const QString phishing = "https://login.example.org/session";

    GIVEN( "a source whose listing fails with a URL from its program" )
    {
        fake->listingError = "fakecap exited with code 1:\nfakecap: sign in at " + phishing;
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );
        REQUIRE( waitFor( [ & ] { return !dialog.form()->isListing(); } ) );

        THEN( "the status shows the URL as text" )
        {
            REQUIRE_FALSE( fields.status->isHidden() );
            REQUIRE( fields.status->text().contains( phishing ) );
            REQUIRE_FALSE( fields.status->text().contains( "<a " ) );
        }
    }

    GIVEN( "a source unavailable for a reason with the plugin's own download link" )
    {
        fake->unavailableReason = "Install Npcap from https://npcap.com/#download.";
        LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
        const Fields fields( &dialog );

        THEN( "the status links to it" )
        {
            REQUIRE( fields.status->text().contains( "<a href=\"https://npcap.com/#download\">" ) );
            REQUIRE( fields.status->openExternalLinks() );
        }
    }

    GIVEN( "a capture that fails with a URL on its program's stderr, and Guidance with the "
           "plugin's own" )
    {
        fake->failure
            = ( "fakecap exited with code 1:\nfakecap: permission denied, see " + phishing )
                  .toStdString();
        fake->hint = "Install Npcap from https://npcap.com/#download.";
        CaptureSessions sessions;
        SidebarWidget sidebar( sessions );
        sessions.setTempRoot( root.path() );
        sessions.setLiveSources( registryOf( fake ) );
        const auto dialog = sessions.makeLiveCaptureDialog( nullptr );
        const Fields fields( dialog.get() );
        REQUIRE( listed( dialog->form(), fields ) );
        startFrom( sessions, sidebar, *dialog );
        REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );

        THEN( "the section's error shows the program's URL as text, the Guidance's as a link" )
        {
            auto* error = sidebar.findChild<QLabel*>( "liveError" );
            REQUIRE_FALSE( error->isHidden() );
            REQUIRE( error->text().contains( "see " + phishing ) );
            REQUIRE_FALSE( error->text().contains( "href=\"" + phishing ) );
            REQUIRE( error->text().contains( "<a href=\"https://npcap.com/#download\">" ) );
            REQUIRE( error->openExternalLinks() );
        }
    }
}

SCENARIO( "A source's status is a note that stands out from the form, in light and dark mode",
          "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->unavailableReason = "fakecap cannot capture: run `fakecap --allow`.";
    LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
    const Fields fields( &dialog );
    auto* note = dialog.findChild<QWidget*>( "liveSourceNote" );
    auto* icon = dialog.findChild<QLabel*>( "liveSourceNoteIcon" );
    REQUIRE( note );
    REQUIRE( icon );

    THEN( "the status is in the note, beside an icon, and wraps, links and selects as before" )
    {
        REQUIRE_FALSE( note->isHidden() );
        REQUIRE( note->isAncestorOf( fields.status ) );
        REQUIRE_FALSE( icon->pixmap().isNull() );
        REQUIRE( fields.status->wordWrap() );
        REQUIRE( fields.status->openExternalLinks() );
        REQUIRE( fields.status->textInteractionFlags().testFlag( Qt::TextSelectableByMouse ) );
        REQUIRE( fields.status->text()
                 == "fakecap cannot capture: run" + commandHtml( "fakecap --allow" ) );
    }

    THEN( "its panel is tinted from the palette: apart from the window, its text still legible" )
    {
        struct Mode {
            const char* name;
            QColor window;
            QColor text;
        };
        for ( const auto& mode :
              { Mode{ "light", QColor( 0xf0, 0xf0, 0xf0 ), Qt::black },
                Mode{ "dark", QColor( 0x2b, 0x2b, 0x2b ), QColor( 0xe0, 0xe0, 0xe0 ) } } ) {
            CAPTURE( mode.name );
            QPalette palette;
            palette.setColor( QPalette::Window, mode.window );
            palette.setColor( QPalette::WindowText, mode.text );
            palette.setColor( QPalette::Highlight, QColor( 0x38, 0x74, 0xd8 ) );
            dialog.setPalette( palette );
            dialog.show();
            QApplication::processEvents();
            const auto image = note->grab().toImage();
            const auto background = image.pixelColor( 3, image.height() / 2 );
            REQUIRE( background != mode.window );
            REQUIRE( std::abs( background.lightness() - mode.window.lightness() ) < 64 );
            REQUIRE( std::abs( background.lightness() - mode.text.lightness() ) > 128 );
        }
    }

    WHEN( "the source has nothing to say" )
    {
        fake->unavailableReason.clear();
        dialog.form()->refresh();
        REQUIRE( listed( dialog.form(), fields ) );

        THEN( "the note is hidden" )
        {
            REQUIRE( note->isHidden() );
            REQUIRE( fields.status->isHidden() );
        }
    }
}

SCENARIO( "Start waits for a source whose listing says it cannot capture, until one says it can",
          "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->cannotCapture = "/dev/bpf0 cannot be read, so fakecap cannot capture.";
    auto other = std::make_shared<FakeSourceKind>( "other", "Other" );
    auto registry = registryOf( fake );
    registry->add( other );
    LiveCaptureDialog dialog( registry, LiveChoice{ "fake", "", "", "", 100 } );
    const Fields fields( &dialog );
    REQUIRE( listed( dialog.form(), fields ) );

    THEN( "the interfaces are listed, the note says why and what to do, and Start is disabled "
          "with the reason" )
    {
        REQUIRE( dialog.choice().networkInterface == "fake0" );
        REQUIRE_FALSE( fields.status->isHidden() );
        REQUIRE( fields.status->text().contains( "/dev/bpf0 cannot be read" ) );
        REQUIRE( fields.status->text().contains( commandHtml( "fakeperm grant" ) ) );
        REQUIRE_FALSE( fields.start->isEnabled() );
        REQUIRE( fields.start->toolTip() == fake->cannotCapture );
    }

    WHEN( "an interface is typed by hand" )
    {
        fields.networkInterface->setEditText( "any" );

        THEN( "Start stays disabled" )
        {
            REQUIRE( dialog.choice().networkInterface == "any" );
            REQUIRE_FALSE( fields.start->isEnabled() );
        }
    }

    WHEN( "access is granted and Refresh is pressed" )
    {
        fake->cannotCapture.clear();
        fields.refresh->click();

        THEN( "Start waits for the listing, and is enabled once it says the source can capture" )
        {
            REQUIRE( dialog.form()->isListing() );
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( waitFor( [ & ] { return !dialog.form()->isListing(); } ) );
            REQUIRE( fields.start->isEnabled() );
            REQUIRE( fields.start->toolTip() == "Start capturing" );
            REQUIRE( fields.status->isHidden() );
        }
    }

    WHEN( "another source is chosen" )
    {
        fields.source->setCurrentIndex( 1 );
        emit fields.source->activated( 1 );
        REQUIRE( listed( dialog.form(), fields ) );

        THEN( "Start is enabled for it" )
        {
            REQUIRE( dialog.choice().source == "other" );
            REQUIRE( fields.start->isEnabled() );
        }
    }
}

SCENARIO( "A listing that only lists nothing leaves Start to an interface typed by hand",
          "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->listingError = "fakecap -D listed no interfaces: it may lack the permission to capture.";
    LiveCaptureDialog dialog( registryOf( fake ), LiveChoice{ "fake", "", "", "", 100 } );
    const Fields fields( &dialog );
    REQUIRE( waitFor( [ & ] { return !dialog.form()->isListing(); } ) );

    THEN( "the note says so, and Start asks for an interface" )
    {
        REQUIRE( fields.status->text().contains( "listed no interfaces" ) );
        REQUIRE_FALSE( fields.start->isEnabled() );
        REQUIRE( fields.start->toolTip() == "Choose an interface." );
    }

    WHEN( "an interface is typed by hand" )
    {
        fields.networkInterface->setEditText( "any" );

        THEN( "Start is enabled" )
        {
            REQUIRE( fields.start->isEnabled() );
        }
    }
}

SCENARIO( "The Start live capture dialog has the section's fields", "[live_ui]" )
{
    FakeHost host;
    auto fake = std::make_shared<FakeSourceKind>();
    LiveCaptureDialog dialog( registryOf( fake ),
                              LiveChoice{ "fake", "", "fake1", "port 53", 96 } );
    const Fields fields( &dialog );

    THEN( "it shows the choice it was given, once listed, and Start is enabled" )
    {
        REQUIRE( listed( dialog.form(), fields ) );
        REQUIRE( dialog.choice() == LiveChoice{ "fake", "", "fake1", "port 53", 96 } );
        REQUIRE( fields.start->isEnabled() );
    }

    WHEN( "the filter is unbalanced" )
    {
        REQUIRE( listed( dialog.form(), fields ) );
        fields.filter->setText( "(port 53" );

        THEN( "Start is disabled" )
        {
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( fields.filterHint->text().contains( "not closed" ) );
        }
    }
}

SCENARIO( "Plugins > tcpdump > Start live capture… starts one capture at a time", "[live_ui]" )
{
    QTemporaryDir root;
    FakeHost host;
    tcpdump::g_state.tempRoot = root.path();
    REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
    auto* sessions = tcpdump::g_state.sessions;
    sessions->setTempRoot( root.path() );
    auto fake = std::make_shared<FakeSourceKind>();
    fake->capture = pcapOf( { datagram( 0 ) } );
    sessions->setLiveSources( registryOf( fake ) );

    const auto entry = [ &host ]( const QString& label ) {
        for ( const auto& action : host.menuActions ) {
            if ( action.label == label ) {
                return action;
            }
        }
        FAIL( "no menu entry " << label.toStdString() );
        return host.menuActions.first();
    };
    const auto startEntry = entry( QString::fromUtf8( "Start live capture\xe2\x80\xa6" ) );
    const auto stopEntry = entry( "Stop live capture" );

    GIVEN( "the entry chosen, and the dialog accepted when it can start" )
    {
        // The real dialog: accepted by its Start button once the
        // interfaces are listed.
        QTimer accepter;
        int dialogs = 0;
        QObject::connect( &accepter, &QTimer::timeout, [ & ] {
            auto* dialog = qobject_cast<LiveCaptureDialog*>( QApplication::activeModalWidget() );
            if ( !dialog ) {
                return;
            }
            const Fields fields( dialog );
            if ( fields.networkInterface->count() == 2 && fields.start->isEnabled() ) {
                ++dialogs;
                fields.networkInterface->setCurrentIndex( 1 );
                fields.filter->setText( "udp" );
                fields.start->click();
            }
        } );
        accepter.start( 20 );
        startEntry.trigger();
        accepter.stop();

        THEN( "the dialog's choice is captured" )
        {
            REQUIRE( dialogs == 1 );
            REQUIRE( sessions->liveSession().isBusy() );
            REQUIRE( fake->started().size() == 1 );
            REQUIRE( fake->started().front().networkInterface == "fake1" );
            REQUIRE( fake->started().front().filter == "udp" );
        }

        AND_WHEN( "the entry is chosen again and the user keeps the running capture" )
        {
            int asked = 0;
            int dialogsAgain = 0;
            sessions->setStopConfirmer( [ & ]( QWidget*, const QString& running ) {
                ++asked;
                REQUIRE( running == "fake1" );
                return false;
            } );
            sessions->setLiveChoiceAsker( [ & ]( QWidget*, LiveChoice& ) {
                ++dialogsAgain;
                return true;
            } );
            startEntry.trigger();

            THEN( "it runs on, and no dialog is shown" )
            {
                REQUIRE( asked == 1 );
                REQUIRE( dialogsAgain == 0 );
                REQUIRE( sessions->liveSession().isBusy() );
                REQUIRE( fake->started().size() == 1 );
            }
        }

        AND_WHEN( "the entry is chosen again and the user stops the running capture" )
        {
            sessions->setStopConfirmer( []( QWidget*, const QString& ) { return true; } );
            sessions->setLiveChoiceAsker( []( QWidget*, LiveChoice& choice ) {
                REQUIRE( choice.networkInterface == "fake1" ); // the last choice is shown
                choice.networkInterface = "fake0";
                return true;
            } );
            startEntry.trigger();

            THEN( "the first ends, then the second starts" )
            {
                REQUIRE( waitFor( [ & ] { return fake->started().size() == 2; } ) );
                REQUIRE( waitFor( [ & ] { return sessions->liveSession().isBusy(); } ) );
                REQUIRE( fake->started().back().networkInterface == "fake0" );
                REQUIRE( waitFor( [ & ] {
                    return !host.openedFiles.isEmpty()
                           && QFileInfo( host.openedFiles.last() ).fileName() == "fake0.log";
                } ) );
            }
        }

        AND_WHEN( "Stop live capture is chosen" )
        {
            stopEntry.trigger();

            THEN( "the capture ends" )
            {
                REQUIRE( waitFor( [ & ] { return !sessions->liveSession().isBusy(); } ) );
            }
        }
    }

    GIVEN( "no capture running" )
    {
        WHEN( "Stop live capture is chosen" )
        {
            stopEntry.trigger();

            THEN( "a notification says so" )
            {
                REQUIRE( host.notifications == QStringList{ "No live capture is running." } );
            }
        }

        WHEN( "the dialog is cancelled" )
        {
            sessions->setLiveChoiceAsker( []( QWidget*, LiveChoice& ) { return false; } );
            startEntry.trigger();

            THEN( "nothing starts" )
            {
                REQUIRE_FALSE( sessions->liveSession().isBusy() );
                REQUIRE( fake->started().empty() );
            }
        }
    }

    logsquirl_plugin_shutdown();
}

#ifdef Q_OS_UNIX

SCENARIO( "A listing that hangs does not hold up closing the plugin or a dialog", "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir dir;
    const auto program = dir.filePath( "hanging-lister" );
    {
        QFile file( program );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( "#!/bin/sh\nsleep 30\n" );
        file.close();
        REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner ) );
    }
    auto fake = std::make_shared<FakeSourceKind>();
    fake->listingProgram = program;
    /// Long enough for the listing program to be running.
    const auto whileListing = [ & ]( const LiveCaptureForm* form ) {
        REQUIRE( form->isListing() );
        QElapsedTimer running;
        running.start();
        waitFor( [ & ] { return running.elapsed() > 300; } );
        REQUIRE( form->isListing() );
    };

    WHEN( "the plugin's dialog, its sidebar and its sessions go while it lists" )
    {
        auto sessions = std::make_unique<CaptureSessions>();
        auto sidebar = std::make_unique<SidebarWidget>( *sessions );
        sessions->setTempRoot( dir.path() );
        sessions->setLiveSources( registryOf( fake ) );
        auto dialog = sessions->makeLiveCaptureDialog( nullptr );
        whileListing( dialog->form() );
        QElapsedTimer took;
        took.start();
        dialog.reset();
        sidebar.reset();
        sessions.reset();

        THEN( "the listing is cancelled, not waited for" )
        {
            REQUIRE( took.elapsed() < 1000 );
        }
    }

    WHEN( "a form with a pool of its own goes while it lists" )
    {
        auto form = std::make_unique<LiveCaptureForm>();
        form->setSources( registryOf( fake ) );
        whileListing( form.get() );
        QElapsedTimer took;
        took.start();
        form.reset();

        THEN( "the listing is cancelled, not waited for" )
        {
            REQUIRE( took.elapsed() < 1000 );
        }
    }
}

SCENARIO( "A source's capture program gets the capture filter as one argument, no shell",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir dir;
    const auto pcapPath = dir.filePath( "fake.pcap" );
    writeFile( pcapPath, pcapOf( { datagram( 0 ) } ) );
    const auto program = dir.filePath( "fakecap" );
    {
        QFile file( program );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( QString( "#!/bin/sh\nfor a in \"$@\"; do printf '[%s]\\n' \"$a\" >&2; done\n"
                             "cat '%1'\n" )
                        .arg( pcapPath )
                        .toUtf8() );
        file.close();
        REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                      | QFileDevice::ExeOwner ) );
    }
    auto fake = std::make_shared<FakeSourceKind>();
    fake->program = program;
    CaptureSessions sessions;
    SidebarWidget sidebar( sessions );
    sessions.setTempRoot( dir.path() );
    sessions.setLiveSources( registryOf( fake ) );

    REQUIRE( sessions.liveSession().start(
        LiveChoice{ "fake", "", "fake0", "host 10.0.0.1 and not (port 22 or port '$(x)')", 64 } ) );
    REQUIRE( waitFor( [ & ] { return !sessions.liveSession().isBusy(); } ) );
    REQUIRE( sidebar.findChild<QPlainTextEdit*>( "liveStderr" )->toPlainText()
             == "[-i]\n[fake0]\n[-s]\n[64]\n[host 10.0.0.1 and not (port 22 or port '$(x)')]" );
    REQUIRE( host.openedFiles.size() == 1 );
}

#endif
