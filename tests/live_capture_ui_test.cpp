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

#include "fake_live_source.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "settings.h"
#include "sidebarwidget.h"
#include "stream_capture.h"

#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTimer>

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
        , interface( in->findChild<QComboBox*>( "liveInterface" ) )
        , refresh( in->findChild<QPushButton*>( "liveRefresh" ) )
        , filter( in->findChild<QLineEdit*>( "liveFilter" ) )
        , filterHint( in->findChild<QLabel*>( "liveFilterHint" ) )
        , snaplen( in->findChild<QSpinBox*>( "liveSnaplen" ) )
        , start( in->findChild<QPushButton*>( "liveStartButton" ) )
    {
        REQUIRE( source );
        REQUIRE( status );
        REQUIRE( interface );
        REQUIRE( refresh );
        REQUIRE( filter );
        REQUIRE( filterHint );
        REQUIRE( snaplen );
        REQUIRE( start );
    }

    QComboBox* source;
    QLabel* status;
    QComboBox* interface;
    QPushButton* refresh;
    QLineEdit* filter;
    QLabel* filterHint;
    QSpinBox* snaplen;
    QPushButton* start;
};

/// Wait until @p form has listed the fake's two interfaces.
bool listed( const LiveCaptureForm* form, const Fields& fields )
{
    return waitFor( [ & ] { return !form->isListing() && fields.interface->count() == 2; } );
}

} // namespace

SCENARIO( "The Live capture section starts a capture from a source, and Stop finalises it",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->capture = pcapOf( { datagram( 0 ), datagram( 1 ), datagram( 2 ) } );

    SidebarWidget sidebar;
    sidebar.setTempRoot( root.path() );
    sidebar.setLiveSources( registryOf( fake ) );
    auto* form = sidebar.liveForm();
    const Fields fields( &sidebar );
    auto* stop = sidebar.findChild<QPushButton*>( "stopButton" );
    auto* stderrView = sidebar.findChild<QPlainTextEdit*>( "liveStderr" );
    REQUIRE( sidebar.findChild<QWidget*>( "liveSection" ) );

    GIVEN( "the fake source chosen and its two interfaces listed" )
    {
        REQUIRE( fields.source->currentText() == "Fake" );
        REQUIRE( listed( form, fields ) );
        REQUIRE( fields.interface->itemText( 0 ) == "fake0 \xe2\x80\x94 Fake Ethernet" );
        REQUIRE( fields.interface->itemData( 1 ).toString() == "fake1" );
        REQUIRE( fields.snaplen->value() == 262144 );
        REQUIRE( fields.start->isEnabled() );

        WHEN( "the second interface, a filter and a snaplen are chosen and Start is pressed" )
        {
            fields.interface->setCurrentIndex( 1 );
            fields.filter->setText( "udp port 9999 and host 10.0.0.1" );
            fields.snaplen->setValue( 1500 );
            fields.start->click();

            THEN( "the source is asked for exactly that, and the tab opens following the file" )
            {
                REQUIRE( sidebar.isCapturing() );
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

            THEN( "Start is gone and the form is locked while it runs; the counters and stderr "
                  "show" )
            {
                REQUIRE( fields.start->isHidden() );
                REQUIRE_FALSE( form->isEnabled() );
                REQUIRE_FALSE( stop->isHidden() );
                auto* live = sidebar.findChild<QLabel*>( "liveProgress" );
                REQUIRE( waitFor( [ & ] { return live->text().contains( "Packets: 3" ); } ) );
                REQUIRE( live->text().contains( "packets/s" ) );
                REQUIRE( live->text().contains( "Elapsed" ) );
                REQUIRE( waitFor( [ & ] { return !stderrView->isHidden(); } ) );
                REQUIRE( stderrView->toPlainText() == "fakecap: listening" );
            }

            AND_WHEN( "Stop is pressed" )
            {
                REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );
                const auto logPath = host.openedFiles.first();
                sidebar.showSummaryFor( logPath );
                REQUIRE( waitFor( [ & ] { return readLines( logPath ).size() == 4; } ) );
                stop->click();
                REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

                THEN( "the capture is final, and Start is back" )
                {
                    REQUIRE( sidebar.findChild<QLabel*>( "summary" )
                                 ->text()
                                 .contains( "Packets: <b>3</b>" ) );
                    REQUIRE_FALSE( fields.start->isHidden() );
                    REQUIRE( fields.start->isEnabled() );
                    REQUIRE( form->isEnabled() );
                    REQUIRE( host.notifications.isEmpty() );
                }

                THEN( "the choice is restored after a restart" )
                {
                    SidebarWidget restarted;
                    restarted.setLiveSources( registryOf( fake ) );
                    const Fields again( &restarted );
                    REQUIRE( listed( restarted.liveForm(), again ) );
                    REQUIRE( restarted.liveForm()->choice()
                             == LiveChoice{ "fake", "", "fake1", "udp port 9999 and host 10.0.0.1",
                                            1500 } );
                    REQUIRE( again.interface->currentIndex() == 1 );
                }
            }
        }

        WHEN( "an interface the source does not list is typed" )
        {
            fields.interface->setEditText( "any" );

            THEN( "it is the choice" )
            {
                REQUIRE( form->choice().interface == "any" );
                REQUIRE( fields.start->isEnabled() );
            }
        }

        WHEN( "Refresh is pressed" )
        {
            fields.interface->setCurrentIndex( 1 );
            const int before = fake->interfaceListings;
            fields.refresh->click();
            REQUIRE( form->isListing() );
            REQUIRE( listed( form, fields ) );

            THEN( "the interfaces are listed anew, and the one chosen stays chosen" )
            {
                REQUIRE( fake->interfaceListings == before + 1 );
                REQUIRE( form->choice().interface == "fake1" );
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
                REQUIRE_FALSE( sidebar.startLiveCapture( form->choice() ) );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( fake->started().empty() );
            }
        }

        WHEN( "a capture file is being read" )
        {
            sidebar.openPcapFile(
                QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( "mixed.pcap" ) );

            THEN( "Start is disabled until it is done" )
            {
                REQUIRE_FALSE( fields.start->isEnabled() );
                REQUIRE( fields.start->toolTip().contains( "being read" ) );
                REQUIRE( waitFor( [ & ] { return !sidebar.isConverting(); } ) );
                REQUIRE( fields.start->isEnabled() );
            }
        }
    }
}

SCENARIO( "An unavailable source says why, and a failed capture shows its error in the section",
          "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();

    GIVEN( "a source that is unavailable" )
    {
        fake->unavailableReason = "fakecap not found: install the Fake Capture Tools";
        SidebarWidget sidebar;
        sidebar.setTempRoot( root.path() );
        sidebar.setLiveSources( registryOf( fake ) );
        const Fields fields( &sidebar );

        THEN( "the section shows the reason, lists nothing, and Start is disabled" )
        {
            REQUIRE_FALSE( fields.status->isHidden() );
            REQUIRE( fields.status->text() == fake->unavailableReason );
            REQUIRE_FALSE( fields.start->isEnabled() );
            REQUIRE( fields.start->toolTip() == fake->unavailableReason );
            REQUIRE( fake->interfaceListings == 0 );
            REQUIRE_FALSE( fields.interface->isEnabled() );
        }

        THEN( "starting it anyway is refused with the reason" )
        {
            REQUIRE_FALSE( sidebar.startLiveCapture( LiveChoice{ "fake", "", "fake0", "", 100 } ) );
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
        SidebarWidget sidebar;
        sidebar.setTempRoot( root.path() );
        sidebar.setLiveSources( registryOf( fake ) );
        const Fields fields( &sidebar );
        REQUIRE( listed( sidebar.liveForm(), fields ) );
        fields.start->click();
        REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );

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
            fields.start->click();

            THEN( "the error goes" )
            {
                REQUIRE( sidebar.findChild<QLabel*>( "liveError" )->isHidden() );
                sidebar.stopLiveCapture();
                REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
            }
        }
    }
}

SCENARIO( "A source with devices lists them, and the interfaces of the one chosen", "[live_ui]" )
{
    FakeHost host;
    QTemporaryDir root;
    auto fake = std::make_shared<FakeSourceKind>();
    fake->deviceMode = LiveSourceKind::Devices::Listed;
    fake->capture = pcapOf( { datagram( 0 ) } );
    SidebarWidget sidebar;
    sidebar.setTempRoot( root.path() );
    sidebar.setLiveSources( registryOf( fake ) );
    const Fields fields( &sidebar );
    auto* device = sidebar.findChild<QComboBox*>( "liveDevice" );
    REQUIRE( listed( sidebar.liveForm(), fields ) );

    THEN( "the unauthorized device is listed with its problem but not chosen" )
    {
        REQUIRE_FALSE( device->isHidden() );
        REQUIRE( device->count() == 2 );
        REQUIRE( device->itemText( 0 ).contains( "unauthorized" ) );
        REQUIRE( device->currentIndex() == 1 );
        REQUIRE( fake->listedDevices() == QStringList{ "phoneA" } );
    }

    WHEN( "Start is pressed" )
    {
        fields.start->click();
        REQUIRE( waitFor( [ & ] { return !host.openedFiles.isEmpty(); } ) );

        THEN( "the device is part of the choice and of the capture's name" )
        {
            REQUIRE( fake->started().front().device == "phoneA" );
            REQUIRE( QFileInfo( host.openedFiles.first() ).fileName() == "phoneA-fake0.log" );
        }
        sidebar.stopLiveCapture();
        REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
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
    auto* sidebar = tcpdump::g_state.sidebarWidget;
    sidebar->setTempRoot( root.path() );
    auto fake = std::make_shared<FakeSourceKind>();
    fake->capture = pcapOf( { datagram( 0 ) } );
    sidebar->setLiveSources( registryOf( fake ) );

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
            if ( fields.interface->count() == 2 && fields.start->isEnabled() ) {
                ++dialogs;
                fields.interface->setCurrentIndex( 1 );
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
            REQUIRE( sidebar->isCapturing() );
            REQUIRE( fake->started().size() == 1 );
            REQUIRE( fake->started().front().interface == "fake1" );
            REQUIRE( fake->started().front().filter == "udp" );
        }

        AND_WHEN( "the entry is chosen again and the user keeps the running capture" )
        {
            int asked = 0;
            int dialogsAgain = 0;
            sidebar->setStopConfirmer( [ & ]( QWidget*, const QString& running ) {
                ++asked;
                REQUIRE( running == "fake1" );
                return false;
            } );
            sidebar->setLiveChoiceAsker( [ & ]( QWidget*, LiveChoice& ) {
                ++dialogsAgain;
                return true;
            } );
            startEntry.trigger();

            THEN( "it runs on, and no dialog is shown" )
            {
                REQUIRE( asked == 1 );
                REQUIRE( dialogsAgain == 0 );
                REQUIRE( sidebar->isCapturing() );
                REQUIRE( fake->started().size() == 1 );
            }
        }

        AND_WHEN( "the entry is chosen again and the user stops the running capture" )
        {
            sidebar->setStopConfirmer( []( QWidget*, const QString& ) { return true; } );
            sidebar->setLiveChoiceAsker( []( QWidget*, LiveChoice& choice ) {
                REQUIRE( choice.interface == "fake1" ); // the last choice is shown
                choice.interface = "fake0";
                return true;
            } );
            startEntry.trigger();

            THEN( "the first ends, then the second starts" )
            {
                REQUIRE( waitFor( [ & ] { return fake->started().size() == 2; } ) );
                REQUIRE( waitFor( [ & ] { return sidebar->isCapturing(); } ) );
                REQUIRE( fake->started().back().interface == "fake0" );
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
                REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );
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
            sidebar->setLiveChoiceAsker( []( QWidget*, LiveChoice& ) { return false; } );
            startEntry.trigger();

            THEN( "nothing starts" )
            {
                REQUIRE_FALSE( sidebar->isCapturing() );
                REQUIRE( fake->started().empty() );
            }
        }
    }

    logsquirl_plugin_shutdown();
}

#ifdef Q_OS_UNIX

SCENARIO( "A listing that hangs does not hold up closing the sidebar or a dialog", "[live_ui]" )
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

    WHEN( "the sidebar goes while its form lists" )
    {
        auto sidebar = std::make_unique<SidebarWidget>();
        sidebar->setTempRoot( dir.path() );
        sidebar->setLiveSources( registryOf( fake ) );
        whileListing( sidebar->liveForm() );
        QElapsedTimer took;
        took.start();
        sidebar.reset();

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
    SidebarWidget sidebar;
    sidebar.setTempRoot( dir.path() );
    sidebar.setLiveSources( registryOf( fake ) );

    REQUIRE( sidebar.startLiveCapture(
        LiveChoice{ "fake", "", "fake0", "host 10.0.0.1 and not (port 22 or port '$(x)')", 64 } ) );
    REQUIRE( waitFor( [ & ] { return !sidebar.isCapturing(); } ) );
    REQUIRE( sidebar.findChild<QPlainTextEdit*>( "liveStderr" )->toPlainText()
             == "[-i]\n[fake0]\n[-s]\n[64]\n[host 10.0.0.1 and not (port 22 or port '$(x)')]" );
    REQUIRE( host.openedFiles.size() == 1 );
}

#endif
