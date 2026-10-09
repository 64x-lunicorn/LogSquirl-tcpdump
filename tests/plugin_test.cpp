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
 * @file plugin_test.cpp
 * @brief BDD tests for the plugin's C entry points and host API wrappers.
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "pcapbuilder.h"
#include "plugin.h"
#include "sidebarwidget.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <vector>

using tcpdump_test::FakeHost;

extern "C" int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );
extern "C" void logsquirl_plugin_shutdown( void );

SCENARIO( "messages reach the host as UTF-8", "[hostapi]" )
{
    GIVEN( "a host that decodes every message as UTF-8" )
    {
        FakeHost host;
        const auto text = QString::fromUtf8( "Aufzeichnung \xE2\x86\x92 m\xC3\xBC"
                                             "de.pcap \xE2\x9C\x93" );

        WHEN( "the plugin logs a message with non-ASCII characters" )
        {
            tcpdump::hostLog( LOGSQUIRL_LOG_INFO, text );

            THEN( "the host receives it unchanged" )
            {
                REQUIRE( host.logs == QStringList{ text } );
            }
        }

        WHEN( "the plugin shows a notification with non-ASCII characters" )
        {
            tcpdump::hostNotify( text );

            THEN( "the host receives it unchanged" )
            {
                REQUIRE( host.notifications == QStringList{ text } );
            }
        }
    }

    GIVEN( "no host (the plugin is not initialised)" )
    {
        WHEN( "the plugin logs and notifies" )
        {
            tcpdump::hostLog( LOGSQUIRL_LOG_INFO, "ignored" );
            tcpdump::hostNotify( "ignored" );

            THEN( "nothing happens" )
            {
                SUCCEED();
            }
        }
    }
}

SCENARIO( "the plugin registers its sidebar tab for its lifetime", "[plugin]" )
{
    GIVEN( "a host" )
    {
        FakeHost host;

        WHEN( "the plugin is initialised" )
        {
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

            THEN( "its sidebar widget is registered as a tab" )
            {
                REQUIRE( host.sidebarTabs.size() == 1 );
                REQUIRE( host.sidebarTabs.first() == tcpdump::g_state.sidebarWidget );
            }

            AND_WHEN( "it is shut down" )
            {
                logsquirl_plugin_shutdown();

                THEN( "the tab is unregistered and the state cleared" )
                {
                    REQUIRE( host.sidebarTabs.isEmpty() );
                    REQUIRE( tcpdump::g_state.sidebarWidget == nullptr );
                    REQUIRE_FALSE( tcpdump::g_state.initialised );
                }
            }

            logsquirl_plugin_shutdown();
        }
    }
}

SCENARIO( "the plugin follows the tab in front for its lifetime", "[plugin]" )
{
    GIVEN( "a host" )
    {
        FakeHost host;

        WHEN( "the plugin is initialised" )
        {
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

            THEN( "it registers for the host's active-file notifications" )
            {
                REQUIRE( host.hasActiveFileCallback() );
            }

            AND_WHEN( "it is shut down and the host still reports a tab switch" )
            {
                logsquirl_plugin_shutdown();

                THEN( "nothing happens" )
                {
                    REQUIRE_NOTHROW( host.activateFile( "/tmp/some.log" ) );
                    REQUIRE( host.logs.filter( "failed" ).isEmpty() );
                }
            }

            logsquirl_plugin_shutdown();
        }
    }
}

SCENARIO( "the plugin learns the later host functions from the table size", "[plugin]" )
{
    GIVEN( "a host of LogSquirl 26.11 or later, with the full table" )
    {
        FakeHost host;

        WHEN( "it initialises the plugin through init_ex" )
        {
            REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

            THEN( "the plugin knows the Regex Lab, Go to line and the selected lines" )
            {
                const auto& caps = tcpdump::g_state.hostCapabilities;
                REQUIRE( caps.regexLab );
                REQUIRE( caps.goToLogLine );
                REQUIRE( caps.selectedLogLines );
            }

            AND_WHEN( "the plugin is shut down" )
            {
                logsquirl_plugin_shutdown();

                THEN( "it no longer knows any of them" )
                {
                    REQUIRE( tcpdump::g_state.hostCapabilities == tcpdump::HostCapabilities{} );
                }
            }

            logsquirl_plugin_shutdown();
        }

        WHEN( "it initialises the plugin through the old init" )
        {
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );

            THEN( "the plugin assumes the base table and knows none of them" )
            {
                REQUIRE( tcpdump::g_state.hostCapabilities == tcpdump::HostCapabilities{} );
            }

            logsquirl_plugin_shutdown();
        }
    }

    GIVEN( "a host older than LogSquirl 26.11, with the base table" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );

        WHEN( "it initialises the plugin through init_ex" )
        {
            REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

            THEN( "the plugin knows none of the later functions" )
            {
                REQUIRE( tcpdump::g_state.hostCapabilities == tcpdump::HostCapabilities{} );
            }

            logsquirl_plugin_shutdown();
        }
    }

    GIVEN( "a table that ends inside a later function's pointer" )
    {
        const size_t size = offsetof( LogSquirlHostApi, go_to_log_line ) + 1;

        THEN( "only the functions it holds whole count" )
        {
            const auto caps = tcpdump::HostCapabilities::of( size );
            REQUIRE( caps.regexLab );
            REQUIRE_FALSE( caps.goToLogLine );
            REQUIRE_FALSE( caps.selectedLogLines );
        }
    }
}

// MSVC's default /EHsc assumes that functions of C linkage, like the host
// API's, never throw, and may drop the handlers this test relies on.
#ifndef _MSC_VER
SCENARIO( "no exception leaves an entry point", "[plugin]" )
{
    GIVEN( "a host whose register_sidebar_tab() throws" )
    {
        FakeHost host;
        host.failSidebarTab = true;

        WHEN( "the plugin is initialised" )
        {
            int rc = 0;
            REQUIRE_NOTHROW( rc = logsquirl_plugin_init( host.api(), &host ) );

            THEN( "initialisation fails, is logged, and leaves nothing behind" )
            {
                REQUIRE( rc != 0 );
                REQUIRE( tcpdump::g_state.sidebarWidget == nullptr );
                REQUIRE_FALSE( host.logs.filter( "no room for another tab" ).isEmpty() );
            }
        }

        // The host would not call shutdown() after a failed init, but it must be harmless.
        REQUIRE_NOTHROW( logsquirl_plugin_shutdown() );
    }

    GIVEN( "a host that fails after the sidebar tab was registered" )
    {
        FakeHost host;
        host.failLogContaining = "ready";

        WHEN( "the plugin is initialised" )
        {
            int rc = 0;
            REQUIRE_NOTHROW( rc = logsquirl_plugin_init( host.api(), &host ) );

            THEN( "initialisation fails and the tab is unregistered before its widget goes" )
            {
                REQUIRE( rc != 0 );
                REQUIRE( host.sidebarTabs.isEmpty() );
                REQUIRE( tcpdump::g_state.sidebarWidget == nullptr );
            }
        }

        REQUIRE_NOTHROW( logsquirl_plugin_shutdown() );
    }
}
#endif

namespace {

/** Write a capture of @p packets UDP packets into @p dir. */
QString writeCaptureFile( const QTemporaryDir& dir, int packets = 1,
                          const QString& name = "capture.pcap" )
{
    using namespace tcpdump_test;
    const std::vector<Bytes> records(
        static_cast<size_t>( packets ),
        eth( tcpdump::EthertypeIpv4, ipv4( tcpdump::IpProtoUdp, udp( 1, 2, text( "x" ) ) ) ) );
    const auto bytes = pcapOf( records );
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( bytes.data() ),
                static_cast<qint64>( bytes.size() ) );
    return path;
}

/** Initialise the plugin, open a capture through its sidebar, return the opened file. */
QString openCapture( FakeHost& host, const QString& capture, const QString& tempRoot )
{
    tcpdump::g_state.tempRoot = tempRoot;
    REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
    auto* sidebar = tcpdump::g_state.sidebarWidget;
    REQUIRE( sidebar->tempRoot() == tempRoot );
    const auto before = host.openedFiles.size();
    sidebar->openPcapFile( capture );
    REQUIRE( tcpdump_test::waitFor(
        [ &host, before ] { return host.openedFiles.size() == before + 1; } ) );
    return host.openedFiles.last();
}

} // namespace

SCENARIO( "temporary files are removed only when LogSquirl quits", "[plugin]" )
{
    QTemporaryDir captures;
    QTemporaryDir tempRoot;
    REQUIRE( captures.isValid() );
    REQUIRE( tempRoot.isValid() );
    const auto capture = writeCaptureFile( captures );

    GIVEN( "an initialised plugin that opened a capture in a tab" )
    {
        FakeHost host;
        const auto opened = openCapture( host, capture, tempRoot.path() );

        WHEN( "LogSquirl quits, which shuts the plugin down" )
        {
            QMetaObject::invokeMethod( QCoreApplication::instance(), "aboutToQuit" );
            logsquirl_plugin_shutdown();

            THEN( "the temporary file and its directory are removed" )
            {
                REQUIRE_FALSE( QFileInfo::exists( opened ) );
                REQUIRE( QDir( tempRoot.path() ).isEmpty() );
            }

            AND_WHEN( "the plugin is loaded again and later disabled" )
            {
                const auto reopened = openCapture( host, capture, tempRoot.path() );
                logsquirl_plugin_shutdown();

                THEN( "the earlier quit does not make it remove the new tab's file" )
                {
                    REQUIRE( QFileInfo::exists( reopened ) );
                }
            }
        }

        WHEN( "the plugin is disabled or updated while LogSquirl keeps running" )
        {
            logsquirl_plugin_shutdown();

            THEN( "the file is kept for its open tab" )
            {
                REQUIRE( QFileInfo::exists( opened ) );
            }

            AND_WHEN( "it is enabled again, and LogSquirl quits later" )
            {
                REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
                QMetaObject::invokeMethod( QCoreApplication::instance(), "aboutToQuit" );
                logsquirl_plugin_shutdown();

                THEN( "the new instance removes the file the earlier one left for its tab" )
                {
                    REQUIRE_FALSE( QFileInfo::exists( opened ) );
                    REQUIRE( QDir( tempRoot.path() ).isEmpty() );
                }
            }
        }
    }
    tcpdump::g_state.tempRoot.clear();
}

SCENARIO( "temporary directories of LogSquirl processes that ended are swept", "[plugin]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    const QDir root( tempRoot.path() );

    GIVEN( "directories left by a process that ended, and by one that runs" )
    {
        // No process has this ID: PIDs stay far below it on Linux and macOS,
        // and on Windows it is a multiple of 4 no process gets in practice.
        const QString dead = "logsquirl-tcpdump-2147483644-AbC123";
#ifdef Q_OS_WIN
        const QString alive = "logsquirl-tcpdump-4-AbC123"; // the System process
#else
        const QString alive = "logsquirl-tcpdump-1-AbC123"; // init / launchd
#endif
        const QString unrelated = "logsquirl-tcpdump-notapid";
        for ( const auto& name : { dead, alive, unrelated } ) {
            REQUIRE( root.mkpath( name + "/sub" ) );
            QFile file( root.filePath( name + "/sub/capture.log" ) );
            REQUIRE( file.open( QIODevice::WriteOnly ) );
        }

        WHEN( "the plugin is initialised" )
        {
            FakeHost host;
            tcpdump::g_state.tempRoot = tempRoot.path();
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
            logsquirl_plugin_shutdown();

            THEN( "only the ended process's directory is removed" )
            {
                REQUIRE_FALSE( root.exists( dead ) );
                REQUIRE( root.exists( alive ) );
                REQUIRE( root.exists( unrelated ) );
            }
        }

        WHEN( "the plugin shuts down as LogSquirl quits" )
        {
            FakeHost host;
            tcpdump::g_state.tempRoot = tempRoot.path();
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
            QMetaObject::invokeMethod( QCoreApplication::instance(), "aboutToQuit" );
            logsquirl_plugin_shutdown();

            THEN( "another running process's directory is kept" )
            {
                REQUIRE( root.exists( alive ) );
                REQUIRE( root.exists( unrelated ) );
            }
        }
    }
    tcpdump::g_state.tempRoot.clear();
}

SCENARIO( "the capture dialog is also in the Plugins menu", "[plugin]" )
{
    QTemporaryDir captures;
    QTemporaryDir tempRoot;
    REQUIRE( captures.isValid() );
    REQUIRE( tempRoot.isValid() );

    GIVEN( "an initialised plugin" )
    {
        FakeHost host;
        tcpdump::g_state.tempRoot = tempRoot.path();
        REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
        auto* sidebar = tcpdump::g_state.sidebarWidget;

        // Stands in for the file dialog the Open button shows.
        int dialogs = 0;
        QString chosen;
        sidebar->setFileChooser( [ &dialogs, &chosen ]( QWidget*, const QString& ) {
            ++dialogs;
            return chosen;
        } );

        THEN( "Plugins > tcpdump > Open pcap\xe2\x80\xa6 is registered, and the live capture's "
              "entries" )
        {
            REQUIRE( host.menuActions.size() == 3 );
            REQUIRE( host.menuActions.at( 1 ).label
                     == QString::fromUtf8( "Start live capture\xe2\x80\xa6" ) );
            REQUIRE( host.menuActions.at( 2 ).label == "Stop live capture" );
            REQUIRE( host.menuActions.first().menuPath == "tcpdump" );
            REQUIRE( host.menuActions.first().label
                     == QString::fromUtf8( "Open pcap\xe2\x80\xa6" ) );
        }

        WHEN( "the entry is chosen and a capture selected" )
        {
            chosen = writeCaptureFile( captures );
            host.menuActions.first().trigger();

            THEN( "the sidebar's dialog is shown and the capture is opened in a tab" )
            {
                REQUIRE( dialogs == 1 );
                REQUIRE(
                    tcpdump_test::waitFor( [ &host ] { return host.openedFiles.size() == 1; } ) );
            }
        }

        WHEN( "the entry is chosen and the dialog cancelled" )
        {
            host.menuActions.first().trigger();

            THEN( "nothing is converted" )
            {
                REQUIRE( dialogs == 1 );
                REQUIRE_FALSE( sidebar->isConverting() );
                REQUIRE( host.notifications.isEmpty() );
            }
        }

        WHEN( "the entry is chosen while a capture is being converted" )
        {
            sidebar->openPcapFile( writeCaptureFile( captures, 20000, "big.pcap" ) );
            REQUIRE( sidebar->isConverting() );
            host.menuActions.first().trigger();

            THEN( "no dialog is shown, and a notification says why" )
            {
                REQUIRE( dialogs == 0 );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "being read" ) );
            }
            sidebar->cancel();
            REQUIRE( tcpdump_test::waitFor( [ sidebar ] { return !sidebar->isConverting(); } ) );
        }

        WHEN( "the plugin is unloaded" )
        {
            host.unloadPlugin();

            THEN( "the entry goes with it" )
            {
                REQUIRE( host.menuActions.isEmpty() );
            }
        }

        host.unloadPlugin();
    }
    tcpdump::g_state.tempRoot.clear();
}
