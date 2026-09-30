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

using tcpdump_test::FakeHost;

extern "C" int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
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
}
#endif

namespace {

QString writeCaptureFile( const QTemporaryDir& dir )
{
    using namespace tcpdump_test;
    const auto bytes = pcapOf(
        { eth( tcpdump::EthertypeIpv4, ipv4( tcpdump::IpProtoUdp, udp( 1, 2, text( "x" ) ) ) ) } );
    const auto path = dir.filePath( "capture.pcap" );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( bytes.data() ),
                static_cast<qint64>( bytes.size() ) );
    return path;
}

/** Initialise the plugin, open a capture through its sidebar, return the opened file. */
QString openCapture( FakeHost& host, const QString& capture, const QString& tempRoot )
{
    REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
    auto* sidebar = tcpdump::g_state.sidebarWidget;
    sidebar->setTempRoot( tempRoot );
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
        }
    }
}
