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
 * @brief BDD tests for opening a capture from the sidebar.
 */

#include <catch2/catch.hpp>

#include "fakehost.h"
#include "pcapbuilder.h"
#include "sidebarwidget.h"

#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QTemporaryDir>

#include <memory>

using tcpdump::SidebarWidget;
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

template <typename T>
T* child( const SidebarWidget& widget, const char* name )
{
    auto* found = widget.findChild<T*>( name );
    REQUIRE( found );
    return found;
}

} // namespace

SCENARIO( "a capture is converted in the background and opened in a tab", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar and a small capture" )
    {
        FakeHost host;
        SidebarWidget widget;
        const auto capture = writeCapture( dir, "small.pcap", captureOf( 3 ) );

        WHEN( "the capture is opened" )
        {
            widget.openPcapFile( capture );

            THEN( "the sidebar shows the conversion running, with a Cancel button" )
            {
                REQUIRE( widget.isConverting() );
                REQUIRE_FALSE( child<QPushButton>( widget, "openButton" )->isEnabled() );
                REQUIRE_FALSE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
                REQUIRE_FALSE( child<QProgressBar>( widget, "progress" )->isHidden() );
            }

            THEN( "the text file is opened in a tab once it is written" )
            {
                REQUIRE( waitFor( [ &host ] { return !host.openedFiles.isEmpty(); } ) );
                REQUIRE( host.openedFiles.size() == 1 );
                QFile out( host.openedFiles.first() );
                REQUIRE( out.open( QIODevice::ReadOnly ) );
                REQUIRE( out.readAll().count( '\n' ) == 4 ); // header + 3 packets
            }

            THEN( "the sidebar returns to idle and shows the summary" )
            {
                REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );
                REQUIRE( child<QPushButton>( widget, "openButton" )->isEnabled() );
                REQUIRE( child<QPushButton>( widget, "cancelButton" )->isHidden() );
                REQUIRE( child<QProgressBar>( widget, "progress" )->isHidden() );
                REQUIRE( child<QLabel>( widget, "summary" )->text().contains( "small.pcap" ) );
            }
        }
    }

    GIVEN( "a file that is not a capture" )
    {
        FakeHost host;
        SidebarWidget widget;
        const auto junk = writeCapture( dir, "junk.pcap", Bytes( 64, 0xEE ) );

        WHEN( "it is opened" )
        {
            widget.openPcapFile( junk );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "the error is shown and notified, and no tab is opened" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE( host.notifications.first().contains( "magic" ) );
                REQUIRE( child<QLabel>( widget, "summary" )->text().contains( "magic" ) );
            }
        }
    }
}

SCENARIO( "a running conversion can be cancelled", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a conversion of a capture that is running" )
    {
        FakeHost host;
        auto widget = std::make_unique<SidebarWidget>();
        widget->openPcapFile( writeCapture( dir, "big.pcap", captureOf( 20000 ) ) );
        REQUIRE( widget->isConverting() );

        WHEN( "the user cancels it" )
        {
            child<QPushButton>( *widget, "cancelButton" )->click();
            REQUIRE( waitFor( [ &widget ] { return !widget->isConverting(); } ) );

            THEN( "no tab is opened, and the sidebar says it was cancelled" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( child<QLabel>( *widget, "summary" )->text().contains( "Cancelled" ) );
                REQUIRE( child<QPushButton>( *widget, "openButton" )->isEnabled() );
            }
        }

        WHEN( "the widget is destroyed, as when the plugin is unloaded" )
        {
            widget.reset();
            QCoreApplication::processEvents();

            THEN( "the conversion is stopped first, and no tab is opened" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
            }
        }
    }
}
