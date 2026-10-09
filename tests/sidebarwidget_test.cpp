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
#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "regex_lab.h"
#include "settings.h"
#include "sidebarwidget.h"

#include <QDesktopServices>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLocale>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QUrl>

#include <memory>
#include <set>

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );

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

} // namespace

SCENARIO( "a capture is converted in the background and opened in a tab", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar and a small capture" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( dir.path() );
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
        widget.setTempRoot( dir.path() );
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

SCENARIO( "each conversion reads the options saved when it starts", "[sidebar][settings]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar, a capture and options saved in the configuration directory" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( dir.path() );
        const auto capture = writeCapture( dir, "small.pcap", captureOf( 2 ) );
        tcpdump::ConversionOptions options;
        options.layout.timeColumns = tcpdump::TimeColumns::RelativeOnly;
        options.preview = false;
        REQUIRE( tcpdump::saveConversionOptions( host.configDir(), options ) );

        auto convertAndRead = [ & ] {
            widget.openPcapFile( capture );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );
            REQUIRE_FALSE( host.openedFiles.isEmpty() );
            QFile out( host.openedFiles.last() );
            REQUIRE( out.open( QIODevice::ReadOnly ) );
            return QString::fromUtf8( out.readAll() );
        };

        WHEN( "the capture is opened" )
        {
            const auto text = convertAndRead();

            THEN( "it is converted with them" )
            {
                REQUIRE_FALSE( text.contains( "UTC Time" ) );
                REQUIRE_FALSE( text.contains( "payload" ) );
            }

            AND_WHEN( "the options change and it is opened again" )
            {
                REQUIRE( tcpdump::saveConversionOptions( host.configDir(), {} ) );
                const auto again = convertAndRead();

                THEN( "the new conversion has the new options, the first keeps its own" )
                {
                    REQUIRE( again.contains( "UTC Time" ) );
                    REQUIRE( again.contains( "payload" ) );
                    QFile first( host.openedFiles.first() );
                    REQUIRE( first.open( QIODevice::ReadOnly ) );
                    REQUIRE( QString::fromUtf8( first.readAll() ) == text );
                }
            }
        }
    }
}

SCENARIO( "the sidebar shows why the output could not be written", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar whose temporary root does not exist" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( dir.filePath( "no-such-root" ) );
        const auto capture = writeCapture( dir, "small.pcap", captureOf( 1 ) );

        WHEN( "a capture is opened" )
        {
            widget.openPcapFile( capture );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "the error names the temporary directory, and no tab is opened" )
            {
                REQUIRE( host.openedFiles.isEmpty() );
                REQUIRE( host.notifications.size() == 1 );
                REQUIRE(
                    host.notifications.first().contains( "Cannot create a temporary directory" ) );
                REQUIRE( child<QLabel>( widget, "summary" )
                             ->text()
                             .contains( "Error: Cannot create a temporary directory" ) );
            }
        }
    }
}

SCENARIO( "the Open button asks for a capture and opens it", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar whose file dialog selects a capture" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( dir.path() );
        const auto capture = writeCapture( dir, "small.pcap", captureOf( 3 ) );
        QWidget* dialogParent = nullptr;
        widget.setFileChooser( [ &dialogParent, &capture ]( QWidget* parent, const QString& ) {
            dialogParent = parent;
            return capture;
        } );

        WHEN( "the Open button is clicked" )
        {
            child<QPushButton>( widget, "openButton" )->click();

            THEN( "the dialog is shown over the sidebar and the capture opened in a tab" )
            {
                REQUIRE( dialogParent == &widget );
                REQUIRE( waitFor( [ &host ] { return host.openedFiles.size() == 1; } ) );
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
        widget->setTempRoot( dir.path() );
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

SCENARIO( "each conversion writes a new private file", "[sidebar]" )
{
    QTemporaryDir captures;
    QTemporaryDir tempRoot;
    REQUIRE( captures.isValid() );
    REQUIRE( tempRoot.isValid() );
    QDir( captures.path() ).mkdir( "a" );
    QDir( captures.path() ).mkdir( "b" );

    GIVEN( "a sidebar whose temporary files go below a test directory" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( tempRoot.path() );

        WHEN( "two captures with the same name are opened one after the other" )
        {
            widget.openPcapFile( writeCapture( captures, "a/capture.pcap", captureOf( 1 ) ) );
            REQUIRE( waitFor( [ &host ] { return host.openedFiles.size() == 1; } ) );
            widget.openPcapFile( writeCapture( captures, "b/capture.pcap", captureOf( 2 ) ) );
            REQUIRE( waitFor( [ &host ] { return host.openedFiles.size() == 2; } ) );
            const auto first = host.openedFiles.at( 0 );
            const auto second = host.openedFiles.at( 1 );

            THEN( "each gets its own file, named after the capture, and the first is kept" )
            {
                REQUIRE( first != second );
                REQUIRE( QFileInfo( first ).fileName() == "capture.log" );
                REQUIRE( QFileInfo( second ).fileName() == "capture.log" );
                QFile out( first );
                REQUIRE( out.open( QIODevice::ReadOnly ) );
                REQUIRE( out.readAll().count( '\n' ) == 2 ); // header + 1 packet
            }

            THEN( "each lives in its own directory below the temporary root" )
            {
                const auto dir = QFileInfo( first ).absoluteDir();
                REQUIRE( QFileInfo( dir.absolutePath() ).absolutePath()
                         == QFileInfo( tempRoot.path() ).absoluteFilePath() );
                REQUIRE(
                    dir.dirName().startsWith( QString( "logsquirl-tcpdump-%1-" )
                                                  .arg( QCoreApplication::applicationPid() ) ) );
            }

#ifdef Q_OS_UNIX
            THEN( "only the user can read the file and enter its directory" )
            {
                const QFileDevice::Permissions groupOrOther
                    = QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                      | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
                REQUIRE( ( QFile::permissions( first ) & groupOrOther ) == 0 );
                REQUIRE( ( QFile::permissions( QFileInfo( first ).absolutePath() ) & groupOrOther )
                         == 0 );
            }
#endif
        }

        WHEN( "a conversion fails" )
        {
            widget.openPcapFile( writeCapture( captures, "junk.pcap", Bytes( 64, 0xEE ) ) );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "its temporary directory is removed" )
            {
                REQUIRE( QDir( tempRoot.path() ).isEmpty() );
            }
        }

        WHEN( "a conversion is cancelled" )
        {
            widget.openPcapFile( writeCapture( captures, "big.pcap", captureOf( 20000 ) ) );
            widget.cancel();
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "its temporary directory is removed" )
            {
                REQUIRE( QDir( tempRoot.path() ).isEmpty() );
            }
        }
    }

    GIVEN( "a sidebar that is destroyed while it converts" )
    {
        FakeHost host;
        auto widget = std::make_unique<SidebarWidget>();
        widget->setTempRoot( tempRoot.path() );
        widget->openPcapFile( writeCapture( captures, "big.pcap", captureOf( 20000 ) ) );
        widget.reset();

        THEN( "the unfinished conversion's directory is removed" )
        {
            REQUIRE( QDir( tempRoot.path() ).isEmpty() );
        }
    }
}

SCENARIO( "the first summary of a session points to the Log Format", "[sidebar]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    GIVEN( "a sidebar, as created when the plugin is loaded" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( dir.path() );
        auto* summary = child<QLabel>( widget, "summary" );
        const QString readmeSection
            = "https://github.com/64x-lunicorn/LogSquirl-tcpdump#log-format";

        WHEN( "a first capture is converted" )
        {
            widget.openPcapFile( writeCapture( dir, "first.pcap", captureOf( 1 ) ) );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "the summary links to the README section on installing the Log Format" )
            {
                REQUIRE( summary->text().contains( "first.pcap" ) );
                REQUIRE( summary->text().contains( "href=\"" + readmeSection + "\"" ) );

                AND_WHEN( "the user clicks the link" )
                {
                    UrlRecorder browser;
                    QDesktopServices::setUrlHandler( "https", &browser, "open" );
                    emit summary->linkActivated( linkTarget( summary->text(), "install it once" ) );
                    QDesktopServices::unsetUrlHandler( "https" );

                    THEN( "the README section opens in the browser" )
                    {
                        REQUIRE( browser.opened == QList<QUrl>{ QUrl( readmeSection ) } );
                        REQUIRE( host.regexLabs.isEmpty() );
                    }
                }
            }

            AND_WHEN( "another capture is converted" )
            {
                widget.openPcapFile( writeCapture( dir, "second.pcap", captureOf( 1 ) ) );
                REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

                THEN( "its summary no longer carries the hint" )
                {
                    REQUIRE( summary->text().contains( "second.pcap" ) );
                    REQUIRE_FALSE( summary->text().contains( readmeSection ) );
                }
            }
        }

        WHEN( "a conversion fails first" )
        {
            widget.openPcapFile( writeCapture( dir, "bad.pcap", Bytes( 64, 0 ) ) );
            REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

            THEN( "the hint waits for the first converted capture" )
            {
                REQUIRE_FALSE( summary->text().contains( readmeSection ) );
                widget.openPcapFile( writeCapture( dir, "good.pcap", captureOf( 1 ) ) );
                REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );
                REQUIRE( summary->text().contains( readmeSection ) );
            }
        }
    }
}

SCENARIO( "the sidebar summary follows the tab in front", "[sidebar]" )
{
    QTemporaryDir dir;
    QTemporaryDir tempRoot;
    REQUIRE( dir.isValid() );
    REQUIRE( tempRoot.isValid() );

    GIVEN( "an initialised plugin that converted two captures, each opened in a tab" )
    {
        FakeHost host;
        tcpdump::g_state.tempRoot = tempRoot.path();
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        REQUIRE( host.hasActiveFileCallback() );
        auto* widget = tcpdump::g_state.sidebarWidget;
        auto* summary = child<QLabel>( *widget, "summary" );

        widget->openPcapFile( writeCapture( dir, "first.pcap", captureOf( 1 ) ) );
        REQUIRE( waitFor( [ widget ] { return !widget->isConverting(); } ) );
        widget->openPcapFile( writeCapture( dir, "second.pcap", captureOf( 2 ) ) );
        REQUIRE( waitFor( [ widget ] { return !widget->isConverting(); } ) );
        REQUIRE( host.openedFiles.size() == 2 );
        const auto first = host.openedFiles.at( 0 );
        const auto second = host.openedFiles.at( 1 );

        WHEN( "the first capture's tab comes to the front" )
        {
            host.activateFile( first );

            THEN( "the sidebar shows the first capture's summary, as it was" )
            {
                REQUIRE( summary->text().contains( "first.pcap" ) );
                REQUIRE_FALSE( summary->text().contains( "second.pcap" ) );
                REQUIRE( summary->text().contains( "#log-format" ) );
            }

            AND_WHEN( "the second capture's tab comes to the front again" )
            {
                host.activateFile( second );

                THEN( "the sidebar shows the second capture's summary" )
                {
                    REQUIRE( summary->text().contains( "second.pcap" ) );
                    REQUIRE_FALSE( summary->text().contains( "first.pcap" ) );
                }
            }
        }

        WHEN( "a tab with a file the plugin did not write comes to the front" )
        {
            host.activateFile( dir.filePath( "server.log" ) );

            THEN( "the sidebar says the tab holds no capture, and names none" )
            {
                REQUIRE( summary->text() == "No capture in this tab." );
            }

            AND_WHEN( "a capture's tab comes back" )
            {
                host.activateFile( first );

                THEN( "its summary is shown again" )
                {
                    REQUIRE( summary->text().contains( "first.pcap" ) );
                }
            }
        }

        WHEN( "a tab that holds no Log File comes to the front, such as the dashboard" )
        {
            host.activateFile( QString() );

            THEN( "the sidebar says the tab holds no capture" )
            {
                REQUIRE( summary->text() == "No capture in this tab." );
            }
        }

        WHEN( "the host names a capture's file by another spelling of its path" )
        {
            const QFileInfo info( first );
            host.activateFile( info.absolutePath() + "/./" + info.fileName() );

            THEN( "the capture is still recognised" )
            {
                REQUIRE( summary->text().contains( "first.pcap" ) );
            }
        }

        WHEN( "a third capture is converted" )
        {
            widget->openPcapFile( writeCapture( dir, "third.pcap", captureOf( 3 ) ) );
            REQUIRE( waitFor( [ widget ] { return !widget->isConverting(); } ) );
            REQUIRE( host.openedFiles.size() == 3 );

            THEN( "the summaries of the others are kept" )
            {
                REQUIRE( summary->text().contains( "third.pcap" ) );
                host.activateFile( first );
                REQUIRE( summary->text().contains( "first.pcap" ) );
                host.activateFile( second );
                REQUIRE( summary->text().contains( "second.pcap" ) );
            }
        }

        WHEN( "the tab in front changes while a capture is being read" )
        {
            widget->openPcapFile( writeCapture( dir, "big.pcap", captureOf( 20000 ) ) );
            host.activateFile( first );

            THEN( "the sidebar keeps showing the reading, until it is done" )
            {
                REQUIRE( summary->text().contains( "Reading big.pcap" ) );
                widget->cancel();
                REQUIRE( waitFor( [ widget ] { return !widget->isConverting(); } ) );
            }
        }

        logsquirl_plugin_shutdown();
    }
}

SCENARIO( "the summary shows names as text, not markup", "[sidebar]" )
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

SCENARIO( "the summary's filter links keep any name intact", "[sidebar]" )
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

SCENARIO( "the summary lists the capture's link-layer types", "[sidebar]" )
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

SCENARIO( "the summary shows the earliest and latest packet time", "[sidebar]" )
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

SCENARIO( "the summary lists the busiest endpoints", "[sidebar]" )
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

SCENARIO( "the summary says what was cut", "[sidebar]" )
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

SCENARIO( "the summary lists the TCP analysis markers", "[sidebar]" )
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

    GIVEN( "a capture without any" )
    {
        THEN( "there is no Analysis heading" )
        {
            const auto html = tcpdump::summaryHtml( "clean.pcap", 100, tcpdump::CaptureSummary() );
            REQUIRE_FALSE( html.contains( "Analysis" ) );
        }
    }
}

SCENARIO( "endpoints and protocols in the summary open the Regex Lab as filters", "[sidebar]" )
{
    QTemporaryDir tempRoot;
    REQUIRE( tempRoot.isValid() );
    const auto capture = QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( "mixed.pcap" );

    GIVEN( "a capture converted on a host with the Regex Lab" )
    {
        FakeHost host;
        SidebarWidget widget;
        widget.setTempRoot( tempRoot.path() );
        auto* summary = child<QLabel>( widget, "summary" );
        widget.openPcapFile( capture );
        REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );
        REQUIRE( host.openedFiles.size() == 1 );
        const auto text = host.openedFiles.first();

        THEN( "each endpoint and protocol listed is a link" )
        {
            for ( const auto& name :
                  { "192.168.1.1", "192.168.1.100", "fe80::1", "HTTP", "ICMPv6", "SOCKS" } ) {
                INFO( name );
                REQUIRE_FALSE( linkTarget( summary->text(), name ).isEmpty() );
            }
        }

        WHEN( "the user clicks an IPv6 endpoint" )
        {
            emit summary->linkActivated( linkTarget( summary->text(), "fe80::1" ) );

            THEN( "the Regex Lab opens with the pattern of that address, matching case" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                const auto& lab = host.regexLabs.first();
                REQUIRE( lab.pattern == tcpdump::endpointPattern( "fe80::1" ) );
                REQUIRE( lab.flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( matchedLines( text, lab.pattern ) == std::set<int>{ 8, 9, 10 } );
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

        WHEN( "the user clicks an IPv4 endpoint that starts another" )
        {
            emit summary->linkActivated( linkTarget( summary->text(), "192.168.1.1" ) );

            THEN( "the pattern matches its lines in Source or Destination, not the other's" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                const auto& lab = host.regexLabs.first();
                REQUIRE( lab.pattern == tcpdump::endpointPattern( "192.168.1.1" ) );
                std::set<int> expected;
                for ( int line = 2; line <= 22; ++line ) {
                    if ( line < 8 || line > 10 ) {
                        expected.insert( line );
                    }
                }
                REQUIRE( matchedLines( text, lab.pattern ) == expected );
            }
        }

        WHEN( "the user clicks the endpoint it starts" )
        {
            emit summary->linkActivated( linkTarget( summary->text(), "192.168.1.100" ) );

            THEN( "the pattern matches that address's line only" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( matchedLines( text, host.regexLabs.first().pattern )
                         == std::set<int>{ 22 } );
            }
        }

        WHEN( "the user clicks a protocol" )
        {
            emit summary->linkActivated( linkTarget( summary->text(), "HTTP" ) );

            THEN( "the Regex Lab opens with the pattern of that Protocol column" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                const auto& lab = host.regexLabs.first();
                REQUIRE( lab.pattern == tcpdump::protocolPattern( "HTTP" ) );
                REQUIRE( matchedLines( text, lab.pattern ) == std::set<int>{ 2, 3, 4 } );
            }
        }
    }

    GIVEN( "a capture converted on a host older than LogSquirl 26.11" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );
        SidebarWidget widget;
        widget.setTempRoot( tempRoot.path() );
        auto* summary = child<QLabel>( widget, "summary" );
        widget.openPcapFile( capture );
        REQUIRE( waitFor( [ &widget ] { return !widget.isConverting(); } ) );

        THEN( "the summary lists endpoints and protocols as plain text, as before" )
        {
            REQUIRE( summary->text().contains( "<b>Endpoints</b>" ) );
            REQUIRE( summary->text().contains( "192.168.1.1: " ) );
            REQUIRE( summary->text().contains( "HTTP: " ) );
            REQUIRE_FALSE( summary->text().contains( "tcpdump-filter:" ) );
        }
    }
}

#include "sidebarwidget_test.moc"
