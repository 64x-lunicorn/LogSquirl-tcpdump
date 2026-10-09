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
 * @file packet_export_test.cpp
 * @brief BDD tests for Export Packets: chosen packets of a capture written
 *        to a new capture file, record for record.
 */

#include <catch2/catch.hpp>

#include "capture_reader.h"
#include "corpus_layouts.h"
#include "export_dialog.h"
#include "fakehost.h"
#include "packet_export.h"
#include "pcap_converter.h"
#include "sidebarwidget.h"

#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QPushButton>
#include <QTemporaryDir>

#include <atomic>
#include <cstring>

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );

using namespace tcpdump;
using tcpdump_test::FakeHost;
using tcpdump_test::waitFor;

namespace {

QByteArray readAll( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return file.readAll();
}

/// A capture's packets with the bytes of their records, as they are in the file.
struct Records {
    ParseResult parsed;
    std::vector<QByteArray> records;
    std::vector<CaptureHeaders> headers;
};

Records recordsOf( const QByteArray& bytes )
{
    Records result;
    const auto* data = reinterpret_cast<const uint8_t*>( bytes.constData() );
    result.parsed = parsePcap( data, static_cast<size_t>( bytes.size() ) );
    REQUIRE( result.parsed.ok );
    MemorySource memory( data, static_cast<size_t>( bytes.size() ) );
    HeadSource source( memory );
    const auto reader = makeCaptureReader( source );
    REQUIRE( reader->open() );
    PacketRecord packet;
    while ( reader->next( packet ) ) {
        result.records.push_back( bytes.mid( static_cast<qsizetype>( reader->recordOffset() ),
                                             static_cast<qsizetype>( reader->recordLength() ) ) );
        result.headers.push_back( reader->headers() );
    }
    return result;
}

ConversionResult convert( const QString& capture, const QString& outputRoot, uint32_t interval )
{
    ConversionOptions options;
    options.checkpointInterval = interval;
    auto result = convertPcap( capture, outputRoot, nullptr, {}, options );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    REQUIRE( result.index );
    return result;
}

/// The first 4 bytes of @p bytes at @p offset in host order.
uint32_t word( const QByteArray& bytes, qsizetype offset )
{
    uint32_t value = 0;
    std::memcpy( &value, bytes.constData() + offset, 4 );
    return value;
}

/// A loaded plugin whose sidebar converted @p capture and whose tab of it is
/// in front; the Export dialog answered by the test.
struct LoadedCapture {
    explicit LoadedCapture( const QString& capture )
    {
        REQUIRE( tempRoot.isValid() );
        g_state.tempRoot = tempRoot.path();
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        sidebar = g_state.sidebarWidget;
        sidebar->openPcapFile( capture );
        REQUIRE( waitFor( [ this ] { return !sidebar->isConverting(); } ) );
        REQUIRE( host.openedFiles.size() == 1 );
        QFile file( host.openedFiles.first() );
        REQUIRE( file.open( QIODevice::ReadOnly ) );
        lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
        host.activateFile( host.openedFiles.first() );
        sidebar->setExportConfirmer( [ this ]( QWidget*, ExportRequest& request ) {
            requests.push_back( request );
            request.outputPath = outputPath;
            return confirm;
        } );
    }

    ~LoadedCapture()
    {
        logsquirl_plugin_shutdown();
    }

    /// Choose Plugins > tcpdump > Export packets… and wait for the export.
    void exportSelected()
    {
        const auto entry
            = std::find_if( host.menuActions.begin(), host.menuActions.end(), []( const auto& a ) {
                  return a.label == "Export packets\xe2\x80\xa6";
              } );
        REQUIRE( entry != host.menuActions.end() );
        entry->trigger();
        REQUIRE( waitFor( [ this ] { return !sidebar->isExporting(); } ) );
    }

    QTemporaryDir tempRoot;
    FakeHost host;
    SidebarWidget* sidebar = nullptr;
    QStringList lines; ///< The text's lines, the header first.
    QString outputPath = tempRoot.filePath( "export.pcap" );
    bool confirm = true;
    std::vector<ExportRequest> requests;
};

} // namespace

SCENARIO( "Exported packets are the capture's records, byte for byte", "[packet_export]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    for ( const auto& capture : tcpdump_test::committedCaptures() ) {
        GIVEN( "the corpus capture " + QFileInfo( capture ).fileName().toStdString() )
        {
            // Checkpoints every 3 packets: the export reads on across them.
            const auto converted = convert( capture, out.path(), 3 );
            const auto source = recordsOf( readAll( capture ) );
            const auto packets = converted.index->packets();
            REQUIRE( packets == source.records.size() );

            // Every other packet and the last one, asked for out of order and twice.
            std::vector<uint32_t> chosen;
            for ( uint32_t number = packets; number >= 1; number -= std::min( number, 2u ) ) {
                chosen.push_back( number );
            }
            chosen.push_back( packets );
            std::vector<uint32_t> expected( chosen );
            std::sort( expected.begin(), expected.end() );
            expected.erase( std::unique( expected.begin(), expected.end() ), expected.end() );

            const auto path = out.filePath( "export" );
            const auto result = exportPackets( converted.index, chosen, path );
            REQUIRE( result.status == ExportResult::Status::Exported );
            REQUIRE( result.packets == expected.size() );
            REQUIRE( result.format == captureFormatOf( capture ) );

            THEN( "the export holds exactly those records, in order, as they are in the capture" )
            {
                const auto exported = recordsOf( readAll( path ) );
                REQUIRE( exported.records.size() == expected.size() );
                REQUIRE_FALSE( exported.parsed.truncated );
                REQUIRE( exported.parsed.precision == source.parsed.precision );
                for ( size_t i = 0; i < expected.size(); ++i ) {
                    INFO( "packet " << expected[ i ] );
                    const auto& original = source.parsed.packets[ expected[ i ] - 1 ];
                    const auto& copy = exported.parsed.packets[ i ];
                    REQUIRE( exported.records[ i ] == source.records[ expected[ i ] - 1 ] );
                    REQUIRE( copy.timestampSec == original.timestampSec );
                    REQUIRE( copy.timestampNsec == original.timestampNsec );
                    REQUIRE( copy.capturedLen == original.capturedLen );
                    REQUIRE( copy.originalLen == original.originalLen );
                    REQUIRE( copy.linkType == original.linkType );
                    REQUIRE( copy.precision == original.precision );
                    REQUIRE( copy.info == original.info );
                }
            }

            THEN( "a pcap's export starts with its global header" )
            {
                if ( result.format == CaptureFormat::Pcap ) {
                    const auto exported = readAll( path );
                    const auto original = readAll( capture );
                    const auto start
                        = static_cast<qsizetype>( source.headers.front().records.front().offset );
                    REQUIRE( exported.left( 24 ) == original.mid( start, 24 ) );
                }
            }
        }
    }
}

SCENARIO( "A pcapng export keeps the interfaces and sections of its packets", "[packet_export]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    // Section 1 (little-endian): Ethernet eth0 and Raw IP tun0 with
    // nanoseconds, packets 1-5; section 2 (big-endian): Linux SLL2, packet 6.
    const auto capture = QStringLiteral( TCPDUMP_CORPUS_DIR "/interfaces.pcapng" );
    const auto converted = convert( capture, out.path(), 2 );
    const auto source = recordsOf( readAll( capture ) );
    REQUIRE( converted.index->packets() == 6 );

    GIVEN( "a packet of the second interface of the first section and the packet of the second" )
    {
        const auto path = out.filePath( "export.pcapng" );
        const auto result = exportPackets( converted.index, { 4, 6 }, path );
        REQUIRE( result.status == ExportResult::Status::Exported );
        REQUIRE( result.format == CaptureFormat::Pcapng );
        const auto bytes = readAll( path );
        const auto exported = recordsOf( bytes );

        THEN( "each packet keeps its interface: link type, timestamp unit and byte order" )
        {
            REQUIRE( exported.records.size() == 2 );
            REQUIRE( exported.records[ 0 ] == source.records[ 3 ] );
            REQUIRE( exported.records[ 1 ] == source.records[ 5 ] );
            REQUIRE( exported.parsed.packets[ 0 ].linkType == DltRaw );
            REQUIRE( exported.parsed.packets[ 0 ].precision == TimePrecision::Nanoseconds );
            REQUIRE( exported.parsed.packets[ 1 ].linkType == DltLinuxSll2 );
            REQUIRE( exported.parsed.linkTypes == source.parsed.linkTypes );
        }

        THEN( "both sections are written with all the interfaces they declared, nothing else" )
        {
            // SHB, 2 IDBs, EPB; SHB, IDB, EPB.
            const auto& first = exported.headers[ 0 ].records;
            const auto& second = exported.headers[ 1 ].records;
            REQUIRE( first.size() == 3 );
            REQUIRE( second.size() == 2 );
            REQUIRE( first[ 0 ].offset == 0 );
            const auto& original = source.headers[ 3 ].records;
            REQUIRE( first[ 1 ].length == original[ 1 ].length );
            REQUIRE( first[ 2 ].length == original[ 2 ].length );
            // Blocks follow each other with nothing between them.
            REQUIRE( first[ 1 ].offset == first[ 0 ].offset + first[ 0 ].length );
            REQUIRE( first[ 2 ].offset == first[ 1 ].offset + first[ 1 ].length );
            const auto firstPacket = first[ 2 ].offset + first[ 2 ].length;
            REQUIRE( second[ 0 ].offset == firstPacket + exported.records[ 0 ].size() );
            REQUIRE( static_cast<qsizetype>( second[ 1 ].offset + second[ 1 ].length
                                             + exported.records[ 1 ].size() )
                     == bytes.size() );
        }

        THEN( "the section headers say their length is unknown" )
        {
            const auto& second = exported.headers[ 1 ].records[ 0 ];
            for ( const auto at :
                  { qsizetype( 16 ), static_cast<qsizetype>( second.offset ) + 16 } ) {
                REQUIRE( word( bytes, at ) == 0xFFFFFFFF );
                REQUIRE( word( bytes, at + 4 ) == 0xFFFFFFFF );
            }
        }
    }

    GIVEN( "packets of the first section only" )
    {
        const auto path = out.filePath( "first.pcapng" );
        REQUIRE( exportPackets( converted.index, { 1, 5 }, path ).status
                 == ExportResult::Status::Exported );

        THEN( "only its section is written" )
        {
            const auto exported = recordsOf( readAll( path ) );
            REQUIRE( exported.records.size() == 2 );
            REQUIRE( exported.headers[ 0 ].records.front().offset
                     == exported.headers[ 1 ].records.front().offset );
            REQUIRE( exported.parsed.linkTypes == std::vector<uint32_t>{ DltEthernet, DltRaw } );
        }
    }
}

SCENARIO( "An export reports its progress, can be cancelled and leaves nothing when it fails",
          "[packet_export]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    const auto capture = dir.filePath( "copy.pcap" );
    REQUIRE( QFile::copy( QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ), capture ) );
    const auto converted = convert( capture, dir.path(), 3 );
    const auto packets = converted.index->packets();
    std::vector<uint32_t> all;
    for ( uint32_t number = 1; number <= packets; ++number ) {
        all.push_back( number );
    }
    const auto path = dir.filePath( "export.pcap" );

    GIVEN( "an export of all packets" )
    {
        std::vector<int> progress;
        const auto result
            = exportPackets( converted.index, all, path, nullptr,
                             [ & ]( int permille ) { progress.push_back( permille ); } );

        THEN( "its progress rises to 1000 permille" )
        {
            REQUIRE( result.status == ExportResult::Status::Exported );
            REQUIRE_FALSE( progress.empty() );
            REQUIRE( std::is_sorted( progress.begin(), progress.end() ) );
            REQUIRE( progress.back() == 1000 );
        }
    }

    GIVEN( "an export cancelled while it runs" )
    {
        std::atomic_bool cancel{ false };
        const auto result
            = exportPackets( converted.index, all, path, &cancel, [ & ]( int ) { cancel = true; } );

        THEN( "it stops and leaves no file" )
        {
            REQUIRE( result.status == ExportResult::Status::Cancelled );
            REQUIRE_FALSE( QFile::exists( path ) );
        }
    }

    GIVEN( "a capture file changed since it was converted" )
    {
        QFile file( capture );
        REQUIRE( file.open( QIODevice::Append ) );
        file.write( QByteArray( 16, '\0' ) );
        file.close();
        const auto result = exportPackets( converted.index, all, path );

        THEN( "the export fails, says why and leaves no file" )
        {
            REQUIRE( result.status == ExportResult::Status::Failed );
            REQUIRE( result.error.contains( "has changed since it was converted" ) );
            REQUIRE_FALSE( QFile::exists( path ) );
        }
    }

    GIVEN( "the capture itself as the export's file" )
    {
        const auto result = exportPackets( converted.index, { 1 }, capture );

        THEN( "it is not replaced" )
        {
            REQUIRE( result.status == ExportResult::Status::Failed );
            REQUIRE( result.error.contains( "cannot replace the capture" ) );
            REQUIRE( converted.index->fileProblem().isEmpty() );
        }
    }

    GIVEN( "no packet, or one the capture does not have" )
    {
        THEN( "nothing is exported" )
        {
            REQUIRE( exportPackets( converted.index, {}, path ).status
                     == ExportResult::Status::Failed );
            const auto beyond = exportPackets( converted.index, { 1, packets + 1 }, path );
            REQUIRE( beyond.status == ExportResult::Status::Failed );
            REQUIRE( beyond.error.contains( "has no packet" ) );
            REQUIRE_FALSE( QFile::exists( path ) );
        }
    }
}

SCENARIO( "The packets to export are read from packet lines, numbers and ranges",
          "[packet_export]" )
{
    GIVEN( "numbers and ranges" )
    {
        const auto set = parsePacketSet( "12-14, 3 7\n2 \xe2\x80\x93 3,,40", 100 );

        THEN( "they name their packets, ascending and each once" )
        {
            REQUIRE( set.numbers == std::vector<uint32_t>{ 2, 3, 7, 12, 13, 14, 40 } );
            REQUIRE( set.skipped == 0 );
        }
    }

    GIVEN( "numbers the capture has no packet of, and text" )
    {
        const auto set = parsePacketSet( "0, 5, 99-101, 120\nno packet here", 100 );

        THEN( "they are skipped and counted" )
        {
            REQUIRE( set.numbers == std::vector<uint32_t>{ 5 } );
            REQUIRE( set.skipped == 6 );
        }
    }

    GIVEN( "packet lines, as copied from LogSquirl" )
    {
        QTemporaryDir out;
        REQUIRE( out.isValid() );
        const auto lines = tcpdump_test::convertedLines(
            QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" ), {}, out.path() );
        const auto set = parsePacketSet( lines[ 4 ] + '\n' + lines[ 1 ] + "\n\n", 1000 );

        THEN( "their No. column counts" )
        {
            REQUIRE( set.numbers == std::vector<uint32_t>{ 2, 5 } );
            REQUIRE( set.skipped == 0 );
        }
    }

    THEN( "numbers are written back as ranges" )
    {
        REQUIRE( formatPacketRanges( { 1, 2, 3, 5, 7, 8 } ) == "1-3, 5, 7-8" );
        REQUIRE( formatPacketRanges( {} ).isEmpty() );
    }
}

SCENARIO( "Export packets writes the packets of the selected lines", "[packet_export]" )
{
    const auto capture = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );
    LoadedCapture loaded( capture );
    auto& host = loaded.host;
    const auto source = recordsOf( readAll( capture ) );

    GIVEN( "the header and three packet lines selected" )
    {
        host.selectedLines
            = { loaded.lines[ 0 ], loaded.lines[ 2 ], loaded.lines[ 5 ], loaded.lines[ 6 ] };
        loaded.exportSelected();

        THEN( "the user confirms their packets, which are written to the file chosen" )
        {
            REQUIRE( loaded.requests.size() == 1 );
            const auto& request = loaded.requests.front();
            REQUIRE( request.numbers == std::vector<uint32_t>{ 2, 5, 6 } );
            REQUIRE( request.captureName == "mixed.pcap" );
            REQUIRE( request.format == CaptureFormat::Pcap );
            REQUIRE_FALSE( request.truncated );

            const auto exported = recordsOf( readAll( loaded.outputPath ) );
            REQUIRE( exported.records.size() == 3 );
            REQUIRE( exported.records[ 0 ] == source.records[ 1 ] );
            REQUIRE( exported.records[ 2 ] == source.records[ 5 ] );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().startsWith( "Exported 3 packets of mixed.pcap" ) );
        }
    }

    GIVEN( "more lines selected than LogSquirl tells" )
    {
        host.selectedLines = { loaded.lines[ 1 ], loaded.lines[ 2 ] };
        host.selectionResult = LOGSQUIRL_LOG_LINES_TRUNCATED;
        loaded.exportSelected();

        THEN( "the user is told, before and after the export" )
        {
            REQUIRE( loaded.requests.front().truncated );
            REQUIRE( loaded.requests.front().selectedLines == 2 );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().contains(
                "LogSquirl told only the first 2 selected lines" ) );

            ExportDialog dialog( loaded.requests.front() );
            REQUIRE( dialog.findChild<QLabel*>( "truncatedNote" ) );
        }
    }

    GIVEN( "no line selected" )
    {
        loaded.confirm = false;
        loaded.exportSelected();

        THEN( "the user may still name the packets, and nothing is exported unconfirmed" )
        {
            REQUIRE( loaded.requests.size() == 1 );
            REQUIRE( loaded.requests.front().numbers.empty() );
            REQUIRE_FALSE( QFile::exists( loaded.outputPath ) );
            REQUIRE( host.notifications.isEmpty() );
        }
    }

    GIVEN( "a tab in front that shows no capture" )
    {
        host.activateFile( QString() );
        loaded.exportSelected();

        THEN( "nothing is asked and the user is told" )
        {
            REQUIRE( loaded.requests.empty() );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().contains( "shows no capture" ) );
        }
    }

    GIVEN( "an export cancelled at once" )
    {
        host.selectedLines = { loaded.lines[ 1 ] };
        const auto entry
            = std::find_if( host.menuActions.begin(), host.menuActions.end(), []( const auto& a ) {
                  return a.label == "Export packets\xe2\x80\xa6";
              } );
        entry->trigger();
        REQUIRE( loaded.sidebar->isExporting() );
        loaded.sidebar->cancelExport();
        REQUIRE( waitFor( [ & ] { return !loaded.sidebar->isExporting(); } ) );

        THEN( "the cancel wins: no file, no notification" )
        {
            REQUIRE_FALSE( QFile::exists( loaded.outputPath ) );
            REQUIRE( host.notifications.isEmpty() );
        }
    }
}

SCENARIO( "The Export dialog shows the packets its text names", "[packet_export]" )
{
    ExportRequest request;
    request.captureName = "mixed.pcap";
    request.packets = 20;
    request.numbers = { 1, 2, 3, 9 };
    ExportDialog dialog( request );
    auto* count = dialog.findChild<QLabel*>( "packetCount" );
    auto* button = dialog.findChild<QPushButton*>( "exportButton" );

    THEN( "the selection's packets are shown as ranges" )
    {
        REQUIRE( dialog.packetSet().numbers == request.numbers );
        REQUIRE( count->text() == "4 packets" );
        REQUIRE( button->isEnabled() );
        REQUIRE_FALSE( dialog.findChild<QLabel*>( "truncatedNote" ) );
    }

    WHEN( "the user names other packets, some of which the capture does not have" )
    {
        dialog.setText( "5-7, 30" );

        THEN( "those it has are taken, the others counted" )
        {
            REQUIRE( dialog.packetSet().numbers == std::vector<uint32_t>{ 5, 6, 7 } );
            REQUIRE( count->text().startsWith( "3 packets; 1 skipped" ) );
        }
    }

    WHEN( "the text names no packet" )
    {
        dialog.setText( "none" );

        THEN( "there is nothing to export" )
        {
            REQUIRE_FALSE( button->isEnabled() );
        }
    }
}
