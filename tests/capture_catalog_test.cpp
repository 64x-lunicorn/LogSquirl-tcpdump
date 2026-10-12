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
 * @file capture_catalog_test.cpp
 * @brief BDD tests for the Capture Catalog: the captures' entries by text
 *        file, the tab in front, a live capture's tabs and the parts Save
 *        capture… saves, with no widget.
 */

#include <catch2/catch.hpp>

#include "capture_catalog.h"
#include "capture_index.h"

#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <memory>
#include <vector>

using namespace tcpdump;

namespace {

/// A file @p name of @p size bytes in @p dir: a capture's text or raw file.
QString fileOf( const QTemporaryDir& dir, const QString& name, int size = 0 )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( QByteArray( size, 'x' ) );
    return path;
}

/// A summary of @p packets packets.
CaptureSummary summaryOf( uint64_t packets )
{
    CaptureSummary summary;
    summary.packets = packets;
    summary.bytes = packets * 100;
    return summary;
}

/// @p path spelled another way, as the host may report a tab's file.
QString otherSpelling( const QTemporaryDir& dir, const QString& name )
{
    return dir.path() + "/./" + name;
}

} // namespace

SCENARIO( "A capture's text file is kept in the catalog, and its entry replaced",
          "[capture_catalog]" )
{
    QTemporaryDir dir;
    CaptureCatalog catalog;

    GIVEN( "a live capture's text file, added before its tab opens" )
    {
        const auto log = fileOf( dir, "eth0.log" );
        const auto raw = fileOf( dir, "eth0.pcap", 24 );
        catalog.startLive();
        catalog.addFile( log, raw, "eth0" );

        THEN( "its entry names its raw file and capture, and has no summary yet" )
        {
            const auto* entry = catalog.find( log );
            REQUIRE( entry );
            REQUIRE( entry->rawPath == raw );
            REQUIRE( entry->captureName == "eth0" );
            REQUIRE( entry->fileName == "eth0.pcap" );
            REQUIRE( entry->fileSize == 24 );
            REQUIRE( entry->summary.packets == 0 );
            REQUIRE_FALSE( entry->index );
            REQUIRE( entry->error.isEmpty() );
            REQUIRE( catalog.find( otherSpelling( dir, "eth0.log" ) ) == entry );
        }

        WHEN( "a snapshot updates it, then one without an index" )
        {
            const auto index = std::make_shared<CaptureIndex>();
            catalog.updateFile( log, summaryOf( 3 ), index, 300 );
            catalog.updateFile( log, summaryOf( 5 ), nullptr, 500 );

            THEN( "it shows the latest summary and size, and keeps the index it has" )
            {
                const auto* entry = catalog.find( log );
                REQUIRE( entry->summary.packets == 5 );
                REQUIRE( entry->fileSize == 500 );
                REQUIRE( entry->index == index );
            }
        }
    }

    GIVEN( "a capture file converted" )
    {
        const auto log = fileOf( dir, "trace.log" );
        const auto capture = fileOf( dir, "trace.pcap", 40 );
        const auto index = std::make_shared<CaptureIndex>();
        catalog.addConverted( log, capture, summaryOf( 7 ), index );

        THEN( "its entry has the summary and index, and no raw file of a live capture" )
        {
            const auto* entry = catalog.find( log );
            REQUIRE( entry );
            REQUIRE( entry->fileName == "trace.pcap" );
            REQUIRE( entry->fileSize == 40 );
            REQUIRE( entry->summary.packets == 7 );
            REQUIRE( entry->index == index );
            REQUIRE( entry->rawPath.isEmpty() );
            REQUIRE_FALSE( catalog.isLive( log ) );
        }

        WHEN( "its summary is replaced" )
        {
            REQUIRE( catalog.updateSummary( log, summaryOf( 9 ) ) );

            THEN( "the entry shows the new one" )
            {
                REQUIRE( catalog.find( log )->summary.packets == 9 );
            }
        }
    }

    WHEN( "a file the plugin did not write is updated" )
    {
        const auto other = fileOf( dir, "other.log" );
        catalog.updateFile( other, summaryOf( 1 ), nullptr, 1 );
        catalog.setFileError( other, "lost" );

        THEN( "nothing is kept for it" )
        {
            REQUIRE_FALSE( catalog.updateSummary( other, summaryOf( 1 ) ) );
            REQUIRE_FALSE( catalog.find( other ) );
            REQUIRE( catalog.isEmpty() );
        }
    }
}

SCENARIO( "The catalog says which capture is in the tab in front", "[capture_catalog]" )
{
    QTemporaryDir dir;
    CaptureCatalog catalog;
    const auto first = fileOf( dir, "first.log" );
    const auto second = fileOf( dir, "second.log" );
    catalog.addConverted( first, fileOf( dir, "first.pcap" ), summaryOf( 1 ), {} );
    catalog.addConverted( second, fileOf( dir, "second.pcap" ), summaryOf( 2 ), {} );

    THEN( "no capture is in front before a tab is" )
    {
        REQUIRE_FALSE( catalog.front() );
    }

    WHEN( "the tabs come to the front in turn, spelled as the host spells them" )
    {
        catalog.setFront( otherSpelling( dir, "second.log" ) );
        REQUIRE( catalog.front() == catalog.find( second ) );
        REQUIRE( catalog.isFront( second ) );
        catalog.setFront( first );

        THEN( "the one in front now is" )
        {
            REQUIRE( catalog.front() == catalog.find( first ) );
            REQUIRE( catalog.front()->summary.packets == 1 );
            REQUIRE( catalog.frontFile() == fileKey( first ) );
            REQUIRE_FALSE( catalog.isFront( second ) );
        }
    }

    WHEN( "a tab of a file the plugin did not write comes to the front" )
    {
        catalog.setFront( fileOf( dir, "notes.txt" ) );

        THEN( "no capture is in front" )
        {
            REQUIRE_FALSE( catalog.front() );
        }
    }

    WHEN( "a tab without a Log File comes to the front" )
    {
        catalog.setFront( first );
        catalog.setFront( QString() );

        THEN( "no capture is in front" )
        {
            REQUIRE_FALSE( catalog.front() );
            REQUIRE( catalog.frontFile().isEmpty() );
            REQUIRE_FALSE( catalog.isFront( QString() ) );
        }
    }

    WHEN( "a file is added after its tab came to the front" )
    {
        const auto log = fileOf( dir, "late.log" );
        catalog.setFront( log );
        REQUIRE_FALSE( catalog.front() );
        catalog.startLive();
        catalog.addFile( log, fileOf( dir, "late.pcap" ), "late" );

        THEN( "it is the one in front" )
        {
            REQUIRE( catalog.front() == catalog.find( log ) );
        }
    }
}

SCENARIO( "A live capture's tabs stay the last capture's when it ends", "[capture_catalog]" )
{
    QTemporaryDir dir;
    CaptureCatalog catalog;
    const auto converted = fileOf( dir, "trace.log" );
    catalog.addConverted( converted, fileOf( dir, "trace.pcap" ), summaryOf( 1 ), {} );
    const auto log1 = fileOf( dir, "eth0_00001.log" );
    const auto log2 = fileOf( dir, "eth0_00002.log" );
    catalog.startLive();
    catalog.addFile( log1, fileOf( dir, "eth0_00001.pcap" ), "eth0" );
    catalog.addFile( log2, fileOf( dir, "eth0_00002.pcap" ), "eth0" );
    catalog.setFront( log1 );

    THEN( "each of its tabs is the running capture's, and a converted file's is not" )
    {
        REQUIRE( catalog.isLive( log1 ) );
        REQUIRE( catalog.isLive( otherSpelling( dir, "eth0_00002.log" ) ) );
        REQUIRE( catalog.isCapturing( log1 ) );
        REQUIRE( catalog.isCapturing( log2 ) );
        REQUIRE_FALSE( catalog.isLive( converted ) );
        REQUIRE_FALSE( catalog.isCapturing( converted ) );
        REQUIRE_FALSE( catalog.isLive( QString() ) );
    }

    WHEN( "it ends" )
    {
        catalog.endLive();

        THEN( "its tabs are the last capture's, no longer capturing" )
        {
            REQUIRE( catalog.isLive( log1 ) );
            REQUIRE( catalog.isLive( log2 ) );
            REQUIRE_FALSE( catalog.isCapturing( log1 ) );
            REQUIRE_FALSE( catalog.isCapturing( log2 ) );
            REQUIRE( catalog.find( log1 ) );
        }

        AND_WHEN( "the next one starts" )
        {
            const auto next = fileOf( dir, "wlan0.log" );
            catalog.startLive();
            catalog.addFile( next, fileOf( dir, "wlan0.pcap" ), "wlan0" );

            THEN( "the tabs before are no longer live, but keep their entries" )
            {
                REQUIRE_FALSE( catalog.isLive( log1 ) );
                REQUIRE_FALSE( catalog.isLive( log2 ) );
                REQUIRE( catalog.isLive( next ) );
                REQUIRE( catalog.isCapturing( next ) );
                REQUIRE( catalog.find( log1 )->captureName == "eth0" );
            }
        }
    }
}

SCENARIO( "A live capture's failed file keeps its error with the final summary",
          "[capture_catalog]" )
{
    QTemporaryDir dir;
    CaptureCatalog catalog;
    const auto log = fileOf( dir, "eth0.log" );
    catalog.startLive();
    catalog.addFile( log, fileOf( dir, "eth0.pcap" ), "eth0" );
    catalog.updateFile( log, summaryOf( 2 ), std::make_shared<CaptureIndex>(), 200 );
    catalog.setFileError( log, "tcpdump: permission denied" );
    catalog.updateFile( log, summaryOf( 3 ), std::make_shared<CaptureIndex>(), 300 );
    catalog.endLive();

    THEN( "the entry has the error and the final summary" )
    {
        const auto* entry = catalog.find( log );
        REQUIRE( entry->error == "tcpdump: permission denied" );
        REQUIRE( entry->summary.packets == 3 );
        REQUIRE( entry->fileSize == 300 );
    }

    WHEN( "the same text file is captured again" )
    {
        catalog.startLive();
        catalog.addFile( log, fileOf( dir, "eth0.pcap" ), "eth0" );

        THEN( "its new entry has no error" )
        {
            REQUIRE( catalog.find( log )->error.isEmpty() );
        }
    }
}

SCENARIO( "Save capture… saves the parts of the capture in front", "[capture_catalog]" )
{
    QTemporaryDir dir;
    CaptureCatalog catalog;

    THEN( "nothing is saved without a capture in front" )
    {
        REQUIRE( catalog.partsToSave().empty() );
        REQUIRE( catalog.saveName().isEmpty() );
    }

    GIVEN( "a ring buffer's live capture, its latest index listing the files it keeps" )
    {
        const auto log1 = fileOf( dir, "eth0_00001.log" );
        const auto log2 = fileOf( dir, "eth0_00002.log" );
        const auto raw1 = fileOf( dir, "eth0_00001.pcapng", 90 );
        const auto raw2 = fileOf( dir, "eth0_00002.pcapng", 40 );
        catalog.startLive();
        catalog.addFile( log1, raw1, "eth0" );
        catalog.addFile( log2, raw2, "eth0" );
        auto index = std::make_shared<CaptureIndex>();
        CapturePart first;
        first.path = raw1;
        CapturePart second;
        second.path = raw2;
        second.packetsBefore = 4;
        index->setCaptureParts( { first, second } );
        catalog.updateFile( log1, summaryOf( 6 ), index, 130 );
        catalog.updateFile( log2, summaryOf( 6 ), index, 130 );

        THEN( "with either of its tabs in front, its parts are the index's files, in order, "
              "named after the capture" )
        {
            for ( const auto& log : { log1, log2 } ) {
                catalog.setFront( log );
                const auto parts = catalog.partsToSave();
                REQUIRE( parts.size() == 2 );
                REQUIRE( parts[ 0 ].path == QFileInfo( raw1 ).canonicalFilePath() );
                REQUIRE( parts[ 1 ].path == QFileInfo( raw2 ).canonicalFilePath() );
                REQUIRE( parts[ 1 ].packetsBefore == 4 );
                REQUIRE( catalog.saveName() == "eth0.pcapng" );
            }
        }
    }

    GIVEN( "a live capture whose tab opened before its first snapshot" )
    {
        const auto log = fileOf( dir, "usb0.log" );
        const auto raw = fileOf( dir, "usb0.pcap", 24 );
        catalog.startLive();
        catalog.addFile( log, raw, "usb0" );
        catalog.setFront( log );

        THEN( "its one part is the raw file" )
        {
            const auto parts = catalog.partsToSave();
            REQUIRE( parts.size() == 1 );
            REQUIRE( parts[ 0 ].path == raw );
            REQUIRE( parts[ 0 ].packetsBefore == 0 );
            REQUIRE( catalog.saveName() == "usb0.pcap" );
        }

        AND_WHEN( "an index without parts comes" )
        {
            catalog.updateFile( log, summaryOf( 1 ), std::make_shared<CaptureIndex>(), 24 );

            THEN( "its one part is still the raw file" )
            {
                const auto parts = catalog.partsToSave();
                REQUIRE( parts.size() == 1 );
                REQUIRE( parts[ 0 ].path == raw );
            }
        }
    }

    GIVEN( "a live capture added without a name" )
    {
        const auto log = fileOf( dir, "anon.log" );
        catalog.startLive();
        catalog.addFile( log, fileOf( dir, "anon_raw.pcap" ), QString() );
        catalog.setFront( log );

        THEN( "it is named after its text file" )
        {
            REQUIRE( catalog.saveName() == "anon.pcap" );
        }
    }

    GIVEN( "a capture file converted, in front" )
    {
        const auto log = fileOf( dir, "trace.log" );
        catalog.addConverted( log, fileOf( dir, "trace.pcap" ), summaryOf( 1 ),
                              std::make_shared<CaptureIndex>() );
        catalog.setFront( log );

        THEN( "there is nothing to save: the file is the user's already" )
        {
            REQUIRE( catalog.partsToSave().empty() );
            REQUIRE( catalog.saveName().isEmpty() );
        }
    }
}
