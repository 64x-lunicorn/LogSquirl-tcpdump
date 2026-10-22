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
 * @file settings_test.cpp
 * @brief BDD tests for the settings file the configuration dialog writes.
 */

#include <catch2/catch.hpp>

#include "settings.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QSettings>
#include <QTemporaryDir>

using namespace tcpdump;

namespace tcpdump {

/// The same options, for REQUIRE.
bool operator==( const ConversionOptions& a, const ConversionOptions& b )
{
    return a.layout.timeColumns == b.layout.timeColumns
           && a.layout.macColumns == b.layout.macColumns && a.layout.hostNames == b.layout.hostNames
           && a.preview == b.preview && a.previewChars == b.previewChars
           && a.maxStreams == b.maxStreams && a.maxEndpoints == b.maxEndpoints
           && a.reassemblyMegabytes == b.reassemblyMegabytes && a.tcpTimestamps == b.tcpTimestamps
           && a.someIpPorts == b.someIpPorts && a.someIpNamesFile == b.someIpNamesFile
           && a.keyLogPath == b.keyLogPath;
}

} // namespace tcpdump

SCENARIO( "The conversion options are kept in the plugin's configuration directory", "[settings]" )
{
    QTemporaryDir configDir;
    REQUIRE( configDir.isValid() );

    GIVEN( "a configuration directory without a settings file" )
    {
        THEN( "the options are the defaults" )
        {
            REQUIRE( loadConversionOptions( configDir.path() ) == ConversionOptions{} );
        }
    }

    GIVEN( "no configuration directory, as without a host" )
    {
        THEN( "the options are the defaults, and they cannot be saved" )
        {
            REQUIRE( loadConversionOptions( {} ) == ConversionOptions{} );
            REQUIRE_FALSE( saveConversionOptions( {}, ConversionOptions{} ) );
        }
    }

    GIVEN( "options other than the defaults" )
    {
        ConversionOptions options;
        options.layout = { TimeColumns::RelativeOnly, true, true };
        options.preview = false;
        options.previewChars = 64;
        options.maxStreams = 5000;
        options.maxEndpoints = 300;
        options.reassemblyMegabytes = 16;
        options.tcpTimestamps = true;
        options.someIpPorts = { 30501, 30502 };
        options.someIpNamesFile = QStringLiteral( "/tmp/some ip, names.txt" );
        options.keyLogPath = configDir.filePath( "sslkeys.log" );

        WHEN( "they are saved" )
        {
            REQUIRE( saveConversionOptions( configDir.path(), options ) );

            THEN( "a settings file holds them, and they are read back, as after a restart" )
            {
                REQUIRE( QFile::exists( settingsFilePath( configDir.path() ) ) );
                REQUIRE( QFileInfo( settingsFilePath( configDir.path() ) ).dir()
                         == QDir( configDir.path() ) );
                REQUIRE( loadConversionOptions( configDir.path() ) == options );
            }
        }
    }

    GIVEN( "one SOME/IP port, then none" )
    {
        THEN( "each is read back" )
        {
            ConversionOptions options;
            options.someIpPorts = { 30501 };
            REQUIRE( saveConversionOptions( configDir.path(), options ) );
            REQUIRE( loadConversionOptions( configDir.path() ).someIpPorts
                     == std::vector<uint16_t>{ 30501 } );
            options.someIpPorts.clear();
            REQUIRE( saveConversionOptions( configDir.path(), options ) );
            REQUIRE( loadConversionOptions( configDir.path() ).someIpPorts.empty() );
        }
    }

    GIVEN( "each choice of time columns" )
    {
        for ( const auto timeColumns :
              { TimeColumns::Both, TimeColumns::AbsoluteOnly, TimeColumns::RelativeOnly } ) {
            ConversionOptions options;
            options.layout.timeColumns = timeColumns;
            REQUIRE( saveConversionOptions( configDir.path(), options ) );
            REQUIRE( loadConversionOptions( configDir.path() ).layout.timeColumns == timeColumns );
        }
    }

    GIVEN( "a settings file with values out of range or unknown" )
    {
        {
            QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            file.setValue( "conversion/timeColumns", "sideways" );
            file.setValue( "conversion/previewChars", 5000 );
            file.setValue( "conversion/maxStreams", 0 );
            file.setValue( "conversion/maxEndpoints", "many" );
            file.setValue( "conversion/reassemblyMegabytes", 1000000 );
            file.setValue( "conversion/someIpPorts", "30501, http, 99999" );
        }

        THEN( "those values are their defaults or the nearest allowed" )
        {
            const auto options = loadConversionOptions( configDir.path() );
            REQUIRE( options.layout.timeColumns == TimeColumns::Both );
            REQUIRE( options.previewChars == kMaxPreviewChars );
            REQUIRE( options.maxStreams == kMinCap );
            REQUIRE( options.maxEndpoints == ConversionOptions{}.maxEndpoints );
            REQUIRE( options.reassemblyMegabytes == kMaxReassemblyMegabytes );
            REQUIRE( options.someIpPorts == std::vector<uint16_t>{ 30501 } );
        }
    }
}

SCENARIO( "The sizes of the sidebar's splitters are kept in the settings file", "[settings]" )
{
    QTemporaryDir configDir;
    REQUIRE( configDir.isValid() );

    GIVEN( "a configuration directory without a settings file" )
    {
        THEN( "no sizes are saved" )
        {
            REQUIRE( loadSplitterSizes( configDir.path(), "summarySplit" ).isEmpty() );
        }
    }

    GIVEN( "no configuration directory, as without a host" )
    {
        THEN( "no sizes are saved, and none can be" )
        {
            REQUIRE( loadSplitterSizes( {}, "summarySplit" ).isEmpty() );
            REQUIRE_FALSE( saveSplitterSizes( {}, "summarySplit", { 200, 600 } ) );
        }
    }

    GIVEN( "the sizes of two splitters saved, and conversion options" )
    {
        ConversionOptions options;
        options.previewChars = 64;
        REQUIRE( saveConversionOptions( configDir.path(), options ) );
        REQUIRE( saveSplitterSizes( configDir.path(), "summarySplit", { 200, 600 } ) );
        REQUIRE( saveSplitterSizes( configDir.path(), "layersSplit", { 150, 90 } ) );

        THEN( "each splitter's sizes are read back, and the options are kept" )
        {
            REQUIRE( loadSplitterSizes( configDir.path(), "summarySplit" )
                     == QList<int>{ 200, 600 } );
            REQUIRE( loadSplitterSizes( configDir.path(), "layersSplit" )
                     == QList<int>{ 150, 90 } );
            REQUIRE( loadSplitterSizes( configDir.path(), "conversationsSplit" ).isEmpty() );
            REQUIRE( loadConversionOptions( configDir.path() ).previewChars == 64 );
        }

        THEN( "they are in the [sidebar] group of settings.ini" )
        {
            const QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            REQUIRE( file.value( "sidebar/summarySplit" ).toStringList()
                     == QStringList{ "200", "600" } );
        }
    }

    GIVEN( "a settings file with sizes that are not numbers of pixels" )
    {
        {
            QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            file.setValue( "sidebar/summarySplit", "200, tall" );
            file.setValue( "sidebar/layersSplit", "-5, 100" );
            file.setValue( "sidebar/conversationsSplit", "" );
        }

        THEN( "they read as none saved" )
        {
            REQUIRE( loadSplitterSizes( configDir.path(), "summarySplit" ).isEmpty() );
            REQUIRE( loadSplitterSizes( configDir.path(), "layersSplit" ).isEmpty() );
            REQUIRE( loadSplitterSizes( configDir.path(), "conversationsSplit" ).isEmpty() );
        }
    }
}
