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
           && a.layout.macColumns == b.layout.macColumns && a.preview == b.preview
           && a.previewChars == b.previewChars && a.maxStreams == b.maxStreams
           && a.maxEndpoints == b.maxEndpoints;
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
        options.layout = { TimeColumns::RelativeOnly, true };
        options.preview = false;
        options.previewChars = 64;
        options.maxStreams = 5000;
        options.maxEndpoints = 300;

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
        }

        THEN( "those values are their defaults or the nearest allowed" )
        {
            const auto options = loadConversionOptions( configDir.path() );
            REQUIRE( options.layout.timeColumns == TimeColumns::Both );
            REQUIRE( options.previewChars == kMaxPreviewChars );
            REQUIRE( options.maxStreams == kMinCap );
            REQUIRE( options.maxEndpoints == ConversionOptions{}.maxEndpoints );
        }
    }
}
