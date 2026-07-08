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
 * @file plugininfo_test.cpp
 * @brief BDD tests verifying the plugin's C ABI metadata.
 */

#include <catch2/catch.hpp>

#include "logsquirl_plugin_api.h"

#include <cstring>

extern "C" const LogSquirlPluginInfo* logsquirl_plugin_get_info( void );

SCENARIO( "logsquirl_plugin_get_info returns valid metadata", "[plugininfo]" )
{
    GIVEN( "the exported get_info function" )
    {
        const auto* info = logsquirl_plugin_get_info();

        THEN( "the returned pointer is not null" )
        {
            REQUIRE( info != nullptr );
        }

        WHEN( "checking the plugin id" )
        {
            THEN( "it matches the expected reverse-domain identifier" )
            {
                REQUIRE( std::strcmp( info->id, "io.github.logsquirl.tcpdump" ) == 0 );
            }
        }

        WHEN( "checking the name" )
        {
            THEN( "it is 'tcpdump / pcap Viewer'" )
            {
                REQUIRE( std::strcmp( info->name, "tcpdump / pcap Viewer" ) == 0 );
            }
        }

        WHEN( "checking the API version" )
        {
            THEN( "it equals LOGSQUIRL_PLUGIN_API_VERSION" )
            {
                REQUIRE( info->api_version == LOGSQUIRL_PLUGIN_API_VERSION );
            }
        }

        WHEN( "checking the plugin type" )
        {
            THEN( "it is LOGSQUIRL_PLUGIN_UI" )
            {
                REQUIRE( info->type == LOGSQUIRL_PLUGIN_UI );
            }
        }

        WHEN( "checking the version string" )
        {
            THEN( "it is a non-empty string" )
            {
                REQUIRE( info->version != nullptr );
                REQUIRE( std::strlen( info->version ) > 0 );
            }
        }
    }
}
