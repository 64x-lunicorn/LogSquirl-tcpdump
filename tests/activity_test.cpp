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
 * @file activity_test.cpp
 * @brief BDD tests for the Activity rule: whether opening a capture file,
 *        starting a live capture or exporting packets may start, for every
 *        combination of a running conversion, live capture and export, and
 *        the one message of each reason.
 */

#include <catch2/catch.hpp>

#include "activity.h"

#include <optional>

using namespace tcpdump;

namespace {

/// What runs, from the bits of @p mask: 1 converting, 2 capturing, 4 exporting.
RunningActivities runningOf( int mask )
{
    RunningActivities running;
    running.converting = ( mask & 1 ) != 0;
    running.capturing = ( mask & 2 ) != 0;
    running.exporting = ( mask & 4 ) != 0;
    return running;
}

} // namespace

SCENARIO( "The Activity rule says whether an activity may start, and why not", "[activity]" )
{
    const auto mask = GENERATE( range( 0, 8 ) );
    const auto running = runningOf( mask );
    CAPTURE( running.converting, running.capturing, running.exporting );

    WHEN( "a capture file is to be opened" )
    {
        const auto refusal = activityRefusal( Activity::OpenFile, running );

        THEN( "a conversion refuses it first, then a live capture; an export does not" )
        {
            if ( running.converting ) {
                REQUIRE( refusal == ActivityRefusal::Converting );
            }
            else if ( running.capturing ) {
                REQUIRE( refusal == ActivityRefusal::Capturing );
            }
            else {
                REQUIRE_FALSE( refusal );
            }
        }
    }

    WHEN( "a live capture is to be started" )
    {
        const auto refusal = activityRefusal( Activity::LiveCapture, running );

        THEN( "a conversion refuses it first, then a live capture; an export does not" )
        {
            if ( running.converting ) {
                REQUIRE( refusal == ActivityRefusal::Converting );
            }
            else if ( running.capturing ) {
                REQUIRE( refusal == ActivityRefusal::Capturing );
            }
            else {
                REQUIRE_FALSE( refusal );
            }
        }
    }

    WHEN( "packets are to be exported" )
    {
        const auto refusal = activityRefusal( Activity::Export, running );

        THEN( "only another export refuses it" )
        {
            if ( running.exporting ) {
                REQUIRE( refusal == ActivityRefusal::Exporting );
            }
            else {
                REQUIRE_FALSE( refusal );
            }
        }
    }

    WHEN( "the message is asked for" )
    {
        const auto activity
            = GENERATE( Activity::OpenFile, Activity::LiveCapture, Activity::Export );
        const auto refusal = activityRefusal( activity, running );

        THEN( "it is the refusal's message, or empty if the activity may start" )
        {
            REQUIRE( activityRefusalMessage( activity, running )
                     == ( refusal ? refusalMessage( *refusal ) : QString() ) );
        }
    }
}

SCENARIO( "Each reason the Activity rule gives has one message", "[activity]" )
{
    THEN( "a conversion, a live capture and an export say what to do" )
    {
        REQUIRE( refusalMessage( ActivityRefusal::Converting )
                 == "A capture is still being read: wait for it, or cancel it first." );
        REQUIRE( refusalMessage( ActivityRefusal::Capturing )
                 == "A live capture is still running: stop it first." );
        REQUIRE( refusalMessage( ActivityRefusal::Exporting )
                 == "Packets are still being exported: wait for it, or cancel it first." );
    }
}
