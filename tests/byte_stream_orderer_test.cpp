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
 * @file byte_stream_orderer_test.cpp
 * @brief BDD tests for the Byte Stream Orderer: segments of a TCP stream
 *        direction placed against the bytes taken, in sequence order.
 */

#include <catch2/catch.hpp>

#include "byte_stream_orderer.h"

#include <string>
#include <vector>

using tcpdump::ByteStreamOrderer;
using tcpdump::ByteView;
using Fit = ByteStreamOrderer::Fit;

namespace {

ByteView view( const std::string& s )
{
    return { reinterpret_cast<const uint8_t*>( s.data() ), s.size() };
}

std::string text( const std::vector<uint8_t>& bytes )
{
    return { bytes.begin(), bytes.end() };
}

} // namespace

SCENARIO( "The Byte Stream Orderer places segments against the bytes taken", "[orderer]" )
{
    GIVEN( "an orderer whose bytes end at sequence number 100" )
    {
        ByteStreamOrderer order( 100 );

        THEN( "a segment at 100 is next, with nothing taken of it" )
        {
            const auto place = order.place( 100, 10 );
            REQUIRE( place.fit == Fit::Next );
            REQUIRE( place.overlap == 0 );
        }

        THEN( "one that begins before and ends after 100 is next, its first bytes taken" )
        {
            const auto place = order.place( 95, 10 );
            REQUIRE( place.fit == Fit::Next );
            REQUIRE( place.overlap == 5 );
        }

        THEN( "one that ends at or before 100 was taken: a retransmission" )
        {
            REQUIRE( order.place( 90, 10 ).fit == Fit::Taken );
        }

        THEN( "one after 100 came early" )
        {
            REQUIRE( order.place( 101, 10 ).fit == Fit::Early );
        }

        THEN( "sequence numbers compare modulo 2^32" )
        {
            ByteStreamOrderer wrapping( 0xFFFFFFF0u );
            REQUIRE( wrapping.place( 0x10, 4 ).fit == Fit::Early );
            wrapping.advance( 0x20 );
            REQUIRE( wrapping.nextSeq() == 0x10 );
            REQUIRE( wrapping.place( 0xFFFFFFF8u, 4 ).fit == Fit::Taken );
        }
    }

    GIVEN( "two segments held early, the second overlapping the first" )
    {
        ByteStreamOrderer order( 100 );
        const std::string later = "klmnop", early = "fghijkl";
        order.holdEarly( 110, view( later ) );
        order.holdEarly( 105, view( early ) );

        THEN( "they are held, the same bytes again recognised" )
        {
            REQUIRE( order.early().size() == 2 );
            REQUIRE( order.earlyBytes() == 13 );
            REQUIRE( order.holds( 105, 7 ) );
            REQUIRE_FALSE( order.holds( 105, 8 ) );
            REQUIRE( order.firstEarlySeq() == 105u );
        }

        THEN( "none is next before the bytes ahead of them are taken" )
        {
            std::vector<uint8_t> bytes;
            REQUIRE_FALSE( order.popNext( bytes ) );
        }

        WHEN( "the bytes before them are taken" )
        {
            order.advance( 5 );

            THEN( "they pop in sequence order, overlapping bytes taken once" )
            {
                std::vector<uint8_t> bytes;
                REQUIRE( order.popNext( bytes ) );
                REQUIRE( text( bytes ) == "fghijkl" );
                order.advance( bytes.size() );
                REQUIRE( order.popNext( bytes ) );
                REQUIRE( text( bytes ) == "mnop" );
                order.advance( bytes.size() );
                REQUIRE_FALSE( order.popNext( bytes ) );
                REQUIRE( order.nextSeq() == 116 );
                REQUIRE( order.early().empty() );
            }
        }

        WHEN( "the bytes before them never come" )
        {
            THEN( "skipping to the first held one counts the gap" )
            {
                REQUIRE( order.skipTo( *order.firstEarlySeq() ) == 5 );
                std::vector<uint8_t> bytes;
                REQUIRE( order.popNext( bytes ) );
                REQUIRE( text( bytes ) == "fghijkl" );
            }

            THEN( "a skip backwards skips nothing" )
            {
                REQUIRE( order.skipTo( 90 ) == 0 );
                REQUIRE( order.nextSeq() == 100 );
            }
        }

        WHEN( "the orderer is reset" )
        {
            order.reset( 7 );

            THEN( "it holds nothing" )
            {
                REQUIRE( order.early().empty() );
                REQUIRE_FALSE( order.firstEarlySeq() );
                REQUIRE( order.nextSeq() == 7 );
            }
        }
    }
}
