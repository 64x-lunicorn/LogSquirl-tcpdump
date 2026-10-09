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
 * @file hpack_test.cpp
 * @brief BDD tests for the HPACK decoder: the examples of RFC 7541,
 *        Appendix C, its bounds, and mutated blocks.
 */

#include <catch2/catch.hpp>

#include "hpack.h"

#include <random>
#include <string>
#include <vector>

using namespace tcpdump;

namespace {

using Bytes = std::vector<uint8_t>;

Bytes fromHex( const std::string& hex )
{
    Bytes bytes;
    for ( size_t i = 0; i + 1 < hex.size(); i += 2 ) {
        bytes.push_back( static_cast<uint8_t>( std::stoul( hex.substr( i, 2 ), nullptr, 16 ) ) );
    }
    return bytes;
}

/// The fields of a decoded block as "name: value" lines.
std::vector<std::string> decoded( HpackDecoder& decoder, const std::string& hex )
{
    const auto block = fromHex( hex );
    std::vector<HeaderField> fields;
    REQUIRE( decoder.decode( block.data(), block.size(), fields ) );
    std::vector<std::string> lines;
    for ( const auto& field : fields ) {
        lines.push_back( field.name + ": " + field.value );
    }
    return lines;
}

using Lines = std::vector<std::string>;

} // namespace

SCENARIO( "HPACK decodes the requests of RFC 7541, C.4", "[hpack]" )
{
    GIVEN( "a decoder and three requests coded with Huffman, each building on the table" )
    {
        HpackDecoder decoder;

        THEN( "each decodes to its header list" )
        {
            REQUIRE( decoded( decoder, "828684418cf1e3c2e5f23a6ba0ab90f4ff" )
                     == Lines{ ":method: GET", ":scheme: http", ":path: /",
                               ":authority: www.example.com" } );
            REQUIRE( decoder.tableSize() == 57 );
            REQUIRE( decoded( decoder, "828684be5886a8eb10649cbf" )
                     == Lines{ ":method: GET", ":scheme: http", ":path: /",
                               ":authority: www.example.com", "cache-control: no-cache" } );
            REQUIRE( decoded( decoder, "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf" )
                     == Lines{ ":method: GET", ":scheme: https", ":path: /index.html",
                               ":authority: www.example.com", "custom-key: custom-value" } );
            REQUIRE( decoder.tableSize() == 164 );
        }
    }
}

SCENARIO( "HPACK decodes the responses of RFC 7541, C.6, evicting old entries", "[hpack]" )
{
    GIVEN( "a decoder whose table holds 256 bytes, and three responses" )
    {
        HpackDecoder decoder( 256 );

        THEN( "each decodes to its header list, the table keeping to its size" )
        {
            REQUIRE( decoded( decoder,
                              "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e0"
                              "82a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3" )
                     == Lines{ ":status: 302", "cache-control: private",
                               "date: Mon, 21 Oct 2013 20:13:21 GMT",
                               "location: https://www.example.com" } );
            REQUIRE( decoded( decoder, "4883640effc1c0bf" )
                     == Lines{ ":status: 307", "cache-control: private",
                               "date: Mon, 21 Oct 2013 20:13:21 GMT",
                               "location: https://www.example.com" } );
            REQUIRE(
                decoded( decoder,
                         "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e"
                         "7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c"
                         "003ed4ee5b1063d5007" )
                == Lines{ ":status: 200", "cache-control: private",
                          "date: Mon, 21 Oct 2013 20:13:22 GMT",
                          "location: https://www.example.com", "content-encoding: gzip",
                          "set-cookie: foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; "
                          "version=1" } );
            REQUIRE( decoder.tableSize() == 215 );
        }
    }
}

SCENARIO( "A header block that breaks a rule breaks the decoder", "[hpack]" )
{
    std::vector<HeaderField> fields;

    GIVEN( "an index past the tables" )
    {
        HpackDecoder decoder;
        const Bytes block{ 0xBF }; // index 63, the dynamic table empty

        THEN( "it is not decoded, nor any block after it" )
        {
            REQUIRE_FALSE( decoder.decode( block.data(), block.size(), fields ) );
            REQUIRE( decoder.broken() );
            const Bytes get{ 0x82 };
            REQUIRE_FALSE( decoder.decode( get.data(), get.size(), fields ) );
        }
    }

    GIVEN( "a table size update larger than the decoder holds" )
    {
        HpackDecoder decoder( 4096 );
        const auto block = fromHex( "3fe21f" ); // 4097

        THEN( "it is refused" )
        {
            REQUIRE_FALSE( decoder.decode( block.data(), block.size(), fields ) );
        }
    }

    GIVEN( "a table size update after a field" )
    {
        HpackDecoder decoder;
        const Bytes block{ 0x82, 0x20 };

        THEN( "it is refused" )
        {
            REQUIRE_FALSE( decoder.decode( block.data(), block.size(), fields ) );
        }
    }

    GIVEN( "a Huffman string padded with zero bits, and one with EOS" )
    {
        HpackDecoder decoder;
        const auto zeroPadded = fromHex( "4081"
                                         "00"
                                         "8100" ); // "0" + 0000000 padding
        HpackDecoder other;
        const auto eos = fromHex( "4084"
                                  "ffffffff"
                                  "8100" );

        THEN( "both are refused" )
        {
            REQUIRE_FALSE( decoder.decode( zeroPadded.data(), zeroPadded.size(), fields ) );
            REQUIRE_FALSE( other.decode( eos.data(), eos.size(), fields ) );
        }
    }

    GIVEN( "a string longer than the block" )
    {
        HpackDecoder decoder;
        const auto block = fromHex( "400a6b6579" );

        THEN( "it is refused" )
        {
            REQUIRE_FALSE( decoder.decode( block.data(), block.size(), fields ) );
        }
    }

    GIVEN( "an integer that does not end" )
    {
        HpackDecoder decoder;
        const auto block = fromHex( "ffffffffffffff" );

        THEN( "it is refused" )
        {
            REQUIRE_FALSE( decoder.decode( block.data(), block.size(), fields ) );
        }
    }
}

SCENARIO( "Mutated header blocks are decoded or refused, within bounds", "[hpack][fuzz]" )
{
    GIVEN( "the blocks of RFC 7541, C.4 and C.6, with random bytes flipped, cut and appended" )
    {
        const std::vector<Bytes> blocks{
            fromHex( "828684418cf1e3c2e5f23a6ba0ab90f4ff" ),
            fromHex( "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf" ),
            fromHex( "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e9"
                     "19d29ad171863c78f0b97c8e9ae82ae43d3" ),
        };
        std::mt19937 random( 84 );

        THEN( "the decoder never reads past a block, and its table keeps to its size" )
        {
            for ( int round = 0; round < 3000; ++round ) {
                HpackDecoder decoder( 512 );
                for ( int i = 0; i < 4; ++i ) {
                    auto block = blocks[ random() % blocks.size() ];
                    const auto flips = random() % 4;
                    for ( unsigned f = 0; f < flips; ++f ) {
                        block[ random() % block.size() ]
                            ^= static_cast<uint8_t>( 1 + random() % 255 );
                    }
                    if ( random() % 3 == 0 ) {
                        block.resize( random() % ( block.size() + 1 ) );
                    }
                    if ( random() % 5 == 0 ) {
                        block.push_back( static_cast<uint8_t>( random() ) );
                    }
                    // Decoded from a copy of its own size: a sanitizer would
                    // see a read past it.
                    const Bytes copy( block );
                    std::vector<HeaderField> fields;
                    decoder.decode( copy.data(), copy.size(), fields );
                    REQUIRE( decoder.tableSize() <= 512 );
                }
            }
        }
    }
}
