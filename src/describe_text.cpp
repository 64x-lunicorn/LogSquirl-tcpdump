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
 * @file describe_text.cpp
 * @brief Payload bytes as text, for every detector of the Payload Describer.
 */

#include "describe_common.h"

#include <cstdio>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── Payload text ─────────────────────────────────────────────────────────

std::string hexCode( uint8_t code )
{
    char buf[ 8 ];
    std::snprintf( buf, sizeof( buf ), "0x%02X", code );
    return buf;
}

void markCut( std::string& text )
{
    if ( text.size() < kEllipsis.size()
         || text.compare( text.size() - kEllipsis.size(), kEllipsis.size(), kEllipsis ) != 0 ) {
        text += " " + kEllipsis;
    }
}

std::string hexValue( uint32_t value, int digits )
{
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "0x%0*X", digits, value );
    return buf;
}

int hexDigit( uint8_t c )
{
    if ( c >= '0' && c <= '9' ) {
        return c - '0';
    }
    if ( c >= 'a' && c <= 'f' ) {
        return c - 'a' + 10;
    }
    if ( c >= 'A' && c <= 'F' ) {
        return c - 'A' + 10;
    }
    return -1;
}

std::string hexBytes( const uint8_t* p, size_t len, size_t maxBytes )
{
    static const char kDigits[] = "0123456789abcdef";
    const auto shown = std::min( len, maxBytes );
    std::string out;
    out.reserve( 2 * shown );
    for ( size_t i = 0; i < shown; ++i ) {
        out += kDigits[ p[ i ] >> 4 ];
        out += kDigits[ p[ i ] & 0x0F ];
    }
    return len > maxBytes ? out + "\xe2\x80\xa6" : out;
}

std::string joinNames( std::vector<std::string> names, size_t maxNames, bool more )
{
    if ( names.size() > maxNames ) {
        names.resize( maxNames );
        more = true;
    }
    if ( more ) {
        names.emplace_back( "\xe2\x80\xa6" );
    }
    std::string joined;
    for ( const auto& name : names ) {
        joined += ( joined.empty() ? "" : ", " ) + name;
    }
    return joined;
}

std::string escapeBytes( const uint8_t* p, size_t len, bool quoted )
{
    std::string out;
    out.reserve( len );
    for ( size_t i = 0; i < len; ++i ) {
        const auto c = p[ i ];
        if ( c == '\\' || ( quoted && c == '"' ) ) {
            out += '\\';
            out += static_cast<char>( c );
        }
        else if ( c >= 0x20 && c < 0x7F ) {
            out += static_cast<char>( c );
        }
        else {
            out += "\\x" + hexCode( c ).substr( 2 );
        }
    }
    return out;
}

std::string quotedBytes( const uint8_t* p, size_t len )
{
    return '"' + escapeBytes( p, len, true ) + '"';
}

std::string firstLine( const uint8_t* payload, size_t len )
{
    size_t end = 0;
    while ( end < len && end < kMaxFirstLineBytes && payload[ end ] != '\r'
            && payload[ end ] != '\n' ) {
        ++end;
    }
    return escapeBytes( payload, end, false );
}

std::string fieldText( const uint8_t* p, size_t len )
{
    if ( len <= kMaxFieldBytes ) {
        return escapeBytes( p, len, false );
    }
    return escapeBytes( p, kMaxFieldBytes, false ) + "\xe2\x80\xa6";
}

bool isAsciiAlpha( uint8_t c )
{
    return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
}

} // namespace tcpdump::describer
