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
 * @file describe_nmea.cpp
 * @brief The NMEA 0183 detector of the Payload Describer.
 */

#include "describe_common.h"

#include <string>

namespace tcpdump::describer {

// ── NMEA ─────────────────────────────────────────────────────────────────

/// Detect NMEA 0183 sentences in payload (GPS: $GPGGA, $GNGSA, $GPGSV, etc.)
/// Requires the mandatory comma after the 5-char sentence ID to avoid false
/// positives on ADB protocol frames like $WRTE which also match $ + 5 alpha.
std::string detectNmea( const uint8_t* payload, size_t len )
{
    // Scan for '$' + 5 alpha chars + ',' (NMEA 0183 mandatory format)
    for ( size_t i = 0; i + 7 < len; ++i ) {
        if ( payload[ i ] == '$' && isAsciiAlpha( payload[ i + 1 ] )
             && isAsciiAlpha( payload[ i + 2 ] ) && isAsciiAlpha( payload[ i + 3 ] )
             && isAsciiAlpha( payload[ i + 4 ] ) && isAsciiAlpha( payload[ i + 5 ] )
             && payload[ i + 6 ] == ',' ) {
            // Found an NMEA sentence — extract until CR/LF
            return firstLine( payload + i, len - i );
        }
    }
    return {};
}

} // namespace tcpdump::describer
