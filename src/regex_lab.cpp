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
 * @file regex_lab.cpp
 * @brief Patterns over the packet list.
 */

#include "regex_lab.h"

namespace tcpdump {

const QRegularExpression& packetLineRegex()
{
    static const QRegularExpression regex(
        R"(^(?<number>\d++) ++(?<stream>\d++|[-?]) ++(?<timestamp>[+-]?\d{4,}-\d{2}-\d{2} )"
        R"(\d{2}:\d{2}:\d{2}\.\d++Z) ++(?<time>-?\d++\.\d++) ++(?<source>\S++) ++)"
        R"((?<destination>\S++) ++(?<protocol>\S++) ++(?<length>\d++) ++(?<body>.*)$)" );
    return regex;
}

} // namespace tcpdump
