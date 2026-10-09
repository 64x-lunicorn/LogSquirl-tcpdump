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
 * @file regex_lab.h
 * @brief Patterns over the packet list, for LogSquirl's Regex Lab.
 */

#pragma once

#include <QRegularExpression>

namespace tcpdump {

/// A packet line, as the Log Format formats/tcpdump_log.json reads it, with
/// the same named groups: the two must be the same, which
/// logformat_test.cpp checks.
const QRegularExpression& packetLineRegex();

} // namespace tcpdump
