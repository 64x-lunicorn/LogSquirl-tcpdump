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
 * @brief Patterns over the packet list, for LogSquirl's Regex Lab, and
 *        opening one there.
 *
 * Follow stream (follow_stream.h) and the sidebar summary's filters, the
 * plugin's Apply as Filter, build their patterns from the columns of the
 * packet line and open them in the Lab, where the user sees the matches and
 * applies one as a filter.  The patterns are opened with Match case.
 */

#pragma once

#include <QRegularExpression>
#include <QString>

namespace tcpdump {

/// A packet line, as the Log Format formats/tcpdump_log.json reads it, with
/// the same named groups: the two must be the same, which
/// logformat_test.cpp checks.
const QRegularExpression& packetLineRegex();

/// @p text as a pattern that matches it literally: '.' in an IPv4 address,
/// the parentheses of ETH(0x88CC) and any other character but a letter, a
/// digit or ':' is escaped.
QString literalPattern( const QString& text );

/// The pattern that matches the packet lines whose Source or Destination is
/// @p address, as the summary lists it; an address inside Info does not
/// count, nor one that @p address only starts or ends.
QString endpointPattern( const QString& address );

/// The pattern that matches the packet lines whose Protocol is @p protocol,
/// as the summary lists it.
QString protocolPattern( const QString& protocol );

/// Open the Regex Lab with @p pattern, matching case, and log the pattern
/// and then what the user did with it, each after "<feature>: ".  A Lab that
/// does not open is notified.  @p feature must outlive the Lab: a string
/// literal.  Does nothing on a host without the Regex Lab; call on the UI
/// thread.
void openRegexLab( const char* feature, const QString& pattern );

} // namespace tcpdump
