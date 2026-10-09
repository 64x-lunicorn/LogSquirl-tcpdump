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
 * @file settings.h
 * @brief The conversion options as the user chose them, kept in a settings
 *        file in the plugin's configuration directory.
 *
 * The configuration dialog (configdialog.h) writes them; the sidebar reads
 * them at the start of each conversion, so that a capture already open
 * keeps the options it was converted with.
 */

#pragma once

#include "pcap_converter.h"

#include <QString>

#include <cstddef>

namespace tcpdump {

/// The least a memory cap may be set to.
constexpr size_t kMinCap = 1;
/// The most the stream cap may be set to: ten times the default.
constexpr size_t kMaxStreamCap = 10 * StreamTracker::kMaxStreams;
/// The most the endpoint cap may be set to: ten times the default.
constexpr size_t kMaxEndpointCap = 10 * CaptureStats::kMaxEndpoints;
/// The most the TCP Reassembly's memory may be set to, in mebibytes: sixteen
/// times the default, 1 GiB.
constexpr size_t kMaxReassemblyMegabytes = 16 * TcpReassembly::kDefaultMemoryLimit / kMegabyte;

/// The settings file in @p configDir.
QString settingsFilePath( const QString& configDir );

/**
 * The options saved in @p configDir.  An option the file does not hold, or
 * holds a value of that is not one, is its default; a number out of range
 * the nearest allowed.  Without a directory, or a file, all are defaults.
 */
ConversionOptions loadConversionOptions( const QString& configDir );

/// Save @p options in @p configDir; false if they could not be written.
bool saveConversionOptions( const QString& configDir, const ConversionOptions& options );

} // namespace tcpdump
