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
 * @file host_converter.h
 * @brief Converting a capture LogSquirl opened itself: File > Open, drag and
 *        drop, the recent files, the command line.
 *
 * LogSquirl 26.12 hands a file to any plugin that exports the converter
 * entry points, whatever its manifest type (LogSquirl #795): by extension
 * (hostConverterExtensions()), or by its first bytes (isCaptureHead()). It
 * calls logsquirl_converter_convert_ex() on a worker thread of its own, with
 * the path of a temporary file to write the text into, shows its progress
 * dialog with Cancel, and opens that file as a Transient Log File when the
 * conversion returns 0.  Older hosts route files to `converter` plugins only,
 * and never call these.
 *
 * convertForHost() converts as Open pcap… does, with convertPcap() into a
 * private directory, then copies the text into the host's file and removes
 * the directory: what the host removes on a failure or a cancellation is its
 * own file, never a directory of the plugin's.  It runs the conversion on a
 * thread of its own and, on the host's thread meanwhile, polls the host's
 * Cancel and reports the progress, as LogSquirlConvertControl asks.  It never
 * waits for the UI thread: the host waits on the UI thread for a conversion
 * under way when it unloads the plugin.  The capture's summary and index go
 * to the sink, which keeps them in the Capture Catalog on the UI thread
 * (CaptureCatalog::keepConverted()), so that the sidebar, the Packet Panel
 * and Follow stream know the tab LogSquirl opens.
 *
 * Whether the plugin takes such files at all is the option
 * ConversionOptions::convertOpenedCaptures: off, it lists no extension and
 * claims no file, and LogSquirl opens them as before.
 */

#pragma once

#include "logsquirl_plugin_api.h"
#include "pcap_converter.h"

#include <QString>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

namespace tcpdump {

/// What logsquirl_converter_get_extensions() lists: the captures named so.
/// Other names (.cap, .dmp, none) are claimed by their content: .dmp is a
/// Windows crash dump as well, and .cap the name of other formats too.
constexpr const char* kHostConverterExtensions = ".pcap;.pcapng";

/// How often convertForHost() polls the host's Cancel and reports progress.
constexpr std::chrono::milliseconds kHostConvertPoll{ 20 };

/// The total of the progress convertForHost() reports: per mille.
constexpr uint64_t kHostProgressTotal = 1000;

/// The bytes convertForHost() copies into the host's file at a time.
constexpr qint64 kHostCopyChunk = 1024 * 1024;

/// What convertForHost() returns: converted, the text in the host's file.
constexpr int kHostConverted = 0;
/// What convertForHost() returns: the capture could not be converted.
constexpr int kHostConvertFailed = 1;
/// What convertForHost() returns: the host cancelled the conversion.
constexpr int kHostConvertCancelled = 2;

/**
 * The host's LogSquirlConvertControl as the plugin uses it: progress out,
 * cancellation in, both called on the thread the host converts on only.
 */
struct HostConvertControl {
    /// @p done of @p total units; a total of 0 means unknown.
    std::function<void( uint64_t done, uint64_t total )> reportProgress;
    /// Whether the user cancelled the conversion.
    std::function<bool()> isCancelled;

    /// The control the host passed, or one that reports nowhere and is never
    /// cancelled for null (logsquirl_converter_convert()).
    static HostConvertControl of( const LogSquirlConvertControl* control );
};

/// Converts as convertPcap() does (the default), for tests to replace.
using HostConversion = std::function<ConversionResult(
    const QString& inputPath, const QString& outputRoot, const std::atomic_bool* cancel,
    const std::function<void( int permille )>& progress, const ConversionOptions& options )>;

/// Where a capture converted for the host goes: its text file, the capture
/// file, its summary and index.  Called on the host's thread.
using ConvertedCaptureSink = std::function<void( const QString& logPath, const QString& capturePath,
                                                 const CaptureSummary& summary,
                                                 std::shared_ptr<const CaptureIndex> index )>;

/// kHostConverterExtensions when the plugin takes the captures opened in
/// LogSquirl (@p enabled), else none: an empty string.
const char* hostConverterExtensions( bool enabled );

/// Whether the first @p length bytes @p head of a file are the start of a
/// pcap or pcapng capture, also behind a text preamble (findCaptureStart()).
bool isCaptureHead( const unsigned char* head, std::size_t length );

/**
 * Convert the capture file @p inputPath for the host into the text file
 * @p outputPath, which the host created (see the file comment), with
 * @p options, through a private directory below @p outputRoot; report to and
 * hear from the host through @p control.  Converted, the capture goes to
 * @p sink before the call returns.
 *
 * @return kHostConverted, kHostConvertFailed (logged with the reason), or
 *         kHostConvertCancelled.  Nothing of the plugin's is left behind,
 *         whatever it returns.
 */
int convertForHost( const QString& inputPath, const QString& outputPath, const QString& outputRoot,
                    const ConversionOptions& options, const HostConvertControl& control,
                    const ConvertedCaptureSink& sink, const HostConversion& convert = {} );

} // namespace tcpdump
