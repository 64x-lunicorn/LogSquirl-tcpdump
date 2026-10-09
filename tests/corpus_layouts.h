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
 * @file corpus_layouts.h
 * @brief The corpus captures converted in each Line Layout, for the tests of
 *        patterns that must read the packet list in any of them.
 */

#pragma once

#include <catch2/catch.hpp>

#include "pcap_converter.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QString>
#include <QStringList>

#include <vector>

namespace tcpdump_test {

/// Every Line Layout the configuration dialog offers, the default first.
inline std::vector<tcpdump::LineLayout> allLineLayouts()
{
    using tcpdump::TimeColumns;
    std::vector<tcpdump::LineLayout> layouts;
    for ( const bool macColumns : { false, true } ) {
        for ( const auto timeColumns :
              { TimeColumns::Both, TimeColumns::AbsoluteOnly, TimeColumns::RelativeOnly } ) {
            layouts.push_back( { timeColumns, macColumns } );
        }
    }
    return layouts;
}

/// @p layout in words, for a test's INFO.
inline std::string describeLayout( const tcpdump::LineLayout& layout )
{
    static const char* const times[]
        = { "both time columns", "UTC time only", "time since the first packet only" };
    return std::string( times[ static_cast<int>( layout.timeColumns ) ] )
           + ( layout.macColumns ? ", MAC columns" : "" );
}

/// The committed corpus captures that have a committed text.
inline QStringList committedCaptures()
{
    const QDir dir( QStringLiteral( TCPDUMP_CORPUS_DIR ) );
    QStringList captures;
    for ( const auto& capture :
          dir.entryList( { "*.pcap", "*.pcapng" }, QDir::Files, QDir::Name ) ) {
        if ( QFile::exists( dir.filePath( QFileInfo( capture ).completeBaseName() + ".txt" ) ) ) {
            captures << dir.filePath( capture );
        }
    }
    REQUIRE_FALSE( captures.isEmpty() );
    return captures;
}

/// The packet lines of @p capture converted in @p layout into @p outputRoot,
/// header excluded.
inline QStringList convertedLines( const QString& capture, const tcpdump::LineLayout& layout,
                                   const QString& outputRoot )
{
    tcpdump::ConversionOptions options;
    options.layout = layout;
    // As the corpus test converts it: with the key log beside it, if any.
    const QFileInfo info( capture );
    const auto keyLog = info.dir().filePath( info.completeBaseName() + ".keys" );
    if ( QFile::exists( keyLog ) ) {
        options.keyLogPath = keyLog;
    }
    const auto result = tcpdump::convertPcap( capture, outputRoot, nullptr, {}, options );
    REQUIRE( result.status == tcpdump::ConversionResult::Status::Converted );
    QFile file( result.outputPath );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
    REQUIRE_FALSE( lines.isEmpty() );
    lines.removeFirst();
    return lines;
}

} // namespace tcpdump_test
