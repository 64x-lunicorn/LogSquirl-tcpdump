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
 * @file capture_catalog.cpp
 * @brief The Capture Catalog's entries, tab in front, live tabs and parts
 *        to save.
 */

#include "capture_catalog.h"

#include <QFileInfo>

namespace tcpdump {

QString fileKey( const QString& filePath )
{
    if ( filePath.isEmpty() ) {
        return {};
    }
    const QFileInfo info( filePath );
    const auto canonical = info.canonicalFilePath();
    return canonical.isEmpty() ? info.absoluteFilePath() : canonical;
}

void CaptureCatalog::addConverted( const QString& logPath, const QString& capturePath,
                                   CaptureSummary summary,
                                   std::shared_ptr<const CaptureIndex> index )
{
    // Whether LogSquirl has the Log Format installed is not known to the
    // plugin, so the hint is shown regardless, but only with the first
    // capture of a load.
    Entry entry;
    entry.fileName = QFileInfo( capturePath ).fileName();
    entry.fileSize = QFileInfo( capturePath ).size();
    entry.summary = std::move( summary );
    entry.index = std::move( index );
    entry.withFormatHint = !formatHintShown_;
    formatHintShown_ = true;
    entries_.insert_or_assign( fileKey( logPath ), std::move( entry ) );
}

void CaptureCatalog::startLive()
{
    liveKeys_.clear();
    capturing_ = true;
}

void CaptureCatalog::addFile( const QString& logPath, const QString& rawPath, const QString& name )
{
    Entry entry;
    entry.fileName = QFileInfo( rawPath ).fileName();
    entry.fileSize = QFileInfo( rawPath ).size();
    entry.rawPath = rawPath;
    entry.captureName = name;
    entry.withFormatHint = !formatHintShown_;
    formatHintShown_ = true;
    const auto key = fileKey( logPath );
    entries_.insert_or_assign( key, std::move( entry ) );
    liveKeys_.insert( key );
}

void CaptureCatalog::updateFile( const QString& logPath, const CaptureSummary& summary,
                                 std::shared_ptr<const CaptureIndex> index, qint64 fileSize )
{
    auto* entry = entryOf( fileKey( logPath ) );
    if ( !entry ) {
        return;
    }
    entry->summary = summary;
    entry->fileSize = fileSize;
    if ( index ) {
        entry->index = std::move( index );
    }
}

void CaptureCatalog::setFileError( const QString& logPath, const QString& error )
{
    if ( auto* entry = entryOf( fileKey( logPath ) ) ) {
        entry->error = error;
    }
}

void CaptureCatalog::endLive()
{
    capturing_ = false;
}

bool CaptureCatalog::updateSummary( const QString& logPath, CaptureSummary summary )
{
    auto* entry = entryOf( fileKey( logPath ) );
    if ( !entry ) {
        return false;
    }
    entry->summary = std::move( summary );
    return true;
}

const CaptureCatalog::Entry* CaptureCatalog::find( const QString& logPath ) const
{
    const auto found = entries_.find( fileKey( logPath ) );
    return found == entries_.end() ? nullptr : &found->second;
}

void CaptureCatalog::setFront( const QString& filePath )
{
    frontKey_ = fileKey( filePath );
}

const CaptureCatalog::Entry* CaptureCatalog::front() const
{
    const auto found = entries_.find( frontKey_ );
    return found == entries_.end() ? nullptr : &found->second;
}

bool CaptureCatalog::isFront( const QString& logPath ) const
{
    return !frontKey_.isEmpty() && fileKey( logPath ) == frontKey_;
}

bool CaptureCatalog::isLive( const QString& logPath ) const
{
    return liveKeys_.count( fileKey( logPath ) ) > 0;
}

bool CaptureCatalog::isCapturing( const QString& logPath ) const
{
    return capturing_ && isLive( logPath );
}

std::vector<CapturePart> CaptureCatalog::partsToSave() const
{
    const auto* entry = front();
    if ( !entry || entry->rawPath.isEmpty() ) {
        return {};
    }
    // The files of the capture, those a ring buffer keeps, as the latest
    // index has them; before the first one, the raw file.
    std::vector<CapturePart> parts;
    if ( entry->index ) {
        parts = entry->index->parts();
    }
    if ( parts.empty() ) {
        CapturePart part;
        part.path = entry->rawPath;
        parts.push_back( part );
    }
    return parts;
}

QString CaptureCatalog::saveName() const
{
    const auto* entry = front();
    if ( !entry || entry->rawPath.isEmpty() ) {
        return {};
    }
    // Named after the capture, <name>.pcap: a ring buffer's text files are numbered.
    const auto name = entry->captureName.isEmpty() ? QFileInfo( frontKey_ ).completeBaseName()
                                                   : entry->captureName;
    return name + "." + QFileInfo( entry->rawPath ).suffix();
}

CaptureCatalog::Entry* CaptureCatalog::entryOf( const QString& key )
{
    const auto found = entries_.find( key );
    return found == entries_.end() ? nullptr : &found->second;
}

} // namespace tcpdump
