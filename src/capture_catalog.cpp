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

#include <algorithm>

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

void CaptureCatalog::openConverted( const QString& logPath, const QString& capturePath,
                                    CaptureSummary summary,
                                    std::shared_ptr<const CaptureIndex> index )
{
    Entry entry;
    entry.fileName = QFileInfo( capturePath ).fileName();
    entry.fileSize = QFileInfo( capturePath ).size();
    entry.summary = std::move( summary );
    entry.index = std::move( index );
    // Written in full already: the tab need not follow it.
    keepAndOpen( fileKey( logPath ), logPath, std::move( entry ), false );
}

void CaptureCatalog::startLive()
{
    liveKeys_.clear();
    capturing_ = true;
}

void CaptureCatalog::openLiveFile( const QString& logPath, const QString& rawPath,
                                   const QString& name )
{
    Entry entry;
    entry.fileName = QFileInfo( rawPath ).fileName();
    entry.fileSize = QFileInfo( rawPath ).size();
    entry.rawPath = rawPath;
    entry.captureName = name;
    // Live before its tab opens, so that a tab in front at once shows that
    // it is capturing.
    const auto key = fileKey( logPath );
    liveKeys_.insert( key );
    keepAndOpen( key, logPath, std::move( entry ), true );
}

void CaptureCatalog::updateFile( const QString& logPath, const CaptureSummary& summary,
                                 std::shared_ptr<const CaptureIndex> index, qint64 fileSize )
{
    const auto key = fileKey( logPath );
    auto* entry = entryOf( key );
    if ( !entry ) {
        return;
    }
    entry->summary = summary;
    entry->fileSize = fileSize;
    if ( index ) {
        entry->index = std::move( index );
    }
    announceIfFront( key );
}

void CaptureCatalog::setFileError( const QString& logPath, const QString& error )
{
    const auto key = fileKey( logPath );
    if ( auto* entry = entryOf( key ) ) {
        entry->error = error;
        announceIfFront( key );
    }
}

void CaptureCatalog::endLive()
{
    // The tab in front stops saying it is capturing, if it did.
    const bool frontCapturing = capturing_ && liveKeys_.count( frontKey_ ) > 0;
    capturing_ = false;
    if ( frontCapturing ) {
        announceFront();
    }
}

bool CaptureCatalog::updateSummary( const QString& logPath, CaptureSummary summary )
{
    const auto key = fileKey( logPath );
    auto* entry = entryOf( key );
    if ( !entry ) {
        return false;
    }
    entry->summary = std::move( summary );
    announceIfFront( key );
    return true;
}

const CaptureCatalog::Entry* CaptureCatalog::find( const QString& logPath ) const
{
    const auto found = entries_.find( fileKey( logPath ) );
    return found == entries_.end() ? nullptr : &found->second;
}

void CaptureCatalog::setFront( const QString& filePath )
{
    // The host may report the tab in front again: it shows what it did.
    auto key = fileKey( filePath );
    if ( key == frontKey_ ) {
        return;
    }
    frontKey_ = std::move( key );
    announceFront();
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

void CaptureCatalog::keepAndOpen( const QString& key, const QString& logPath, Entry entry,
                                  bool follow )
{
    // Whether LogSquirl has the Log Format installed is not known to the
    // plugin, so the hint is shown regardless, but only with the first
    // capture of a load, converted or live.
    entry.withFormatHint = !formatHintShown_;
    formatHintShown_ = true;
    // Kept before the tab is opened: the host may report it in front at once.
    // A tab in front already, of a file captured again, shows it now.
    entries_.insert_or_assign( key, std::move( entry ) );
    announceIfFront( key );
    tabs_.openTab( logPath, follow );
}

CaptureCatalog::Entry* CaptureCatalog::entryOf( const QString& key )
{
    const auto found = entries_.find( key );
    return found == entries_.end() ? nullptr : &found->second;
}

CaptureCatalog::ObserverId CaptureCatalog::observeFront( std::function<void()> observer )
{
    const auto id = nextObserverId_++;
    frontObservers_.emplace_back( id, std::move( observer ) );
    return id;
}

void CaptureCatalog::stopObserving( ObserverId id )
{
    frontObservers_.erase(
        std::remove_if( frontObservers_.begin(), frontObservers_.end(),
                        [ id ]( const auto& observer ) { return observer.first == id; } ),
        frontObservers_.end() );
}

void CaptureCatalog::announceIfFront( const QString& key ) const
{
    if ( !key.isEmpty() && key == frontKey_ ) {
        announceFront();
    }
}

void CaptureCatalog::announceFront() const
{
    // An observer may remove itself or another as it is told: those of now
    // are told, but not one removed meanwhile.
    std::vector<ObserverId> ids;
    ids.reserve( frontObservers_.size() );
    for ( const auto& observer : frontObservers_ ) {
        ids.push_back( observer.first );
    }
    for ( const auto id : ids ) {
        const auto found
            = std::find_if( frontObservers_.begin(), frontObservers_.end(),
                            [ id ]( const auto& observer ) { return observer.first == id; } );
        if ( found != frontObservers_.end() ) {
            // A copy: the observer may remove itself.
            const auto observer = found->second;
            observer();
        }
    }
}

} // namespace tcpdump
