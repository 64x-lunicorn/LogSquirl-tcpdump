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
 * @file capture_catalog.h
 * @brief The Capture Catalog: what the tab of each text file the plugin
 *        wrote shows, and which of them is in front.
 *
 * The catalog keeps an entry per text file, under one spelling of its path
 * (fileKey()), so that the path the host reports for a tab finds the file
 * the plugin wrote:
 *
 *   - a capture file converted (openConverted()): its summary and index;
 *   - each text file of a live capture (a ring buffer's, one per raw
 *     file, openLiveFile()), whose summary, index and size its Live Capture
 *     Session replaces as the snapshots and the outcome come, and the error
 *     of a capture that failed.
 *
 * Either way the catalog keeps the entry first and then opens the file's
 * tab through its CaptureTabHost, as the host may report that tab in front
 * at once.  The first entry of a load, of either kind, links to the Log
 * Format section (Entry::withFormatHint); no other does.
 *
 * It knows the tab in front (setFront(), on every tab switch), which text
 * files are the live capture's, running or the last (isLive(),
 * isCapturing()), and which files Save capture… saves for the tab in front
 * (partsToSave()): the parts of the latest index, a ring buffer's files,
 * or the raw file before the capture has an index with any.
 *
 * The sidebar renders the capture in front: its summary, the Packet Panel's
 * index and whether Save capture… shows.  No widget is in here.  The
 * entries live as long as the plugin is loaded.
 */

#pragma once

#include "capture_index.h"
#include "pcap_converter.h"

#include <QString>

#include <map>
#include <memory>
#include <set>
#include <vector>

namespace tcpdump {

/// One spelling of @p filePath, as the catalog keys it: e.g. on macOS the
/// temporary directory /var/folders/... is a link to /private/var/folders/....
/// Empty for an empty path.
QString fileKey( const QString& filePath );

/// Where the Capture Catalog opens a capture's tab: LogSquirl, through the
/// sidebar, in the app; a fake in tests.
class CaptureTabHost {
public:
    virtual ~CaptureTabHost() = default;

    /// Open the text file @p logPath in a tab, on the UI thread; @p follow:
    /// follow the file as it grows (a live capture's).
    virtual void openTab( const QString& logPath, bool follow ) = 0;
};

/**
 * The entries of the captures' text files, the tab in front, the live
 * capture's tabs and the parts to save (see the file comment).
 */
class CaptureCatalog {
public:
    /// What the tab of a text file shows of its capture.
    struct Entry {
        QString fileName;       ///< The capture's name, without directory.
        qint64 fileSize = 0;    ///< The capture's size in bytes.
        CaptureSummary summary; ///< What was converted, so far or final.
        /// Where its packets are in the capture file, for the Packet Panel;
        /// null before a live capture's first snapshot.
        std::shared_ptr<const CaptureIndex> index;
        /// Links to the Log Format section: the first capture of a load,
        /// converted or live.
        bool withFormatHint = false;
        QString rawPath; ///< A live capture's raw file; empty for a file.
        /// What Save capture… names the capture: a live capture's name (a
        /// ring buffer's text files are numbered); empty for a file.
        QString captureName;
        QString error; ///< Why a live capture failed, keeping what it had.
    };

    /// Open tabs through @p tabs, which outlives the catalog.
    explicit CaptureCatalog( CaptureTabHost& tabs )
        : tabs_( tabs )
    {
    }

    /// Keep the capture file @p capturePath converted into the text file
    /// @p logPath, with its @p summary and @p index, and open its tab.
    void openConverted( const QString& logPath, const QString& capturePath, CaptureSummary summary,
                        std::shared_ptr<const CaptureIndex> index );

    /// A live capture starts: the text files of the one before are no
    /// longer live.
    void startLive();
    /// Keep the text file @p logPath of the live capture @p name, written
    /// from the raw file @p rawPath, live, and open its tab, following it.
    void openLiveFile( const QString& logPath, const QString& rawPath, const QString& name );
    /// What the text file @p logPath shows from now on: @p summary, the
    /// capture's @p index (null: the one it has) and the size of its raw
    /// capture, @p fileSize; so far, or final.  Nothing for a file not kept.
    void updateFile( const QString& logPath, const CaptureSummary& summary,
                     std::shared_ptr<const CaptureIndex> index, qint64 fileSize );
    /// The capture of the text file @p logPath failed with @p error; what it
    /// captured is kept.  Nothing for a file not kept.
    void setFileError( const QString& logPath, const QString& error );
    /// The live capture ended: its text files stay the last capture's.
    void endLive();

    /// Replace the summary of the text file @p logPath with @p summary;
    /// false for a file not kept.
    bool updateSummary( const QString& logPath, CaptureSummary summary );

    /// The text file @p logPath, or null for one the plugin did not write.
    const Entry* find( const QString& logPath ) const;
    /// Whether no text file is kept.
    bool isEmpty() const
    {
        return entries_.empty();
    }

    /// The tab whose text file is @p filePath came to the front (empty: a
    /// tab without a Log File), whether or not it holds a capture.
    void setFront( const QString& filePath );
    /// The capture in the tab in front, or null for a tab that holds none.
    const Entry* front() const;
    /// The file in the tab in front, as fileKey() spells it, whether or not
    /// it holds a capture; empty for a tab without a Log File.
    const QString& frontFile() const
    {
        return frontKey_;
    }
    /// Whether the text file @p logPath is the one in the tab in front.
    bool isFront( const QString& logPath ) const;

    /// Whether @p logPath is a text file of the live capture, running or
    /// the last.
    bool isLive( const QString& logPath ) const;
    /// Whether @p logPath is a text file of the live capture that runs.
    bool isCapturing( const QString& logPath ) const;

    /// The files Save capture… saves for the tab in front, in order: the
    /// parts of its latest index (a ring buffer's files that are kept), or
    /// its raw file before an index has any; none for a tab without a live
    /// capture.
    std::vector<CapturePart> partsToSave() const;
    /// The name Save capture… suggests for the tab in front, <name>.pcap
    /// after its capture (or its text file); empty when partsToSave() is.
    QString saveName() const;

private:
    /// Keep @p entry for the text file of @p key, with the Log Format hint
    /// if it is the first of the load, then open the tab of @p logPath.
    void keepAndOpen( const QString& key, const QString& logPath, Entry entry, bool follow );
    /// The entry of @p key; null for one not kept.
    Entry* entryOf( const QString& key );

    CaptureTabHost& tabs_; ///< Where the captures' tabs open.
    /// The text files kept, by fileKey().
    std::map<QString, Entry> entries_;
    /// The key of the text file in the tab in front, kept or not.
    QString frontKey_;
    /// The keys of the live capture's text files, running or the last.
    std::set<QString> liveKeys_;
    bool capturing_ = false;       ///< The live capture runs.
    bool formatHintShown_ = false; ///< An entry got the Log Format hint.
};

} // namespace tcpdump
