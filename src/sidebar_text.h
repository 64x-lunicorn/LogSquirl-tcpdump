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
 * @file sidebar_text.h
 * @brief What the sidebar says, decided without a widget: the summary
 *        label's text from one status, a capture's summary, a live
 *        capture's progress and error, and the filter a summary link opens.
 *
 * The sidebar (sidebarwidget.h) only sets these texts in its labels; what
 * they say of the sessions, the Capture Catalog and the palette is decided
 * here, so that it is tested with the sessions and no widget.
 */

#pragma once

#include "capture_catalog.h"
#include "live_capture.h"
#include "live_capture_session.h"
#include "pcap_converter.h"

#include <QPalette>
#include <QString>

namespace tcpdump {

class CaptureSessions;

/// The README section on installing the Log Format and what it unlocks,
/// which the first capture's summary links to.
extern const char* const kLogFormatHelpUrl;

/// What the summary label says, of what last claimed it: a session's start,
/// file or outcome, or the tab in front.  An export claims nothing: its
/// progress dialog says how it goes.
enum class SummaryStatus {
    NothingLoaded, ///< Nothing was opened or captured since the plugin was loaded.
    Front,         ///< The capture in the tab in front, or that it holds none.
    Conversion,    ///< The File Conversion session's label: reading, or its outcome.
    LiveStarted,   ///< A live capture waits for its first packet.
    LiveFile,      ///< A live capture's tab opened, behind another one or in front.
    LiveOutcome,   ///< A live capture ended.
};

/// The summary label's text, as rich text: @p status, as @p sessions and the
/// tab in front of their catalog say it now, the summary's line in a colour
/// of @p palette, and with @p filterLinks its endpoints and protocols links
/// (summaryHtml()).  While a capture is being read, the label says so,
/// whatever the status.  The one place that decides it.
QString summaryLabelText( SummaryStatus status, const CaptureSessions& sessions, bool filterLinks,
                          const QPalette& palette );

/// The summary of the capture in front of @p catalog, as rich text, or that
/// the tab holds no capture of this plugin: a live capture's says that it
/// is capturing, a failed one's its error above the summary, and the entry
/// with the Log Format hint links to kLogFormatHelpUrl.
QString frontSummaryHtml( const CaptureCatalog& catalog, bool filterLinks,
                          const QPalette& palette );

/// The capture summary shown in the sidebar, as rich text.  With
/// @p filterLinks, each endpoint and protocol listed is a link that opens it
/// in the Regex Lab as a filter (summaryLinkPattern()).  A tunnel's endpoints
/// are listed apart and never a link: no column of a line shows them.
/// The line under the capture's name is drawn in a colour of @p palette.
QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks = false, const QPalette& palette = QPalette() );

/// The Regex Lab pattern a link of the summary opens, an endpoint's or a
/// protocol's; empty for any other link, a web page.
QString summaryLinkPattern( const QString& link );

/// The progress of a live capture as the sidebar shows it, in place of a
/// percentage (a stream has no size): packets, bytes and packets/s as of
/// @p snapshot, and the time since the capture started, @p elapsedMs.  With
/// @p limits, how far the capture is to each stop condition, and the ring
/// buffer's file.
QString liveProgressText( const LiveSnapshot& snapshot, qint64 elapsedMs,
                          const LiveLimits& limits = {} );

/// What the Live capture section says of @p live as it is now: that its
/// choice is being checked, its progress (liveProgressText()), and that it
/// is stopping; empty while idle.
QString liveStateText( const LiveCaptureSession& live );

/// Why a live capture failed, and what its source says to do, as rich text
/// with its commands and links (guidanceHtml()).
QString liveErrorHtml( const LiveOutcome& outcome );

} // namespace tcpdump
