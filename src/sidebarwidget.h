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
 * @file sidebarwidget.h
 * @brief Sidebar tab for opening pcap files and viewing capture summary.
 *
 * Provides a "Open pcap…" button and shows the summary (packet count,
 * link-layer type, duration) of the capture in the tab in front.
 */

#pragma once

#include "capture_sessions.h"
#include "sidebar_text.h"

#include <QLabel>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressBar>
#include <QProgressDialog>
#include <QPushButton>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

namespace tcpdump {

class PacketPanel;

/**
 * Sidebar widget displayed in the LogSquirl sidebar panel: a view of the
 * plugin's CaptureSessions (capture_sessions.h).  It builds its widgets,
 * forwards its buttons to the sessions, and shows what the sessions, the
 * Activity rule and the Capture Catalog say; it keeps no state of a
 * conversion, live capture or export of its own, and tells none.  What its
 * labels say is decided in sidebar_text.h.
 *
 * Contains:
 *   - "Open pcap…" button (opens a file dialog, as Plugins > tcpdump does),
 *     enabled while the Activity rule allows opening a file
 *   - "Stream lines in Regex Lab" button, as in Plugins > tcpdump, only on a
 *     host that has the Regex Lab and tells the selected lines:
 *     g_state.hostCapabilities when the widget is created; enabled only when
 *     the Packet Panel can tell the selected line's stream, its tooltip
 *     says why not
 *   - progress bar and Cancel button, while the File Conversion session
 *     converts a capture
 *   - the Live capture section: Start live capture…, which asks in the Start
 *     live capture dialog (live_capture_form.h), enabled while the Activity
 *     rule allows a live capture; while the Live Capture Session's capture
 *     runs, its packets, bytes, packets/s and elapsed time, a Stop button
 *     and the capture program's stderr lines; after it failed, why, and what
 *     the source says to do about it
 *   - "Save capture…", for a live capture's raw file, which lives in the
 *     temporary directory and goes when LogSquirl quits
 *   - Summary label showing the stats of the capture in the tab in front,
 *     or that the tab holds none; the summary of the first capture after
 *     the plugin is loaded also links to the README section on installing
 *     the Log Format, which the plugin cannot tell is installed; on a host
 *     with the Regex Lab, a click on an endpoint or a protocol listed opens
 *     the Lab on its lines, as Wireshark's Apply as Filter; what the label
 *     says is one status, decided in summaryLabelText() (sidebar_text.h)
 *     from the sessions and the tab in front, and said again on a palette
 *     change
 *   - the Packet Panel (packet_panel.h): the layer tree and hex dump of the
 *     packet of the line selected in the tab in front, and the
 *     Conversations table of the capture in front
 *   - while the Export session exports, a progress dialog with Cancel
 *
 * A long summary scrolls in itself, up to kSummaryMaxLines tall, so that
 * the Packet Panel keeps kPacketPanelMinLines.  A sidebar shorter than the
 * minimum of all of it scrolls as a whole ("sidebarScroll"), rather than
 * squeeze its widgets over one another or cut off its bottom.
 *
 * The sidebar is the sessions' dialog parent while it lives.  Destroying it
 * leaves the sessions running; the plugin destroys them after it.  The
 * sessions must outlive the sidebar, whoever deletes it: its destructor
 * tells the sessions and the Capture Catalog to stop telling it.
 */
class SidebarWidget : public QWidget {
    Q_OBJECT

public:
    /// The height the summary asks for at most, in lines of text: a longer
    /// one scrolls and leaves the Packet panel room in a tall sidebar.
    static constexpr int kSummaryMaxLines = 24;
    /// The height the summary gives in to in a short sidebar, in lines.
    static constexpr int kSummaryMinLines = 3;
    /// The height the Packet panel keeps for its tabs and the
    /// Conversations, however long the summary, in lines.
    static constexpr int kPacketPanelMinLines = 16;

    /// A view of @p sessions, which must outlive it, with an optional parent.
    explicit SidebarWidget( CaptureSessions& sessions, QWidget* parent = nullptr );
    ~SidebarWidget() override;

    /// Plugins > tcpdump > Packet details: show the packet of the line
    /// selected now in the Packet Panel; if the panel is not in view, a
    /// notification names the packet's layers.
    void showPacketDetails();

    /// Plugins > tcpdump > Show stream content: show the content of the
    /// selected line's stream in the Packet Panel's Stream tab, or notify
    /// the user why not; if the panel is not in view, a notification says
    /// where it is.
    void followStreamContent();

    /// Plugins > tcpdump > Stream lines in Regex Lab: open the Regex Lab on
    /// the lines of the selected line's stream (followStream()), or notify
    /// the user why not, as the sidebar's button says in its tooltip
    /// (PacketPanel::streamLinesProblem()): a line that only looks like a
    /// packet line, in a tab that shows no capture, opens nothing.  The
    /// selection is read once, by the Packet Panel, for both.
    void openStreamLines();

    /// The Packet Panel.
    PacketPanel* packetPanel() const
    {
        return packetPanel_;
    }

protected:
    void changeEvent( QEvent* event ) override;

private:
    /// Open a link of the summary: a filter in the Regex Lab, or a web page.
    void openLink( const QString& link );
    /// Show the outcome of a conversion: its label, unless its tab shows
    /// its summary.
    void showConversionOutcome( const FileConversionOutcome& outcome );
    /// Show the File Conversion session's state: the idle, converting or
    /// cancelling controls, and its label while it runs.
    void showConversionState();
    /// Enable Open pcap… if the Activity rule allows opening a file.
    void updateOpenButton();

    /// A live capture started: clear the last one's error and stderr lines.
    void showLiveStart();
    /// Show the live capture's state: the controls of a capture running,
    /// stopping, being checked, or none.
    void showLiveState();
    /// The live capture's latest text file was kept and opened in a tab:
    /// say it is capturing, unless its tab came to the front at once.
    void showLiveFile();
    /// Show what the tab in front shows: its capture's summary, Packet Panel
    /// index and Conversations, and Save capture… if it saves anything; on
    /// every change the catalog announces.  While a capture is being read,
    /// the label keeps saying so.
    void showFront();
    /// Show the outcome of a live capture: its error, and what it came to,
    /// unless its tab in front shows its final summary already.
    void showLiveOutcome( const LiveOutcome& outcome );
    /// Show the live capture's packets, bytes, packets/s and elapsed time.
    void showLiveProgress();
    /// Enable Start if the Activity rule allows a live capture; its tooltip
    /// says why not.
    void updateStartButton();
    /// Show why the live capture failed, and what its source says to do.
    void showLiveError( const LiveOutcome& outcome );
    /// Show the Export session's state: its progress dialog while it
    /// exports, with its label, and none once it is idle.
    void showExportState();
    /// Say @p status in the summary label from now on, as summaryLabelText()
    /// decides it (sidebar_text.h), in this widget's palette.
    void showSummary( SummaryStatus status );
    /// Enable Stream lines in Regex Lab when the Packet Panel can tell the
    /// selected line's stream; its tooltip says why not.
    void updateStreamLinesButton();
    /// Run @p action of the sessions for a button, logging what it throws:
    /// an exception must not escape into Qt or the host.
    void forward( const char* what, void ( CaptureSessions::*action )() );

    /// What this sidebar shows, and its buttons start.
    CaptureSessions& sessions_;
    /// This sidebar as the catalog's observer of the tab in front, removed
    /// when it goes.
    CaptureCatalog::ObserverId frontObserver_ = 0;

    QPushButton* openButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QProgressBar* progressBar_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    PacketPanel* packetPanel_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* saveButton_ = nullptr;
    QLabel* liveLabel_ = nullptr;
    QPushButton* startButton_ = nullptr;       ///< Start live capture…
    QPushButton* streamLinesButton_ = nullptr; ///< Stream lines in Regex Lab, if offered.
    QPlainTextEdit* liveStderr_ = nullptr;     ///< The capture program's stderr lines.
    QLabel* liveError_ = nullptr;              ///< Why the last live capture failed.
    /// What the summary label says, drawn by summaryLabelText().
    SummaryStatus summaryStatus_ = SummaryStatus::NothingLoaded;
    QTimer liveTicker_;                        ///< Moves the elapsed time on.
    QPointer<QProgressDialog> exportProgress_; ///< The export's progress, and Cancel.
};

} // namespace tcpdump
