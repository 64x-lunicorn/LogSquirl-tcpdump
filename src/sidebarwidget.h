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

#include "activity.h"
#include "capture_catalog.h"
#include "export_session.h"
#include "file_conversion_session.h"
#include "live_capture.h"
#include "live_capture_session.h"
#include "live_source.h"
#include "pcap_converter.h"
#include "session_host.h"

#include <QLabel>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProgressBar>
#include <QProgressDialog>
#include <QPushButton>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <QWidget>

#include <atomic>
#include <functional>
#include <memory>

namespace tcpdump {

class LiveCaptureDialog;
class PacketPanel;

/// The capture summary shown in the sidebar, as rich text.  With
/// @p filterLinks, each endpoint and protocol listed is a link that
/// SidebarWidget opens in the Regex Lab as a filter.  A tunnel's endpoints
/// are listed apart and never a link: no column of a line shows them.
/// The line under the capture's name is drawn in a colour of @p palette.
QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks = false, const QPalette& palette = QPalette() );

/// The progress of a live capture as the sidebar shows it, in place of a
/// percentage (a stream has no size): packets, bytes and packets/s as of
/// @p snapshot, and the time since the capture started, @p elapsedMs.  With
/// @p limits, how far the capture is to each stop condition, and the ring
/// buffer's file.
QString liveProgressText( const LiveSnapshot& snapshot, qint64 elapsedMs,
                          const LiveLimits& limits = {} );

/**
 * Sidebar widget displayed in the LogSquirl sidebar panel.
 *
 * Contains:
 *   - "Open pcap…" button (opens a file dialog, as Plugins > tcpdump does)
 *   - "Stream lines in Regex Lab" button, as in Plugins > tcpdump, only on a
 *     host that has the Regex Lab and tells the selected lines:
 *     g_state.hostCapabilities when the widget is created; enabled only when
 *     the Packet Panel can tell the selected line's stream, its tooltip
 *     says why not
 *   - progress bar and Cancel button, while a capture is converted
 *   - the Live capture section: the live capture form (source, device,
 *     interface, capture filter, snaplen; live_capture_form.h) and Start;
 *     while a capture runs, its packets, bytes, packets/s and elapsed time,
 *     a Stop button and the capture program's stderr lines; after it
 *     failed, why, and what the source says to do about it
 *   - "Save capture…", for a live capture's raw file, which lives in the
 *     temporary directory and goes when LogSquirl quits
 *   - Summary label showing the stats of the capture in the tab in front,
 *     or that the tab holds none; the summary of the first capture after
 *     the plugin is loaded also links to the README section on installing
 *     the Log Format, which the plugin cannot tell is installed; on a host
 *     with the Regex Lab, a click on an endpoint or a protocol listed opens
 *     the Lab on its lines, as Wireshark's Apply as Filter
 *   - the Packet Panel (packet_panel.h): the layer tree and hex dump of the
 *     packet of the line selected in the tab in front, and the
 *     Conversations table of the capture in front
 *
 * A long summary scrolls in itself, up to kSummaryMaxLines tall, so that
 * the Packet Panel keeps kPacketPanelMinLines.  A sidebar shorter than the
 * minimum of all of it scrolls as a whole ("sidebarScroll"), rather than
 * squeeze its widgets over one another or cut off its bottom.
 *
 * Plugins > tcpdump > Start live capture… shows the same form in a dialog
 * (LiveCaptureDialog).  The last choice started is kept in settings.ini and
 * shown again after a restart.  Start is disabled while a capture is read
 * or captured; from the menu, a running capture is offered to be stopped
 * first, and the new one starts once it has ended.
 *
 * Plugins > tcpdump > Export packets… writes the packets of the lines
 * selected in the tab in front to a new capture file (packet_export.h), on
 * a worker thread of its own, with a progress dialog and Cancel: the export
 * is its ExportSession's (export_session.h), which asks with the sidebar's
 * Export dialog and save dialog; the sidebar shows its progress dialog.
 *
 * The summaries of all captures converted while the plugin is loaded are
 * kept with their CaptureIndex in a CaptureCatalog (capture_catalog.h),
 * keyed by the text file written for each, so that a capture's tab that
 * comes to the front again shows its own, and the Packet Panel its packets.
 * The catalog opens each capture's tab, through the sidebar, and decides
 * which summary links to the Log Format.  The sidebar renders the capture
 * the catalog says is in front: its summary, the Packet Panel's index, and
 * whether Save capture… shows.
 *
 * A live capture's tab is opened, following its file, once the header and
 * the first packet line are in it; with a ring buffer, each file's text in
 * a tab of its own as it starts, the tabs before left as they are.  Its
 * summary in the sidebar follows the snapshots while it runs, in every tab
 * of the capture, and is final when it ends.
 *
 * A live capture's lifecycle and outcome are its LiveCaptureSession's
 * (live_capture_session.h): the sidebar is its host (a notification), the
 * session keeps its summaries in the sidebar's catalog, which opens their
 * tabs, and the sidebar shows what it is told.
 *
 * Opening a capture file is its FileConversionSession's
 * (file_conversion_session.h) alike: Open, the menu's Open pcap… and Cancel
 * forward to it, and the sidebar shows its progress, label and outcome.  A
 * capture is converted on a worker thread, so that a large one neither
 * freezes LogSquirl nor can be interrupted only by killing it.  Destroying
 * the widget destroys the session, which cancels a running conversion and
 * waits for it: no code of the plugin runs on the worker thread
 * afterwards, and the host may unload the library.
 */
class SidebarWidget : public QWidget, private SessionHost, private CaptureTabHost {
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

    /// Construct with an optional parent.
    explicit SidebarWidget( QWidget* parent = nullptr );
    ~SidebarWidget() override;

    /// Ask for a capture in a file dialog, as the Open button does, and open
    /// it.  While the Activity rule refuses opening a file, only a
    /// notification says why.
    void chooseAndOpen();

    /// Open a pcap file: its File Conversion session converts it in the
    /// background, and its text opens in LogSquirl.
    void openPcapFile( const QString& filePath );

    /// Asks for a capture file: given the dialog's parent and the directory
    /// to start in, returns the chosen path, or an empty one if none was.
    using FileChooser = std::function<QString( QWidget* parent, const QString& dir )>;

    /// Ask with @p chooser instead of a file dialog (for tests).
    void setFileChooser( FileChooser chooser )
    {
        chooseFile_ = std::move( chooser );
    }

    /// Show the summary of the capture whose text is @p filePath, the file
    /// in the tab now in front (empty: a tab without a Log File), or that the
    /// tab holds no capture of this plugin.  While a capture is being read,
    /// the label keeps saying so.  The tab in front reported again shows
    /// what it did.
    void showSummaryFor( const QString& filePath );

    /// Stop a running conversion; nothing is opened then.
    void cancel();

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

    /// Plugins > tcpdump > Export packets…: the packets of the lines selected
    /// in the tab in front, confirmed by the user, written to a new capture
    /// file in the background, by its Export session.  While an export
    /// runs, only a notification says so.
    void exportSelectedPackets();

    /// Whether an export is running.
    bool isExporting() const
    {
        return export_ && export_->isBusy();
    }

    /// Stop a running export, unless it has written its file.
    void cancelExport();

    /// The Export session Export packets… and its progress dialog's Cancel
    /// forward to; it asks with the Export dialog and a save dialog, which
    /// tests replace (ExportSession::setConfirmer(), setFileChooser()).
    ExportSession* exportSession() const
    {
        return export_.get();
    }

    /// The Packet Panel.
    PacketPanel* packetPanel() const
    {
        return packetPanel_;
    }

    /// Replace the summary kept for the capture whose text is @p textPath
    /// with @p summary, taken anew (a live capture's snapshot or its final
    /// summary), and show it if its tab is in front: the summary and the
    /// Conversations table.  Does nothing for a file the plugin did not write.
    void updateSummary( const QString& textPath, CaptureSummary summary );

    /**
     * Capture live from the stream @p makeSource makes on the worker thread
     * (LiveCapture), named @p name: its files are <name>.log and the raw
     * <name>.pcap or .pcapng.  Its tab opens, following the file, once the
     * first packet line is in it; a capture that ends without packets opens
     * none and says so.  It stops by itself, and keeps a ring buffer, as
     * @p limits say; a failure is explained by @p kind, if given.  False,
     * with a notification, while a capture is being read or captured.
     */
    bool startLiveCapture( const QString& name, LiveCapture::SourceFactory makeSource,
                           const LiveLimits& limits = {},
                           std::shared_ptr<const LiveSourceKind> kind = {} );

    /**
     * Capture @p choice live: its source (a kind of the live sources, see
     * setLiveSources()) makes the stream, named after its device and
     * interface (liveCaptureName()).  The choice is saved in settings.ini.
     * False, with a notification, if the source is unknown or unavailable,
     * the choice is not one it can capture, or a capture is being read or
     * captured.  A source that must be asked first (an extcap's arguments)
     * is asked, and then the choice starts, or is refused with a
     * notification (LiveCaptureSession::start()).
     */
    bool startLiveCapture( const LiveChoice& choice );

    /// Plugins > tcpdump > Start live capture…: offer to stop a capture that
    /// runs, ask for a choice in the Start live capture dialog, and start
    /// it, once the running one has ended.
    void chooseAndStartLiveCapture();

    /// Asks the user for a live capture choice, given the one to show first;
    /// false if the user does not want to capture.
    using LiveChoiceAsker = std::function<bool( QWidget* parent, LiveChoice& choice )>;

    /// Ask with @p asker instead of the Start live capture dialog (for tests).
    void setLiveChoiceAsker( LiveChoiceAsker asker )
    {
        askLiveChoice_ = std::move( asker );
    }

    /// Asks whether to stop the live capture @p running; false: keep it.
    using StopConfirmer = std::function<bool( QWidget* parent, const QString& running )>;

    /// Ask with @p confirmer instead of a message box (for tests).
    void setStopConfirmer( StopConfirmer confirmer )
    {
        confirmStop_ = std::move( confirmer );
    }

    /// Offer the kinds of @p sources in the Start live capture dialog (for
    /// tests; the plugin's own are builtInLiveSources()).
    void setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// The kinds every SidebarWidget constructed afterwards offers until
    /// setLiveSources(): builtInLiveSources(), unless @p sources is set.
    /// The test runner sets an empty registry, so that no test runs a real
    /// capture program (tcpdump -D, adb) by constructing a sidebar.
    static void setDefaultLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// The Start live capture dialog as Start live capture… shows it: the
    /// choice last started, saved in settings.ini, and each other source
    /// with its own saved options.  It lists on this widget's pool.
    std::unique_ptr<LiveCaptureDialog> makeLiveCaptureDialog( QWidget* parent );

    /// End the running live capture and keep what was captured.
    void stopLiveCapture();

    /// Whether a live capture runs, or a choice is being checked to start.
    bool isCapturing() const
    {
        return live_ && live_->isBusy();
    }

    /// The Live Capture Session the Live capture section shows.
    LiveCaptureSession* liveSession() const
    {
        return live_.get();
    }

    /// Ask where to save the raw capture of the tab in front, and copy it
    /// there; what Save capture… does.
    void saveCapture();

    /// Asks where to save a capture: given the dialog's parent and the
    /// suggested path, returns the chosen path, or an empty one.
    using SaveChooser = std::function<QString( QWidget* parent, const QString& suggested )>;

    /// Ask with @p chooser instead of a file dialog (for tests).
    void setSaveChooser( SaveChooser chooser )
    {
        chooseSaveFile_ = std::move( chooser );
    }

    /// Create the temporary files below @p dir instead of the system's
    /// temporary directory (for tests).
    void setTempRoot( const QString& dir )
    {
        tempRoot_ = dir;
        conversion_->setOutputRoot( dir );
        live_->setOutputRoot( dir );
    }

    /// The directory the temporary directories are created in.
    const QString& tempRoot() const
    {
        return tempRoot_;
    }

    /// Whether a conversion is running.
    bool isConverting() const
    {
        return conversion_ && conversion_->isBusy();
    }

    /// The File Conversion session the Open button and Cancel forward to.
    FileConversionSession* conversionSession() const
    {
        return conversion_.get();
    }

    /// What runs now, which the Activity rule weighs before Open, Start
    /// live capture and Export packets start.
    RunningActivities runningActivities() const
    {
        RunningActivities running;
        running.converting = isConverting();
        running.capturing = isCapturing();
        running.exporting = isExporting();
        return running;
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
    // The Capture Catalog's tab host.
    void openTab( const QString& logPath, bool follow ) override;
    // The sessions' host.
    void notify( const QString& message ) override;
    RunningActivities runningElsewhere() const override;

    /// A live capture started: clear the last one's error and stderr lines.
    void showLiveStart();
    /// Show the live capture's state: the controls of a capture running,
    /// stopping, being checked, or none.
    void showLiveState();
    /// The live capture's text file @p logPath was kept and opened in a tab:
    /// say it is capturing, unless its tab came to the front at once.
    void showLiveFile( const QString& logPath );
    /// Show what the tab in front shows: its capture's summary, Packet Panel
    /// index and Conversations, and Save capture… if it saves anything; on
    /// every change the catalog announces.  While a capture is being read,
    /// the label keeps saying so.
    void showFront();
    /// Show the outcome of a live capture; its tabs show their final summary
    /// already.
    void showLiveOutcome( const LiveOutcome& outcome );
    /// Show the live capture's packets, bytes, packets/s and elapsed time.
    void showLiveProgress();
    /// Enable Start if the Activity rule allows a live capture; its tooltip
    /// says why not.
    void updateStartButton();
    /// The Start live capture dialog showing @p choice.
    std::unique_ptr<LiveCaptureDialog> makeLiveCaptureDialog( QWidget* parent,
                                                              const LiveChoice& choice );
    /// Show why the live capture failed, and what its source says to do.
    void showLiveError( const LiveOutcome& outcome );
    /// Show the Export session's state: its progress dialog while it
    /// exports, with its label, and none once it is idle.
    void showExportState();
    /// The summary of the capture in the tab in front, in the palette's
    /// colours, or that the tab holds no capture of this plugin.
    QString frontSummaryHtml() const;
    /// Enable Stream lines in Regex Lab when the Packet Panel can tell the
    /// selected line's stream; its tooltip says why not.
    void updateStreamLinesButton();

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
    QString lastDir_;                          ///< Remembers the last browsed directory.
    FileChooser chooseFile_;                   ///< Shows the file dialog.
    SaveChooser chooseSaveFile_;               ///< Shows the save dialog.
    /// The summary frontSummaryHtml() made last, as the label showed it.
    QString shownSummary_;
    /// The captures converted and captured so far, by the text file written
    /// for each, and which is in front; the Live Capture Session's catalog.
    /// It opens their tabs through this sidebar.
    CaptureCatalog catalog_{ *this };

    /// Where the private temporary directories are created.
    QString tempRoot_;
    /// Opening a capture file, running or the last, and what it comes to;
    /// its conversion is cancelled and waited for when the widget goes.
    std::unique_ptr<FileConversionSession> conversion_;

    /// The live capture, running or the last one, and what it comes to.
    std::unique_ptr<LiveCaptureSession> live_;
    QTimer liveTicker_; ///< Moves the elapsed time on.
    /// Where the Start live capture dialog lists devices and interfaces;
    /// cancelled and waited for when the widget goes.
    QThreadPool listingPool_;
    /// The kinds of live sources offered.
    std::shared_ptr<const LiveSourceRegistry> liveSources_;
    LiveChoiceAsker askLiveChoice_; ///< Shows the Start live capture dialog.
    StopConfirmer confirmStop_;     ///< Asks whether to stop the running capture.

    /// Exporting packets, running or the last, and what it comes to; its
    /// export is cancelled and waited for when the widget goes.
    std::unique_ptr<ExportSession> export_;
    QPointer<QProgressDialog> exportProgress_; ///< Its progress, and Cancel.
};

} // namespace tcpdump
