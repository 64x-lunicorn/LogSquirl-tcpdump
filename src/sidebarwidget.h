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

#include "export_dialog.h"
#include "live_capture.h"
#include "live_source.h"
#include "pcap_converter.h"

#include <QElapsedTimer>
#include <QFutureWatcher>
#include <QLabel>
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
#include <map>
#include <memory>
#include <optional>

namespace tcpdump {

class LiveCaptureForm;
class PacketPanel;

/// The capture summary shown in the sidebar, as rich text.  With
/// @p filterLinks, each endpoint and protocol listed is a link that
/// SidebarWidget opens in the Regex Lab as a filter.  A tunnel's endpoints
/// are listed apart and never a link: no column of a line shows them.
QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks = false );

/// The progress of a live capture as the sidebar shows it, in place of a
/// percentage (a stream has no size): packets, bytes and packets/s as of
/// @p snapshot, and the time since the capture started, @p elapsedMs.  With
/// @p limits, how far the capture is to each stop condition, and the ring
/// buffer's file.
QString liveProgressText( const LiveSnapshot& snapshot, qint64 elapsedMs,
                          const LiveLimits& limits = {} );

/// What the sidebar says of a live capture @p name that @p condition of
/// @p limits stopped: "The capture eth0 stopped after 1,000 packets."
QString liveStopText( const QString& name, StopCondition condition, const LiveLimits& limits );

/**
 * Sidebar widget displayed in the LogSquirl sidebar panel.
 *
 * Contains:
 *   - "Open pcap…" button (opens a file dialog, as Plugins > tcpdump does)
 *   - "Follow stream" button, as in Plugins > tcpdump, only on a host that
 *     has the Regex Lab and tells the selected lines: g_state.hostCapabilities
 *     when the widget is created
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
 * Plugins > tcpdump > Start live capture… shows the same form in a dialog
 * (LiveCaptureDialog).  The last choice started is kept in settings.ini and
 * shown again after a restart.  Start is disabled while a capture is read
 * or captured; from the menu, a running capture is offered to be stopped
 * first, and the new one starts once it has ended.
 *
 * Plugins > tcpdump > Export packets… writes the packets of the lines
 * selected in the tab in front to a new capture file (packet_export.h), on
 * a worker thread of its own, with a progress dialog and Cancel.
 *
 * The summaries of all captures converted while the plugin is loaded are
 * kept with their CaptureIndex, keyed by the text file written for each, so
 * that a capture's tab that comes to the front again shows its own, and the
 * Packet Panel its packets.
 *
 * A live capture's tab is opened, following its file, once the header and
 * the first packet line are in it; with a ring buffer, each file's text in
 * a tab of its own as it starts, the tabs before left as they are.  Its
 * summary in the sidebar follows the snapshots while it runs, in every tab
 * of the capture, and is final when it ends.
 *
 * A capture is converted on a worker thread, so that a large one neither
 * freezes LogSquirl nor can be interrupted only by killing it.  Destroying
 * the widget cancels a running conversion and waits for it: no code of the
 * plugin runs on the worker thread afterwards, and the host may unload the
 * library.
 */
class SidebarWidget : public QWidget {
    Q_OBJECT

public:
    /// Construct with an optional parent.
    explicit SidebarWidget( QWidget* parent = nullptr );
    ~SidebarWidget() override;

    /// Ask for a capture in a file dialog, as the Open button does, and open
    /// it.  While a conversion runs, only a notification says so.
    void chooseAndOpen();

    /// Convert a pcap file in the background, then open the text in LogSquirl.
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
    /// the label keeps saying so.
    void showSummaryFor( const QString& filePath );

    /// Stop a running conversion; nothing is opened then.
    void cancel();

    /// Plugins > tcpdump > Packet details: show the packet of the line
    /// selected now in the Packet Panel; if the panel is not in view, a
    /// notification names the packet's layers.
    void showPacketDetails();

    /// Plugins > tcpdump > Follow stream content: show the content of the
    /// selected line's stream in the Packet Panel's Stream tab, or notify
    /// the user why not; if the panel is not in view, a notification says
    /// where it is.
    void followStreamContent();

    /// Plugins > tcpdump > Export packets…: the packets of the lines selected
    /// in the tab in front, confirmed by the user, written to a new capture
    /// file in the background.  While an export runs, only a notification
    /// says so.
    void exportSelectedPackets();

    /// Asks the user to confirm the packets of @p request and where to write
    /// them; false if the user does not want them exported.
    using ExportConfirmer = std::function<bool( QWidget* parent, ExportRequest& request )>;

    /// Ask with @p confirmer instead of the Export dialog and a file dialog
    /// (for tests).
    void setExportConfirmer( ExportConfirmer confirmer )
    {
        confirmExport_ = std::move( confirmer );
    }

    /// Whether an export is running.
    bool isExporting() const
    {
        return exportWatcher_ != nullptr;
    }

    /// Stop a running export; nothing is left of it then.
    void cancelExport();

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
     * @p limits say.  False, with a notification, while a capture is being
     * read or captured.
     */
    bool startLiveCapture( const QString& name, LiveCapture::SourceFactory makeSource,
                           const LiveLimits& limits = {} );

    /**
     * Capture @p choice live: its source (a kind of the live sources, see
     * setLiveSources()) makes the stream, named after its device and
     * interface (liveCaptureName()).  The choice is saved in settings.ini.
     * False, with a notification, if the source is unknown or unavailable,
     * the choice is not one it can capture, or a capture is being read or
     * captured.
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

    /// Offer the kinds of @p sources in the Live capture section and the
    /// dialog, showing the choice saved in settings.ini (for tests; the
    /// plugin's own are builtInLiveSources()).
    void setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// The kinds every SidebarWidget constructed afterwards offers until
    /// setLiveSources(): builtInLiveSources(), unless @p sources is set.
    /// The test runner sets an empty registry, so that no test runs a real
    /// capture program (tcpdump -D, adb) by constructing a sidebar.
    static void setDefaultLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// The Live capture section's form.
    LiveCaptureForm* liveForm() const
    {
        return liveForm_;
    }

    /// End the running live capture and keep what was captured.
    void stopLiveCapture();

    /// Whether a live capture runs.
    bool isCapturing() const
    {
        return capturing_;
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
    }

    /// The directory the temporary directories are created in.
    const QString& tempRoot() const
    {
        return tempRoot_;
    }

    /// Whether a conversion is running.
    bool isConverting() const
    {
        return converting_;
    }

private:
    /// A capture converted while the plugin is loaded, as its summary shows it.
    struct ConvertedCapture {
        QString fileName;       ///< The capture's name, without directory.
        qint64 fileSize = 0;    ///< The capture's size in bytes.
        CaptureSummary summary; ///< What was converted.
        /// Where its packets are in the capture file, for the Packet Panel.
        std::shared_ptr<const CaptureIndex> index;
        bool withFormatHint = false; ///< Links to the Log Format section.
        QString rawPath;             ///< A live capture's raw file; empty for a file.
        /// What Save capture… names the capture: a live capture's name (a
        /// ring buffer's text files are numbered); empty for a file.
        QString captureName;
        QString error; ///< Why a live capture failed, keeping what it had.
    };

    /// Open a link of the summary: a filter in the Regex Lab, or a web page.
    void openLink( const QString& link );
    /// Show the outcome of a conversion and return to idle.
    void finishConversion( const QString& filePath, ConversionResult result );
    /// Show the idle or the converting controls.
    void setConverting( bool converting );
    /// Show the idle or the capturing controls.
    void setCapturing( bool capturing );
    /// The live capture's file is ready: keep its summary, open its tab.
    void openLiveCapture( const QString& logPath, const QString& rawPath );
    /// The live capture's summary so far.
    void takeLiveSnapshot( const LiveSnapshot& snapshot );
    /// Show the outcome of a live capture, and return to idle.
    void finishLiveCapture( const ConversionResult& result );
    /// The live capture's worker is done: start the capture Start live
    /// capture… asked for meanwhile.
    void startPendingLiveCapture();
    /// Show the outcome of a live capture and return to idle.
    void reportLiveOutcome( const ConversionResult& result );
    /// Whether @p key is a text file of the live capture, running or the last.
    bool isLiveKey( const QString& key ) const;
    /// Show the live capture's packets, bytes, packets/s and elapsed time.
    void showLiveProgress();
    /// Whether a capture is being read or captured, said in a notification.
    bool refuseWhileBusy();
    /// Enable Start if no capture is read or captured and the form's choice
    /// can be captured; its tooltip says why not.
    void updateStartButton();
    /// Show why the live capture failed, and what its source says to do.
    void showLiveError( const QString& error );
    /// Report the outcome of the export @p request asked for.
    void finishExport( const ExportRequest& request, ExportResult result );

    QPushButton* openButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QProgressBar* progressBar_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    PacketPanel* packetPanel_ = nullptr;
    QPushButton* stopButton_ = nullptr;
    QPushButton* saveButton_ = nullptr;
    QLabel* liveLabel_ = nullptr;
    LiveCaptureForm* liveForm_ = nullptr;
    QPushButton* startButton_ = nullptr;
    QPlainTextEdit* liveStderr_ = nullptr; ///< The capture program's stderr lines.
    QLabel* liveError_ = nullptr;          ///< Why the last live capture failed.
    QString lastDir_;                      ///< Remembers the last browsed directory.
    bool formatHintShown_ = false;         ///< The Log Format hint was shown once.
    FileChooser chooseFile_;               ///< Shows the file dialog.
    SaveChooser chooseSaveFile_;           ///< Shows the save dialog.
    /// The key in converted_ of the file in the tab in front, as fileKey()
    /// spells it, whether or not it holds a capture.
    QString frontKey_;
    /// The captures converted so far, by the text file written for each.
    std::map<QString, ConvertedCapture> converted_;

    bool converting_ = false;
    /// Cancels the running conversion.
    std::shared_ptr<std::atomic_bool> cancelRunning_;
    /// Where the private temporary directories are created.
    QString tempRoot_;
    /// The running conversion's outcome, delivered on this thread.
    QFutureWatcher<ConversionResult>* watcher_ = nullptr;
    /// One worker thread, owned here so that it can be waited for.
    QThreadPool pool_;

    bool capturing_ = false;
    /// The live capture, running or the last one; kept until the next starts,
    /// as its worker may still be ending the capture program.
    std::unique_ptr<LiveCapture> live_;
    QString liveKey_; ///< The live capture's text file, once it is there.
    /// Every text file of the live capture, oldest first, the last liveKey_:
    /// a ring buffer's, one per raw file, each in a tab of its own.
    std::vector<QString> liveKeys_;
    LiveSnapshot liveSnapshot_; ///< The latest snapshot of the live capture.
    LiveLimits liveLimits_;     ///< The live capture's stop conditions and ring buffer.
    QElapsedTimer liveClock_;   ///< Since the live capture started.
    QTimer liveTicker_;         ///< Moves the elapsed time on.
    /// Where the live capture form and dialog list devices and interfaces;
    /// cancelled and waited for when the widget goes.
    QThreadPool listingPool_;
    /// The kinds of live sources offered.
    std::shared_ptr<const LiveSourceRegistry> liveSources_;
    /// The kind of the live capture, running or the last one.
    std::shared_ptr<const LiveSourceKind> liveKind_;
    /// Started when the running capture has ended (Start live capture…).
    std::optional<LiveChoice> pendingStart_;
    LiveChoiceAsker askLiveChoice_; ///< Shows the Start live capture dialog.
    StopConfirmer confirmStop_;     ///< Asks whether to stop the running capture.

    ExportConfirmer confirmExport_; ///< Shows the Export dialog and a file dialog.
    /// Cancels the running export.
    std::shared_ptr<std::atomic_bool> cancelExport_;
    /// The running export's outcome, delivered on this thread; null while none runs.
    QFutureWatcher<ExportResult>* exportWatcher_ = nullptr;
    QPointer<QProgressDialog> exportProgress_; ///< Its progress, and Cancel.
    /// The export's worker thread, apart from the conversion's.
    QThreadPool exportPool_;
};

} // namespace tcpdump
