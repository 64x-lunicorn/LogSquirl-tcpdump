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

#include "pcap_converter.h"

#include <QFutureWatcher>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QThreadPool>
#include <QVBoxLayout>
#include <QWidget>

#include <atomic>
#include <functional>
#include <map>
#include <memory>

namespace tcpdump {

class PacketPanel;

/// The capture summary shown in the sidebar, as rich text.  With
/// @p filterLinks, each endpoint and protocol listed is a link that
/// SidebarWidget opens in the Regex Lab as a filter.  A tunnel's endpoints
/// are listed apart and never a link: no column of a line shows them.
QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks = false );

/**
 * Sidebar widget displayed in the LogSquirl sidebar panel.
 *
 * Contains:
 *   - "Open pcap…" button (opens a file dialog, as Plugins > tcpdump does)
 *   - "Follow stream" button, as in Plugins > tcpdump, only on a host that
 *     has the Regex Lab and tells the selected lines: g_state.hostCapabilities
 *     when the widget is created
 *   - progress bar and Cancel button, while a capture is converted
 *   - Summary label showing the stats of the capture in the tab in front,
 *     or that the tab holds none; the summary of the first capture after
 *     the plugin is loaded also links to the README section on installing
 *     the Log Format, which the plugin cannot tell is installed; on a host
 *     with the Regex Lab, a click on an endpoint or a protocol listed opens
 *     the Lab on its lines, as Wireshark's Apply as Filter
 *   - the Packet Panel (packet_panel.h): the layer tree and hex dump of the
 *     packet of the line selected in the tab in front
 *
 * The summaries of all captures converted while the plugin is loaded are
 * kept with their CaptureIndex, keyed by the text file written for each, so
 * that a capture's tab that comes to the front again shows its own, and the
 * Packet Panel its packets.
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

    /// The Packet Panel.
    PacketPanel* packetPanel() const
    {
        return packetPanel_;
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
    };

    /// Open a link of the summary: a filter in the Regex Lab, or a web page.
    void openLink( const QString& link );
    /// Show the outcome of a conversion and return to idle.
    void finishConversion( const QString& filePath, ConversionResult result );
    /// Show the idle or the converting controls.
    void setConverting( bool converting );

    QPushButton* openButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QProgressBar* progressBar_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    PacketPanel* packetPanel_ = nullptr;
    QString lastDir_;              ///< Remembers the last browsed directory.
    bool formatHintShown_ = false; ///< The Log Format hint was shown once.
    FileChooser chooseFile_;       ///< Shows the file dialog.
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
};

} // namespace tcpdump
