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
 * @file packet_panel.h
 * @brief The Packet Panel: the layer tree and hex dump of the packet of the
 *        selected packet line, as Wireshark's lower panes show it.
 *
 * The packet list stays LogSquirl's view of the converted text; the panel
 * is its companion in the sidebar.  It follows the tab in front (the
 * sidebar hands it the capture's CaptureIndex) and the line selected there,
 * which it reads through the host's get_selected_log_lines (LogSquirl
 * 26.11).  The host has no selection-changed callback, so the panel asks
 * for the selection while it is visible, every kPollIntervalMs, and does
 * nothing when it did not change; Plugins > tcpdump > Packet details reads
 * it at once.  The packet is found by the No. column of the first selected
 * line and read back from the capture file by a CaptureCursor, on a worker
 * thread of the panel's own (up to a checkpoint interval of records): the
 * panel says "Reading packet N…" meanwhile, and a read the selection has
 * moved on from is dropped, not started if it has not begun.
 *
 * Its Stream tab shows the content of the shown packet's conversation
 * (Follow stream content, StreamContentView) once the user asks for it: by
 * the panel's button or Plugins > tcpdump > Follow stream content.
 *
 * Below the tabs, the Conversations table (conversation_table.h) lists the
 * streams of the capture in front, from its Capture Summary.
 */

#pragma once

#include "capture_index.h"
#include "packet_layers.h"

#include <QByteArray>
#include <QString>
#include <QThreadPool>
#include <QTimer>
#include <QWidget>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>
#include <vector>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;

namespace tcpdump {

class StreamContentView;
class ConversationTable;

/// The hex dump of @p bytes, 16 to a line: the offset, the bytes in hex in
/// two groups of 8, then as ASCII, '.' for a byte that is not printable.
QString hexDump( const std::vector<uint8_t>& bytes );

/// Where hexDump() of @p total bytes shows bytes [@p offset, @p offset +
/// @p length): the character ranges, as {start, length}, of their hex and
/// their ASCII on each line they are on.
std::vector<std::pair<int, int>> hexDumpRanges( size_t total, size_t offset, size_t length );

/**
 * The Packet Panel.  Shows the reason when there is no packet to show: a tab
 * that holds no capture of the plugin, no selection, a line that is not a
 * packet line, a capture file changed since it was converted.
 */
class PacketPanel : public QWidget {
    Q_OBJECT

public:
    /// How often the selection is asked for while the panel is visible.
    static constexpr int kPollIntervalMs = 250;

    explicit PacketPanel( QWidget* parent = nullptr );
    ~PacketPanel() override;

    /// Show the packets of the capture @p index points into, that of the tab
    /// now in front; null for a tab that holds no capture of the plugin.
    void setCapture( std::shared_ptr<const CaptureIndex> index );

    /// Read the selection now and show its packet, even if it did not
    /// change; @p then runs once it is shown, or why not (on this thread).
    void refresh( std::function<void()> then = {} );

    /// Whether the selection is being asked for: only while the panel is visible.
    bool isPolling() const
    {
        return timer_.isActive();
    }

    /// The number of the packet of the selected line, also while it is
    /// read; 0 while none is selected.
    uint32_t selectedPacket() const
    {
        return selectedPacket_;
    }

    /// The number of the packet shown; 0 while none is.
    uint32_t shownPacket() const
    {
        return shownPacket_;
    }

    /// The layers of the packet shown.
    const std::vector<PacketLayer>& layers() const
    {
        return layers_;
    }

    /// The panel's status line: the packet shown, or why there is none.
    QString statusText() const;

    /// Follow stream content: show the content of the selected packet's
    /// stream in the Stream tab, also while the packet is being read.
    /// False, and the reason in @p why, when no packet line of a TCP or
    /// UDP stream is selected.
    bool followStreamContent( QString* why = nullptr );

    /// The Stream tab.
    StreamContentView* streamView() const
    {
        return streamView_;
    }

    /// The Conversations table of the capture in front.
    ConversationTable* conversationTable() const
    {
        return conversations_;
    }

protected:
    void showEvent( QShowEvent* event ) override;
    void hideEvent( QHideEvent* event ) override;

private:
    /// Ask for the selection; show its packet if it changed (or @p force).
    void poll( bool force = false );
    /// Show the packet of @p selection, the selected lines' text.
    void showSelection( const QString& selection );
    /// Read packet @p number on the worker, then show it.
    void showPacket( uint32_t number );
    /// What a read on the worker found.
    struct PacketRead;
    void showRead( const PacketRead& read );
    /// The packet shown, or why none is: run what waited for it.
    void settled();
    /// Show no packet, only @p reason.
    void showReason( const QString& reason );
    /// Highlight the bytes of @p item in the dump.
    void highlight( QTreeWidgetItem* item );

    QLabel* status_ = nullptr;
    QPushButton* followButton_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    StreamContentView* streamView_ = nullptr;
    QTreeWidget* tree_ = nullptr;
    QPlainTextEdit* dump_ = nullptr;
    ConversationTable* conversations_ = nullptr;
    QTimer timer_;

    std::shared_ptr<const CaptureIndex> index_;
    /// Used by the worker only, one read at a time.
    std::shared_ptr<CaptureCursor> cursor_;
    QThreadPool pool_;
    /// Counts the reads asked for: a result of an earlier one is dropped,
    /// and one not begun yet is not started.
    uint64_t generation_ = 0;
    std::shared_ptr<std::atomic<uint64_t>> latest_;
    bool reading_ = false;
    std::vector<std::function<void()>> whenSettled_;
    /// What the selection was when last asked: the host's result and text.
    int lastResult_ = 0;
    QByteArray lastSelection_;
    bool haveLast_ = false;

    uint32_t selectedPacket_ = 0; ///< The packet of the selected line, read or not.
    uint32_t shownPacket_ = 0;
    /// The Stream column of the shown packet's line: its number, or
    /// kNoStream ("-") or kUnnumbered ("?").
    int shownStream_ = -1;
    size_t shownBytes_ = 0;
    std::vector<PacketLayer> layers_;
};

} // namespace tcpdump
