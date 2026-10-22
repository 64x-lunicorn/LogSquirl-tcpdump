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
 * which it reads through Selected Packet Line (selected_packet_line.h),
 * from the host's get_selected_log_lines (LogSquirl 26.11).  The host has
 * no selection-changed callback, so the panel asks for the selection while
 * it is visible, every kPollIntervalMs, and does nothing when it did not
 * change; Plugins > tcpdump > Packet details reads it at once.  The packet
 * is found by the No. column of the first selected line and read back from
 * the capture file by a CaptureCursor, on a worker thread of the panel's
 * own (up to a checkpoint interval of records): the panel says "Reading
 * packet N…" meanwhile, and a read the selection has moved on from is
 * dropped, not started if it has not begun.
 *
 * Its Stream tab shows the content of the shown packet's conversation
 * (Follow stream content, StreamContentView) once the user asks for it: by
 * the panel's button or Plugins > tcpdump > Follow stream content.  The
 * button is enabled only when the selected line's stream can be shown, its
 * tooltip says why not; streamActionsChanged() tells the sidebar, whose
 * Filter stream in Regex Lab button follows the selection too.
 *
 * Below the tabs, the Conversations table (conversation_table.h) lists the
 * streams of the capture in front, from its Capture Summary.
 */

#pragma once

#include "capture_index.h"
#include "packet_layers.h"
#include "selected_packet_line.h"

#include <QString>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>
#include <QWidget>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSplitter;
class QTabWidget;
class QTreeWidgetItem;

namespace tcpdump {

class StreamContentView;
class ConversationTable;

/// Bytes on a line of the hex dump, as Wireshark shows it.
constexpr size_t kDumpBytesPerLine = 16;
/// Bytes on a line of the hex dump where a line of kDumpBytesPerLine does
/// not fit, as in a narrow sidebar.
constexpr size_t kNarrowDumpBytesPerLine = 8;

/// The hex dump of @p bytes, @p bytesPerLine (kDumpBytesPerLine or
/// kNarrowDumpBytesPerLine) to a line: the offset, the bytes in hex, in
/// groups of 8, then as ASCII, '.' for a byte that is not printable.
QString hexDump( const std::vector<uint8_t>& bytes, size_t bytesPerLine = kDumpBytesPerLine );

/// The characters of a full line of hexDump() of @p total bytes, @p
/// bytesPerLine to a line: what the dump needs to be wide enough for.
int hexDumpLineChars( size_t total, size_t bytesPerLine = kDumpBytesPerLine );

/// Where hexDump() of @p total bytes, @p bytesPerLine to a line, shows
/// bytes [@p offset, @p offset + @p length): the character ranges, as
/// {start, length}, of their hex and their ASCII on each line they are on.
std::vector<std::pair<int, int>> hexDumpRanges( size_t total, size_t offset, size_t length,
                                                size_t bytesPerLine = kDumpBytesPerLine );

/// Enable @p button, its tooltip @p whatItDoes, when @p problem is empty;
/// otherwise disable it, its tooltip @p problem: why it would not work.
void enableUnlessProblem( QPushButton* button, const QString& problem, const QString& whatItDoes );

/// The tree of a packet's layers, which says what it will show while it
/// holds none.
class LayerTree : public QTreeWidget {
    Q_OBJECT

public:
    using QTreeWidget::QTreeWidget;

    /// The text shown while the tree is empty; none if empty.
    QString placeholderText() const
    {
        return placeholderText_;
    }
    void setPlaceholderText( const QString& text );

protected:
    void paintEvent( QPaintEvent* event ) override;

private:
    QString placeholderText_;
};

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
    /// The rows the Conversations keep below the tabs, in lines of text.
    static constexpr int kConversationsMinLines = 5;

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

    /// The packet line selected, as the panel read it when it last asked,
    /// also while its packet is read; none while selectedPacket() is 0.
    /// Filter stream in Regex Lab follows its stream, so that the button
    /// and the action decide on the same reading of the selection.
    std::optional<PacketLine> selectedLine() const;

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
    /// It is hidden while it would say what the summary or the empty layer
    /// tree and hex dump say (no capture, no line selected), and tells it
    /// all the same.
    QString statusText() const;

    /// Follow stream content: show the content of the selected packet's
    /// stream in the Stream tab, also while the packet is being read.
    /// False, and the reason in @p why, when no packet line of a TCP or
    /// UDP stream is selected.
    bool followStreamContent( QString* why = nullptr );

    /// Why Follow stream content cannot show a stream now, for the user: no
    /// capture in the tab in front, a read that failed, or what
    /// SelectedPacketLine::streamContentProblem() says; empty when it can.
    QString streamContentProblem() const;

    /// Why Filter stream in Regex Lab cannot filter a stream's lines now, as
    /// streamContentProblem(), with SelectedPacketLine::streamLinesProblem();
    /// empty when it can.
    QString streamLinesProblem() const;

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

    /// The splitter between the layer tree and the hex dump; the sidebar
    /// remembers where the user left it.
    QSplitter* layersSplitter() const
    {
        return layersSplitter_;
    }

    /// The splitter between the tabs and the Conversations, as remembered.
    QSplitter* conversationsSplitter() const
    {
        return conversationsSplitter_;
    }

signals:
    /// The selected line changed what streamContentProblem() and
    /// streamLinesProblem() say (or may have).
    void streamActionsChanged();

protected:
    void showEvent( QShowEvent* event ) override;
    void hideEvent( QHideEvent* event ) override;
    /// Lays the dump out again when its viewport is resized.
    bool eventFilter( QObject* watched, QEvent* event ) override;

private:
    /// Ask for the selection; show its packet if it changed (or @p force).
    void poll( bool force = false );
    /// Show the packet of the line @p selected, or why there is none.
    void showSelection( const SelectedPacketLine& selected );
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
    /// kDumpBytesPerLine if a full line of it fits the dump's viewport,
    /// kNarrowDumpBytesPerLine if not.
    size_t fittingBytesPerLine() const;
    /// Show the dump of the packet's bytes with fittingBytesPerLine(), if
    /// not already, the selected item highlighted again.
    void layOutDump();
    /// Enable the Follow stream content button, or say why not in its
    /// tooltip, and tell streamActionsChanged().
    void updateStreamActions();

    QLabel* status_ = nullptr;
    QPushButton* followButton_ = nullptr;
    QTabWidget* tabs_ = nullptr;
    StreamContentView* streamView_ = nullptr;
    LayerTree* tree_ = nullptr;
    QPlainTextEdit* dump_ = nullptr;
    ConversationTable* conversations_ = nullptr;
    QSplitter* layersSplitter_ = nullptr;
    QSplitter* conversationsSplitter_ = nullptr;
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
    /// What the host told of the selection when last asked; none since a
    /// capture came to the front.
    std::optional<SelectedLines> last_;
    /// The line selected when last asked, read: its packet's number,
    /// stream and iRTT, or why it has none.
    SelectedPacketLine selected_;

    uint32_t selectedPacket_ = 0; ///< The packet of the selected line, read or not.
    uint32_t shownPacket_ = 0;
    /// The bytes of the packet shown, kept to lay its dump out again.
    std::vector<uint8_t> bytes_;
    /// The bytes on a line of the dump shown.
    size_t dumpBytesPerLine_ = kDumpBytesPerLine;
    std::vector<PacketLayer> layers_;
};

} // namespace tcpdump
