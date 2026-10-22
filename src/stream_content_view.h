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
 * @file stream_content_view.h
 * @brief The Stream tab of the Packet Panel: Follow stream content, the
 *        payload of the selected packet's conversation as text or hex.
 *
 * As Wireshark's Follow TCP/UDP Stream shows it: the client's and the
 * server's bytes interleaved in two colours, or one direction alone, as
 * text or a hex dump; gaps as "[n bytes missing]".  The content is read
 * from the capture file off the UI thread (StreamContentReader), with a
 * Cancel, and what is shown is bounded: kShowBytes at first, Show more
 * reads that much more, up to kMaxShownBytes, with a note when there is
 * more.  Export writes the whole stream to a file, raw bytes or as shown,
 * without holding it.
 */

#pragma once

#include "capture_index.h"
#include "stream_content.h"
#include "stream_tracker.h"

#include <QFutureWatcher>
#include <QString>
#include <QThreadPool>
#include <QWidget>

#include <atomic>
#include <cstdint>
#include <memory>
#include <vector>

class QComboBox;
class QLabel;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;

namespace tcpdump {

class StreamContentView : public QWidget {
    Q_OBJECT

public:
    /// Bytes of content read at first, and by each Show more.
    static constexpr uint64_t kShowBytes = 1024 * 1024;
    /// Bytes of content shown at most; Export writes the rest.
    static constexpr uint64_t kMaxShownBytes = 16 * 1024 * 1024;

    explicit StreamContentView( QWidget* parent = nullptr );
    /// Cancels what runs, and waits for it: the host may unload the library next.
    ~StreamContentView() override;

    /// Follow the stream of packet @p number of the capture @p index points
    /// into, numbered @p streamId in the Stream column (negative: unnumbered).
    void follow( std::shared_ptr<const CaptureIndex> index, uint32_t number, int streamId );

    /// Show no stream, only @p reason; cancels what runs.
    void clear( const QString& reason );

    /// Read kShowBytes more of the stream, while there is more and room.
    void showMore();

    /// Stop the read or export that runs.
    void cancel();

    /// Write the whole stream to @p path in the background: with @p raw the
    /// bytes of the directions shown, otherwise the text as shown.
    void exportTo( const QString& path, bool raw );

    void setFormat( StreamFormat format );
    void setDirections( unsigned directions );

    /// Whether a read or an export runs.
    bool isBusy() const
    {
        return busy_;
    }

    /// Whether the stream has more than was read.
    bool hasMore() const
    {
        return more_;
    }

    QString statusText() const;
    QString noteText() const;
    /// The content as shown, as plain text.
    QString contentText() const;

private:
    struct Batch {
        StreamContentReader::Status status = StreamContentReader::Status::Done;
        std::vector<StreamChunk> chunks;
        QString error;
    };

    void startRead( uint64_t budget );
    void finishRead( const std::shared_ptr<Batch>& batch );
    /// Append @p chunks to the content shown, rendered as now chosen.
    void appendChunks( const std::vector<StreamChunk>& chunks, size_t from );
    /// Render all chunks afresh, after the format or direction changed.
    void rerender();
    void updateLabels();
    void setBusy( bool busy, const QString& status = {} );
    void chooseExport( bool raw );

    QLabel* status_ = nullptr;
    QComboBox* directionBox_ = nullptr;
    QComboBox* formatBox_ = nullptr;
    QPlainTextEdit* content_ = nullptr;
    QLabel* note_ = nullptr;
    QProgressBar* progress_ = nullptr;
    QPushButton* moreButton_ = nullptr;
    QPushButton* cancelButton_ = nullptr;
    QPushButton* exportButton_ = nullptr;

    QThreadPool pool_;
    std::shared_ptr<std::atomic_bool> cancel_;
    /// The format or directions changed while busy: what is shown is
    /// rendered anew when the read or export ends.
    bool rerenderPending_ = false;
    /// Counts the streams followed: a result of an earlier one is dropped.
    uint64_t generation_ = 0;

    std::shared_ptr<const CaptureIndex> index_;
    uint32_t number_ = 0;
    int streamId_ = kNoStream;
    /// The reader of the stream shown; only a worker uses it while busy_.
    std::shared_ptr<StreamContentReader> reader_;
    std::vector<StreamChunk> chunks_; ///< The content read, for the view.
    uint64_t shownBytes_ = 0;         ///< Bytes of content in chunks_.
    std::unique_ptr<StreamRenderer> renderer_;
    StreamFormat format_ = StreamFormat::Text;
    unsigned directions_ = kBothDirections;
    bool busy_ = false;
    bool more_ = false;
    QString lastError_;
};

} // namespace tcpdump
