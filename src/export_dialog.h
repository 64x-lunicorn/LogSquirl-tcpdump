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
 * @file export_dialog.h
 * @brief The dialog of Plugins > tcpdump > Export packets…: which packets
 *        to export, confirmed or changed by the user.
 */

#pragma once

#include "packet_export.h"

#include <QDialog>

#include <cstddef>
#include <cstdint>
#include <vector>

class QLabel;
class QPlainTextEdit;
class QPushButton;
class QTimer;

namespace tcpdump {

/// What Export packets… asks the user to confirm, and where the export goes.
struct ExportRequest {
    QString captureName;      ///< The capture's file name, without directory.
    uint32_t packets = 0;     ///< Packets of the capture.
    PacketNumbers numbers;    ///< The packets to export.
    size_t selectedLines = 0; ///< Lines the host told as selected.
    /// The host told only the first selected lines: at most
    /// LOGSQUIRL_SELECTED_LOG_LINES_MAX_LINES or _MAX_BYTES of them.
    bool truncated = false;
    CaptureFormat format = CaptureFormat::Pcap; ///< The capture's, and so the export's.
    QString outputPath;                         ///< Where the export goes.
};

/**
 * Shows the packets of the selected lines as numbers and ranges, which the
 * user may change, or replace by packet lines pasted from LogSquirl, e.g.
 * all lines of a Filtered View, which the host does not tell.  Says when
 * the host told only the first selected lines, and how many packets the
 * text names.
 */
class ExportDialog : public QDialog {
    Q_OBJECT

public:
    explicit ExportDialog( const ExportRequest& request, QWidget* parent = nullptr );

    /// The packets the text names now.
    const PacketSet& packetSet();

    /// Replace the text, as the user would (for tests).
    void setText( const QString& text );

private:
    /// Read the text again and show what it names.
    void update();

    /// The text is read again this long after the last change, not on
    /// every key: a long paste of packet lines takes a while.
    static constexpr int kUpdateDelayMs = 200;

    uint32_t packets_;
    PacketSet set_;
    QTimer* updateTimer_ = nullptr;
    QPlainTextEdit* text_ = nullptr;
    QLabel* count_ = nullptr;
    QPushButton* exportButton_ = nullptr;
};

} // namespace tcpdump
