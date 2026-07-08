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
 * link-layer type, duration) of the last opened capture.
 */

#pragma once

#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>
#include <QWidget>

namespace tcpdump {

/**
 * Sidebar widget displayed in the LogSquirl sidebar panel.
 *
 * Contains:
 *   - "Open pcap…" button (opens a file dialog)
 *   - Summary label showing the last capture's stats
 */
class SidebarWidget : public QWidget {
    Q_OBJECT

public:
    /// Construct with an optional parent.
    explicit SidebarWidget( QWidget* parent = nullptr );

private Q_SLOTS:
    /// Show a file dialog and open the selected pcap file.
    void onOpenClicked();

private:
    /// Parse a pcap file, write a formatted text file, and open it in LogSquirl.
    void openPcapFile( const QString& filePath );

    QPushButton* openButton_ = nullptr;
    QLabel* summaryLabel_ = nullptr;
    QString lastDir_;  ///< Remembers the last browsed directory.
};

} // namespace tcpdump
