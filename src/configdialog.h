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
 * @file configdialog.h
 * @brief The plugin's configuration dialog, opened by Configure… in
 *        LogSquirl's Plugin Management.
 */

#pragma once

#include "pcap_converter.h"

#include <QDialog>

class QCheckBox;
class QComboBox;
class QSpinBox;

namespace tcpdump {

/**
 * Edits the ConversionOptions: the time columns, the MAC columns, the
 * payload preview and its length, the TCP timestamps on every segment, and, for advanced users, the
 * stream and endpoint caps.  Says that a capture already open keeps the options it was converted
 * with.  Saving them is the caller's (settings.h).
 */
class ConfigDialog : public QDialog {
    Q_OBJECT

public:
    /// A dialog showing @p options.
    explicit ConfigDialog( const ConversionOptions& options, QWidget* parent = nullptr );

    /// The options as the controls show them.
    ConversionOptions options() const;

private:
    /// Show @p options in the controls.
    void showOptions( const ConversionOptions& options );

    QComboBox* timeColumns_ = nullptr;
    QCheckBox* macColumns_ = nullptr;
    QCheckBox* preview_ = nullptr;
    QSpinBox* previewChars_ = nullptr;
    QCheckBox* tcpTimestamps_ = nullptr;
    QSpinBox* maxStreams_ = nullptr;
    QSpinBox* maxEndpoints_ = nullptr;
    QSpinBox* reassemblyMegabytes_ = nullptr;
};

} // namespace tcpdump
