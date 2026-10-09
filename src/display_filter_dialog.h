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
 * @file display_filter_dialog.h
 * @brief Plugins > tcpdump > Display filter…: the dialog in which the user
 *        types a display filter, told at once what is wrong with it, and
 *        the Regex Lab it opens.
 */

#pragma once

#include "display_filter.h"

#include <QDialog>

class QLabel;
class QLineEdit;
class QPushButton;

namespace tcpdump {

/**
 * Asks for a display filter.  Each change of the text is translated: a
 * filter outside the supported subset shows the column and the reason
 * below the field, and cannot be accepted; an empty one says nothing.
 */
class DisplayFilterDialog : public QDialog {
    Q_OBJECT

public:
    explicit DisplayFilterDialog( const QString& filter = {}, QWidget* parent = nullptr );

    /// The filter as typed.
    QString filter() const;

    /// Its pattern; empty while the filter is rejected.
    QString pattern() const;

private:
    void update();

    QLineEdit* edit_ = nullptr;
    QLabel* error_ = nullptr;
    QPushButton* openButton_ = nullptr;
    DisplayFilterPattern translated_;
};

/// Plugins > tcpdump > Display filter…: ask for a filter, offering the one
/// accepted last, and open the Regex Lab with its pattern.  The filter and
/// what the user does in the Lab are logged.  Call only when
/// g_state.hostCapabilities has the Regex Lab, on the UI thread.
void openDisplayFilter( QWidget* parent );

} // namespace tcpdump
