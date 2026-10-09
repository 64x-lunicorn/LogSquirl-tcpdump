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
 * @file plugin.h
 * @brief Global plugin state shared across all translation units.
 *
 * Centralises the host API pointer, opaque handle, and sidebar widget.
 */

#pragma once

#include "logsquirl_plugin_api.h"

#include <QString>

#include <cstddef>

namespace tcpdump {
class SidebarWidget;
} // namespace tcpdump

namespace tcpdump {

/**
 * Which host functions added after the base table the running host offers
 * (all LogSquirl 26.11).  Told by the size of the host's table, following
 * the SDK's growing-API rules: a member of LogSquirlHostApi that is not
 * reported here must never be called or even read, as an older host's table
 * ends before it.
 */
struct HostCapabilities {
    bool regexLab = false;         ///< open_regex_lab
    bool goToLogLine = false;      ///< go_to_log_line
    bool selectedLogLines = false; ///< get_selected_log_lines

    /// What a host table of @p apiSize bytes offers.
    static HostCapabilities of( std::size_t apiSize );

    bool operator==( const HostCapabilities& other ) const
    {
        return regexLab == other.regexLab && goToLogLine == other.goToLogLine
               && selectedLogLines == other.selectedLogLines;
    }
    bool operator!=( const HostCapabilities& other ) const
    {
        return !( *this == other );
    }
};

/// Global plugin state.  Only accessed from the main (GUI) thread.
struct PluginState {
    const LogSquirlHostApi* api = nullptr;  ///< Host API function table.
    void* handle = nullptr;                 ///< Opaque plugin instance handle.
    HostCapabilities hostCapabilities;      ///< The later functions api offers.
    SidebarWidget* sidebarWidget = nullptr; ///< Sidebar panel for pcap control.
    bool sidebarTabRegistered = false;      ///< The host holds sidebarWidget as a tab.
    bool initialised = false;               ///< True between init() and shutdown().
    bool quitting = false; ///< LogSquirl is quitting (aboutToQuit), not just unloading the plugin.
    QString tempRoot;      ///< Where temporary directories go; empty: the system's (for tests).
};

/// Singleton plugin state.  Defined in plugin.cpp.
extern PluginState g_state;

/// Log a message through the host API (no-op if not initialised).
/// The host decodes the message as UTF-8.
void hostLog( int level, const QString& message );

/// The plugin's configuration directory, as the host names it; empty
/// without a host.
QString hostConfigDir();

/// Show a host notification (no-op if not initialised).
/// The host decodes the message as UTF-8.
void hostNotify( const QString& message );

} // namespace tcpdump
