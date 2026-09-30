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

namespace tcpdump {
class SidebarWidget;
} // namespace tcpdump

namespace tcpdump {

/// Global plugin state.  Only accessed from the main (GUI) thread.
struct PluginState {
    const LogSquirlHostApi* api = nullptr;  ///< Host API function table.
    void* handle = nullptr;                 ///< Opaque plugin instance handle.
    SidebarWidget* sidebarWidget = nullptr; ///< Sidebar panel for pcap control.
    bool sidebarTabRegistered = false;      ///< The host holds sidebarWidget as a tab.
    bool initialised = false;               ///< True between init() and shutdown().
    bool quitting = false; ///< LogSquirl is quitting (aboutToQuit), not just unloading the plugin.
};

/// Singleton plugin state.  Defined in plugin.cpp.
extern PluginState g_state;

/// Log a message through the host API (no-op if not initialised).
/// The host decodes the message as UTF-8.
void hostLog( int level, const QString& message );

/// Show a host notification (no-op if not initialised).
/// The host decodes the message as UTF-8.
void hostNotify( const QString& message );

} // namespace tcpdump
