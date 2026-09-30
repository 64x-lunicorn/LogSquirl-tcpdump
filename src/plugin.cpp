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
 * @file plugin.cpp
 * @brief C ABI entry points for the LogSquirl tcpdump plugin.
 *
 * Implements the four exported symbols:
 *
 *   - logsquirl_plugin_get_info()   → static metadata
 *   - logsquirl_plugin_init()       → store host API, create sidebar tab
 *   - logsquirl_plugin_shutdown()   → tear down widget, clear state
 *   - logsquirl_plugin_configure()  → (no-op for now)
 *
 * PLUGIN LIFECYCLE
 * ────────────────
 *   1. Host calls get_info() to read metadata.
 *   2. Host calls init(api, handle) — we store the pointers, create
 *      a SidebarWidget, and register it as a sidebar tab.
 *   3. User clicks "Open pcap…", selects a .pcap file, plugin parses
 *      it and opens the formatted text in LogSquirl.
 *   4. Host calls shutdown() — we unregister + delete the widget.
 */

#include "plugin.h"
#include "sidebarwidget.h"

#include <exception>

// ── Global state ─────────────────────────────────────────────────────────

namespace tcpdump {
PluginState g_state;

void hostLog( int level, const QString& message )
{
    if ( g_state.api && g_state.handle ) {
        g_state.api->log_message( g_state.handle, level, message.toUtf8().constData() );
    }
}

void hostNotify( const QString& message )
{
    if ( g_state.api && g_state.handle ) {
        g_state.api->show_notification( g_state.handle, message.toUtf8().constData() );
    }
}
} // namespace tcpdump

// ── Plugin metadata ──────────────────────────────────────────────────────

static const LogSquirlPluginInfo kPluginInfo = {
    /* id          */ "io.github.logsquirl.tcpdump",
    /* name        */ "tcpdump / pcap Viewer",
    /* version     */ LOGSQUIRL_PLUGIN_VERSION,
    /* description */ "Parse and display tcpdump/pcap capture files",
    /* author      */ "LogSquirl Contributors",
    /* license     */ "GPL-3.0-or-later",
    /* type        */ LOGSQUIRL_PLUGIN_UI,
    /* api_version */ LOGSQUIRL_PLUGIN_API_VERSION,
};

// ── Internal helpers ─────────────────────────────────────────────────────

/// Log that work for the host failed.
static void logFailure( const char* what, const char* reason ) noexcept
{
    try {
        tcpdump::hostLog( LOGSQUIRL_LOG_ERROR, QStringLiteral( "tcpdump plugin: %1 failed: %2" )
                                                   .arg( what, QString::fromUtf8( reason ) ) );
    } catch ( ... ) {
        // Nothing left to report it with.
    }
}

/// Run work for the host, logging instead of throwing: the host is C, and
/// an exception escaping into it would terminate LogSquirl.
/// Returns false if it threw.
template <typename Work>
static bool guarded( const char* what, Work&& work ) noexcept
{
    try {
        work();
        return true;
    } catch ( const std::exception& e ) {
        logFailure( what, e.what() );
    } catch ( ... ) {
        logFailure( what, "unknown exception" );
    }
    return false;
}

// ── Exported C entry points ──────────────────────────────────────────────

extern "C" {

LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_shutdown( void );

/// Return static plugin metadata.
LOGSQUIRL_PLUGIN_EXPORT const LogSquirlPluginInfo* logsquirl_plugin_get_info( void )
{
    return &kPluginInfo;
}

/// Initialise the plugin — create sidebar tab for pcap viewing.
LOGSQUIRL_PLUGIN_EXPORT int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle )
{
    if ( !api || !handle ) {
        return 1;
    }

    tcpdump::g_state.api = api;
    tcpdump::g_state.handle = handle;
    tcpdump::g_state.initialised = true;

    const bool ok = guarded( "initialisation", [ api, handle ] {
        api->log_message( handle, LOGSQUIRL_LOG_INFO, "tcpdump plugin initialising\xe2\x80\xa6" );

        // Register a sidebar tab for pcap file management
        tcpdump::g_state.sidebarWidget = new tcpdump::SidebarWidget();
        api->register_sidebar_tab( handle, "tcpdump",
                                   static_cast<void*>( tcpdump::g_state.sidebarWidget ) );

        api->log_message( handle, LOGSQUIRL_LOG_INFO, "tcpdump plugin ready." );
    } );

    if ( !ok ) {
        // The tab may not have been registered: just delete the widget.
        delete tcpdump::g_state.sidebarWidget;
        tcpdump::g_state.sidebarWidget = nullptr;
        logsquirl_plugin_shutdown();
        return 1;
    }
    return 0;
}

/// Shut down the plugin — unregister sidebar and release resources.
LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_shutdown( void )
{
    guarded( "shutdown", [] {
        auto& st = tcpdump::g_state;
        tcpdump::hostLog( LOGSQUIRL_LOG_INFO, "tcpdump plugin shutting down\u2026" );

        if ( st.sidebarWidget ) {
            if ( st.api && st.handle ) {
                st.api->unregister_sidebar_tab( st.handle, static_cast<void*>( st.sidebarWidget ) );
            }
            delete st.sidebarWidget;
            st.sidebarWidget = nullptr;
        }
    } );

    tcpdump::g_state.api = nullptr;
    tcpdump::g_state.handle = nullptr;
    tcpdump::g_state.initialised = false;
}

/// Configuration dialog (not implemented yet).
LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_configure( void* /* parent_widget */ )
{
    // No configuration needed for this plugin yet.
}

} // extern "C"
