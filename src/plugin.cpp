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
 * Implements the five exported symbols:
 *
 *   - logsquirl_plugin_get_info()   → static metadata
 *   - logsquirl_plugin_init_ex()    → store host API and what it offers,
 *                                     create sidebar tab
 *   - logsquirl_plugin_init()       → init_ex() with the base table size
 *   - logsquirl_plugin_shutdown()   → tear down widget, clear state
 *   - logsquirl_plugin_configure()  → the configuration dialog
 *
 * PLUGIN LIFECYCLE
 * ────────────────
 *   1. Host calls get_info() to read metadata.
 *   2. Host calls init_ex(api, handle, api_size) — or init(api, handle)
 *      if it is older than LogSquirl 26.11 — we store the pointers and
 *      the host capabilities the size tells, create a SidebarWidget,
 *      register it as a sidebar tab, add Plugins > tcpdump >
 *      Open pcap… to the menu (and Follow stream, on a host with the
 *      Regex Lab and the selected lines; Packet details on a host with the
 *      selected lines), and register for the host's active-file
 *      notifications, so the sidebar shows the summary and the Packet Panel
 *      the packets of the tab in front.
 *   3. User clicks "Open pcap…" in the sidebar or the menu, selects a
 *      .pcap file, plugin parses it and opens the formatted text in
 *      LogSquirl.
 *   Plugins > Plugin Management > Configure… calls configure(), which
 *   shows the options and saves them in the plugin's configuration
 *   directory; the next conversion reads them.
 *   4. Host calls shutdown() — we unregister + delete the widget; the
 *      host removes the menu entry when it unloads the plugin.
 */

#include "plugin.h"
#include "configdialog.h"
#include "follow_stream.h"
#include "settings.h"
#include "sidebarwidget.h"
#include "tempdirs.h"

#include <QCoreApplication>
#include <QDir>

#include <exception>

// ── Global state ─────────────────────────────────────────────────────────

namespace tcpdump {
PluginState g_state;

HostCapabilities HostCapabilities::of( std::size_t apiSize )
{
    HostCapabilities caps;
    caps.regexLab = LOGSQUIRL_HOST_API_HAS( apiSize, open_regex_lab );
    caps.goToLogLine = LOGSQUIRL_HOST_API_HAS( apiSize, go_to_log_line );
    caps.selectedLogLines = LOGSQUIRL_HOST_API_HAS( apiSize, get_selected_log_lines );
    return caps;
}

void hostLog( int level, const QString& message )
{
    if ( g_state.api && g_state.handle ) {
        g_state.api->log_message( g_state.handle, level, message.toUtf8().constData() );
    }
}

QString hostConfigDir()
{
    if ( g_state.api && g_state.handle && g_state.api->get_config_dir ) {
        if ( const char* dir = g_state.api->get_config_dir( g_state.handle ) ) {
            return QString::fromUtf8( dir );
        }
    }
    return {};
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

/// Plugins > tcpdump > Open pcap…: the same as the sidebar's Open button.
static void openFromMenu( void* /* user_data */ )
{
    guarded( "opening a capture from the menu", [] {
        // The host removes the entry only after shutdown(), and a failed
        // init leaves no widget.
        if ( auto* sidebar = tcpdump::g_state.sidebarWidget ) {
            sidebar->chooseAndOpen();
        }
    } );
}

/// Plugins > tcpdump > Follow stream: the same as the sidebar's button.
static void followStreamFromMenu( void* /* user_data */ )
{
    guarded( "following a stream from the menu", [] { tcpdump::followSelectedStream(); } );
}

/// Plugins > tcpdump > Packet details: the selected line's packet in the panel.
static void packetDetailsFromMenu( void* /* user_data */ )
{
    guarded( "showing the packet details", [] {
        if ( auto* sidebar = tcpdump::g_state.sidebarWidget ) {
            sidebar->showPacketDetails();
        }
    } );
}

/// The host brought another tab to the front: show its capture's summary.
static void onActiveFileChanged( void* /* user_data */, const char* filePath )
{
    guarded( "showing the summary of the tab in front", [ filePath ] {
        // A failed init leaves no widget, and the host keeps the callback.
        if ( auto* sidebar = tcpdump::g_state.sidebarWidget ) {
            sidebar->showSummaryFor( QString::fromUtf8( filePath ? filePath : "" ) );
        }
    } );
}

// ── Exported C entry points ──────────────────────────────────────────────

extern "C" {

LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_shutdown( void );

/// Return static plugin metadata.
LOGSQUIRL_PLUGIN_EXPORT const LogSquirlPluginInfo* logsquirl_plugin_get_info( void )
{
    return &kPluginInfo;
}

/// Initialise the plugin — create sidebar tab for pcap viewing.  A host of
/// LogSquirl 26.11 or later calls this one, with the size of its table.
LOGSQUIRL_PLUGIN_EXPORT int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                                      size_t api_size )
{
    if ( !api || !handle ) {
        return 1;
    }

    tcpdump::g_state.api = api;
    tcpdump::g_state.handle = handle;
    tcpdump::g_state.hostCapabilities = tcpdump::HostCapabilities::of( api_size );
    tcpdump::g_state.initialised = true;
    tcpdump::g_state.quitting = false;

    const bool ok = guarded( "initialisation", [ api, handle ] {
        api->log_message( handle, LOGSQUIRL_LOG_INFO, "tcpdump plugin initialising\xe2\x80\xa6" );

        // Files of LogSquirl processes that ended without removing them,
        // e.g. after a crash: no tab can show them any more.
        tcpdump::removeStaleTempDirs( tcpdump::tempRoot() );

        // Register a sidebar tab for pcap file management
        tcpdump::g_state.sidebarWidget = new tcpdump::SidebarWidget();
        api->register_sidebar_tab( handle, "tcpdump",
                                   static_cast<void*>( tcpdump::g_state.sidebarWidget ) );
        tcpdump::g_state.sidebarTabRegistered = true;

        // Also in the Plugins menu, and so in the Command Palette.  There is
        // no call to remove it: the host does when it unloads the plugin.
        api->register_menu_action( handle, "tcpdump", "Open pcap\xe2\x80\xa6", &openFromMenu,
                                   nullptr );
        // The Packet Panel reads the selected line: only a host that tells
        // it gets the entry.
        if ( tcpdump::g_state.hostCapabilities.selectedLogLines ) {
            api->register_menu_action( handle, "tcpdump", "Packet details", &packetDetailsFromMenu,
                                       nullptr );
        }
        // Only a host that has the Regex Lab and tells the selected lines
        // can follow a stream.
        if ( tcpdump::g_state.hostCapabilities.regexLab
             && tcpdump::g_state.hostCapabilities.selectedLogLines ) {
            api->register_menu_action( handle, "tcpdump", "Follow stream", &followStreamFromMenu,
                                       nullptr );
        }

        // The summary follows the tab in front.  There is no call to remove
        // the callback either: the host drops it with the plugin.
        api->register_active_file_callback( handle, &onActiveFileChanged, nullptr );

        // The host shuts the plugin down both when LogSquirl quits (after
        // aboutToQuit) and when the plugin is disabled or updated at runtime,
        // with the tabs left open; only in the first case may the temporary
        // files go.  The widget as context ends the connection with it,
        // before the library is unloaded.
        if ( auto* app = QCoreApplication::instance() ) {
            QObject::connect( app, &QCoreApplication::aboutToQuit, tcpdump::g_state.sidebarWidget,
                              [] { tcpdump::g_state.quitting = true; } );
        }

        api->log_message( handle, LOGSQUIRL_LOG_INFO, "tcpdump plugin ready." );
    } );

    if ( !ok ) {
        // Undo what was set up, in reverse: shutdown() unregisters the tab
        // only if the host took it, then deletes the widget.
        logsquirl_plugin_shutdown();
        return 1;
    }
    return 0;
}

/// Initialise the plugin for a host older than init_ex(): its table has no
/// function added later.  The host refuses a plugin without this entry point.
LOGSQUIRL_PLUGIN_EXPORT int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle )
{
    return logsquirl_plugin_init_ex( api, handle, LOGSQUIRL_HOST_API_BASE_SIZE );
}

/// Shut down the plugin — unregister sidebar and release resources.
LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_shutdown( void )
{
    auto& st = tcpdump::g_state;
    // Each step on its own, so that one failing does not skip the others.
    guarded( "shutdown", [] {
        tcpdump::hostLog( LOGSQUIRL_LOG_INFO, "tcpdump plugin shutting down\xe2\x80\xa6" );
    } );

    // The host must let go of the tab before its widget is deleted.
    if ( st.sidebarTabRegistered ) {
        st.sidebarTabRegistered = false;
        guarded( "unregistering the sidebar tab", [] {
            auto& st = tcpdump::g_state;
            if ( st.api && st.handle ) {
                st.api->unregister_sidebar_tab( st.handle, static_cast<void*>( st.sidebarWidget ) );
            }
        } );
    }
    if ( st.sidebarWidget ) {
        // Deleting it stops a running conversion and waits for it.
        guarded( "shutdown", [] { delete tcpdump::g_state.sidebarWidget; } );
        st.sidebarWidget = nullptr;
    }

    // The tabs close with LogSquirl: remove the files of every instance of
    // the plugin in this process, also those of instances before a runtime
    // disable or update, which only the directory names remember.
    if ( st.quitting ) {
        guarded( "removing temporary files",
                 [] { tcpdump::removeOwnTempDirs( tcpdump::tempRoot() ); } );
    }

    tcpdump::g_state.api = nullptr;
    tcpdump::g_state.handle = nullptr;
    tcpdump::g_state.hostCapabilities = {};
    tcpdump::g_state.initialised = false;
}

/// Configuration dialog: shows the conversion options saved in the plugin's
/// configuration directory, and saves them there when accepted.
LOGSQUIRL_PLUGIN_EXPORT void logsquirl_plugin_configure( void* parent_widget )
{
    guarded( "configuring", [ parent_widget ] {
        const auto configDir = tcpdump::hostConfigDir();
        tcpdump::ConfigDialog dialog( tcpdump::loadConversionOptions( configDir ),
                                      static_cast<QWidget*>( parent_widget ) );
        if ( dialog.exec() != QDialog::Accepted ) {
            return;
        }
        if ( !tcpdump::saveConversionOptions( configDir, dialog.options() ) ) {
            const auto message
                = QStringLiteral( "The tcpdump options could not be saved in %1" )
                      .arg( QDir::toNativeSeparators( tcpdump::settingsFilePath( configDir ) ) );
            tcpdump::hostLog( LOGSQUIRL_LOG_ERROR, message );
            tcpdump::hostNotify( message );
        }
    } );
}

} // extern "C"
