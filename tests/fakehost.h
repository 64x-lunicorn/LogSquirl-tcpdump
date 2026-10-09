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
 * @file fakehost.h
 * @brief In-process stand-in for the LogSquirl host API, for tests.
 *
 * A FakeHost installs itself into g_state for its lifetime: the plugin
 * gets a private, empty config directory (so tests never read or write
 * real settings), and every log message, notification, open_file()
 * request and menu entry is recorded for the test to inspect.
 *
 * It presents itself as a host of LogSquirl 26.11 or later, whose table holds
 * the Regex Lab, Go to line and the selected Log Lines, or, constructed with
 * LOGSQUIRL_HOST_API_BASE_SIZE, as an older host whose table ends before
 * them: their pointers are then null, so a plugin that calls one crashes the
 * test.
 */

#pragma once

#include "plugin.h"

#include <catch2/catch.hpp>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QList>
#include <QStringList>
#include <QTemporaryDir>
#include <QThread>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>

extern "C" void logsquirl_plugin_shutdown( void );

namespace tcpdump_test {

class FakeHost {
public:
    /** A menu entry the plugin registered. */
    struct MenuAction {
        QString menuPath;
        QString label;
        void ( *callback )( void* userData );
        void* userData;

        /** Click the entry. */
        void trigger() const
        {
            callback( userData );
        }
    };

    /** A Regex Lab the plugin opened. */
    struct RegexLab {
        QString pattern;
        int flags;
        LogSquirlRegexLabCallbackFn callback;
        void* userData;

        /** The user applies @p appliedPattern. */
        void apply( const QString& appliedPattern, int appliedFlags = 0 ) const
        {
            callback( userData, LOGSQUIRL_REGEX_LAB_APPLIED, appliedPattern.toUtf8().constData(),
                      appliedFlags );
        }

        /** The user cancels the Lab. */
        void cancel() const
        {
            callback( userData, LOGSQUIRL_REGEX_LAB_CANCELLED, nullptr, 0 );
        }
    };

    /**
     * A host whose table is @p apiSize bytes long: the whole table by
     * default, LOGSQUIRL_HOST_API_BASE_SIZE for a host older than 26.11.
     */
    explicit FakeHost( std::size_t apiSize = sizeof( LogSquirlHostApi ) )
        : configDirUtf8_( configDir_.path().toUtf8() )
        , apiSize_( apiSize )
    {
        api_.api_version = LOGSQUIRL_PLUGIN_API_VERSION;
        api_.log_message = []( void* handle, int, const char* message ) {
            auto* host = self( handle );
            const auto text = QString::fromUtf8( message );
            if ( !host->failLogContaining.isEmpty() && text.contains( host->failLogContaining ) ) {
                throw std::runtime_error( "cannot log that" );
            }
            host->logs << text;
        };
        api_.get_config_dir
            = []( void* handle ) { return self( handle )->configDirUtf8_.constData(); };
        api_.show_notification = []( void* handle, const char* message ) {
            self( handle )->notifications << QString::fromUtf8( message );
        };
        api_.open_file = []( void* handle, const char* filePath, int ) {
            self( handle )->openedFiles << QString::fromUtf8( filePath );
        };
        api_.register_menu_action = []( void* handle, const char* menuPath, const char* label,
                                        void ( *callback )( void* ), void* userData ) {
            self( handle )->menuActions.append(
                { QString::fromUtf8( menuPath ), QString::fromUtf8( label ), callback, userData } );
        };
        api_.register_sidebar_tab = []( void* handle, const char*, void* widget ) {
            if ( self( handle )->failSidebarTab ) {
                throw std::runtime_error( "no room for another tab" );
            }
            self( handle )->sidebarTabs.append( widget );
        };
        api_.unregister_sidebar_tab
            = []( void* handle, void* widget ) { self( handle )->sidebarTabs.removeAll( widget ); };

        // Added later: only a table long enough holds them.
        if ( LOGSQUIRL_HOST_API_HAS( apiSize_, open_regex_lab ) ) {
            api_.open_regex_lab = []( void* handle, const char* pattern, int flags,
                                      LogSquirlRegexLabCallbackFn callback, void* userData ) {
                if ( !callback ) {
                    return 1;
                }
                self( handle )->regexLabs.append(
                    { QString::fromUtf8( pattern ), flags, callback, userData } );
                return 0;
            };
        }
        if ( LOGSQUIRL_HOST_API_HAS( apiSize_, go_to_log_line ) ) {
            api_.go_to_log_line = []( void* handle, std::uint64_t lineNumber ) {
                if ( lineNumber == 0 ) {
                    return static_cast<int>( LOGSQUIRL_LOG_LINES_OUT_OF_RANGE );
                }
                self( handle )->wentToLines.append( lineNumber );
                return static_cast<int>( LOGSQUIRL_LOG_LINES_OK );
            };
        }
        if ( LOGSQUIRL_HOST_API_HAS( apiSize_, get_selected_log_lines ) ) {
            api_.get_selected_log_lines = []( void* handle, const char** text, std::size_t* length,
                                              std::size_t* lineCount ) {
                auto* host = self( handle );
                if ( !text ) {
                    return static_cast<int>( LOGSQUIRL_LOG_LINES_INVALID_ARGUMENT );
                }
                *text = nullptr;
                if ( length ) {
                    *length = 0;
                }
                if ( lineCount ) {
                    *lineCount = 0;
                }
                if ( host->selectionResult < 0 ) {
                    return host->selectionResult;
                }
                if ( host->selectedLines.isEmpty() ) {
                    return static_cast<int>( LOGSQUIRL_LOG_LINES_NO_SELECTION );
                }
                host->selectedUtf8_ = host->selectedLines.join( '\n' ).toUtf8();
                *text = host->selectedUtf8_.constData();
                if ( length ) {
                    *length = static_cast<std::size_t>( host->selectedUtf8_.size() );
                }
                if ( lineCount ) {
                    *lineCount = static_cast<std::size_t>( host->selectedLines.size() );
                }
                return host->selectionResult;
            };
        }

        tcpdump::g_state.api = &api_;
        tcpdump::g_state.handle = this;
        tcpdump::g_state.hostCapabilities = tcpdump::HostCapabilities::of( apiSize_ );
    }

    ~FakeHost()
    {
        tcpdump::g_state.api = nullptr;
        tcpdump::g_state.handle = nullptr;
        tcpdump::g_state.hostCapabilities = {};
        tcpdump::g_state.tempRoot.clear();
    }

    FakeHost( const FakeHost& ) = delete;
    FakeHost& operator=( const FakeHost& ) = delete;

    /**
     * Shut the plugin down and unload it, as LogSquirl does: there is no
     * call to unregister a menu entry, the host removes the plugin's entries
     * itself once it is shut down.
     */
    void unloadPlugin()
    {
        logsquirl_plugin_shutdown();
        menuActions.clear();
    }

    /** The plugin's config directory (empty until a test writes to it). */
    QString configDir() const
    {
        return configDir_.path();
    }

    QStringList logs;
    QStringList notifications;
    QStringList openedFiles;
    QList<MenuAction> menuActions; ///< Registered, until the plugin is unloaded.
    QList<void*> sidebarTabs;      ///< Registered and not yet unregistered.

    /** Make register_sidebar_tab() throw, as a misbehaving host might. */
    bool failSidebarTab = false;

    /** Make log_message() throw for a message containing this text. */
    QString failLogContaining;

    QList<RegexLab> regexLabs;        ///< Opened through open_regex_lab(), in order.
    QList<std::uint64_t> wentToLines; ///< Line numbers passed to go_to_log_line().
    QStringList selectedLines;        ///< What get_selected_log_lines() returns.
    /** get_selected_log_lines()'s result when lines are selected, or a negative one to fail. */
    int selectionResult = LOGSQUIRL_LOG_LINES_OK;

    /** The host API table, to pass to logsquirl_plugin_init() or _init_ex(). */
    const LogSquirlHostApi* api() const
    {
        return &api_;
    }

    /** The size of the table, to pass to logsquirl_plugin_init_ex(). */
    std::size_t apiSize() const
    {
        return apiSize_;
    }

private:
    static FakeHost* self( void* handle )
    {
        return static_cast<FakeHost*>( handle );
    }

    QTemporaryDir configDir_;
    QByteArray configDirUtf8_;
    QByteArray selectedUtf8_; ///< The text get_selected_log_lines() last returned.
    std::size_t apiSize_;
    LogSquirlHostApi api_{};
};

/**
 * Run the event loop until @p condition holds.  The deadline only guards
 * against a hang: a correct run meets the condition long before it, even on
 * a slow CI runner, so no test depends on how fast the machine is.
 */
inline bool waitFor( const std::function<bool()>& condition, int hangGuardMs = 120000 )
{
    QElapsedTimer timer;
    timer.start();
    while ( !condition() ) {
        if ( timer.elapsed() > hangGuardMs ) {
            return false;
        }
        QCoreApplication::processEvents( QEventLoop::AllEvents, 50 );
        QThread::msleep( 1 );
    }
    return true;
}

} // namespace tcpdump_test

// Let Catch print Qt strings in failure messages.
namespace Catch {
template <>
struct StringMaker<QString> {
    static std::string convert( const QString& value )
    {
        return '"' + value.toStdString() + '"';
    }
};

template <>
struct StringMaker<QByteArray> {
    static std::string convert( const QByteArray& value )
    {
        return '"' + value.toStdString() + '"';
    }
};
} // namespace Catch
