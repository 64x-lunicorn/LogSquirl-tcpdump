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

#include <functional>
#include <stdexcept>

namespace tcpdump_test {

class FakeHost {
public:
    /** A menu entry the plugin registered. */
    struct MenuAction {
        QString label;
        void ( *callback )( void* userData );
        void* userData;

        /** Click the entry. */
        void trigger() const
        {
            callback( userData );
        }
    };

    FakeHost()
        : configDirUtf8_( configDir_.path().toUtf8() )
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
        api_.register_menu_action = []( void* handle, const char*, const char* label,
                                        void ( *callback )( void* ), void* userData ) {
            self( handle )->menuActions.append(
                { QString::fromUtf8( label ), callback, userData } );
        };
        api_.register_sidebar_tab = []( void* handle, const char*, void* widget ) {
            if ( self( handle )->failSidebarTab ) {
                throw std::runtime_error( "no room for another tab" );
            }
            self( handle )->sidebarTabs.append( widget );
        };
        api_.unregister_sidebar_tab
            = []( void* handle, void* widget ) { self( handle )->sidebarTabs.removeAll( widget ); };

        tcpdump::g_state.api = &api_;
        tcpdump::g_state.handle = this;
    }

    ~FakeHost()
    {
        tcpdump::g_state.api = nullptr;
        tcpdump::g_state.handle = nullptr;
        tcpdump::g_state.tempRoot.clear();
    }

    FakeHost( const FakeHost& ) = delete;
    FakeHost& operator=( const FakeHost& ) = delete;

    /** The plugin's config directory (empty until a test writes to it). */
    QString configDir() const
    {
        return configDir_.path();
    }

    QStringList logs;
    QStringList notifications;
    QStringList openedFiles;
    QList<MenuAction> menuActions;
    QList<void*> sidebarTabs; ///< Registered and not yet unregistered.

    /** Make register_sidebar_tab() throw, as a misbehaving host might. */
    bool failSidebarTab = false;

    /** Make log_message() throw for a message containing this text. */
    QString failLogContaining;

    /** The host API table, to pass to logsquirl_plugin_init(). */
    const LogSquirlHostApi* api() const
    {
        return &api_;
    }

private:
    static FakeHost* self( void* handle )
    {
        return static_cast<FakeHost*>( handle );
    }

    QTemporaryDir configDir_;
    QByteArray configDirUtf8_;
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
