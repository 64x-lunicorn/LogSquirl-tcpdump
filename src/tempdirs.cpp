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
 * @file tempdirs.cpp
 * @brief Implementation of the temporary directory bookkeeping.
 */

#include "tempdirs.h"

#include "plugin.h"

#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>
#include <QRegularExpression>

#include <functional>

#ifdef Q_OS_WIN
#include <windows.h>
#else
#include <cerrno>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace tcpdump {

namespace {

const QString kPrefix = QStringLiteral( "logsquirl-tcpdump-" );

/// Remove the directories below @p root that are ours and whose process ID
/// @p shouldRemove accepts.
void removeTempDirs( const QString& root, const std::function<bool( qint64 )>& shouldRemove )
{
    static const QRegularExpression pattern(
        QStringLiteral( "^logsquirl-tcpdump-(\\d{1,10})-[A-Za-z0-9]{6}$" ) );
    const auto entries = QDir( root ).entryInfoList(
        { kPrefix + "*" }, QDir::Dirs | QDir::NoDotAndDotDot | QDir::Hidden | QDir::System );
    for ( const auto& entry : entries ) {
        const auto match = pattern.match( entry.fileName() );
        // Never follow a link, and on Unix leave other users' directories
        // in a shared temporary directory alone.
        if ( !match.hasMatch() || entry.isSymLink() ) {
            continue;
        }
#ifdef Q_OS_UNIX
        if ( entry.ownerId() != ::getuid() ) {
            continue;
        }
#endif
        bool ok = false;
        const auto pid = match.captured( 1 ).toLongLong( &ok );
        if ( ok && shouldRemove( pid ) ) {
            QDir( entry.absoluteFilePath() ).removeRecursively();
        }
    }
}

} // namespace

QString tempRoot()
{
    return g_state.tempRoot.isEmpty() ? QDir::tempPath() : g_state.tempRoot;
}

QString tempDirTemplate( const QString& root )
{
    return QStringLiteral( "%1/%2%3-XXXXXX" )
        .arg( root, kPrefix )
        .arg( QCoreApplication::applicationPid() );
}

bool isProcessRunning( qint64 pid )
{
    if ( pid <= 0 ) {
        return true; // not a process ID we wrote: do not touch
    }
#ifdef Q_OS_WIN
    if ( pid > 0xFFFFFFFFll ) {
        return false;
    }
    HANDLE process
        = ::OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>( pid ) );
    if ( !process ) {
        // No such process, or one we may not look at (which runs).
        return ::GetLastError() != ERROR_INVALID_PARAMETER;
    }
    DWORD exitCode = 0;
    const bool running = !::GetExitCodeProcess( process, &exitCode ) || exitCode == STILL_ACTIVE;
    ::CloseHandle( process );
    return running;
#else
    if ( pid > 0x7FFFFFFFll ) {
        return false;
    }
    // Signal 0 only checks: ESRCH means no such process, EPERM one of
    // another user.
    return ::kill( static_cast<pid_t>( pid ), 0 ) == 0 || errno != ESRCH;
#endif
}

void removeOwnTempDirs( const QString& root )
{
    const auto self = QCoreApplication::applicationPid();
    removeTempDirs( root, [ self ]( qint64 pid ) { return pid == self; } );
}

void removeStaleTempDirs( const QString& root )
{
    const auto self = QCoreApplication::applicationPid();
    removeTempDirs( root,
                    [ self ]( qint64 pid ) { return pid != self && !isProcessRunning( pid ); } );
}

} // namespace tcpdump
