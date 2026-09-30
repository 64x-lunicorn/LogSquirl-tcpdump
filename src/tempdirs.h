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
 * @file tempdirs.h
 * @brief The plugin's temporary directories, named after the process.
 *
 * Each conversion writes into a directory "logsquirl-tcpdump-<pid>-XXXXXX"
 * in the temporary root.  The process ID in the name lets a plugin instance
 * find the directories of earlier instances in the same LogSquirl process
 * (after the plugin was disabled, updated and enabled again), and those of
 * LogSquirl processes that ended without removing theirs.
 */

#pragma once

#include <QString>

namespace tcpdump {

/// The directory the temporary directories are created in.
QString tempRoot();

/// The QTemporaryDir template for a new temporary directory of this process.
QString tempDirTemplate( const QString& root );

/// Whether a process with this ID runs (or may run: when in doubt, true).
bool isProcessRunning( qint64 pid );

/// Remove every temporary directory of this process below @p root.
void removeOwnTempDirs( const QString& root );

/// Remove the temporary directories below @p root of processes that no
/// longer run.  Those of running processes, this one included, are kept.
void removeStaleTempDirs( const QString& root );

} // namespace tcpdump
