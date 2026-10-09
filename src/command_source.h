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
 * @file command_source.h
 * @brief The Custom command source: live capture from a command the user
 *        wrote, whose stdout is a pcap or pcapng stream.
 *
 * The command is one line, e.g. `ssh router tcpdump -i {interface} -U -w -
 * {filter}`, split into a program and its arguments like a POSIX shell
 * would split it, without running one (splitCommandLine()): quotes and
 * backslashes group and escape, nothing is expanded, no pipe or redirection
 * is made.  The placeholders {interface}, {filter} and {snaplen} are then
 * replaced inside the arguments, so a value is always part of one argument
 * and never read by a shell; an argument that is {filter} alone is left out
 * when the filter is empty.
 *
 * "Run through the shell" (off by default) hands the line to /bin/sh -c
 * (cmd.exe /c on Windows) as it is, for pipes and redirections: anything
 * in it runs.  The placeholders are then replaced by their values quoted as
 * one word for that shell (shellQuote(); on Windows in double quotes, a
 * value cmd.exe would still read refused).
 *
 * Commands can be saved by name (with whether they run through the shell)
 * and chosen again; the examples (tcpdump here, over adb, over ssh) are
 * offered to start from, never run by themselves.  The saved commands are a
 * per-source option, written to settings.ini as they are saved or deleted.
 */

#pragma once

#include "live_source.h"
#include "local_source.h"

#include <QString>
#include <QStringList>

#include <functional>
#include <vector>

namespace tcpdump {

/// The option holding the command line.
inline const QString kCommandLineOption = QStringLiteral( "command" );
/// The option "run through the shell": "true" or "false" (the default).
inline const QString kCommandShellOption = QStringLiteral( "shell" );
/// The option holding the saved commands (savedCommands()).
inline const QString kCommandSavedOption = QStringLiteral( "saved" );
/// The option naming the saved command the line was taken from, if any.
inline const QString kCommandNameOption = QStringLiteral( "name" );

/// A command line split into words (splitCommandLine()).
struct SplitCommand {
    QStringList words;
    /// Why the line cannot be split (an open quote, a '\' at its end);
    /// empty if it can.
    QString error;
    /// The first unquoted word that a shell would read as a pipe, a list or
    /// a redirection ("|", "&&", ";", ">"); empty if there is none.
    QString shellOperator;
};

/**
 * @p line split into words as a POSIX shell splits it, without running one:
 * words are separated by blanks; '…' quotes everything up to the next ';
 * "…" quotes everything but '\' before '"' or '\'; outside quotes '\'
 * escapes the next character; '' and "" make an empty word.  Nothing is
 * expanded: $VAR, ~, *, `…` and $(…) stay as they are.
 */
SplitCommand splitCommandLine( const QString& line );

/// A command saved by name.
struct SavedCommand {
    QString name;
    QString line;       ///< The command line, placeholders unreplaced.
    bool shell = false; ///< Run through the shell.

    bool operator==( const SavedCommand& other ) const
    {
        return name == other.name && line == other.line && shell == other.shell;
    }
};

/// The saved commands in @p options, in the order they were saved; none if
/// the option is missing or unreadable.
std::vector<SavedCommand> savedCommands( const LiveOptions& options );

/// @p commands as the value of kCommandSavedOption (JSON).
QString savedCommandsOption( const std::vector<SavedCommand>& commands );

/// The examples offered to start from: tcpdump on this computer, on an
/// Android device over adb, on a server over ssh.
std::vector<SavedCommand> commandExamples();

/// The command a choice of the Custom command source runs, or why it cannot.
struct CustomCommand {
    ProcessCommand command;
    QString problem; ///< Empty if the command can run.
};

/// The command for @p choice: its line split (or, with the shell option,
/// as it is), the placeholders replaced by the choice's interface, filter
/// and snaplen.
CustomCommand customCommand( const LiveChoice& choice );

/// Live capture with a command the user wrote.
class CustomCommandSourceKind : public LiveSourceKind {
public:
    /// @param configDir  Where saved commands are written as they are
    ///                   saved (settings.ini); by default the host's.
    /// @param local      Where the interfaces suggested are listed from.
    explicit CustomCommandSourceKind( std::function<QString()> configDir = {},
                                      LocalPrograms local = LocalPrograms::forThisComputer() );

    QString id() const override;
    QString displayName() const override;
    /// This computer's interfaces, as Local lists them: suggestions for
    /// {interface}; any can be typed.
    LiveListing listInterfaces( const QString& device,
                                std::chrono::milliseconds timeout ) const override;
    QString validate( const LiveChoice& choice ) const override;
    LiveOptionsWidget* makeOptionsWidget() const override;
    ProcessCommand command( const LiveChoice& choice ) const override;
    QString explainFailure( const QString& error ) const override;

private:
    std::function<QString()> configDir_;
    LocalPrograms local_;
};

} // namespace tcpdump
