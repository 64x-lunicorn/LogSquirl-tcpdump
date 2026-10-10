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
 * @file command_source_test.cpp
 * @brief BDD tests for the Custom command source: the splitting of a command
 *        line without a shell, the placeholders, the shell option, saved
 *        commands, and live capture with fake capture scripts.
 */

#include <catch2/catch.hpp>

#include "command_source.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "settings.h"
#include "sidebarwidget.h"
#include "ssh_source.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QProcess>
#include <QPushButton>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A choice of the Custom command source running @p line.
LiveChoice commandChoice( const QString& line, bool shell = false, const QString& iface = "eth0",
                          const QString& filter = {}, int snaplen = 96 )
{
    LiveChoice choice{ "command", {}, iface, filter, snaplen, {} };
    choice.options[ kCommandLineOption ] = line;
    choice.options[ kCommandShellOption ] = shell ? "true" : "false";
    return choice;
}

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( std::shared_ptr<const LiveSourceKind> kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( std::move( kind ) );
    return registry;
}

} // namespace

SCENARIO( "A command line is split like a shell splits it, without running one",
          "[command_source]" )
{
    THEN( "blanks separate words, quotes and backslashes group and escape" )
    {
        const auto split = splitCommandLine(
            "  tcpdump  -i 'en 0'\t\"a \\\"b\\\" \\\\ \\c\" x\\ y '' \"\" 'it'\\''s'  " );
        REQUIRE( split.error.isEmpty() );
        REQUIRE( split.shellOperator.isEmpty() );
        REQUIRE(
            split.words
            == QStringList{ "tcpdump", "-i", "en 0", "a \"b\" \\ \\c", "x y", "", "", "it's" } );
    }

    THEN( "nothing is expanded" )
    {
        REQUIRE( splitCommandLine( "echo $HOME ~ * `id` $(id) ${PATH}" ).words
                 == QStringList{ "echo", "$HOME", "~", "*", "`id`", "$(id)", "${PATH}" } );
    }

    THEN( "an open quote or a backslash at the end is an error" )
    {
        REQUIRE_FALSE( splitCommandLine( "tcpdump 'host" ).error.isEmpty() );
        REQUIRE_FALSE( splitCommandLine( "tcpdump \"host" ).error.isEmpty() );
        REQUIRE_FALSE( splitCommandLine( "tcpdump host\\" ).error.isEmpty() );
    }

    THEN( "an unquoted pipe, list or redirection is pointed out; a quoted one is a word" )
    {
        REQUIRE( splitCommandLine( "ssh r tcpdump -w - | tee x" ).shellOperator == "|" );
        REQUIRE( splitCommandLine( "a && b" ).shellOperator == "&&" );
        REQUIRE( splitCommandLine( "a > out" ).shellOperator == ">" );
        REQUIRE( splitCommandLine( "a ;" ).shellOperator == ";" );
        REQUIRE( splitCommandLine( "a '|' \\; \">\"" ).shellOperator.isEmpty() );
        REQUIRE( splitCommandLine( "a 'not (port 22)'" ).shellOperator.isEmpty() );
    }
}

SCENARIO( "The placeholders are replaced inside arguments, never split or run", "[command_source]" )
{
    GIVEN( "a command line with each placeholder, alone and inside an argument" )
    {
        const auto line = QStringLiteral( "tcpdump -i {interface} -s{snaplen} -U -w - {filter}" );

        THEN( "each value is part of one argument" )
        {
            const auto built
                = customCommand( commandChoice( line, false, "en0", "tcp port 443", 128 ) );
            REQUIRE( built.problem.isEmpty() );
            REQUIRE_FALSE( built.command.viaShell );
            REQUIRE( built.command.program == "tcpdump" );
            REQUIRE( built.command.arguments
                     == QStringList{ "-i", "en0", "-s128", "-U", "-w", "-", "tcp port 443" } );
        }

        THEN( "an argument that is {filter} alone is left out when the filter is empty" )
        {
            REQUIRE( customCommand( commandChoice( line, false, "en0", "", 128 ) ).command.arguments
                     == QStringList{ "-i", "en0", "-s128", "-U", "-w", "-" } );
        }

        THEN( "hostile values reach the program as they are" )
        {
            const QString iface = "eth0; touch pwned $(id) {snaplen}";
            const QString filter = "host 10.0.0.1 and not port 22 \"$(touch pwned)\" `id` "
                                   "$HOME ' '' ; | & > pwned * ? {interface}";
            const auto built = customCommand( commandChoice( line, false, iface, filter, 64 ) );
            REQUIRE( built.problem.isEmpty() );
            REQUIRE( built.command.arguments
                     == QStringList{ "-i", iface, "-s64", "-U", "-w", "-", filter } );
        }
    }

    THEN( "a command that uses {interface} needs one; a command that does not, none" )
    {
        const CustomCommandSourceKind kind;
        REQUIRE( kind.validate( commandChoice( "tcpdump -i {interface} -w -", false, "" ) )
                     .contains( "{interface}" ) );
        REQUIRE( kind.validate( commandChoice( "cat capture.pcap", false, "" ) ).isEmpty() );
        REQUIRE( kind.validate( commandChoice( "tcpdump -i {interface}", false, "-w/tmp/x" ) )
                     .contains( "'-'" ) );
        REQUIRE( kind.validate( commandChoice( "tcpdump -i {interface}", false, "a\nb" ) )
                     .contains( "one line" ) );
    }

    THEN( "an empty line, an open quote and an unquoted pipe without the shell are problems" )
    {
        const CustomCommandSourceKind kind;
        REQUIRE( kind.validate( commandChoice( "  " ) ).contains( "Enter a command" ) );
        REQUIRE( kind.validate( commandChoice( "tcpdump 'host" ) ).contains( "quote" ) );
        const auto pipe = kind.validate( commandChoice( "ssh r tcpdump -w - | cat" ) );
        REQUIRE( pipe.contains( "Run through the shell" ) );
        REQUIRE( kind.validate( commandChoice( "ssh r tcpdump -w - | cat", true ) ).isEmpty() );
        REQUIRE( kind.validate( commandChoice( "{filter}", false, "eth0", "" ) )
                     .contains( "no program" ) );
    }
}

SCENARIO( "The examples are offered, with the placeholders", "[command_source]" )
{
    const auto examples = commandExamples();
    REQUIRE( examples.size() == 3 );
    for ( const auto& example : examples ) {
        CAPTURE( example.line );
        REQUIRE_FALSE( example.name.isEmpty() );
        REQUIRE_FALSE( example.shell );
        REQUIRE( example.line.contains( "-U -w -" ) );
        REQUIRE( example.line.contains( "{filter" ) );
        REQUIRE( splitCommandLine( example.line ).error.isEmpty() );
    }
    REQUIRE( examples[ 0 ].line == "tcpdump -i {interface} -U -w - {filter}" );
    REQUIRE( examples[ 1 ].line.startsWith( "adb exec-out tcpdump " ) );
    REQUIRE( examples[ 2 ].line.startsWith( "ssh " ) );
    // adb and ssh hand their joined arguments to a remote shell.
    for ( const auto& remote : { examples[ 1 ], examples[ 2 ] } ) {
        CAPTURE( remote.line );
        REQUIRE( remote.line.contains( "{filter:sh}" ) );
        REQUIRE( remote.line.contains( "{interface:sh}" ) );
        REQUIRE_FALSE( remote.line.contains( "{filter}" ) );
    }
}

SCENARIO( "A {…:sh} placeholder is quoted for the remote shell adb or ssh hand it to",
          "[command_source]" )
{
    const QString filter = "host 10.0.0.1 and port 22 ; touch pwned $(id) 'x' \"y\"";
    const QString iface = "wlan0'; reboot; '";

    THEN( "without the local shell, the value is single-quoted inside its argument" )
    {
        const auto built = customCommand( commandChoice(
            "ssh srv tcpdump -i {interface:sh} -w - {filter:sh}", false, iface, filter ) );
        REQUIRE( built.problem.isEmpty() );
        REQUIRE( built.command.arguments
                 == QStringList{ "srv", "tcpdump", "-i", shellQuote( iface ), "-w", "-",
                                 shellQuote( filter ) } );
    }

    THEN( "{filter:sh} alone is left out when the filter is empty" )
    {
        const auto built = customCommand(
            commandChoice( "ssh srv tcpdump -i {interface:sh} -w - {filter:sh}", false, "eth0" ) );
        REQUIRE( built.command.arguments
                 == QStringList{ "srv", "tcpdump", "-i", "'eth0'", "-w", "-" } );
    }

#ifdef Q_OS_UNIX
    THEN( "the remote shell reads each value as one argument, running nothing of it" )
    {
        const auto built = customCommand(
            commandChoice( "x tcpdump -i {interface:sh} -w - {filter:sh}", false, iface, filter ) );
        // What ssh or adb hand the remote shell: the arguments joined.
        const auto remoteLine = built.command.arguments.join( ' ' );
        QProcess shell;
        shell.start( "/bin/sh", { "-c", "tcpdump() { for a; do printf '[%s]\\n' \"$a\"; done; }; "
                                            + remoteLine } );
        REQUIRE( shell.waitForFinished( 10000 ) );
        REQUIRE( QString::fromUtf8( shell.readAllStandardOutput() )
                 == "[-i]\n[" + iface + "]\n[-w]\n[-]\n[" + filter + "]\n" );
    }

    THEN( "through the local shell, it reaches the program quoted for the remote one" )
    {
        const auto built = customCommand(
            commandChoice( "printf '%s\\n' {interface:sh} {filter:sh}", true, iface, filter ) );
        REQUIRE( built.problem.isEmpty() );
        QProcess shell;
        shell.start( "/bin/sh", { "-c", built.command.program } );
        REQUIRE( shell.waitForFinished( 10000 ) );
        REQUIRE( QString::fromUtf8( shell.readAllStandardOutput() )
                 == shellQuote( iface ) + "\n" + shellQuote( filter ) + "\n" );
    }
#endif
}

SCENARIO( "Saved commands are kept as an option", "[command_source]" )
{
    const std::vector<SavedCommand> commands{
        { "router", "ssh router tcpdump -i {interface} -U -w - {filter}", false },
        { "pipe \"quoted\", with = and / in it", "cat a.pcap | cat", true }
    };
    LiveOptions options;
    options[ kCommandSavedOption ] = savedCommandsOption( commands );
    REQUIRE( savedCommands( options ) == commands );
    REQUIRE( savedCommands( {} ).empty() );
    REQUIRE( savedCommands( { { kCommandSavedOption, "not json" } } ).empty() );

    THEN( "settings.ini keeps them as they are" )
    {
        QTemporaryDir configDir;
        REQUIRE( saveLiveOption( configDir.path(), "command", kCommandSavedOption,
                                 options[ kCommandSavedOption ] ) );
        REQUIRE( savedCommands( loadLiveOptions( configDir.path(), "command" ) ) == commands );
    }
}

SCENARIO( "Commands are saved, edited and deleted in the source's options", "[command_source]" )
{
    QTemporaryDir configDir;
    const auto dir = configDir.path();
    const auto kind = std::make_shared<CustomCommandSourceKind>( [ dir ] { return dir; } );
    std::unique_ptr<LiveOptionsWidget> widget( kind->makeOptionsWidget() );
    REQUIRE( widget );
    widget->setOptions( {} );
    auto* saved = widget->findChild<QComboBox*>( "commandSaved" );
    auto* line = widget->findChild<QLineEdit*>( "commandLine" );
    auto* shell = widget->findChild<QCheckBox*>( "commandShell" );
    auto* warning = widget->findChild<QLabel*>( "commandShellWarning" );
    auto* name = widget->findChild<QLineEdit*>( "commandName" );
    auto* save = widget->findChild<QPushButton*>( "commandSave" );
    auto* remove = widget->findChild<QPushButton*>( "commandDelete" );
    REQUIRE( saved );
    REQUIRE( line );
    REQUIRE( shell );
    REQUIRE( warning );
    REQUIRE( name );
    REQUIRE( save );
    REQUIRE( remove );

    THEN( "the shell is off by default, and its warning shows only when it is on" )
    {
        REQUIRE_FALSE( shell->isChecked() );
        REQUIRE( warning->isHidden() );
        shell->setChecked( true );
        REQUIRE_FALSE( warning->isHidden() );
        REQUIRE( widget->options().value( kCommandShellOption ) == "true" );
    }

    THEN( "an example fills the line, and runs nothing" )
    {
        const auto example = saved->findText( commandExamples()[ 1 ].name, Qt::MatchContains );
        REQUIRE( example >= 0 );
        saved->setCurrentIndex( example );
        emit saved->activated( example );
        REQUIRE( line->text() == commandExamples()[ 1 ].line );
        REQUIRE( savedCommands( loadLiveOptions( dir, "command" ) ).empty() );
    }

    WHEN( "a command is saved by name" )
    {
        line->setText( "ssh router tcpdump -i {interface} -U -w - {filter}" );
        name->setText( "router" );
        save->click();

        THEN( "settings.ini has it at once, and it can be chosen" )
        {
            const auto stored = savedCommands( loadLiveOptions( dir, "command" ) );
            REQUIRE( stored.size() == 1 );
            REQUIRE( stored[ 0 ]
                     == SavedCommand{
                         "router", "ssh router tcpdump -i {interface} -U -w - {filter}", false } );
            REQUIRE( savedCommands( widget->options() ) == stored );
            REQUIRE( saved->findText( "router" ) >= 0 );
            REQUIRE( remove->isEnabled() );
        }

        AND_WHEN( "another line is chosen, then the saved one again" )
        {
            line->setText( "something else" );
            const auto index = saved->findText( "router" );
            saved->setCurrentIndex( index );
            emit saved->activated( index );

            THEN( "the saved line is back" )
            {
                REQUIRE( line->text() == "ssh router tcpdump -i {interface} -U -w - {filter}" );
                REQUIRE( name->text() == "router" );
            }
        }

        AND_WHEN( "it is edited and saved under its name" )
        {
            line->setText( "ssh -p 2222 router tcpdump -U -w - {filter}" );
            shell->setChecked( true );
            save->click();

            THEN( "it is replaced, not added" )
            {
                const auto stored = savedCommands( loadLiveOptions( dir, "command" ) );
                REQUIRE( stored.size() == 1 );
                REQUIRE( stored[ 0 ].line == "ssh -p 2222 router tcpdump -U -w - {filter}" );
                REQUIRE( stored[ 0 ].shell );
            }
        }

        AND_WHEN( "another widget of the source is open, as the dialog's is" )
        {
            std::unique_ptr<LiveOptionsWidget> other( kind->makeOptionsWidget() );
            other->setOptions( {} );
            REQUIRE( other->findChild<QComboBox*>( "commandSaved" )->findText( "router" ) >= 0 );

            AND_WHEN( "it deletes the command" )
            {
                other->findChild<QLineEdit*>( "commandName" )->setText( "router" );
                other->findChild<QPushButton*>( "commandDelete" )->click();

                THEN( "it is gone from settings.ini and from both" )
                {
                    REQUIRE( savedCommands( loadLiveOptions( dir, "command" ) ).empty() );
                    REQUIRE( saved->findText( "router" ) < 0 );
                    REQUIRE( savedCommands( widget->options() ).empty() );
                    REQUIRE( savedCommands( other->options() ).empty() );
                }
            }
        }
    }

    THEN( "a nameless command cannot be saved" )
    {
        line->setText( "tcpdump -w -" );
        name->setText( "  " );
        REQUIRE_FALSE( save->isEnabled() );
    }
}

#ifdef Q_OS_UNIX

#include "pcapbuilder.h"
#include "stream_capture.h"

namespace {

/// A fake capture script @p name in @p dir running @p body.
QString fakeScript( const QTemporaryDir& dir, const QString& name, const QString& body )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( ( "#!/bin/sh\n" + body + "\n" ).toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
    return path;
}

/// Run @p choice in a sidebar until it ends; the sidebar for its labels.
struct Captured {
    FakeHost host;
    QTemporaryDir temp;
    SidebarWidget sidebar;

    explicit Captured( const LiveChoice& choice )
    {
        sidebar.setTempRoot( temp.path() );
        sidebar.setLiveSources( registryOf( std::make_shared<CustomCommandSourceKind>() ) );
        REQUIRE( sidebar.startLiveCapture( choice ) );
        REQUIRE( waitFor( [ this ] { return !sidebar.isCapturing(); } ) );
    }

    QString stderrText() const
    {
        return sidebar.findChild<QPlainTextEdit*>( "liveStderr" )->toPlainText();
    }
    QLabel* error() const
    {
        return sidebar.findChild<QLabel*>( "liveError" );
    }
};

} // namespace

SCENARIO( "A custom command's capture converts live", "[command_source]" )
{
    QTemporaryDir dir;
    const auto capture = pcapOf( somePackets() );
    const auto pcapPath = dir.filePath( "fake.pcap" );
    writeFile( pcapPath, capture );
    // Prints each argument in brackets on stderr, then the capture, after a
    // line of text a capture program may print first.
    const auto script = fakeScript( dir, "fake-capture",
                                    "for a in \"$@\"; do printf '[%s]\\n' \"$a\" >&2; done\n"
                                    "echo 'listening' \n"
                                    "cat \"$CAPTURE\"" );
    qputenv( "CAPTURE", pcapPath.toUtf8() );
    const auto pwned = dir.filePath( "pwned" );
    const QString filter = "host 10.0.0.1 \"$(touch " + pwned + ")\" `touch " + pwned
                           + "` ' '' ; | & > " + pwned + " {snaplen}";
    const QString iface = "eth0'; touch " + pwned + "; echo '";

    GIVEN( "the command as an argument list" )
    {
        Captured run( commandChoice( shellQuote( script ) + " -i {interface} -s {snaplen} {filter}",
                                     false, iface, filter, 77 ) );

        THEN( "the capture is opened, and each value was one argument" )
        {
            REQUIRE( run.host.openedFiles.size() == 1 );
            REQUIRE( run.error()->isHidden() );
            const auto text = run.stderrText();
            REQUIRE( text.contains( "[-i]\n[" + iface + "]\n[-s]\n[77]\n[" + filter + "]" ) );
            REQUIRE_FALSE( QFileInfo::exists( pwned ) );
        }
    }

    GIVEN( "the command run through the shell, with a pipe" )
    {
        Captured run(
            commandChoice( shellQuote( script ) + " -i {interface} -s {snaplen} {filter} | cat",
                           true, iface, filter, 77 ) );

        THEN( "the shell runs the pipe, and the values are quoted for it" )
        {
            REQUIRE( run.host.openedFiles.size() == 1 );
            REQUIRE( run.error()->isHidden() );
            REQUIRE( run.stderrText().contains( "[-i]\n[" + iface + "]\n[-s]\n[77]\n[" + filter
                                                + "]" ) );
            REQUIRE_FALSE( QFileInfo::exists( pwned ) );
        }
    }

    qunsetenv( "CAPTURE" );
}

SCENARIO( "A custom command whose stdout is not a capture says so, with its stderr",
          "[command_source]" )
{
    QTemporaryDir dir;
    const auto script = fakeScript( dir, "not-pcap",
                                    "echo 'not-pcap: writing text, use -w -' >&2\n"
                                    "echo 'Hello, world'" );
    Captured run( commandChoice( shellQuote( script ) ) );

    THEN( "the capture fails as not a capture, with the stderr lines and what to do" )
    {
        REQUIRE( run.host.openedFiles.isEmpty() );
        const auto error = run.error()->text();
        REQUIRE_FALSE( run.error()->isHidden() );
        REQUIRE( error.contains( "Not a capture" ) );
        REQUIRE( error.contains( "not-pcap: writing text, use -w -" ) );
        REQUIRE( error.contains( "pcap or pcapng" ) );
        REQUIRE( run.stderrText().contains( "not-pcap: writing text, use -w -" ) );
    }
}

SCENARIO( "A custom command that cannot be started says what to check", "[command_source]" )
{
    QTemporaryDir dir;
    Captured run( commandChoice( shellQuote( dir.filePath( "no-such-program" ) ) + " -w -" ) );
    const auto error = run.error()->text();
    REQUIRE( error.contains( "Cannot start no-such-program" ) );
    REQUIRE( error.contains( "full path" ) );
}

#endif
