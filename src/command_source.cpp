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
 * @file command_source.cpp
 * @brief The Custom command source: splitting a command line without a
 *        shell, the placeholders, the saved commands and their widget.
 */

#include "command_source.h"

#include "live_capture_form.h"
#include "plugin.h"
#include "settings.h"
#include "ssh_source.h"

#include <QCheckBox>
#include <QComboBox>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

#include <algorithm>
#include <optional>

namespace tcpdump {

namespace {

const QString kSourceId = QStringLiteral( "command" );

const QString kInterfacePlaceholder = QStringLiteral( "{interface}" );
const QString kFilterPlaceholder = QStringLiteral( "{filter}" );

/// The characters by which a shell would make a pipe, a list or a redirection.
const QString kShellOperators = QStringLiteral( "|&;<>" );

/// Whether @p text holds a control character other than a tab.
bool hasControl( const QString& text )
{
    return hasControlCharacter( text, true );
}

bool shellOn( const LiveOptions& options )
{
    return liveOptionOn( options, kCommandShellOption, false );
}

/// The placeholders, {name} or {name:sh}.
const QRegularExpression& placeholderPattern()
{
    static const QRegularExpression placeholder(
        QStringLiteral( "\\{(interface|filter|snaplen)(:sh)?\\}" ) );
    return placeholder;
}

/// Whether @p word is the filter's placeholder alone, left out when the
/// filter is empty.
bool isFilterAlone( const QString& word )
{
    return word == kFilterPlaceholder || word == kFilterPlaceholder.chopped( 1 ) + ":sh}";
}

/// @p text with each placeholder replaced by what @p value gives for its
/// name, in one pass: a value holding a placeholder is not replaced again.
/// A {name:sh} placeholder's value is single-quoted for a POSIX shell
/// (shellQuote()) first: one word for the remote shell that adb shell or
/// ssh hand their joined arguments to.
QString replacePlaceholders( const QString& text,
                             const std::function<QString( const QString& )>& value )
{
    QString replaced;
    qsizetype done = 0;
    auto matches = placeholderPattern().globalMatch( text );
    while ( matches.hasNext() ) {
        const auto match = matches.next();
        replaced += text.mid( done, match.capturedStart() - done );
        const auto plain = value( match.captured( 1 ) );
        replaced += match.captured( 2 ).isEmpty() ? plain : shellQuote( plain );
        done = match.capturedEnd();
    }
    return replaced + text.mid( done );
}

/// @p text as one word for the system's shell, or an empty optional if it
/// cannot be one: on Windows a value in double quotes that cmd.exe would
/// still read (a '"', '%', '!', or a '\' before the closing quote).
std::optional<QString> shellWord( const QString& text )
{
#ifdef Q_OS_WIN
    if ( text.contains( QRegularExpression( QStringLiteral( "[\"%!]" ) ) )
         || text.endsWith( QLatin1Char( '\\' ) ) ) {
        return std::nullopt;
    }
    return QLatin1Char( '"' ) + text + QLatin1Char( '"' );
#else
    return shellQuote( text );
#endif
}

/// The widgets of the source's options that are open (the sidebar's, the
/// dialog's), all on the UI thread: a command saved or deleted in one is
/// shown in the others.
std::vector<class CommandOptionsWidget*> openWidgets;

/// The source's options: the command line, the shell option with its
/// warning, and the saved commands with the examples.
class CommandOptionsWidget : public LiveOptionsWidget {
public:
    explicit CommandOptionsWidget( std::function<QString()> configDir )
        : configDir_( std::move( configDir ) )
    {
        auto* layout = new QVBoxLayout( this );
        layout->setContentsMargins( 0, 0, 0, 0 );

        saved_ = new QComboBox;
        saved_->setObjectName( QStringLiteral( "commandSaved" ) );
        saved_->setToolTip( QStringLiteral(
            "A saved command, or an example to start from; choosing one fills the command "
            "line and runs nothing" ) );
        layout->addWidget( saved_ );

        line_ = new QLineEdit;
        line_->setObjectName( QStringLiteral( "commandLine" ) );
        line_->setPlaceholderText( QStringLiteral( "tcpdump -i {interface} -U -w - {filter}" ) );
        line_->setToolTip( QStringLiteral(
            "A program and its arguments, whose stdout is a pcap or pcapng capture. Split like "
            "a shell splits it, without running one: '…' and \"…\" quote, \\ escapes; nothing "
            "is expanded, no pipe or redirection is made. {interface}, {filter} and {snaplen} "
            "are replaced inside an argument by the fields above; {filter} alone is left out "
            "when the filter is empty. adb shell, adb exec-out and ssh join their arguments "
            "into a line for the device's or the server's shell: write {interface:sh} and "
            "{filter:sh} there, which are quoted for that shell" ) );
        line_->setClearButtonEnabled( true );
        layout->addWidget( line_ );

        auto* hint = new QLabel( QStringLiteral(
            "Placeholders: {interface}, {filter}, {snaplen}; {interface:sh} and {filter:sh} "
            "quoted for a remote shell (after adb or ssh). The output must be pcap or "
            "pcapng on stdout (tcpdump -U -w -)." ) );
        hint->setWordWrap( true );
        layout->addWidget( hint );

        shell_ = new QCheckBox( QStringLiteral( "Run through the shell" ) );
        shell_->setObjectName( QStringLiteral( "commandShell" ) );
#ifdef Q_OS_WIN
        const auto shellName = QStringLiteral( "cmd.exe /c" );
#else
        const auto shellName = QStringLiteral( "/bin/sh -c" );
#endif
        shell_->setToolTip(
            QStringLiteral( "Hand the line to %1 as it is, for pipes and redirections" )
                .arg( shellName ) );
        layout->addWidget( shell_ );
        warning_ = new QLabel(
            QStringLiteral( "The line is run by %1 as it is: anything in it runs, as you. "
                            "The placeholders are put in quoted as one word each: write them "
                            "outside of quotes." )
                .arg( shellName ) );
        warning_->setObjectName( QStringLiteral( "commandShellWarning" ) );
        warning_->setWordWrap( true );
        warning_->setHidden( true );
        layout->addWidget( warning_ );

        auto* saveRow = new QHBoxLayout;
        saveRow->setContentsMargins( 0, 0, 0, 0 );
        name_ = new QLineEdit;
        name_->setObjectName( QStringLiteral( "commandName" ) );
        name_->setPlaceholderText( QStringLiteral( "Name" ) );
        name_->setToolTip( QStringLiteral( "The name to save the command under" ) );
        save_ = new QPushButton( QStringLiteral( "Save" ) );
        save_->setObjectName( QStringLiteral( "commandSave" ) );
        save_->setToolTip( QStringLiteral(
            "Save the command under the name, replacing a command saved under it" ) );
        delete_ = new QPushButton( QStringLiteral( "Delete" ) );
        delete_->setObjectName( QStringLiteral( "commandDelete" ) );
        delete_->setToolTip( QStringLiteral( "Delete the command saved under the name" ) );
        saveRow->addWidget( name_, 1 );
        saveRow->addWidget( save_ );
        saveRow->addWidget( delete_ );
        layout->addLayout( saveRow );

        connect( saved_, &QComboBox::activated, this, [ this ]( int index ) { choose( index ); } );
        connect( line_, &QLineEdit::textChanged, this, [ this ] {
            updateButtons();
            emit changed();
        } );
        connect( shell_, &QCheckBox::toggled, this, [ this ]( bool on ) {
            warning_->setHidden( !on );
            emit changed();
        } );
        connect( name_, &QLineEdit::textChanged, this, [ this ] { updateButtons(); } );
        connect( save_, &QPushButton::clicked, this, [ this ] { saveCommand(); } );
        connect( delete_, &QPushButton::clicked, this, [ this ] { deleteCommand(); } );

        openWidgets.push_back( this );
        setOptions( {} );
    }

    ~CommandOptionsWidget() override
    {
        openWidgets.erase( std::remove( openWidgets.begin(), openWidgets.end(), this ),
                           openWidgets.end() );
    }

    CommandOptionsWidget( const CommandOptionsWidget& ) = delete;
    CommandOptionsWidget& operator=( const CommandOptionsWidget& ) = delete;

    void setOptions( const LiveOptions& options ) override
    {
        // settings.ini has the commands saved last, also by another widget.
        const auto dir = configDir();
        commands_ = savedCommands( dir.isEmpty() ? options : loadLiveOptions( dir, kSourceId ) );
        line_->setText( options.value( kCommandLineOption ) );
        shell_->setChecked( shellOn( options ) );
        warning_->setHidden( !shell_->isChecked() );
        name_->setText( options.value( kCommandNameOption ) );
        fillSaved();
    }

    LiveOptions options() const override
    {
        return { { kCommandLineOption, line_->text() },
                 { kCommandShellOption, liveOptionValue( shell_->isChecked() ) },
                 { kCommandNameOption, name_->text().trimmed() },
                 { kCommandSavedOption, savedCommandsOption( commands_ ) } };
    }

private:
    enum Role { KindRole = Qt::UserRole, IndexRole };
    enum ItemKind { Prompt, Saved, Example };

    QString configDir() const
    {
        return configDir_ ? configDir_() : QString();
    }

    void fillSaved()
    {
        saved_->clear();
        saved_->addItem( QStringLiteral( "Saved commands and examples\xe2\x80\xa6" ) );
        saved_->setItemData( 0, Prompt, KindRole );
        for ( size_t i = 0; i < commands_.size(); ++i ) {
            saved_->addItem( commands_[ i ].name );
            saved_->setItemData( saved_->count() - 1, Saved, KindRole );
            saved_->setItemData( saved_->count() - 1, static_cast<int>( i ), IndexRole );
            saved_->setItemData( saved_->count() - 1, commands_[ i ].line, Qt::ToolTipRole );
        }
        saved_->insertSeparator( saved_->count() );
        const auto examples = commandExamples();
        for ( size_t i = 0; i < examples.size(); ++i ) {
            saved_->addItem( QStringLiteral( "Example: " ) + examples[ i ].name );
            saved_->setItemData( saved_->count() - 1, Example, KindRole );
            saved_->setItemData( saved_->count() - 1, static_cast<int>( i ), IndexRole );
            saved_->setItemData( saved_->count() - 1, examples[ i ].line, Qt::ToolTipRole );
        }
        const auto current = savedIndex( name_->text().trimmed() );
        saved_->setCurrentIndex( current < 0 ? 0 : saved_->findText( commands_[ current ].name ) );
        updateButtons();
    }

    /// The index of the command saved as @p name in commands_, or -1.
    int savedIndex( const QString& name ) const
    {
        for ( size_t i = 0; i < commands_.size(); ++i ) {
            if ( commands_[ i ].name == name ) {
                return static_cast<int>( i );
            }
        }
        return -1;
    }

    /// The item @p index of saved_ chosen: fill the fields from it.
    void choose( int index )
    {
        const auto kind = saved_->itemData( index, KindRole ).toInt();
        const auto at = static_cast<size_t>( saved_->itemData( index, IndexRole ).toInt() );
        const auto examples = commandExamples();
        SavedCommand command;
        if ( kind == Saved && at < commands_.size() ) {
            command = commands_[ at ];
        }
        else if ( kind == Example && at < examples.size() ) {
            command = examples[ at ];
        }
        else {
            return;
        }
        line_->setText( command.line );
        shell_->setChecked( command.shell );
        name_->setText( command.name );
        emit changed();
    }

    void updateButtons()
    {
        const auto name = name_->text().trimmed();
        save_->setEnabled( !name.isEmpty() && !line_->text().trimmed().isEmpty() );
        delete_->setEnabled( savedIndex( name ) >= 0 );
    }

    void saveCommand()
    {
        const SavedCommand command{ name_->text().trimmed(), line_->text(), shell_->isChecked() };
        if ( command.name.isEmpty() ) {
            return;
        }
        const auto at = savedIndex( command.name );
        if ( at >= 0 ) {
            commands_[ static_cast<size_t>( at ) ] = command;
        }
        else {
            commands_.push_back( command );
        }
        name_->setText( command.name );
        keep();
    }

    void deleteCommand()
    {
        const auto at = savedIndex( name_->text().trimmed() );
        if ( at < 0 ) {
            return;
        }
        commands_.erase( commands_.begin() + at );
        keep();
    }

    /// Write commands_ to settings.ini and show them in every open widget.
    void keep()
    {
        if ( const auto dir = configDir(); !dir.isEmpty() ) {
            saveLiveOption( dir, kSourceId, kCommandSavedOption, savedCommandsOption( commands_ ) );
        }
        for ( auto* widget : openWidgets ) {
            widget->commands_ = commands_;
            widget->fillSaved();
            emit widget->changed();
        }
    }

    std::function<QString()> configDir_;
    std::vector<SavedCommand> commands_;
    QComboBox* saved_ = nullptr;
    QLineEdit* line_ = nullptr;
    QCheckBox* shell_ = nullptr;
    QLabel* warning_ = nullptr;
    QLineEdit* name_ = nullptr;
    QPushButton* save_ = nullptr;
    QPushButton* delete_ = nullptr;
};

} // namespace

SplitCommand splitCommandLine( const QString& line )
{
    SplitCommand split;
    QString word;
    bool inWord = false;
    bool plain = true; // the word has no quote or escape
    const auto finish = [ & ] {
        if ( !inWord ) {
            return;
        }
        if ( plain && split.shellOperator.isEmpty()
             && std::any_of( word.begin(), word.end(),
                             []( QChar c ) { return kShellOperators.contains( c ); } ) ) {
            split.shellOperator = word;
        }
        split.words << word;
        word.clear();
        inWord = false;
        plain = true;
    };
    for ( qsizetype i = 0; i < line.size(); ++i ) {
        const auto c = line[ i ];
        if ( c == QLatin1Char( ' ' ) || c == QLatin1Char( '\t' ) ) {
            finish();
            continue;
        }
        inWord = true;
        if ( c == QLatin1Char( '\'' ) ) {
            plain = false;
            const auto close = line.indexOf( QLatin1Char( '\'' ), i + 1 );
            if ( close < 0 ) {
                split.error = QStringLiteral( "A quote (') is not closed." );
                return split;
            }
            word += line.mid( i + 1, close - i - 1 );
            i = close;
        }
        else if ( c == QLatin1Char( '"' ) ) {
            plain = false;
            bool closed = false;
            for ( ++i; i < line.size(); ++i ) {
                const auto q = line[ i ];
                if ( q == QLatin1Char( '"' ) ) {
                    closed = true;
                    break;
                }
                if ( q == QLatin1Char( '\\' ) && i + 1 < line.size()
                     && ( line[ i + 1 ] == QLatin1Char( '"' )
                          || line[ i + 1 ] == QLatin1Char( '\\' ) ) ) {
                    word += line[ ++i ];
                    continue;
                }
                word += q;
            }
            if ( !closed ) {
                split.error = QStringLiteral( "A quote (\") is not closed." );
                return split;
            }
        }
        else if ( c == QLatin1Char( '\\' ) ) {
            plain = false;
            if ( i + 1 >= line.size() ) {
                split.error = QStringLiteral( "A '\\' at the end escapes nothing." );
                return split;
            }
            word += line[ ++i ];
        }
        else {
            word += c;
        }
    }
    finish();
    return split;
}

std::vector<SavedCommand> savedCommands( const LiveOptions& options )
{
    std::vector<SavedCommand> commands;
    const auto document = QJsonDocument::fromJson( options.value( kCommandSavedOption ).toUtf8() );
    for ( const auto& entry : document.array() ) {
        const auto object = entry.toObject();
        SavedCommand command{ object.value( QStringLiteral( "name" ) ).toString().trimmed(),
                              object.value( QStringLiteral( "command" ) ).toString(),
                              object.value( QStringLiteral( "shell" ) ).toBool() };
        if ( !command.name.isEmpty() ) {
            commands.push_back( std::move( command ) );
        }
    }
    return commands;
}

QString savedCommandsOption( const std::vector<SavedCommand>& commands )
{
    QJsonArray array;
    for ( const auto& command : commands ) {
        array.append( QJsonObject{ { QStringLiteral( "name" ), command.name },
                                   { QStringLiteral( "command" ), command.line },
                                   { QStringLiteral( "shell" ), command.shell } } );
    }
    return QString::fromUtf8( QJsonDocument( array ).toJson( QJsonDocument::Compact ) );
}

std::vector<SavedCommand> commandExamples()
{
    return {
        { QStringLiteral( "tcpdump on this computer" ),
          QStringLiteral( "tcpdump -i {interface} -U -w - {filter}" ), false },
        // adb and ssh join their arguments into one line for the device's
        // or the server's shell: the values are quoted for it ({…:sh}).
        { QStringLiteral( "tcpdump on an Android device (adb, root)" ),
          QStringLiteral(
              "adb exec-out tcpdump -i {interface:sh} -s {snaplen} -U -w - {filter:sh}" ),
          false },
        { QStringLiteral( "tcpdump on a server (ssh)" ),
          QStringLiteral( "ssh -o BatchMode=yes user@host tcpdump -i {interface:sh} -s {snaplen} "
                          "-U -w - {filter:sh}" ),
          false },
    };
}

CustomCommand customCommand( const LiveChoice& choice )
{
    CustomCommand built;
    const auto line = choice.options.value( kCommandLineOption );
    if ( line.trimmed().isEmpty() ) {
        built.problem = QStringLiteral( "Enter a command whose stdout is a pcap or pcapng "
                                        "capture, e.g. tcpdump -i {interface} -U -w - {filter}." );
        return built;
    }
    if ( hasControl( line ) ) {
        built.problem = QStringLiteral( "A command is one line, without control characters." );
        return built;
    }
    const auto& iface = choice.networkInterface;
    if ( line.contains( kInterfacePlaceholder )
         || line.contains( kInterfacePlaceholder.chopped( 1 ) + ":sh}" ) ) {
        if ( iface.trimmed().isEmpty() ) {
            built.problem
                = QStringLiteral( "Choose or type an interface: the command uses {interface}." );
            return built;
        }
        if ( hasControl( iface ) ) {
            built.problem
                = QStringLiteral( "An interface is one line, without control characters." );
            return built;
        }
        if ( iface.startsWith( QLatin1Char( '-' ) ) ) {
            built.problem = QStringLiteral(
                "An interface cannot start with '-': the program would read it as an option." );
            return built;
        }
    }
    const auto snaplen = QString::number( choice.snaplen );

    if ( shellOn( choice.options ) ) {
        // Each value one word for the local shell; a {name:sh} one, quoted
        // for the remote shell first, is one word for both.
        bool quotable = true;
        QString commandLine;
        qsizetype done = 0;
        auto matches = placeholderPattern().globalMatch( line );
        while ( matches.hasNext() ) {
            const auto match = matches.next();
            commandLine += line.mid( done, match.capturedStart() - done );
            done = match.capturedEnd();
            const auto name = match.captured( 1 );
            if ( name == QStringLiteral( "snaplen" ) ) {
                commandLine += snaplen;
                continue;
            }
            auto value = name == QStringLiteral( "interface" ) ? iface : choice.filter;
            if ( name == QStringLiteral( "filter" ) && value.isEmpty() ) {
                continue;
            }
            if ( !match.captured( 2 ).isEmpty() ) {
                value = shellQuote( value );
            }
            const auto word = shellWord( value );
            quotable = quotable && word.has_value();
            commandLine += word.value_or( QString() );
        }
        commandLine += line.mid( done );
        if ( !quotable ) {
            built.problem = QStringLiteral(
                "cmd.exe would read the interface or the filter even in quotes: without \"Run "
                "through the shell\" they can hold \", %, ! and a '\\' at their end." );
            return built;
        }
        built.command = ProcessCommand::shell( commandLine );
        return built;
    }

    const auto split = splitCommandLine( line );
    if ( !split.error.isEmpty() ) {
        built.problem = split.error;
        return built;
    }
    if ( !split.shellOperator.isEmpty() ) {
        built.problem = QStringLiteral( "%1 would reach the program as an argument: the command "
                                        "runs without a shell. Turn on \"Run through the shell\" "
                                        "for a pipe or a redirection, or quote it." )
                            .arg( split.shellOperator );
        return built;
    }
    QStringList words;
    for ( const auto& word : split.words ) {
        if ( isFilterAlone( word ) && choice.filter.isEmpty() ) {
            continue;
        }
        words << replacePlaceholders( word, [ & ]( const QString& name ) {
            if ( name == QStringLiteral( "interface" ) ) {
                return iface;
            }
            return name == QStringLiteral( "filter" ) ? choice.filter : snaplen;
        } );
    }
    if ( words.isEmpty() || words.first().isEmpty() ) {
        built.problem = QStringLiteral( "The command names no program." );
        return built;
    }
    built.command.program = words.takeFirst();
    built.command.arguments = words;
    built.command.name = QFileInfo( built.command.program ).fileName();
    return built;
}

CustomCommandSourceKind::CustomCommandSourceKind( std::function<QString()> configDir,
                                                  LocalPrograms local )
    : configDir_( configDir ? std::move( configDir ) : std::function<QString()>( hostConfigDir ) )
    , local_( std::move( local ) )
{
}

QString CustomCommandSourceKind::id() const
{
    return kSourceId;
}

QString CustomCommandSourceKind::displayName() const
{
    return QStringLiteral( "Custom command" );
}

LiveListing CustomCommandSourceKind::listInterfaces( const QString& device,
                                                     std::chrono::milliseconds timeout ) const
{
    const LocalSourceKind local( local_ );
    LiveListing listing;
    if ( local.availability().available ) {
        listing = local.listInterfaces( device, timeout );
    }
    if ( !listing.error.isEmpty() || listing.targets.empty() ) {
        listing.targets.clear();
        listing.error = QStringLiteral( "Type the interface {interface} stands for, if the "
                                        "command uses it." );
    }
    return listing;
}

QString CustomCommandSourceKind::validate( const LiveChoice& choice ) const
{
    return customCommand( choice ).problem;
}

LiveOptionsWidget* CustomCommandSourceKind::makeOptionsWidget() const
{
    return new CommandOptionsWidget( configDir_ );
}

ProcessCommand CustomCommandSourceKind::command( const LiveChoice& choice ) const
{
    return customCommand( choice ).command;
}

QString CustomCommandSourceKind::explainFailure( const QString& error ) const
{
    if ( error.contains( QStringLiteral( "Not a capture" ) ) ) {
        return QStringLiteral(
            "The command must write a pcap or pcapng capture to stdout, and its messages to "
            "stderr: tcpdump -U -w -, dumpcap -w -, tshark -w -. Text before the capture's "
            "header is skipped (up to 4 KB); a program that prints a capture as text, or "
            "writes it to a file, gives none." );
    }
    if ( error.contains( QStringLiteral( "Cannot start" ) ) ) {
        return QStringLiteral(
            "Check the program: give its full path if it is not on LogSquirl's PATH (which can "
            "be shorter than a terminal's), and make sure it may be run. A shell alias, "
            "function or builtin needs \"Run through the shell\"." );
    }
    if ( isCapturePermissionError( error ) ) {
        return QStringLiteral(
            "The capture program may not capture. On this computer, the Local source's "
            "guidance applies (README: ChmodBPF, the wireshark group, setcap, Npcap); on a "
            "server or a device, run it as a user who may (e.g. sudo -n with a NOPASSWD rule). "
            "LogSquirl never answers a password prompt." );
    }
    if ( error.contains( QStringLiteral( "ssh" ), Qt::CaseInsensitive ) ) {
        return explainSshFailure( error );
    }
    return {};
}

} // namespace tcpdump
