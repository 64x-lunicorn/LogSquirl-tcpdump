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
 * @file extcap_source.cpp
 * @brief Finding extcaps, reading what they say, and capturing through them.
 */

#include "extcap_source.h"

#include "capture_pipe.h"
#include "extcap_options.h"

#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QUrl>

#include <algorithm>
#include <cstdint>
#include <map>
#include <stdexcept>

namespace tcpdump {

namespace {

/// The most interfaces of one extcap, arguments of one interface, and
/// values of one argument that are read.
constexpr size_t kMaxInterfaces = 256;
constexpr size_t kMaxArgs = 256;
constexpr size_t kMaxValues = 1024;

/// A long option an argument may be passed as: --name.
const QRegularExpression& longOption()
{
    static const QRegularExpression pattern(
        QStringLiteral( "^--[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$" ) );
    return pattern;
}

/// Whether @p call is the protocol's own, which an argument may not be.
bool isProtocolCall( const QString& call )
{
    return call == QLatin1String( "--capture" ) || call == QLatin1String( "--fifo" )
           || call.startsWith( QLatin1String( "--extcap-" ) );
}

bool isTrue( const QString& value )
{
    return value.compare( QLatin1String( "true" ), Qt::CaseInsensitive ) == 0;
}

/// @p networkInterface as it is in an option name.
QString encodedInterface( const QString& networkInterface )
{
    return QString::fromLatin1( QUrl::toPercentEncoding( networkInterface ) );
}

bool isNumber( ExtcapArgType type )
{
    return type == ExtcapArgType::Integer || type == ExtcapArgType::Unsigned
           || type == ExtcapArgType::Long || type == ExtcapArgType::Double;
}

/// Why @p value is no number of @p arg's type and range; empty if it is.
QString numberProblem( const ExtcapArg& arg, const QString& value )
{
    bool ok = false;
    double number = 0;
    switch ( arg.type ) {
    case ExtcapArgType::Integer: {
        const auto whole = value.toLongLong( &ok );
        ok = ok && whole >= INT32_MIN && whole <= INT32_MAX;
        number = static_cast<double>( whole );
        break;
    }
    case ExtcapArgType::Unsigned:
        number = static_cast<double>( value.toULongLong( &ok ) );
        break;
    case ExtcapArgType::Long:
        number = static_cast<double>( value.toLongLong( &ok ) );
        break;
    default:
        number = value.toDouble( &ok );
        break;
    }
    if ( !ok ) {
        return QStringLiteral( "%1 must be %2." )
            .arg( arg.display, arg.type == ExtcapArgType::Double ? QStringLiteral( "a number" )
                               : arg.type == ExtcapArgType::Unsigned
                                   ? QStringLiteral( "a whole number, not negative" )
                                   : QStringLiteral( "a whole number" ) );
    }
    bool hasMin = false;
    bool hasMax = false;
    const auto min = arg.rangeMin.toDouble( &hasMin );
    const auto max = arg.rangeMax.toDouble( &hasMax );
    if ( ( hasMin && number < min ) || ( hasMax && number > max ) ) {
        return QStringLiteral( "%1 must be from %2 to %3." )
            .arg( arg.display, arg.rangeMin, arg.rangeMax );
    }
    return {};
}

} // namespace

// ── Parsing ──────────────────────────────────────────────────────────────

std::vector<ExtcapSentence> parseExtcapSentences( const QString& out )
{
    std::vector<ExtcapSentence> sentences;
    const auto lines = QStringView( out ).split( QLatin1Char( '\n' ) );
    for ( const auto& rawLine : lines ) {
        if ( sentences.size() >= static_cast<size_t>( kMaxExtcapSentences ) ) {
            break;
        }
        const auto line = rawLine.trimmed();
        if ( line.isEmpty() || line.size() > kMaxExtcapLine ) {
            continue;
        }
        qsizetype at = 0;
        while ( at < line.size() && line[ at ].isLetter() ) {
            ++at;
        }
        if ( at == 0 ) {
            continue;
        }
        ExtcapSentence sentence;
        sentence.keyword = line.left( at ).toString().toLower();
        while ( true ) {
            while ( at < line.size() && line[ at ].isSpace() ) {
                ++at;
            }
            if ( at >= line.size() || line[ at ] != QLatin1Char( '{' ) ) {
                break;
            }
            ++at;
            QString key;
            QString value;
            bool inValue = false;
            bool closed = false;
            for ( ; at < line.size(); ++at ) {
                const auto c = line[ at ];
                if ( c == QLatin1Char( '\\' ) && at + 1 < line.size() ) {
                    ( inValue ? value : key ) += line[ ++at ];
                }
                else if ( c == QLatin1Char( '}' ) ) {
                    closed = true;
                    ++at;
                    break;
                }
                else if ( c == QLatin1Char( '=' ) && !inValue ) {
                    inValue = true;
                }
                else {
                    ( inValue ? value : key ) += c;
                }
            }
            if ( !closed ) {
                break; // cut off: the rest is no item
            }
            key = key.trimmed().toLower();
            if ( !key.isEmpty() && !sentence.items.contains( key ) ) {
                sentence.items.insert( key, value );
            }
        }
        sentences.push_back( std::move( sentence ) );
    }
    return sentences;
}

ExtcapInterfaces parseExtcapInterfaces( const QString& out )
{
    ExtcapInterfaces result;
    QSet<QString> seen;
    for ( const auto& sentence : parseExtcapSentences( out ) ) {
        if ( sentence.keyword == QLatin1String( "extcap" ) ) {
            result.version = sentence.items.value( QStringLiteral( "version" ) );
            result.help = sentence.items.value( QStringLiteral( "help" ) );
        }
        else if ( sentence.keyword == QLatin1String( "interface" ) ) {
            const auto value = sentence.items.value( QStringLiteral( "value" ) );
            if ( value.isEmpty() || seen.contains( value )
                 || result.interfaces.size() >= kMaxInterfaces ) {
                continue;
            }
            seen.insert( value );
            result.interfaces.push_back(
                { value, sentence.items.value( QStringLiteral( "display" ) ) } );
        }
    }
    return result;
}

std::vector<ExtcapDlt> parseExtcapDlts( const QString& out )
{
    std::vector<ExtcapDlt> dlts;
    for ( const auto& sentence : parseExtcapSentences( out ) ) {
        if ( sentence.keyword != QLatin1String( "dlt" ) || dlts.size() >= kMaxInterfaces ) {
            continue;
        }
        bool ok = false;
        const auto number = sentence.items.value( QStringLiteral( "number" ) ).toInt( &ok );
        if ( ok ) {
            dlts.push_back( { number, sentence.items.value( QStringLiteral( "name" ) ),
                              sentence.items.value( QStringLiteral( "display" ) ) } );
        }
    }
    return dlts;
}

ExtcapArgType extcapArgType( const QString& name )
{
    static const std::map<QString, ExtcapArgType> types{
        { QStringLiteral( "string" ), ExtcapArgType::String },
        { QStringLiteral( "timestamp" ), ExtcapArgType::String },
        { QStringLiteral( "password" ), ExtcapArgType::Password },
        { QStringLiteral( "integer" ), ExtcapArgType::Integer },
        { QStringLiteral( "unsigned" ), ExtcapArgType::Unsigned },
        { QStringLiteral( "long" ), ExtcapArgType::Long },
        { QStringLiteral( "double" ), ExtcapArgType::Double },
        { QStringLiteral( "boolean" ), ExtcapArgType::Boolean },
        { QStringLiteral( "boolflag" ), ExtcapArgType::BoolFlag },
        { QStringLiteral( "selector" ), ExtcapArgType::Selector },
        { QStringLiteral( "radio" ), ExtcapArgType::Radio },
        { QStringLiteral( "editselector" ), ExtcapArgType::EditSelector },
        { QStringLiteral( "multicheck" ), ExtcapArgType::Multicheck },
        { QStringLiteral( "fileselect" ), ExtcapArgType::FileSelect },
    };
    const auto found = types.find( name.trimmed().toLower() );
    return found == types.end() ? ExtcapArgType::String : found->second;
}

std::vector<ExtcapArg> parseExtcapConfig( const QString& out )
{
    std::map<int, ExtcapArg> args; // by number
    std::vector<ExtcapSentence> values;
    QSet<QString> calls;
    for ( auto& sentence : parseExtcapSentences( out ) ) {
        if ( sentence.keyword == QLatin1String( "value" ) ) {
            values.push_back( std::move( sentence ) );
            continue;
        }
        if ( sentence.keyword != QLatin1String( "arg" ) || args.size() >= kMaxArgs ) {
            continue;
        }
        const auto& items = sentence.items;
        bool ok = false;
        ExtcapArg arg;
        arg.number = items.value( QStringLiteral( "number" ) ).toInt( &ok );
        arg.call = items.value( QStringLiteral( "call" ) ).trimmed();
        if ( !ok || args.count( arg.number ) > 0 || !longOption().match( arg.call ).hasMatch()
             || isProtocolCall( arg.call ) || calls.contains( arg.call ) ) {
            continue;
        }
        calls.insert( arg.call );
        arg.display = items.value( QStringLiteral( "display" ), arg.call );
        arg.tooltip = items.value( QStringLiteral( "tooltip" ) );
        arg.placeholder = items.value( QStringLiteral( "placeholder" ) );
        arg.defaultValue = items.value( QStringLiteral( "default" ) );
        arg.validation = items.value( QStringLiteral( "validation" ) );
        arg.fileExtension = items.value( QStringLiteral( "fileext" ) );
        arg.type = extcapArgType( items.value( QStringLiteral( "type" ) ) );
        arg.required = isTrue( items.value( QStringLiteral( "required" ) ) );
        arg.mustExist = isTrue( items.value( QStringLiteral( "mustexist" ) ) );
        arg.secret = arg.type == ExtcapArgType::Password
                     || items.value( QStringLiteral( "save" ) )
                                .compare( QLatin1String( "false" ), Qt::CaseInsensitive )
                            == 0;
        const auto range = items.value( QStringLiteral( "range" ) );
        if ( range.contains( QLatin1Char( ',' ) ) ) {
            arg.rangeMin = range.section( QLatin1Char( ',' ), 0, 0 ).trimmed();
            arg.rangeMax = range.section( QLatin1Char( ',' ), 1, 1 ).trimmed();
        }
        args.emplace( arg.number, std::move( arg ) );
    }
    for ( const auto& sentence : values ) {
        bool ok = false;
        const auto number = sentence.items.value( QStringLiteral( "arg" ) ).toInt( &ok );
        const auto arg = args.find( number );
        if ( !ok || arg == args.end() || arg->second.values.size() >= kMaxValues ) {
            continue;
        }
        ExtcapValue value;
        value.value = sentence.items.value( QStringLiteral( "value" ) );
        value.display = sentence.items.value( QStringLiteral( "display" ), value.value );
        value.parent = sentence.items.value( QStringLiteral( "parent" ) );
        value.isDefault = isTrue( sentence.items.value( QStringLiteral( "default" ) ) );
        value.enabled = sentence.items.value( QStringLiteral( "enabled" ) )
                            .compare( QLatin1String( "false" ), Qt::CaseInsensitive )
                        != 0;
        arg->second.values.push_back( std::move( value ) );
    }
    std::vector<ExtcapArg> ordered;
    ordered.reserve( args.size() );
    for ( auto& [ number, arg ] : args ) {
        ordered.push_back( std::move( arg ) );
    }
    return ordered;
}

// ── Options and arguments ────────────────────────────────────────────────

QString extcapOptionName( const QString& networkInterface, const ExtcapArg& arg )
{
    const auto separator
        = arg.type == ExtcapArgType::BoolFlag ? QLatin1Char( '?' ) : QLatin1Char( ':' );
    auto name = encodedInterface( networkInterface ) + separator + arg.call;
    return arg.secret ? kSecretOptionMark + name : name;
}

QStringList extcapArguments( const LiveOptions& options, const QString& networkInterface )
{
    const auto prefix = encodedInterface( networkInterface );
    QStringList arguments;
    for ( auto option = options.cbegin(); option != options.cend(); ++option ) {
        auto name = option.key();
        if ( isSecretLiveOption( name ) ) {
            name.remove( 0, 1 );
        }
        if ( !name.startsWith( prefix ) || name.size() <= prefix.size() ) {
            continue;
        }
        const auto separator = name[ prefix.size() ];
        const auto call = name.mid( prefix.size() + 1 );
        if ( !longOption().match( call ).hasMatch() || isProtocolCall( call ) ) {
            continue;
        }
        if ( separator == QLatin1Char( '?' ) ) {
            if ( isTrue( option.value() ) ) {
                arguments << call;
            }
        }
        else if ( separator == QLatin1Char( ':' ) && !option.value().isEmpty() ) {
            // One word: a value starting with '-' is not read as an option.
            arguments << call + QLatin1Char( '=' ) + option.value();
        }
    }
    return arguments;
}

QString extcapArgumentProblem( const std::vector<ExtcapArg>& args, const LiveOptions& options,
                               const QString& networkInterface )
{
    for ( const auto& arg : args ) {
        if ( arg.type == ExtcapArgType::Boolean || arg.type == ExtcapArgType::BoolFlag ) {
            continue;
        }
        const auto value = options.value( extcapOptionName( networkInterface, arg ) );
        if ( value.isEmpty() ) {
            if ( arg.required ) {
                return QStringLiteral( "%1 is required." ).arg( arg.display );
            }
            continue;
        }
        if ( isNumber( arg.type ) ) {
            if ( auto wrong = numberProblem( arg, value ); !wrong.isEmpty() ) {
                return wrong;
            }
        }
        if ( !arg.validation.isEmpty() ) {
            const QRegularExpression pattern(
                QRegularExpression::anchoredPattern( arg.validation ) );
            if ( pattern.isValid() && !pattern.match( value ).hasMatch() ) {
                return QStringLiteral( "%1 is not valid." ).arg( arg.display );
            }
        }
        if ( arg.type == ExtcapArgType::FileSelect && arg.mustExist
             && !QFileInfo::exists( value ) ) {
            return QStringLiteral( "%1: %2 does not exist." ).arg( arg.display, value );
        }
    }
    return {};
}

// ── Places ───────────────────────────────────────────────────────────────

ExtcapPlaces ExtcapPlaces::forThisComputer()
{
    ExtcapPlaces places;
    QStringList bases;
    for ( const auto& dir : qEnvironmentVariable( "WIRESHARK_EXTCAP_DIR" )
                                .split( QDir::listSeparator(), Qt::SkipEmptyParts ) ) {
        bases << dir;
    }
    const auto home = QDir::homePath();
    if ( places.os == CaptureOs::Windows ) {
        const auto appData = qEnvironmentVariable( "APPDATA" );
        if ( !appData.isEmpty() ) {
            bases << appData + QStringLiteral( "/Wireshark/extcap" );
        }
        for ( const auto* variable : { "ProgramFiles", "ProgramW6432", "ProgramFiles(x86)" } ) {
            const auto programs = qEnvironmentVariable( variable );
            if ( !programs.isEmpty() ) {
                bases << programs + QStringLiteral( "/Wireshark/extcap" );
            }
        }
        bases << QStringLiteral( "C:/Program Files/Wireshark/extcap" );
    }
    else {
        bases << home + QStringLiteral( "/.local/lib/wireshark/extcap" )
              << home + QStringLiteral( "/.config/wireshark/extcap" );
        if ( places.os == CaptureOs::MacOS ) {
            bases << QStringLiteral( "/Applications/Wireshark.app/Contents/MacOS/extcap" )
                  << home + QStringLiteral( "/Applications/Wireshark.app/Contents/MacOS/extcap" )
                  << QStringLiteral( "/opt/homebrew/lib/wireshark/extcap" )
                  << QStringLiteral( "/usr/local/lib/wireshark/extcap" );
        }
        else {
            // Debian and Ubuntu put it below the multiarch triplet.
            for ( const auto& triplet : QDir( QStringLiteral( "/usr/lib" ) )
                                            .entryList( { QStringLiteral( "*-linux-gnu*" ) },
                                                        QDir::Dirs | QDir::NoDotAndDotDot ) ) {
                bases << QStringLiteral( "/usr/lib/%1/wireshark/extcap" ).arg( triplet );
            }
            bases << QStringLiteral( "/usr/lib/x86_64-linux-gnu/wireshark/extcap" )
                  << QStringLiteral( "/usr/lib/aarch64-linux-gnu/wireshark/extcap" )
                  << QStringLiteral( "/usr/lib/wireshark/extcap" )
                  << QStringLiteral( "/usr/lib64/wireshark/extcap" )
                  << QStringLiteral( "/usr/libexec/wireshark/extcap" )
                  << QStringLiteral( "/usr/local/lib/wireshark/extcap" );
        }
    }
    for ( const auto& base : bases ) {
        // Wireshark 4.2 and later keep its own below "wireshark".
        for ( const auto& dir : { base, base + QStringLiteral( "/wireshark" ) } ) {
            const auto clean = QDir::cleanPath( dir );
            if ( !places.directories.contains( clean ) ) {
                places.directories << clean;
            }
        }
    }
    return places;
}

QString extcapInstallHint( const ExtcapPlaces& places )
{
    QString where;
    switch ( places.os ) {
    case CaptureOs::MacOS:
        where = QStringLiteral( "install Wireshark (its extcaps are in "
                                "Wireshark.app/Contents/MacOS/extcap)" );
        break;
    case CaptureOs::Linux:
        where = QStringLiteral( "install Wireshark (e.g. sudo apt install wireshark; its extcaps "
                                "are in /usr/lib/<arch>/wireshark/extcap)" );
        break;
    case CaptureOs::Windows:
        where = QStringLiteral( "install Wireshark (its extcaps are in "
                                "Program Files\\Wireshark\\extcap)" );
        break;
    }
    return QStringLiteral( "No Wireshark extcap found: %1, put an extcap in your personal "
                           "extcap directory (%2), or set WIRESHARK_EXTCAP_DIR." )
        .arg( where, places.os == CaptureOs::Windows
                         ? QStringLiteral( "%APPDATA%\\Wireshark\\extcap" )
                         : QStringLiteral( "~/.local/lib/wireshark/extcap" ) );
}

// ── ExtcapSourceKind ─────────────────────────────────────────────────────

ExtcapSourceKind::ExtcapSourceKind( ExtcapPlaces places )
    : places_( std::move( places ) )
{
}

std::vector<ExtcapSourceKind::Extcap> ExtcapSourceKind::extcaps() const
{
    std::vector<Extcap> found;
    QSet<QString> names;
    for ( const auto& directory : places_.directories ) {
        const QDir dir( directory );
        if ( directory.isEmpty() || !dir.exists() ) {
            continue;
        }
        const auto entries = dir.entryInfoList( QDir::Files | QDir::Executable, QDir::Name );
        for ( const auto& entry : entries ) {
            const auto name = entry.fileName();
            if ( names.contains( name ) || name.startsWith( QLatin1Char( '.' ) ) ) {
                continue;
            }
            if ( places_.os == CaptureOs::Windows ) {
                const auto suffix = entry.suffix().toLower();
                if ( suffix != QLatin1String( "exe" ) && suffix != QLatin1String( "bat" )
                     && suffix != QLatin1String( "cmd" ) ) {
                    continue;
                }
            }
            names.insert( name );
            found.push_back( { name, entry.absoluteFilePath() } );
        }
    }
    std::sort( found.begin(), found.end(),
               []( const Extcap& a, const Extcap& b ) { return a.name < b.name; } );
    return found;
}

QString ExtcapSourceKind::program( const QString& name ) const
{
    if ( name.isEmpty() ) {
        return {};
    }
    for ( const auto& extcap : extcaps() ) {
        if ( extcap.name == name ) {
            return extcap.path;
        }
    }
    return {};
}

QString ExtcapSourceKind::id() const
{
    return QStringLiteral( "extcap" );
}

QString ExtcapSourceKind::displayName() const
{
    return QStringLiteral( "Wireshark extcap" );
}

LiveAvailability ExtcapSourceKind::availability() const
{
    if ( extcaps().empty() ) {
        return LiveAvailability::unavailable( extcapInstallHint( places_ ) );
    }
    return {};
}

LiveSourceKind::Devices ExtcapSourceKind::devices() const
{
    return Devices::Listed;
}

QString ExtcapSourceKind::deviceLabel() const
{
    return QStringLiteral( "Extcap" );
}

QString ExtcapSourceKind::ask( const QString& path, const QStringList& arguments,
                               std::chrono::milliseconds timeout ) const
{
    ProcessCommand command;
    command.program = path;
    command.arguments = arguments;
    const auto output = runListing( command, timeout );
    const auto name = command.displayName();
    if ( !output.error.isEmpty() ) {
        throw std::runtime_error( output.error.toStdString() );
    }
    if ( output.exitCode != 0 ) {
        const auto lines = output.err.trimmed().split( QLatin1Char( '\n' ) );
        auto message = QStringLiteral( "%1 %2 exited with code %3" )
                           .arg( name, arguments.value( 0 ) )
                           .arg( output.exitCode );
        if ( !output.err.trimmed().isEmpty() ) {
            message += QStringLiteral( ": " )
                       + lines.mid( std::max<qsizetype>( 0, lines.size() - 3 ) )
                             .join( QLatin1Char( ' ' ) )
                             .left( 500 );
        }
        throw std::runtime_error( message.toStdString() );
    }
    return output.out;
}

LiveListing ExtcapSourceKind::listDevices( std::chrono::milliseconds timeout ) const
{
    LiveListing listing;
    const auto found = extcaps();
    if ( found.empty() ) {
        listing.error = extcapInstallHint( places_ );
        return listing;
    }
    // One after another, within the timeout in all.
    QElapsedTimer clock;
    clock.start();
    for ( const auto& extcap : found ) {
        LiveTarget target;
        target.id = extcap.name;
        const auto left = timeout - std::chrono::milliseconds( clock.elapsed() );
        if ( left <= std::chrono::milliseconds( 0 ) ) {
            target.problem = QStringLiteral( "not asked: listing took too long; Refresh" );
            listing.targets.push_back( target );
            continue;
        }
        try {
            const auto said = parseExtcapInterfaces(
                ask( extcap.path, { QStringLiteral( "--extcap-interfaces" ) }, left ) );
            if ( said.interfaces.empty() ) {
                target.problem = QStringLiteral( "reports no interface" );
            }
            else {
                QStringList shown;
                for ( const auto& reported : said.interfaces ) {
                    shown << ( reported.display.isEmpty() ? reported.value : reported.display );
                }
                target.description = shown.join( QStringLiteral( ", " ) ).left( 200 );
                if ( !said.version.isEmpty() ) {
                    target.description += QStringLiteral( " (%1)" ).arg( said.version.left( 40 ) );
                }
            }
        } catch ( const std::exception& e ) {
            // Skipped: it is listed with why, and cannot be chosen.
            target.problem = QString::fromUtf8( e.what() );
        }
        listing.targets.push_back( target );
    }
    return listing;
}

LiveListing ExtcapSourceKind::listInterfaces( const QString& device,
                                              std::chrono::milliseconds timeout ) const
{
    LiveListing listing;
    const auto path = program( device );
    if ( path.isEmpty() ) {
        listing.error
            = device.isEmpty()
                  ? QStringLiteral( "Choose an extcap." )
                  : QStringLiteral( "%1 is not in the extcap directories." ).arg( device );
        return listing;
    }
    try {
        const auto said = parseExtcapInterfaces(
            ask( path, { QStringLiteral( "--extcap-interfaces" ) }, timeout ) );
        for ( const auto& reported : said.interfaces ) {
            listing.targets.push_back( { reported.value, reported.display, {} } );
        }
        if ( said.interfaces.empty() ) {
            listing.error = QStringLiteral( "%1 reports no interface." ).arg( device );
        }
    } catch ( const std::exception& e ) {
        listing.error = QString::fromUtf8( e.what() );
    }
    return listing;
}

ExtcapConfig ExtcapSourceKind::config( const QString& device, const QString& networkInterface,
                                       std::chrono::milliseconds timeout ) const
{
    ExtcapConfig config;
    const auto path = program( device );
    if ( path.isEmpty() ) {
        config.error = QStringLiteral( "%1 is not in the extcap directories." ).arg( device );
        return config;
    }
    QElapsedTimer clock;
    clock.start();
    try {
        config.args
            = parseExtcapConfig( ask( path,
                                      { QStringLiteral( "--extcap-interface" ), networkInterface,
                                        QStringLiteral( "--extcap-config" ) },
                                      timeout ) );
        const auto left = timeout - std::chrono::milliseconds( clock.elapsed() );
        if ( left > std::chrono::milliseconds( 0 ) ) {
            // Only shown: a capture's link type is in its header.
            try {
                config.dlts
                    = parseExtcapDlts( ask( path,
                                            { QStringLiteral( "--extcap-interface" ),
                                              networkInterface, QStringLiteral( "--extcap-dlts" ) },
                                            left ) );
            } catch ( const std::exception& ) {
            }
        }
    } catch ( const std::exception& e ) {
        config.error = QString::fromUtf8( e.what() );
    }
    {
        const std::lock_guard<std::mutex> lock( knownArgs_->mutex );
        const auto key = std::make_pair( device, networkInterface );
        if ( config.error.isEmpty() ) {
            knownArgs_->byInterface.insert_or_assign( key, config.args );
        }
        else {
            knownArgs_->byInterface.erase( key );
        }
    }
    return config;
}

QString ExtcapSourceKind::validate( const LiveChoice& choice ) const
{
    if ( choice.device.trimmed().isEmpty() ) {
        return QStringLiteral( "Choose an extcap." );
    }
    if ( program( choice.device ).isEmpty() ) {
        return QStringLiteral( "%1 is not in the extcap directories." ).arg( choice.device );
    }
    if ( auto problem = LiveSourceKind::validate( choice ); !problem.isEmpty() ) {
        return problem;
    }
    // A .bat or .cmd extcap is run by cmd.exe, which reads its arguments
    // again: startProcess() refuses them too, this says so before Start.
    if ( places_.os == CaptureOs::Windows ) {
        if ( auto problem = batchArgumentProblem( command( choice ) ); !problem.isEmpty() ) {
            return problem;
        }
    }
    const std::lock_guard<std::mutex> lock( knownArgs_->mutex );
    const auto known
        = knownArgs_->byInterface.find( std::make_pair( choice.device, choice.networkInterface ) );
    if ( known == knownArgs_->byInterface.end() ) {
        return {};
    }
    return extcapArgumentProblem( known->second, choice.options, choice.networkInterface );
}

LiveOptionsWidget* ExtcapSourceKind::makeOptionsWidget() const
{
    // Its listings may outlive the registry this kind is in: they hold a copy.
    return new ExtcapOptionsWidget( std::make_shared<ExtcapSourceKind>( *this ) );
}

ProcessCommand ExtcapSourceKind::command( const LiveChoice& choice ) const
{
    ProcessCommand command;
    const auto path = program( choice.device );
    command.program = path.isEmpty() ? choice.device : path;
    command.name = choice.device;
    command.arguments << QStringLiteral( "--capture" ) << QStringLiteral( "--extcap-interface" )
                      << choice.networkInterface;
    if ( !choice.filter.trimmed().isEmpty() ) {
        command.arguments << QStringLiteral( "--extcap-capture-filter" ) << choice.filter.trimmed();
    }
    command.arguments << extcapArguments( choice.options, choice.networkInterface );
    return command;
}

LiveCapture::SourceFactory ExtcapSourceKind::makeSource( const LiveChoice& choice ) const
{
    const auto base = command( choice );
    return [ base ]( const std::atomic_bool* stop,
                     std::function<void( const QString& )> onStderrLine ) {
        return std::make_unique<PipeSource>(
            [ &base ]( const QString& pipe ) {
                auto run = base;
                // After --capture --extcap-interface <if>, as Wireshark passes it.
                run.arguments.insert( 3, QStringLiteral( "--fifo" ) );
                run.arguments.insert( 4, pipe );
                return run;
            },
            stop, std::move( onStderrLine ) );
    };
}

} // namespace tcpdump
