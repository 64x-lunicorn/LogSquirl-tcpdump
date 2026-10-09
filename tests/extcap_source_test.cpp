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
 * @file extcap_source_test.cpp
 * @brief BDD tests for the Wireshark extcap source: the protocol's output
 *        parsed, extcaps found in their directories, an interface's
 *        arguments as a form whose values reach the command line (a
 *        password never settings.ini), the pipe a capture is read from,
 *        and live captures through a fake extcap script.
 */

#include <catch2/catch.hpp>

#include "capture_pipe.h"
#include "extcap_options.h"
#include "extcap_source.h"
#include "fakehost.h"
#include "live_capture_form.h"
#include "settings.h"
#include "sidebarwidget.h"
#include "stream_capture.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QTemporaryDir>

#include <memory>
#include <thread>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// An `--extcap-config` output with an argument of each type, and two an
/// extcap may not have: one named like the protocol's own, one no option.
const char* const kConfig
    = "arg {number=0}{call=--remote-host}{display=Remote host}{type=string}{required=true}"
      "{tooltip=The host to capture on}\n"
      "arg {number=1}{call=--remote-port}{display=Port}{type=unsigned}{default=22}"
      "{range=1,65535}\n"
      "arg {number=2}{call=--count}{display=Count}{type=integer}{default=-1}\n"
      "arg {number=3}{call=--big}{display=Big}{type=long}\n"
      "arg {number=4}{call=--ratio}{display=Ratio}{type=double}{default=0.5}\n"
      "arg {number=5}{call=--verbose}{display=Verbose}{type=boolflag}{default=true}\n"
      "arg {number=6}{call=--promisc}{display=Promiscuous}{type=boolean}\n"
      "arg {number=7}{call=--if}{display=Remote interface}{type=selector}\n"
      "value {arg=7}{value=eth0}{display=Ethernet}\n"
      "value {arg=7}{value=wlan0}{display=Wi-Fi}{default=true}\n"
      "arg {number=8}{call=--mode}{display=Mode}{type=radio}\n"
      "value {arg=8}{value=fast}{display=Fast}\n"
      "value {arg=8}{value=slow}{display=Slow}{default=true}\n"
      "arg {number=9}{call=--channels}{display=Channels}{type=multicheck}\n"
      "value {arg=9}{value=1}{display=One}{default=true}\n"
      "value {arg=9}{value=2}{display=Two}\n"
      "value {arg=9}{value=3}{display=Three}{default=true}{parent=2}\n"
      "arg {number=10}{call=--sink}{display=Sink}{type=editselector}\n"
      "value {arg=10}{value=a}{display=A}\n"
      "arg {number=11}{call=--keyfile}{display=Key file}{type=fileselect}{mustexist=true}\n"
      "arg {number=12}{call=--password}{display=Password}{type=password}\n"
      "arg {number=13}{call=--token}{display=Token}{type=string}{save=false}\n"
      "arg {number=14}{call=--fifo}{display=Evil}{type=string}\n"
      "arg {number=15}{call=rm -rf}{display=Evil too}{type=string}\n";

/// The extcap @p name's options holding @p values for the interface @p ifc.
ExtcapArg argOf( const QString& call, ExtcapArgType type = ExtcapArgType::String,
                 bool secret = false )
{
    ExtcapArg arg;
    arg.call = call;
    arg.type = type;
    arg.secret = secret;
    return arg;
}

} // namespace

SCENARIO( "The extcap source reads what an extcap says", "[extcap_source]" )
{
    THEN( "a sentence's items are read, escaped braces and backslashes as they are" )
    {
        const auto sentences
            = parseExtcapSentences( "extcap {version=1.2}{help=https://example.org/help}\r\n"
                                    "interface {value=a\\}b}{display=Say \\{hi\\} \\\\ there}\n"
                                    "garbage without braces\n"
                                    "{value=nokeyword}\n"
                                    "interface {value=cut off\n" );
        REQUIRE( sentences.size() == 4 );
        REQUIRE( sentences[ 0 ].keyword == "extcap" );
        REQUIRE( sentences[ 0 ].items.value( "version" ) == "1.2" );
        REQUIRE( sentences[ 1 ].items.value( "value" ) == "a}b" );
        REQUIRE( sentences[ 1 ].items.value( "display" ) == "Say {hi} \\ there" );
        REQUIRE( sentences[ 2 ].keyword == "garbage" );
        REQUIRE( sentences[ 2 ].items.isEmpty() );
        REQUIRE( sentences[ 3 ].items.isEmpty() );
    }

    THEN( "interfaces come with the extcap's version; one without a value, or twice, is not" )
    {
        const auto said
            = parseExtcapInterfaces( "extcap {version=4.4.0}{help=file:///help.html}\n"
                                     "interface {value=sshdump}{display=SSH remote capture}\n"
                                     "interface {display=no value}\n"
                                     "interface {value=sshdump}{display=again}\n"
                                     "interface {value=ciscodump}\n"
                                     "control {number=0}{type=button}{display=Ignored}\n" );
        REQUIRE( said.version == "4.4.0" );
        REQUIRE( said.help == "file:///help.html" );
        REQUIRE( said.interfaces.size() == 2 );
        REQUIRE( said.interfaces[ 0 ].value == "sshdump" );
        REQUIRE( said.interfaces[ 0 ].display == "SSH remote capture" );
        REQUIRE( said.interfaces[ 1 ].value == "ciscodump" );
    }

    THEN( "link types are read" )
    {
        const auto dlts = parseExtcapDlts( "dlt {number=147}{name=USER0}{display=Demo}\n"
                                           "dlt {number=x}{name=bad}\n" );
        REQUIRE( dlts.size() == 1 );
        REQUIRE( dlts[ 0 ].number == 147 );
        REQUIRE( dlts[ 0 ].name == "USER0" );
        REQUIRE( dlts[ 0 ].display == "Demo" );
    }

    THEN( "every argument type is read, with its values, and calls an extcap may not have are "
          "not" )
    {
        const auto args = parseExtcapConfig( kConfig );
        REQUIRE( args.size() == 14 );
        REQUIRE( args[ 0 ].call == "--remote-host" );
        REQUIRE( args[ 0 ].required );
        REQUIRE( args[ 0 ].tooltip == "The host to capture on" );
        REQUIRE( args[ 1 ].type == ExtcapArgType::Unsigned );
        REQUIRE( args[ 1 ].rangeMin == "1" );
        REQUIRE( args[ 1 ].rangeMax == "65535" );
        REQUIRE( args[ 2 ].type == ExtcapArgType::Integer );
        REQUIRE( args[ 3 ].type == ExtcapArgType::Long );
        REQUIRE( args[ 4 ].type == ExtcapArgType::Double );
        REQUIRE( args[ 5 ].type == ExtcapArgType::BoolFlag );
        REQUIRE( args[ 6 ].type == ExtcapArgType::Boolean );
        REQUIRE( args[ 7 ].type == ExtcapArgType::Selector );
        REQUIRE( args[ 7 ].values.size() == 2 );
        REQUIRE( args[ 7 ].values[ 1 ].isDefault );
        REQUIRE( args[ 8 ].type == ExtcapArgType::Radio );
        REQUIRE( args[ 9 ].type == ExtcapArgType::Multicheck );
        REQUIRE( args[ 9 ].values[ 2 ].parent == "2" );
        REQUIRE( args[ 10 ].type == ExtcapArgType::EditSelector );
        REQUIRE( args[ 11 ].type == ExtcapArgType::FileSelect );
        REQUIRE( args[ 11 ].mustExist );
        REQUIRE( args[ 12 ].type == ExtcapArgType::Password );
        REQUIRE( args[ 12 ].secret );
        REQUIRE( args[ 13 ].secret ); // {save=false}
        REQUIRE_FALSE( args[ 0 ].secret );
        REQUIRE( extcapArgType( "timestamp" ) == ExtcapArgType::String );
        REQUIRE( extcapArgType( "something new" ) == ExtcapArgType::String );
    }

    THEN( "an output too long to be honest is read only so far" )
    {
        QString flood;
        for ( int i = 0; i < kMaxExtcapSentences + 100; ++i ) {
            flood += QString( "arg {number=%1}{call=--a%1}{display=A}{type=string}\n" ).arg( i );
        }
        flood += "interface {value=" + QString( kMaxExtcapLine + 1, 'x' ) + "}\n";
        REQUIRE( parseExtcapSentences( flood ).size() == size_t( kMaxExtcapSentences ) );
        REQUIRE( parseExtcapConfig( flood ).size() == 256 );
        REQUIRE( parseExtcapInterfaces( "interface {value=" + QString( kMaxExtcapLine, 'x' ) + "}" )
                     .interfaces.empty() );
    }
}

SCENARIO( "An extcap's options are named after its interface and reach its command line",
          "[extcap_source]" )
{
    THEN( "a name holds the interface encoded, and a secret is marked" )
    {
        REQUIRE( extcapOptionName( "sshdump", argOf( "--remote-host" ) )
                 == "sshdump:--remote-host" );
        REQUIRE( extcapOptionName( "sshdump", argOf( "--verbose", ExtcapArgType::BoolFlag ) )
                 == "sshdump?--verbose" );
        REQUIRE( extcapOptionName( "ssh/dump:1?", argOf( "--x" ) ) == "ssh%2Fdump%3A1%3F:--x" );
        const auto secret
            = extcapOptionName( "sshdump", argOf( "--password", ExtcapArgType::Password, true ) );
        REQUIRE( secret == "*sshdump:--password" );
        REQUIRE( isSecretLiveOption( secret ) );
    }

    THEN( "the arguments are those of the interface, one word each" )
    {
        const LiveOptions options{
            { "sshdump:--remote-host", "--evil $(touch x)" },
            { "sshdump:--empty", "" },
            { "sshdump?--verbose", "true" },
            { "sshdump?--quiet", "false" },
            { "*sshdump:--password", "s3cret" },
            { "other:--remote-host", "elsewhere" },
            { "sshdump:--fifo", "/tmp/evil" },
            { "sshdump:not-an-option", "x" },
        };
        REQUIRE(
            extcapArguments( options, "sshdump" )
            == QStringList{ "--password=s3cret", "--remote-host=--evil $(touch x)", "--verbose" } );
    }

    THEN( "a choice's command captures its interface, with its filter and options" )
    {
        const ExtcapSourceKind kind( ExtcapPlaces{} );
        LiveChoice choice{ "extcap", "sshdump", "sshdump", "tcp port 80", 96 };
        choice.options = { { "sshdump:--remote-host", "h" } };
        const auto command = kind.command( choice );
        REQUIRE( command.arguments
                 == QStringList{ "--capture", "--extcap-interface", "sshdump",
                                 "--extcap-capture-filter", "tcp port 80", "--remote-host=h" } );
        REQUIRE_FALSE( command.viaShell );
        REQUIRE( command.displayName() == "sshdump" );
    }

    THEN( "a password is handed to the capture, but never written to settings.ini" )
    {
        QTemporaryDir config;
        LiveChoice choice{ "extcap", "sshdump", "sshdump", "", 96 };
        choice.options = { { "sshdump:--remote-host", "h" }, { "*sshdump:--password", "s3cret" } };
        REQUIRE( saveLiveChoice( config.path(), choice ) );
        QFile file( settingsFilePath( config.path() ) );
        REQUIRE( file.open( QIODevice::ReadOnly ) );
        const auto written = QString::fromUtf8( file.readAll() );
        REQUIRE_FALSE( written.contains( "s3cret" ) );
        REQUIRE_FALSE( written.contains( "password" ) );
        REQUIRE( loadLiveOptions( config.path(), "extcap" )
                 == LiveOptions{ { "sshdump:--remote-host", "h" } } );
    }
}

namespace {

/// Write @p body as the executable script @p path (on Unix).
void writeScript( const QString& path, const QString& body )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( ( "#!/bin/sh\n" + body + "\n" ).toUtf8() );
    file.close();
    REQUIRE( file.setPermissions( QFileDevice::ReadOwner | QFileDevice::WriteOwner
                                  | QFileDevice::ExeOwner ) );
}

/// The text of the file @p path, empty if there is none.
QString readText( const QString& path )
{
    QFile file( path );
    return file.open( QIODevice::ReadOnly ) ? QString::fromUtf8( file.readAll() ) : QString();
}

} // namespace

SCENARIO( "Extcaps are found in their directories", "[extcap_source]" )
{
    THEN( "this computer's places start with WIRESHARK_EXTCAP_DIR, then the personal one, each "
          "with its wireshark subdirectory" )
    {
        const auto before = qgetenv( "WIRESHARK_EXTCAP_DIR" );
        qputenv( "WIRESHARK_EXTCAP_DIR", "/opt/my-extcaps" );
        const auto places = ExtcapPlaces::forThisComputer();
        if ( before.isNull() ) {
            qunsetenv( "WIRESHARK_EXTCAP_DIR" );
        }
        else {
            qputenv( "WIRESHARK_EXTCAP_DIR", before );
        }
        REQUIRE( places.directories.value( 0 ) == QDir::cleanPath( "/opt/my-extcaps" ) );
        REQUIRE( places.directories.value( 1 ) == QDir::cleanPath( "/opt/my-extcaps/wireshark" ) );
#if defined( Q_OS_MACOS )
        REQUIRE( places.directories.contains( QDir::homePath() + "/.local/lib/wireshark/extcap" ) );
        REQUIRE( places.directories.contains( QDir::homePath() + "/.config/wireshark/extcap" ) );
        REQUIRE(
            places.directories.contains( "/Applications/Wireshark.app/Contents/MacOS/extcap" ) );
#elif defined( Q_OS_WIN )
        REQUIRE( places.directories.contains( "C:/Program Files/Wireshark/extcap" ) );
#else
        REQUIRE( places.directories.contains( QDir::homePath() + "/.local/lib/wireshark/extcap" ) );
        REQUIRE( places.directories.contains( "/usr/lib/x86_64-linux-gnu/wireshark/extcap" ) );
        REQUIRE( places.directories.contains( "/usr/lib/wireshark/extcap" ) );
#endif
    }

#ifdef Q_OS_UNIX
    GIVEN( "a personal and a global directory" )
    {
        QTemporaryDir root;
        REQUIRE( QDir( root.path() ).mkpath( "personal" ) );
        REQUIRE( QDir( root.path() ).mkpath( "global/wireshark" ) );
        writeScript( root.filePath( "personal/sshdump" ), "exit 0" );
        writeScript( root.filePath( "global/sshdump" ), "exit 0" );
        writeScript( root.filePath( "global/wireshark/udpdump" ), "exit 0" );
        writeScript( root.filePath( "global/.hidden" ), "exit 0" );
        writeFile( root.filePath( "global/README" ), text( "not executable" ) );
        ExtcapPlaces places;
        places.os = CaptureOs::Linux;
        places.directories = { root.filePath( "personal" ), root.filePath( "missing" ),
                               root.filePath( "global" ), root.filePath( "global/wireshark" ) };
        const ExtcapSourceKind kind( places );

        THEN( "the executables are its extcaps, a name in two directories the first's" )
        {
            const auto found = kind.extcaps();
            REQUIRE( found.size() == 2 );
            REQUIRE( found[ 0 ].name == "sshdump" );
            REQUIRE( found[ 0 ].path == root.filePath( "personal/sshdump" ) );
            REQUIRE( found[ 1 ].name == "udpdump" );
            REQUIRE( kind.program( "udpdump" ) == root.filePath( "global/wireshark/udpdump" ) );
            REQUIRE( kind.program( "README" ).isEmpty() );
            REQUIRE( kind.availability().available );
        }
    }
#endif

    GIVEN( "no extcap anywhere" )
    {
        QTemporaryDir empty;
        ExtcapPlaces places;
        places.os = CaptureOs::MacOS;
        places.directories = { empty.path() };
        const ExtcapSourceKind kind( places );

        THEN( "the source is unavailable, and says where extcaps come from" )
        {
            const auto availability = kind.availability();
            REQUIRE_FALSE( availability.available );
            REQUIRE( availability.reason.contains( "No Wireshark extcap found" ) );
            REQUIRE( availability.reason.contains( "WIRESHARK_EXTCAP_DIR" ) );
            REQUIRE( availability.reason.contains( "Wireshark.app" ) );
            REQUIRE( kind.listDevices( LiveSourceKind::kListTimeout ).error
                     == availability.reason );
        }
    }

    THEN( "it is registered as Wireshark extcap, with extcaps as its devices" )
    {
        const auto kind = builtInLiveSources()->find( "extcap" );
        REQUIRE( kind );
        REQUIRE( kind->displayName() == "Wireshark extcap" );
        REQUIRE( kind->devices() == LiveSourceKind::Devices::Listed );
        REQUIRE( kind->deviceLabel() == "Extcap" );
    }
}

#ifdef Q_OS_UNIX
SCENARIO( "A Windows batch extcap is given nothing cmd.exe would read", "[extcap_source]" )
{
    QTemporaryDir root;
    writeScript( root.filePath( "dump.bat" ), "exit 0" );
    ExtcapPlaces places;
    places.os = CaptureOs::Windows;
    places.directories = { root.path() };
    const ExtcapSourceKind kind( places );
    REQUIRE( kind.program( "dump.bat" ) == root.filePath( "dump.bat" ) );
    LiveChoice choice{ "extcap", "dump.bat", "eth0", "host 10.0.0.1", 96, {} };

    THEN( "a plain filter and plain arguments pass" )
    {
        choice.options[ "eth0:--remote-host" ] = "router.local";
        REQUIRE( kind.validate( choice ).isEmpty() );
    }

    THEN( "a filter cmd.exe would read is refused before anything runs" )
    {
        choice.filter = "host 10.0.0.1 & calc";
        REQUIRE( kind.validate( choice ).contains( "is a batch file" ) );
    }

    THEN( "so is an argument's value, or an interface" )
    {
        choice.options[ "eth0:--remote-host" ] = "%COMSPEC%";
        REQUIRE( kind.validate( choice ).contains( "is a batch file" ) );
        choice.options.clear();
        choice.networkInterface = "eth0|calc";
        REQUIRE( kind.validate( choice ).contains( "is a batch file" ) );
    }

    THEN( "an extcap that is no batch file takes them as they are" )
    {
        writeScript( root.filePath( "dump.exe" ), "exit 0" );
        choice.device = "dump.exe";
        choice.filter = "host 10.0.0.1 & calc";
        REQUIRE( kind.validate( choice ).isEmpty() );
    }
}
#endif

namespace {

/// Write all of @p bytes into the pipe @p path, as an extcap does, and close it.
void writeIntoPipe( const QString& path, const Bytes& bytes )
{
#ifdef Q_OS_WIN
    HANDLE pipe = CreateFileW( reinterpret_cast<LPCWSTR>( path.utf16() ), GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr );
    if ( pipe == INVALID_HANDLE_VALUE ) {
        return;
    }
    DWORD written = 0;
    WriteFile( pipe, bytes.data(), static_cast<DWORD>( bytes.size() ), &written, nullptr );
    CloseHandle( pipe );
#else
    const int fd = ::open( QFile::encodeName( path ).constData(), O_WRONLY );
    if ( fd < 0 ) {
        return;
    }
    size_t done = 0;
    while ( done < bytes.size() ) {
        const auto n = ::write( fd, bytes.data() + done, bytes.size() - done );
        if ( n <= 0 ) {
            break;
        }
        done += static_cast<size_t>( n );
    }
    ::close( fd );
#endif
}

/// A program that runs for a while and writes nothing.
ProcessCommand sleeper()
{
    ProcessCommand command;
#ifdef Q_OS_WIN
    command.program = "ping";
    command.arguments = { "-n", "60", "127.0.0.1" };
#else
    command.program = "/bin/sleep";
    command.arguments = { "60" };
#endif
    return command;
}

/// Read @p source until it has given @p n bytes, or has ended.
Bytes readBytes( ByteSource& source, size_t n )
{
    Bytes got;
    uint8_t buffer[ 4096 ];
    while ( got.size() < n ) {
        const auto read = source.read( buffer, sizeof buffer );
        if ( read == 0 ) {
            break;
        }
        got.insert( got.end(), buffer, buffer + read );
    }
    return got;
}

} // namespace

SCENARIO( "A capture is read from a pipe the plugin made: a FIFO, or a named pipe on Windows",
          "[extcap_source]" )
{
    QTemporaryDir root;
    const auto capture
        = pcapOf( { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 1, 2, text( "hi" ) ) ) ) } );
    std::atomic_bool stop{ false };
    QString pipePath;
    auto source = std::make_unique<PipeSource>(
        [ & ]( const QString& path ) {
            pipePath = path;
            auto command = sleeper();
            command.arguments << "--fifo" << path; // as an extcap is given it
            return command;
        },
        &stop );
    REQUIRE_FALSE( pipePath.isEmpty() );
    REQUIRE( source->process()->started() );
#ifdef Q_OS_WIN
    REQUIRE( pipePath.startsWith( "\\\\.\\pipe\\logsquirl-tcpdump-" ) );
#else
    REQUIRE( QFileInfo( pipePath ).fileName() == "capture.fifo" );
    REQUIRE( QFileInfo( QFileInfo( pipePath ).path() ).permissions()
             == ( QFileDevice::ReadOwner | QFileDevice::WriteOwner | QFileDevice::ExeOwner
                  | QFileDevice::ReadUser | QFileDevice::WriteUser | QFileDevice::ExeUser ) );
#endif

    WHEN( "nothing is written yet" )
    {
        THEN( "the stream has not ended" )
        {
            REQUIRE_FALSE( source->ready() );
        }
    }

    WHEN( "a writer writes the capture and closes the pipe" )
    {
        std::thread writer( [ & ] { writeIntoPipe( pipePath, capture ); } );
        const auto got = readBytes( *source, capture.size() );
        writer.join();

        THEN( "its bytes are read as they were written" )
        {
            REQUIRE( got == capture );
        }

        AND_WHEN( "Stop is pressed" )
        {
            stop = true;
            uint8_t byte = 0;
            REQUIRE( source->read( &byte, 1 ) == 0 );

            THEN( "the stream reads as stopped, and the program and the pipe go with it" )
            {
                REQUIRE( source->stopped() );
                REQUIRE( source->error().empty() );
                source.reset();
#ifndef Q_OS_WIN
                REQUIRE_FALSE( QFileInfo::exists( QFileInfo( pipePath ).path() ) );
#endif
            }
        }
    }
}

#ifdef Q_OS_UNIX

namespace {

/**
 * A directory of fake extcaps: `fakedump` logs each call (its arguments,
 * each in brackets) and answers the protocol from files: its interfaces
 * from interfaces.txt, an interface's arguments from config-<if>.txt, its
 * link type; a capture writes capture.pcap into the FIFO it is given and,
 * if hang exists, runs until it is ended; if fail exists, it fails.
 * `brokendump` fails every call.
 */
struct FakeExtcaps {
    QTemporaryDir dir;

    FakeExtcaps()
    {
        REQUIRE( dir.isValid() );
        REQUIRE( QDir( dir.path() ).mkpath( "extcap" ) );
        writeScript( path( "extcap/fakedump" ),
                     QString( "d='%1'\n"
                              "for a in \"$@\"; do printf '[%s]' \"$a\"; done >>\"$d/calls.log\"\n"
                              "echo >>\"$d/calls.log\"\n"
                              "mode=; ifc=; fifo=\n"
                              "while [ $# -gt 0 ]; do\n"
                              "  case \"$1\" in\n"
                              "  --extcap-interfaces) mode=interfaces ;;\n"
                              "  --extcap-config) mode=config ;;\n"
                              "  --extcap-dlts) mode=dlts ;;\n"
                              "  --capture) mode=capture ;;\n"
                              "  --extcap-interface) shift; ifc=\"$1\" ;;\n"
                              "  --fifo) shift; fifo=\"$1\" ;;\n"
                              "  esac\n"
                              "  shift\n"
                              "done\n"
                              "case \"$mode\" in\n"
                              "interfaces) cat \"$d/interfaces.txt\" ;;\n"
                              "config) cat \"$d/config-$ifc.txt\" ;;\n"
                              "dlts) echo 'dlt {number=1}{name=EN10MB}{display=Ethernet}' ;;\n"
                              "capture)\n"
                              "  if [ -f \"$d/fail\" ]; then echo 'fakedump: cannot reach the "
                              "host' >&2; exit 1; fi\n"
                              "  trap 'echo killed >>\"$d/calls.log\"; exit 0' TERM\n"
                              "  echo 'fakedump: capturing' >&2\n"
                              "  echo 'debug output on stdout'\n"
                              "  cat \"$d/capture.pcap\" >\"$fifo\"\n"
                              "  if [ -f \"$d/hang\" ]; then while :; do sleep 0.05; done; fi ;;\n"
                              "esac\n"
                              "exit 0" )
                         .arg( dir.path() ) );
        writeScript( path( "extcap/brokendump" ), "echo 'brokendump: no libfoo' >&2; exit 3" );
        writeFile( path( "interfaces.txt" ),
                   text( "extcap {version=1.0}{help=https://example.org}\n"
                         "interface {value=fake0}{display=Fake capture}\n"
                         "interface {value=fake1}{display=Other fake}\n" ) );
        writeFile( path( "config-fake0.txt" ), text( kConfig ) );
        writeFile( path( "config-fake1.txt" ),
                   text( "arg {number=0}{call=--level}{display=Level}{type=integer}\n" ) );
        writeFile( path( "capture.pcap" ), capture() );
    }

    QString path( const QString& name ) const
    {
        return dir.filePath( name );
    }

    static Bytes capture()
    {
        return pcapOf(
            { eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999, text( "one" ) ) ) ),
              eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, 9999, text( "two" ) ) ) ) } );
    }

    std::shared_ptr<ExtcapSourceKind> kind() const
    {
        ExtcapPlaces places;
        places.os = CaptureOs::Linux;
        places.directories = { path( "extcap" ) };
        return std::make_shared<ExtcapSourceKind>( places );
    }

    QString calls() const
    {
        return readText( path( "calls.log" ) );
    }

    /// The calls that captured.
    QStringList captures() const
    {
        return calls().split( '\n' ).filter( "[--capture]" );
    }
};

std::shared_ptr<LiveSourceRegistry> registryOf( std::shared_ptr<const LiveSourceKind> kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( std::move( kind ) );
    return registry;
}

/// A sidebar with the extcap source of @p extcaps, below @p tempRoot.
std::unique_ptr<SidebarWidget> sidebarFor( const FakeExtcaps& extcaps,
                                           const QTemporaryDir& tempRoot )
{
    auto sidebar = std::make_unique<SidebarWidget>();
    sidebar->setTempRoot( tempRoot.path() );
    sidebar->setLiveSources( registryOf( extcaps.kind() ) );
    REQUIRE( waitFor( [ & ] { return !sidebar->liveForm()->isListing(); } ) );
    return sidebar;
}

/// The extcap options widget below @p parent, once it has its arguments.
ExtcapOptionsWidget* optionsOf( QWidget* parent )
{
    ExtcapOptionsWidget* options = nullptr;
    REQUIRE( waitFor( [ & ] {
        options = parent->findChild<ExtcapOptionsWidget*>( "extcapOptions" );
        return options && !options->isListing() && !options->config().args.empty();
    } ) );
    return options;
}

} // namespace

SCENARIO( "The extcap source lists extcaps, their interfaces and an interface's arguments",
          "[extcap_source]" )
{
    FakeExtcaps extcaps;
    const auto kind = extcaps.kind();

    THEN( "each extcap is a device, one whose --extcap-interfaces fails with why" )
    {
        const auto listing = kind->listDevices( LiveSourceKind::kListTimeout );
        REQUIRE( listing.error.isEmpty() );
        REQUIRE( listing.targets.size() == 2 );
        REQUIRE( listing.targets[ 0 ].id == "brokendump" );
        REQUIRE( listing.targets[ 0 ].problem.contains( "exited with code 3" ) );
        REQUIRE( listing.targets[ 0 ].problem.contains( "no libfoo" ) );
        REQUIRE( listing.targets[ 1 ].id == "fakedump" );
        REQUIRE( listing.targets[ 1 ].problem.isEmpty() );
        REQUIRE( listing.targets[ 1 ].description == "Fake capture, Other fake (1.0)" );
    }

    THEN( "an extcap's interfaces are those it reports" )
    {
        const auto listing = kind->listInterfaces( "fakedump", LiveSourceKind::kListTimeout );
        REQUIRE( listing.error.isEmpty() );
        REQUIRE( listing.targets.size() == 2 );
        REQUIRE( listing.targets[ 0 ].id == "fake0" );
        REQUIRE( listing.targets[ 0 ].description == "Fake capture" );
        REQUIRE( kind->listInterfaces( "brokendump", LiveSourceKind::kListTimeout )
                     .error.contains( "no libfoo" ) );
        REQUIRE( kind->listInterfaces( "gone", LiveSourceKind::kListTimeout )
                     .error.contains( "not in the extcap directories" ) );
    }

    THEN( "an interface's arguments and link type are asked for it" )
    {
        const auto config = kind->config( "fakedump", "fake0", LiveSourceKind::kListTimeout );
        REQUIRE( config.error.isEmpty() );
        REQUIRE( config.args.size() == 14 );
        REQUIRE( config.dlts.size() == 1 );
        REQUIRE( config.dlts[ 0 ].name == "EN10MB" );
        REQUIRE( extcaps.calls().contains( "[--extcap-interface][fake0][--extcap-config]" ) );
        REQUIRE( extcaps.calls().contains( "[--extcap-interface][fake0][--extcap-dlts]" ) );
    }

    THEN( "a choice needs an extcap that is there, and an interface" )
    {
        REQUIRE( kind->validate( { "extcap", "", "fake0", "", 96 } ) == "Choose an extcap." );
        REQUIRE( kind->validate( { "extcap", "gone", "fake0", "", 96 } )
                     .contains( "not in the extcap directories" ) );
        REQUIRE_FALSE( kind->validate( { "extcap", "fakedump", "", "", 96 } ).isEmpty() );
        REQUIRE( kind->validate( { "extcap", "fakedump", "fake0", "", 96 } ).isEmpty() );
    }
}

SCENARIO( "An extcap interface's arguments are a form whose values reach the command line",
          "[extcap_source]" )
{
    FakeHost host;
    FakeExtcaps extcaps;
    QTemporaryDir tempRoot;
    auto sidebar = sidebarFor( extcaps, tempRoot );
    auto* form = sidebar->liveForm();
    REQUIRE( waitFor( [ & ] { return form->choice().networkInterface == "fake0"; } ) );
    REQUIRE( form->choice().device == "fakedump" );
    auto* options = optionsOf( sidebar.get() );

    THEN( "each argument has a field of its type, showing its default" )
    {
        REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--remote-host" ) );
        REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--remote-port" )->text() == "22" );
        REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--ratio" )->text() == "0.5" );
        REQUIRE( sidebar->findChild<QCheckBox*>( "extcapArg--verbose" )->isChecked() );
        REQUIRE_FALSE( sidebar->findChild<QCheckBox*>( "extcapArg--promisc" )->isChecked() );
        REQUIRE( sidebar->findChild<QComboBox*>( "extcapArg--if" )->currentData() == "wlan0" );
        REQUIRE( sidebar->findChild<QRadioButton*>( "extcapArg--mode=slow" )->isChecked() );
        auto* channels = sidebar->findChild<QListWidget*>( "extcapArg--channels" );
        REQUIRE( channels->count() == 3 );
        REQUIRE( channels->item( 0 )->checkState() == Qt::Checked );
        REQUIRE( channels->item( 1 )->checkState() == Qt::Unchecked );
        REQUIRE( channels->item( 2 )->text() == "  Three" );
        REQUIRE( sidebar->findChild<QComboBox*>( "extcapArg--sink" )->isEditable() );
        REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--keyfilePath" ) );
        REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--password" )->echoMode()
                 == QLineEdit::Password );
        REQUIRE_FALSE( sidebar->findChild<QWidget*>( "extcapArg--fifo" ) );
        REQUIRE( sidebar->findChild<QLabel*>( "extcapStatus" )->text().contains( "EN10MB" ) );
    }

    THEN( "a required argument left empty keeps Start disabled" )
    {
        REQUIRE( form->problem() == "Remote host is required." );
        REQUIRE_FALSE( sidebar->findChild<QPushButton*>( "liveStartButton" )->isEnabled() );
    }

    WHEN( "the fields are filled" )
    {
        QTemporaryDir files;
        const auto keyFile = files.filePath( "key" );
        writeFile( keyFile, text( "k" ) );
        sidebar->findChild<QLineEdit*>( "extcapArg--remote-host" )->setText( "it's $(rm -rf ~)" );
        sidebar->findChild<QLineEdit*>( "extcapArg--remote-port" )->setText( "2222" );
        sidebar->findChild<QLineEdit*>( "extcapArg--big" )->setText( "-5000000000" );
        sidebar->findChild<QCheckBox*>( "extcapArg--verbose" )->setChecked( false );
        sidebar->findChild<QCheckBox*>( "extcapArg--promisc" )->setChecked( true );
        sidebar->findChild<QComboBox*>( "extcapArg--if" )->setCurrentIndex( 0 );
        sidebar->findChild<QRadioButton*>( "extcapArg--mode=fast" )->setChecked( true );
        sidebar->findChild<QListWidget*>( "extcapArg--channels" )
            ->item( 1 )
            ->setCheckState( Qt::Checked );
        sidebar->findChild<QComboBox*>( "extcapArg--sink" )->setEditText( "typed sink" );
        sidebar->findChild<QLineEdit*>( "extcapArg--keyfilePath" )->setText( keyFile );
        sidebar->findChild<QLineEdit*>( "extcapArg--password" )->setText( "s3cret" );

        THEN( "Start is enabled, and the command passes each value as one word" )
        {
            REQUIRE( form->problem().isEmpty() );
            const auto choice = form->choice();
            const auto arguments = extcaps.kind()->command( choice ).arguments;
            for ( const QString& expected :
                  QStringList{ "--remote-host=it's $(rm -rf ~)", "--remote-port=2222", "--count=-1",
                               "--big=-5000000000", "--ratio=0.5", "--promisc=true", "--if=eth0",
                               "--mode=fast", "--channels=1,2,3", "--sink=typed sink",
                               "--keyfile=" + keyFile, "--password=s3cret" } ) {
                CAPTURE( expected );
                REQUIRE( arguments.contains( expected ) );
            }
            REQUIRE_FALSE( arguments.contains( "--verbose" ) );
            REQUIRE_FALSE( arguments.join( ' ' ).contains( "--token" ) );
        }

        THEN( "a value out of range, or not a number, is pointed out" )
        {
            auto* port = sidebar->findChild<QLineEdit*>( "extcapArg--remote-port" );
            port->setText( "70000" );
            REQUIRE( form->problem() == "Port must be from 1 to 65535." );
            port->setText( "-1" );
            REQUIRE( form->problem() == "Port must be a whole number, not negative." );
            port->setText( "22" );
            sidebar->findChild<QLineEdit*>( "extcapArg--count" )->setText( "3000000000" );
            REQUIRE( form->problem() == "Count must be a whole number." );
            sidebar->findChild<QLineEdit*>( "extcapArg--count" )->setText( "1" );
            sidebar->findChild<QLineEdit*>( "extcapArg--keyfilePath" )
                ->setText( files.filePath( "missing" ) );
            REQUIRE( form->problem().contains( "does not exist" ) );
        }

        AND_WHEN( "the capture is started" )
        {
            REQUIRE( sidebar->startLiveCapture( form->choice() ) );
            REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

            THEN( "the password reached the extcap but not settings.ini" )
            {
                REQUIRE( extcaps.captures().size() == 1 );
                REQUIRE( extcaps.captures().front().contains( "[--password=s3cret]" ) );
                const auto written = readText( settingsFilePath( host.configDir() ) );
                REQUIRE( written.contains( "2222" ) );
                REQUIRE_FALSE( written.contains( "s3cret" ) );
            }

            THEN( "after a restart the options are shown again, but the password is not" )
            {
                SidebarWidget restarted;
                restarted.setTempRoot( tempRoot.path() );
                restarted.setLiveSources( registryOf( extcaps.kind() ) );
                optionsOf( &restarted );
                REQUIRE( restarted.findChild<QLineEdit*>( "extcapArg--remote-port" )->text()
                         == "2222" );
                REQUIRE(
                    restarted.findChild<QLineEdit*>( "extcapArg--password" )->text().isEmpty() );
            }
        }
    }

    WHEN( "another interface is chosen" )
    {
        auto* interfaces = sidebar->findChild<QComboBox*>( "liveInterface" );
        sidebar->findChild<QLineEdit*>( "extcapArg--remote-host" )->setText( "kept" );
        interfaces->setCurrentIndex( 1 );
        REQUIRE( waitFor(
            [ & ] { return !options->isListing() && options->config().args.size() == 1; } ) );

        THEN( "its own arguments are shown, and the first interface's options are kept" )
        {
            REQUIRE( sidebar->findChild<QLineEdit*>( "extcapArg--level" ) );
            REQUIRE_FALSE( sidebar->findChild<QLineEdit*>( "extcapArg--remote-host" ) );
            const auto choice = form->choice();
            REQUIRE( choice.options.value( "fake0:--remote-host" ) == "kept" );
            REQUIRE( extcaps.kind()->command( choice ).arguments
                     == QStringList{ "--capture", "--extcap-interface", "fake1" } );
        }
    }
}

SCENARIO( "The extcap source captures live through a FIFO", "[extcap_source]" )
{
    FakeHost host;
    FakeExtcaps extcaps;
    QTemporaryDir tempRoot;
    const auto marker = extcaps.path( "pwned" );
    LiveChoice choice{ "extcap", "fakedump", "fake0", "udp port 9999", 4096 };
    choice.options = { { "fake0:--remote-host", QString( "x'; touch %1; echo '" ).arg( marker ) },
                       { "fake0:--sink", QString( "$(touch %1)" ).arg( marker ) },
                       { "fake0?--verbose", "true" } };

    GIVEN( "an extcap that writes its capture and exits" )
    {
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "the capture is converted, its bytes as they were written" )
        {
            REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
            REQUIRE( host.openedFiles.size() == 1 );
            const QFileInfo log( host.openedFiles.first() );
            REQUIRE( log.fileName() == "fakedump-fake0.log" );
            QFile raw( log.dir().filePath( "fakedump-fake0.pcap" ) );
            REQUIRE( raw.open( QIODevice::ReadOnly ) );
            const auto bytes = raw.readAll();
            REQUIRE( Bytes( bytes.begin(), bytes.end() ) == FakeExtcaps::capture() );
        }

        THEN( "the extcap got the protocol's arguments and each value as one word, and no "
              "shell ran them" )
        {
            REQUIRE( extcaps.captures().size() == 1 );
            const auto call = extcaps.captures().front();
            REQUIRE( call.startsWith( "[--capture][--extcap-interface][fake0][--fifo][" ) );
            REQUIRE( call.contains( "/capture.fifo][--extcap-capture-filter][udp port 9999]" ) );
            REQUIRE(
                call.contains( QString( "[--remote-host=x'; touch %1; echo ']" ).arg( marker ) ) );
            REQUIRE( call.contains( QString( "[--sink=$(touch %1)]" ).arg( marker ) ) );
            REQUIRE( call.contains( "[--verbose]" ) );
            REQUIRE_FALSE( call.contains( "--extcap-control" ) );
            REQUIRE_FALSE( QFileInfo::exists( marker ) );
        }

        THEN( "its stderr is shown, its stdout is not taken for the capture, and the FIFO is gone" )
        {
            REQUIRE( sidebar->findChild<QPlainTextEdit*>( "liveStderr" )
                         ->toPlainText()
                         .contains( "fakedump: capturing" ) );
            const auto call = extcaps.captures().front();
            const auto fifo = call.section( "[--fifo][", 1 ).section( ']', 0, 0 );
            REQUIRE( fifo.endsWith( "/capture.fifo" ) );
            REQUIRE( waitFor( [ & ] { return !QFileInfo::exists( QFileInfo( fifo ).path() ); } ) );
        }
    }

    GIVEN( "an extcap that runs until it is stopped" )
    {
        writeFile( extcaps.path( "hang" ), {} );
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return host.openedFiles.size() == 1; } ) );
        const auto fifo
            = extcaps.captures().value( 0 ).section( "[--fifo][", 1 ).section( ']', 0, 0 );
        REQUIRE( QFileInfo::exists( fifo ) );

        sidebar->stopLiveCapture();
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "Stop ends the extcap and removes the FIFO, and the capture is kept" )
        {
            REQUIRE( waitFor( [ & ] { return extcaps.calls().contains( "killed" ); } ) );
            REQUIRE( waitFor( [ & ] { return !QFileInfo::exists( QFileInfo( fifo ).path() ); } ) );
            REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
        }
    }

    GIVEN( "an extcap that runs on, and a capture that stops after a packet" )
    {
        writeFile( extcaps.path( "hang" ), {} );
        choice.limits.packets = 1;
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "the capture stops by itself, as for any source, and ends the extcap" )
        {
            REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
            REQUIRE( host.notifications.size() == 1 );
            REQUIRE( host.notifications.first().contains( "stopped after 1 packets" ) );
            REQUIRE( waitFor( [ & ] { return extcaps.calls().contains( "killed" ); } ) );
            REQUIRE( host.openedFiles.size() == 1 );
            REQUIRE( readText( host.openedFiles.first() ).count( "UDP" ) == 1 );
        }
    }

    GIVEN( "an extcap whose capture fills a ring buffer of one file" )
    {
        choice.limits.ringFiles = 1;
        choice.limits.fileBytes = 1;
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "the raw capture is split, only the newest file kept, each file's text in a tab" )
        {
            REQUIRE( sidebar->findChild<QLabel*>( "liveError" )->isHidden() );
            REQUIRE( host.openedFiles.size() == 2 );
            const QFileInfo log( host.openedFiles.last() );
            const auto files = log.dir().entryList( { "fakedump-fake0_*.pcap" }, QDir::Files );
            REQUIRE( files.size() == 1 );
            REQUIRE( files.first().startsWith( "fakedump-fake0_00002_" ) );
            REQUIRE( log.fileName().startsWith( "fakedump-fake0_00002_" ) );
            const auto text = readText( log.filePath() );
            REQUIRE( text.count( "UDP" ) == 1 );
            REQUIRE( text.contains( "two" ) );
            // The first file's text stays as it was.
            REQUIRE( readText( host.openedFiles.first() ).count( "UDP" ) == 1 );
        }
    }

    GIVEN( "an extcap that writes something else than a capture into the FIFO" )
    {
        writeFile( extcaps.path( "capture.pcap" ), text( "usage: fakedump [options]\n" ) );
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "it is not a capture, with what the extcap wrote on stderr" )
        {
            const auto error = sidebar->findChild<QLabel*>( "liveError" )->text();
            REQUIRE( error.contains( "Not a capture" ) );
            REQUIRE( error.contains( "fakedump: capturing" ) );
            REQUIRE( host.openedFiles.isEmpty() );
        }
    }

    GIVEN( "an extcap that fails" )
    {
        writeFile( extcaps.path( "fail" ), {} );
        auto sidebar = sidebarFor( extcaps, tempRoot );
        REQUIRE( sidebar->startLiveCapture( choice ) );
        REQUIRE( waitFor( [ & ] { return !sidebar->isCapturing(); } ) );

        THEN( "its exit code and stderr are the error" )
        {
            const auto text = sidebar->findChild<QLabel*>( "liveError" )->text();
            REQUIRE( text.contains( "fakedump exited with code 1" ) );
            REQUIRE( text.contains( "cannot reach the host" ) );
            REQUIRE( host.openedFiles.isEmpty() );
        }
    }
}

#endif
