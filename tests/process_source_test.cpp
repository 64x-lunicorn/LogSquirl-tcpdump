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
 * @file process_source_test.cpp
 * @brief BDD tests for the Process Source: a capture program run as tcpdump
 *        would be, its stdout converted, its stderr shown, its group ended.
 *
 * The capture programs are fake: shell scripts that write a synthetic pcap
 * to stdout and text to stderr, exit with an error, crash, start a child,
 * ignore SIGTERM.  They need a Unix shell; on Windows only the line
 * splitting of stderr is tested (the job object is built there, not run).
 */

#include <catch2/catch.hpp>

#include "process_source.h"

#include <QtGlobal>

using namespace tcpdump;

SCENARIO( "A program's stderr is split into lines, the last ones kept", "[process_source]" )
{
    GIVEN( "lines that come in pieces, with Unix and Windows line ends and blank lines" )
    {
        QStringList handedOn;
        StderrLines lines( [ &handedOn ]( const QString& line ) { handedOn << line; } );
        lines.append( "tcpdump: listen" );
        lines.append( "ing on eth0\r\n\n  \nsecond" );
        REQUIRE( handedOn == QStringList{ "tcpdump: listening on eth0" } );
        lines.append( " line\nno end" );
        lines.finish();

        THEN( "each complete line is handed on once, without its line end" )
        {
            REQUIRE( handedOn
                     == QStringList{ "tcpdump: listening on eth0", "second line", "no end" } );
            REQUIRE( lines.last() == handedOn );
        }
    }

    GIVEN( "more lines than are kept, and a line without end longer than any" )
    {
        StderrLines lines;
        for ( size_t i = 0; i < StderrLines::kKept + 5; ++i ) {
            lines.append( QByteArray::number( qulonglong( i ) ) + '\n' );
        }
        THEN( "the last ones are kept, the latest last" )
        {
            REQUIRE( lines.last().size() == static_cast<qsizetype>( StderrLines::kKept ) );
            REQUIRE( lines.last().first() == "5" );
            REQUIRE( lines.last().last() == QString::number( StderrLines::kKept + 4 ) );
        }
        lines.append( QByteArray( 10000, 'x' ) );
        THEN( "a line that does not end is handed on in pieces, not held" )
        {
            REQUIRE( lines.last().last() == QString( 4096, 'x' ) );
        }
    }
}

SCENARIO( "A command names its program", "[process_source]" )
{
    REQUIRE( ProcessCommand{ "/usr/sbin/tcpdump", {} }.displayName() == "tcpdump" );
    REQUIRE( ProcessCommand{ "adb", {}, "adb on Pixel" }.displayName() == "adb on Pixel" );
    const auto shell = ProcessCommand::shell( "  ssh router tcpdump -w - | tee x.pcap" );
    REQUIRE( shell.viaShell );
    REQUIRE( shell.displayName() == "ssh" );
}

SCENARIO( "A batch file's arguments that cmd.exe would read are refused", "[process_source]" )
{
    GIVEN( "a batch file, as Windows runs it through cmd.exe" )
    {
        for ( const auto* program : { "C:/extcap/dump.bat", "C:/extcap/DUMP.CMD" } ) {
            CAPTURE( program );

            THEN( "a plain argument passes" )
            {
                REQUIRE( batchArgumentProblem(
                             { program, { "--capture", "host 10.0.0.1 and port 443" } } )
                             .isEmpty() );
            }

            THEN( "every character cmd.exe reads in an argument, quoted or not, is refused" )
            {
                for ( const auto* hostile : { "x & calc", "x | calc", "x > out", "x < in", "%PATH%",
                                              "!x!", "a^b", "(x)", "\"x\" & calc", "x\r\ncalc" } ) {
                    CAPTURE( hostile );
                    const auto problem
                        = batchArgumentProblem( { program, { "--capture-filter", hostile } } );
                    REQUIRE( problem.contains( "is a batch file" ) );
                }
            }
        }
    }

    THEN( "a program that is no batch file, or a command for the shell, is not checked" )
    {
        REQUIRE( batchArgumentProblem( { "C:/extcap/dump.exe", { "x & calc" } } ).isEmpty() );
        REQUIRE( batchArgumentProblem( ProcessCommand::shell( "dump.bat x & calc" ) ).isEmpty() );
    }
}

#ifdef Q_OS_UNIX

#include "pcap_converter.h"
#include "pcapbuilder.h"
#include "plugin.h"
#include "stream_capture.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <csignal>
#include <mutex>
#include <thread>

#include <cerrno>
#include <signal.h>

extern "C" int logsquirl_plugin_init( const LogSquirlHostApi* api, void* handle );
extern "C" void logsquirl_plugin_shutdown( void );

#include "fakehost.h"

using namespace tcpdump_test;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

namespace {

/// A fake capture program: a shell script @p name in @p dir running @p body.
QString fakeProgram( const QTemporaryDir& dir, const QString& name, const QString& body )
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

/// Whether the process @p pid is gone, waiting up to a second for it: an
/// orphan is reaped by init, not at once.
bool gone( qint64 pid )
{
    const auto until = Clock::now() + milliseconds( 1000 );
    while ( ::kill( static_cast<pid_t>( pid ), 0 ) == 0 && Clock::now() < until ) {
        std::this_thread::sleep_for( milliseconds( 10 ) );
    }
    return ::kill( static_cast<pid_t>( pid ), 0 ) != 0 && errno == ESRCH;
}

/// The child's pid that a line of stderr names ("child <pid>"), handed on
/// on another thread.  A fake program names it once it is ready: after it
/// has written what the test needs, so that the test waits on that line, not
/// on time.
class Collected {
public:
    /// @param onChild  If set, called with the pid as it is named, on the
    ///                 thread that reads the stream.
    explicit Collected( std::function<void()> onChild = {} )
        : onChild_( std::move( onChild ) )
    {
    }

    std::function<void( const QString& )> sink()
    {
        return [ this ]( const QString& line ) {
            if ( !line.startsWith( "child " ) ) {
                return;
            }
            {
                const std::lock_guard<std::mutex> lock( mutex_ );
                child_ = line.mid( 6 ).toLongLong();
            }
            if ( onChild_ ) {
                onChild_();
            }
        };
    }

    /// The child's pid, once it has been named; 0 after 20 s without (a
    /// deadline for a broken test only: a loaded machine gets there sooner).
    qint64 child()
    {
        const auto until = Clock::now() + milliseconds( 20000 );
        while ( Clock::now() < until ) {
            {
                const std::lock_guard<std::mutex> lock( mutex_ );
                if ( child_ != 0 ) {
                    return child_;
                }
            }
            std::this_thread::sleep_for( milliseconds( 5 ) );
        }
        return 0;
    }

private:
    std::function<void()> onChild_;
    std::mutex mutex_;
    qint64 child_ = 0;
};

} // namespace

SCENARIO( "A capture program's stdout is the capture and its stderr is shown", "[process_source]" )
{
    QTemporaryDir dir;
    const auto capture = pcapOf( somePackets() );
    const auto pcapPath = dir.filePath( "fake.pcap" );
    writeFile( pcapPath, capture );

    GIVEN( "a program that writes a pcap to stdout in parts and talks on stderr between them" )
    {
        const auto program
            = fakeProgram( dir, "fake-tcpdump",
                           "echo 'tcpdump: listening on fake0, link-type EN10MB (Ethernet)' >&2\n"
                           "head -c 30 \"$1\"; sleep 0.1\n"
                           "echo 'still capturing' >&2\n"
                           "tail -c +31 \"$1\"\n"
                           "printf '4 packets captured' >&2" );
        QStringList handedOn;
        ProcessSource source( { program, { pcapPath } }, nullptr,
                              [ &handedOn ]( const QString& line ) { handedOn << line; } );
        QTemporaryDir out;
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture converts as the file does, and every stderr line is handed on" )
        {
            REQUIRE( source.started() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( readLines( result.outputPath ) == linesFromFile( capture ) );
            const QStringList expected{ "tcpdump: listening on fake0, link-type EN10MB (Ethernet)",
                                        "still capturing", "4 packets captured" };
            REQUIRE( handedOn == expected );
            REQUIRE( source.lastStderrLines() == expected );
        }
    }

    GIVEN( "arguments with spaces, quotes and shell syntax" )
    {
        const QStringList arguments{ "with space", "\"double\" 'single'", "$(touch pwned)",
                                     "a;b|c > d", "*" };
        const auto program = fakeProgram( dir, "args",
                                          "for a in \"$@\"; do printf '%s\\n' \"$a\" >&2; done\n"
                                          "cat \"$1\"" );
        QStringList handedOn;
        ProcessSource source( { program, QStringList{ pcapPath } + arguments }, nullptr,
                              [ &handedOn ]( const QString& line ) { handedOn << line; } );
        QTemporaryDir out;
        const auto result = convertStream( source, "live", out.path() );

        THEN( "each reaches the program as one argument, untouched by a shell" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( handedOn == QStringList{ pcapPath } + arguments );
            REQUIRE_FALSE( QFile::exists( "pwned" ) );
            REQUIRE_FALSE( QFile::exists( dir.filePath( "pwned" ) ) );
        }
    }

    GIVEN( "a custom command that opts into the shell" )
    {
        auto command = ProcessCommand::shell(
            QStringLiteral( "echo piped >&2; cat '%1' | cat" ).arg( pcapPath ) );
        QStringList handedOn;
        ProcessSource source( command, nullptr,
                              [ &handedOn ]( const QString& line ) { handedOn << line; } );
        QTemporaryDir out;
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the shell runs it" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == somePackets().size() );
            REQUIRE( handedOn == QStringList{ "piped" } );
        }
    }
}

SCENARIO( "A capture program that fails says why", "[process_source]" )
{
    QTemporaryDir dir;
    QTemporaryDir out;

    GIVEN( "a program that cannot be started" )
    {
        ProcessSource source( { dir.filePath( "no-such-tcpdump" ), {} } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture fails, naming the program" )
        {
            REQUIRE_FALSE( source.started() );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "Cannot start no-such-tcpdump" ) );
            REQUIRE( QDir( out.path() ).isEmpty() );
        }
    }

    GIVEN( "a program that complains and exits with code 1 before any capture" )
    {
        const auto program = fakeProgram( dir, "fake-tcpdump",
                                          "echo 'tcpdump: fake9: No such device exists' >&2\n"
                                          "echo '(SIOCGIFHWADDR: No such device)' >&2\n"
                                          "exit 1" );
        ProcessSource source( { program, {} } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture fails with the program, the exit code and the last stderr lines" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "fake-tcpdump exited with code 1" ) );
            REQUIRE( result.error.contains( "tcpdump: fake9: No such device exists\n"
                                            "(SIOCGIFHWADDR: No such device)" ) );
        }
    }

    GIVEN( "a program that exits with code 2 in the middle of a capture" )
    {
        const auto capture = pcapOf( somePackets() );
        writeFile( dir.filePath( "fake.pcap" ), capture );
        const auto program = fakeProgram( dir, "fake-dumpcap",
                                          "head -c 100 \"$1\"\n"
                                          "echo 'dumpcap: interface went down' >&2\n"
                                          "exit 2" );
        ProcessSource source( { program, { dir.filePath( "fake.pcap" ) } } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture fails with the exit code" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "fake-dumpcap exited with code 2" ) );
            REQUIRE( result.error.contains( "dumpcap: interface went down" ) );
        }
    }

    GIVEN( "a program that writes text, not a capture, to stdout and exits with 0" )
    {
        const auto program = fakeProgram( dir, "not-a-capture",
                                          "echo 'usage: not-a-capture [-w file]' >&2\n"
                                          "echo 'writing to the terminal instead' >&2\n"
                                          "i=0; while [ $i -lt 20 ]; do echo 'Hello, world'; "
                                          "i=$((i+1)); done" );
        ProcessSource source( { program, {} } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture fails as not a capture, with the program's last stderr lines" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.startsWith( "Not a capture: " ) );
            REQUIRE( result.error.contains( "no pcap magic" ) );
            REQUIRE( result.error.contains( "not-a-capture wrote on stderr:\n"
                                            "usage: not-a-capture [-w file]\n"
                                            "writing to the terminal instead" ) );
        }
    }

    GIVEN( "a program that writes more text than a preamble may be, and runs on" )
    {
        const auto program = fakeProgram( dir, "chatty",
                                          "echo 'chatty: started' >&2\n"
                                          "while :; do echo 'not pcap, just text'; done" );
        ProcessSource source( { program, {} } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "it fails as not a capture without waiting for the program to end" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.startsWith( "Not a capture: " ) );
            REQUIRE( result.error.contains( "chatty: started" ) );
        }
    }

    GIVEN( "a program that crashes" )
    {
        const auto program = fakeProgram( dir, "fake-tcpdump",
                                          "echo 'about to crash' >&2\n"
                                          "kill -SEGV $$" );
        ProcessSource source( { program, {} } );
        const auto result = convertStream( source, "live", out.path() );

        THEN( "the capture fails as a crash, with the code and the last stderr lines" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains(
                QStringLiteral( "fake-tcpdump crashed (exit code %1)" ).arg( SIGSEGV ) ) );
            REQUIRE( result.error.contains( "about to crash" ) );
        }
    }
}

SCENARIO( "Ending a capture program ends what it started", "[process_source]" )
{
    QTemporaryDir dir;
    writeFile( dir.filePath( "header.pcap" ), pcapOf( {} ) );
    const auto args = QStringList{ dir.filePath( "header.pcap" ) };

    GIVEN( "a program that starts a child and waits, having sent a packet" )
    {
        writeFile( dir.filePath( "packet.pcap" ), pcapOf( { somePackets().front() } ) );
        const auto program = fakeProgram( dir, "wrapper",
                                          "sleep 60 &\n"
                                          "echo \"child $!\" >&2\n"
                                          "cat \"$1\"\n"
                                          "wait" );
        Collected stderrLines;
        std::atomic_bool stop{ false };
        ProcessSource source( { program, { dir.filePath( "packet.pcap" ) } }, &stop,
                              stderrLines.sink() );
        // Stop once the packet is converted: the capture has begun.
        LiveObserver live;
        live.firstPacket = [ &stop ]( const QString&, const QString& ) { stop = true; };
        QTemporaryDir out;
        const auto result = convertStream( source, "live", out.path(), nullptr, {}, live );

        WHEN( "the capture is stopped and the program terminated" )
        {
            const auto before = Clock::now();
            source.terminate();
            const auto took = Clock::now() - before;
            const auto child = stderrLines.child(); // all of stderr is read by now

            THEN( "the capture is Converted, and the program and its child end on SIGTERM" )
            {
                REQUIRE( stop );
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( result.summary.packets == 1 );
                REQUIRE( took < milliseconds( 1000 ) );
                REQUIRE( child != 0 );
                REQUIRE( gone( source.processId() ) );
                REQUIRE( gone( child ) );
            }
        }
    }

    GIVEN( "a program that starts a child and waits, and has sent nothing" )
    {
        const auto program = fakeProgram( dir, "silent",
                                          "sleep 60 &\n"
                                          "echo \"child $!\" >&2\n"
                                          "wait" );
        std::atomic_bool stop{ false };
        // Stop once the program has started its child: it is running.
        Collected stderrLines( [ &stop ] { stop = true; } );
        ProcessSource source( { program, {} }, &stop, stderrLines.sink() );
        QTemporaryDir out;
        const auto result = convertStream( source, "live", out.path() );

        WHEN( "the capture is stopped and the program terminated" )
        {
            source.terminate();

            THEN( "it was stopped before anything was captured, not failed, leaving nothing" )
            {
                REQUIRE( source.stopped() );
                REQUIRE( result.status == ConversionResult::Status::Stopped );
                REQUIRE( result.error.isEmpty() );
                REQUIRE( QDir( out.path() ).isEmpty() );
                REQUIRE( gone( source.processId() ) );
                REQUIRE( gone( stderrLines.child() ) );
            }
        }
    }

    GIVEN( "a program and a child that both ignore SIGTERM" )
    {
        const auto program = fakeProgram( dir, "stubborn",
                                          "trap '' TERM\n"
                                          "sleep 60 &\n"
                                          "echo \"child $!\" >&2\n"
                                          "cat \"$1\"\n"
                                          "wait" );
        Collected stderrLines;
        qint64 pid = 0;
        Clock::time_point before;
        {
            ProcessSource source( { program, args }, nullptr, stderrLines.sink() );
            pid = source.processId();
            uint8_t header[ 24 ];
            size_t got = 0;
            while ( got < sizeof header ) { // the traps are set by then
                const auto n = source.read( header + got, sizeof header - got );
                REQUIRE( n > 0 );
                got += n;
            }
            before = Clock::now();
        }
        const auto took = Clock::now() - before;

        THEN( "destroying the source kills them after the grace period" )
        {
            REQUIRE( took >= ProcessSource::kTerminateGrace );
            REQUIRE( took < ProcessSource::kTerminateGrace + milliseconds( 1000 ) );
            REQUIRE( gone( pid ) );
            const auto child = stderrLines.child(); // handed on as the source ended it
            REQUIRE( child != 0 );
            REQUIRE( gone( child ) );
        }
    }
}

SCENARIO( "Shutting the plugin down ends every capture program", "[process_source]" )
{
    QTemporaryDir dir;
    writeFile( dir.filePath( "header.pcap" ), pcapOf( {} ) );
    // The child is named once the header is written (if there is one): it
    // is in the pipe then, and is read even after the program has ended.
    const auto program = fakeProgram( dir, "wrapper",
                                      "sleep 60 &\n"
                                      "[ -n \"$1\" ] && cat \"$1\"\n"
                                      "echo \"child $!\" >&2\n"
                                      "wait" );

    struct Case {
        const char* given;
        QStringList arguments;
        ConversionResult::Status status;
    };
    for ( const auto& c :
          { Case{ "a capture that has sent its header",
                  { dir.filePath( "header.pcap" ) },
                  ConversionResult::Status::Converted },
            Case{
                "a capture that has sent nothing yet", {}, ConversionResult::Status::Stopped } } ) {
        GIVEN( std::string( c.given ) + ", read on a worker thread, running in the plugin" )
        {
            FakeHost host;
            REQUIRE( logsquirl_plugin_init( host.api(), &host ) == 0 );
            Collected stderrLines;
            std::atomic<qint64> pid{ 0 };
            ConversionResult result;
            QTemporaryDir out;
            std::thread worker( [ & ] {
                ProcessSource source( { program, c.arguments }, nullptr, stderrLines.sink() );
                pid = source.processId();
                result = convertStream( source, "live", out.path() );
            } );
            const auto child = stderrLines.child();
            REQUIRE( child != 0 );

            WHEN( "the plugin is shut down (LogSquirl quits or the plugin is disabled)" )
            {
                logsquirl_plugin_shutdown();
                worker.join();

                THEN( "the program and its child are gone, and the capture ends without failing" )
                {
                    REQUIRE( gone( pid ) );
                    REQUIRE( gone( child ) );
                    REQUIRE( result.status == c.status );
                    REQUIRE( result.error.isEmpty() );
                }
            }
            if ( worker.joinable() ) {
                terminateCaptureProcesses();
                worker.join();
            }
            logsquirl_plugin_shutdown();
        }
    }
}

SCENARIO( "Ending a group never signals LogSquirl's own", "[process_source]" )
{
    // A signal to group 0 (kill(-0)) would end this test run with it.
    GIVEN( "a program that could not be started" )
    {
        QProcess process;
        const auto group = newProcessGroup();
        const auto start = startProcess( process, { "/nonexistent/capture-program", {} }, *group,
                                         milliseconds( 5000 ) );
        REQUIRE_FALSE( start.started );
        REQUIRE( start.error.contains( "Cannot start capture-program" ) );

        THEN( "ending its group, at once or after a grace, signals nothing" )
        {
            endProcessGroup( *group, &process, milliseconds( 0 ) );
            endProcessGroup( *group, &process, milliseconds( 50 ) );
            REQUIRE( ::kill( ::getpid(), 0 ) == 0 );
        }
    }

    GIVEN( "a listing whose program has ended as its time is up" )
    {
        QTemporaryDir dir;
        const auto program = fakeProgram( dir, "quick", "exit 0" );
        QProcess process;
        const auto group = newProcessGroup();
        REQUIRE( startProcess( process, { program, {} }, *group, milliseconds( 5000 ) ).started );
        REQUIRE( process.waitForFinished( 5000 ) );
        REQUIRE( process.processId() == 0 ); // reaped: what a kill would have used

        THEN( "ending its group signals nothing of LogSquirl's" )
        {
            endProcessGroup( *group, &process, milliseconds( 0 ) );
            REQUIRE( ::kill( ::getpid(), 0 ) == 0 );
        }
    }
}

#endif // Q_OS_UNIX
