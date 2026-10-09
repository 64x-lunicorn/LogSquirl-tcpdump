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
 * @file live_source_test.cpp
 * @brief BDD tests for the Live Source Kinds' registry and what every kind
 *        shares: the capture filter check, the capture's name, the listing
 *        program, and the choice kept in settings.ini.
 */

#include <catch2/catch.hpp>

#include "fake_live_source.h"
#include "fakehost.h"
#include "live_source.h"
#include "settings.h"

#include <QElapsedTimer>
#include <QFile>
#include <QSettings>
#include <QTemporaryDir>

#include <atomic>
#include <memory>
#include <thread>

using namespace tcpdump;
using namespace tcpdump_test;

SCENARIO( "Live Source Kinds are registered in one place, in order, by id", "[live_source]" )
{
    LiveSourceRegistry registry;
    registry.add( std::make_shared<FakeSourceKind>( "a", "First" ) );
    registry.add( std::make_shared<FakeSourceKind>( "b", "Second" ) );
    registry.add( nullptr );
    REQUIRE( registry.kinds().size() == 2 );
    REQUIRE( registry.find( "b" )->displayName() == "Second" );
    REQUIRE_FALSE( registry.find( "c" ) );

    WHEN( "a kind with an id that is taken is added" )
    {
        registry.add( std::make_shared<FakeSourceKind>( "a", "Replacement" ) );

        THEN( "it replaces the other, in its place" )
        {
            REQUIRE( registry.kinds().size() == 2 );
            REQUIRE( registry.kinds().front()->displayName() == "Replacement" );
        }
    }

    THEN( "the built-in kinds have ids of their own" )
    {
        const auto builtIn = builtInLiveSources();
        REQUIRE( builtIn );
        QStringList ids;
        for ( const auto& kind : builtIn->kinds() ) {
            REQUIRE_FALSE( ids.contains( kind->id() ) );
            ids << kind->id();
        }
    }

    THEN( "a kind needs an interface unless it says otherwise" )
    {
        FakeSourceKind kind;
        LiveChoice choice;
        REQUIRE_FALSE( kind.validate( choice ).isEmpty() );
        choice.networkInterface = "fake0";
        REQUIRE( kind.validate( choice ).isEmpty() );
    }
}

SCENARIO( "A capture filter is checked for what would be misread before BPF", "[live_source]" )
{
    THEN( "BPF passes, and an empty filter captures everything" )
    {
        for ( const auto* filter :
              { "", "  ", "host 10.0.0.1 and tcp port 443", "not port 22",
                "(udp port 53 or tcp port 53) && !host example.com", "ip[0] & 0xf != 5",
                "ether host 00:11:22:33:44:55", "vlan 10 and ip6", "len >= 100" } ) {
            CAPTURE( filter );
            REQUIRE( captureFilterProblem( filter ).isEmpty() );
        }
    }

    THEN( "a line break, a leading '-' and unbalanced parentheses are rejected" )
    {
        REQUIRE( captureFilterProblem( "port 80\nport 81" ).contains( "one line" ) );
        REQUIRE( captureFilterProblem( "-w /tmp/x" ).contains( "option" ) );
        REQUIRE( captureFilterProblem( "(port 80" ).contains( "not closed" ) );
        REQUIRE( captureFilterProblem( "port 80)" ).contains( "no '('" ) );
    }

    THEN( "a Wireshark display filter is named as one" )
    {
        const auto problem = captureFilterProblem( "ip.addr == 10.0.0.1" );
        REQUIRE( problem.contains( "ip.addr" ) );
        REQUIRE( problem.contains( "display filter" ) );
        REQUIRE_FALSE( captureFilterProblem( "tcp.port == 443" ).isEmpty() );
        REQUIRE( captureFilterProblem( "host www.ip.example" ).isEmpty() );
    }
}

SCENARIO( "A live capture is named after its device and interface", "[live_source]" )
{
    LiveChoice choice;
    REQUIRE( liveCaptureName( choice ) == "live" );
    choice.networkInterface = "en0";
    REQUIRE( liveCaptureName( choice ) == "en0" );
    choice.device = "emulator-5554";
    REQUIRE( liveCaptureName( choice ) == "emulator-5554-en0" );
    choice.device = "root@host:2222";
    choice.networkInterface = "\\Device\\NPF_{1234}";
    REQUIRE( liveCaptureName( choice ) == "root_host_2222-_Device_NPF__1234_" );
    choice.device.clear();
    choice.networkInterface = "..";
    REQUIRE( liveCaptureName( choice ) == "_.." );
}

SCENARIO( "The last live capture choice is kept in settings.ini", "[live_source][settings]" )
{
    QTemporaryDir configDir;

    THEN( "without a file, the choice is empty with the default snaplen" )
    {
        const auto choice = loadLiveChoice( configDir.path() );
        REQUIRE( choice == LiveChoice{} );
        REQUIRE( choice.snaplen == 262144 );
        REQUIRE( loadLiveChoice( {} ) == LiveChoice{} );
    }

    WHEN( "a choice is saved" )
    {
        LiveChoice choice{ "fake", "phone 1", "fake1", "udp port 53 and host \"x\"", 1500 };
        REQUIRE( saveLiveChoice( configDir.path(), choice ) );

        THEN( "it is read back, next to the conversion options, without a password" )
        {
            REQUIRE( loadLiveChoice( configDir.path() ) == choice );
            const QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            REQUIRE( file.value( "live/interface" ).toString() == "fake1" );
            for ( const auto& key : file.allKeys() ) {
                REQUIRE_FALSE( key.contains( "pass", Qt::CaseInsensitive ) );
            }
        }
    }

    WHEN( "choices with options are saved for two sources" )
    {
        LiveChoice first{ "a", "", "en0", "", 100, { { "note", "one" }, { "port", "22" } } };
        REQUIRE( saveLiveChoice( configDir.path(), first ) );
        LiveChoice second{ "b", "", "en1", "", 100, { { "note", "two" } } };
        REQUIRE( saveLiveChoice( configDir.path(), second ) );

        THEN( "the last one is read back with its options, and each source keeps its own" )
        {
            REQUIRE( loadLiveChoice( configDir.path() ) == second );
            REQUIRE( loadLiveOptions( configDir.path(), "a" ) == first.options );
            REQUIRE( loadLiveOptions( configDir.path(), "b" ) == second.options );
            REQUIRE( loadLiveOptions( configDir.path(), "c" ).isEmpty() );
            REQUIRE( loadLiveOptions( {}, "a" ).isEmpty() );
        }

        AND_WHEN( "the first source is saved again with fewer options" )
        {
            first.options.remove( "port" );
            REQUIRE( saveLiveChoice( configDir.path(), first ) );

            THEN( "the one left out is gone" )
            {
                REQUIRE( loadLiveOptions( configDir.path(), "a" )
                         == LiveOptions{ { "note", "one" } } );
                REQUIRE( loadLiveOptions( configDir.path(), "b" ) == second.options );
            }
        }
    }

    WHEN( "a choice with stop conditions and a ring buffer is saved" )
    {
        LiveChoice choice{ "fake", "", "fake0", "", 1500 };
        choice.limits.duration = std::chrono::seconds( 3600 );
        choice.limits.packets = 100000;
        choice.limits.bytes = 500 * kMegabyte;
        choice.limits.ringFiles = 5;
        choice.limits.fileBytes = 100 * kMegabyte;
        choice.limits.fileDuration = std::chrono::seconds( 600 );
        REQUIRE( saveLiveChoice( configDir.path(), choice ) );

        THEN( "they are read back, the sizes kept in MB" )
        {
            REQUIRE( loadLiveChoice( configDir.path() ) == choice );
            const QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            REQUIRE( file.value( "live/stopMegabytes" ).toInt() == 500 );
            REQUIRE( file.value( "live/ringFiles" ).toInt() == 5 );
        }

        AND_WHEN( "the file holds values out of range" )
        {
            QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
            file.setValue( "live/ringFiles", 100000 );
            file.setValue( "live/stopSeconds", -5 );
            file.setValue( "live/stopPackets", "many" );
            file.sync();

            THEN( "they are the nearest allowed, or none" )
            {
                const auto limits = loadLiveChoice( configDir.path() ).limits;
                REQUIRE( limits.ringFiles == static_cast<uint32_t>( kMaxRingFiles ) );
                REQUIRE( limits.duration.count() == 0 );
                REQUIRE( limits.packets == 0 );
            }
        }
    }

    WHEN( "the snaplen in the file is out of range or not a number" )
    {
        QSettings file( settingsFilePath( configDir.path() ), QSettings::IniFormat );
        file.setValue( "live/snaplen", 0 );
        file.sync();
        REQUIRE( loadLiveChoice( configDir.path() ).snaplen == 1 );
        file.setValue( "live/snaplen", 10000000 );
        file.sync();
        REQUIRE( loadLiveChoice( configDir.path() ).snaplen == kMaxSnaplen );
        file.setValue( "live/snaplen", "lots" );
        file.sync();
        REQUIRE( loadLiveChoice( configDir.path() ).snaplen == kDefaultSnaplen );
    }

    THEN( "nothing is saved without a directory" )
    {
        REQUIRE_FALSE( saveLiveChoice( {}, LiveChoice{} ) );
    }
}

#ifdef Q_OS_UNIX

namespace {

/// A listing program: a shell script @p name in @p dir running @p body.
QString listingProgram( const QTemporaryDir& dir, const QString& name, const QString& body )
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

} // namespace

SCENARIO( "A listing program is run with a timeout and nothing to answer a prompt with",
          "[live_source]" )
{
    QTemporaryDir dir;

    GIVEN( "a program that lists and exits" )
    {
        const auto program = listingProgram(
            dir, "lister",
            "printf '1.en0 (Wi-Fi)\\n2.lo0 [Loopback]\\n'; echo 'warning: x' >&2; exit 3" );
        const auto output = runListing( { program, {} }, std::chrono::milliseconds( 10000 ) );

        THEN( "its stdout, stderr and exit code are returned" )
        {
            REQUIRE( output.error.isEmpty() );
            REQUIRE( output.out == "1.en0 (Wi-Fi)\n2.lo0 [Loopback]\n" );
            REQUIRE( output.err == "warning: x\n" );
            REQUIRE( output.exitCode == 3 );
        }
    }

    GIVEN( "a program that would ask on stdin" )
    {
        const auto program = listingProgram( dir, "asker",
                                             "if read answer; then echo \"got $answer\"; "
                                             "else echo 'no input'; fi" );
        const auto output = runListing( { program, {} }, std::chrono::milliseconds( 10000 ) );

        THEN( "it reads the end of its input at once" )
        {
            REQUIRE( output.out == "no input\n" );
        }
    }

    GIVEN( "a program, and what it started, that does not finish" )
    {
        const auto marker = dir.filePath( "still-there" );
        const auto program = listingProgram(
            dir, "hang", QString( "(sleep 1; touch '%1') &\nsleep 30" ).arg( marker ) );
        QElapsedTimer took;
        took.start();
        const auto output = runListing( { program, {} }, std::chrono::milliseconds( 300 ) );

        THEN( "it is given up at the timeout, and its group is killed" )
        {
            REQUIRE( took.elapsed() < 5000 );
            REQUIRE( output.error.contains( "did not answer" ) );
            REQUIRE( output.exitCode == -1 );
            QElapsedTimer quiet;
            quiet.start();
            waitFor( [ & ] { return quiet.elapsed() > 1500; } );
            REQUIRE_FALSE( QFile::exists( marker ) );
        }
    }

    GIVEN( "a program that does not finish, and its listing cancelled" )
    {
        const auto program = listingProgram( dir, "hang", "sleep 30" );
        ListingOutput output;
        QElapsedTimer took;
        took.start();
        std::thread lister(
            [ & ] { output = runListing( { program, {} }, std::chrono::milliseconds( 20000 ) ); } );
        QElapsedTimer started;
        started.start();
        waitFor( [ & ] { return started.elapsed() > 300; } );
        cancelListings();
        lister.join();

        THEN( "it ends at once, cancelled, without waiting for its timeout" )
        {
            REQUIRE( took.elapsed() < 1500 );
            REQUIRE( output.error.contains( "cancelled" ) );
            REQUIRE( output.exitCode == -1 );
        }

        THEN( "a listing started afterwards is not cancelled" )
        {
            const auto quick = listingProgram( dir, "quick", "echo en0" );
            REQUIRE( runListing( { quick, {} }, std::chrono::milliseconds( 10000 ) ).out
                     == "en0\n" );
        }
    }

    GIVEN( "a program that does not finish, run under a cancel flag" )
    {
        const auto program = listingProgram( dir, "hang", "sleep 30" );
        auto cancel = std::make_shared<std::atomic_bool>( false );
        ListingOutput output;
        QElapsedTimer took;
        took.start();
        std::thread lister( [ & ] {
            const ListingCancelScope scope( cancel );
            output = runListing( { program, {} }, std::chrono::milliseconds( 20000 ) );
        } );
        QElapsedTimer started;
        started.start();
        waitFor( [ & ] { return started.elapsed() > 300; } );
        cancel->store( true );
        lister.join();

        THEN( "setting the flag ends it" )
        {
            REQUIRE( took.elapsed() < 1500 );
            REQUIRE( output.error.contains( "cancelled" ) );
        }
    }

    GIVEN( "a program that does not exist" )
    {
        const auto output
            = runListing( { dir.filePath( "missing" ), {} }, std::chrono::milliseconds( 10000 ) );

        THEN( "it says it cannot be started" )
        {
            REQUIRE( output.error.startsWith( "Cannot start missing" ) );
        }
    }
}

#endif
