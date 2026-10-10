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
 * @file live_capture_session_test.cpp
 * @brief BDD tests for the Live Capture Session: what a live capture's
 *        start, events and outcome do to the host, the capture catalog and
 *        the output directory, with scripted runs and fake adapters, and
 *        no event loop.
 */

#include <catch2/catch.hpp>

#include "fake_live_session.h"
#include "fake_live_source.h"
#include "fakehost.h"
#include "live_capture_session.h"
#include "settings.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

#include <memory>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

/// A registry of @p kind alone.
std::shared_ptr<LiveSourceRegistry> registryOf( const std::shared_ptr<FakeSourceKind>& kind )
{
    auto registry = std::make_shared<LiveSourceRegistry>();
    registry->add( kind );
    return registry;
}

/// A file @p name of @p size bytes in @p dir: a capture's text or raw file.
QString fileOf( const QTemporaryDir& dir, const QString& name, int size = 0 )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( QByteArray( size, 'x' ) );
    return path;
}

/// A summary of @p packets packets.
CaptureSummary summaryOf( uint64_t packets )
{
    CaptureSummary summary;
    summary.packets = packets;
    summary.bytes = packets * 100;
    return summary;
}

/// An outcome of the conversion: @p status, writing @p outputPath.
ConversionResult resultOf( ConversionResult::Status status, const QString& outputPath = {},
                           uint64_t packets = 0 )
{
    ConversionResult result;
    result.status = status;
    result.outputPath = outputPath;
    result.summary = summaryOf( packets );
    result.index = std::make_shared<CaptureIndex>();
    return result;
}

/// A session with the fake kind's registry, its runs scripted.
struct Session {
    FakeHost host; // its config directory, for the saved choice
    FakeLiveHost adapters;
    ScriptedRuns runs;
    std::shared_ptr<FakeSourceKind> kind = std::make_shared<FakeSourceKind>();
    LiveCaptureSession session{ adapters, adapters };

    Session()
    {
        kind->hint = "Ask for capture permissions.";
        session.setSources( registryOf( kind ) );
        session.setRunFactory( runs.factory() );
    }
};

const LiveChoice kChoice{ "fake", "", "fake0", "udp", 96 };

} // namespace

SCENARIO( "A live capture's text file opens in a tab and its summary follows the snapshots",
          "[live_session]" )
{
    Session s;
    QTemporaryDir dir;
    REQUIRE( s.session.start( kChoice ) );

    THEN( "the choice's kind makes the source, and the run is named after the choice" )
    {
        REQUIRE( s.session.state() == LiveCaptureSession::State::Capturing );
        REQUIRE( s.runs.runs.size() == 1 );
        REQUIRE( s.runs.last().started );
        REQUIRE( s.runs.last().request.name == "fake0" );
        REQUIRE( s.kind->started().size() == 1 );
        REQUIRE( s.kind->started().front() == kChoice );
        REQUIRE( s.session.choice() == kChoice );
        REQUIRE( loadLiveChoice( s.host.configDir() ) == kChoice );
    }

    WHEN( "a packet line is written, and a snapshot comes" )
    {
        const auto log = fileOf( dir, "fake0.log" );
        const auto raw = fileOf( dir, "fake0.pcap", 64 );
        s.runs.last().open( log, raw );
        LiveSnapshot snapshot;
        snapshot.summary = summaryOf( 3 );
        snapshot.rawBytes = 300;
        snapshot.index = std::make_shared<CaptureIndex>();
        s.runs.last().snapshot( snapshot );

        THEN( "the file is in the catalog before its tab opens, with the summary so far" )
        {
            REQUIRE( s.adapters.openedTabs == QStringList{ log } );
            const auto& entry = s.adapters.catalog.at( log );
            REQUIRE( entry.rawPath == raw );
            REQUIRE( entry.name == "fake0" );
            REQUIRE( entry.summary.packets == 3 );
            REQUIRE( entry.index == snapshot.index );
            REQUIRE( entry.fileSize == 300 );
            REQUIRE( s.session.progress().summary.packets == 3 );
            REQUIRE( s.session.files() == QStringList{ log } );
        }

        AND_WHEN( "it ends, stopped" )
        {
            s.session.stop();
            REQUIRE( s.runs.last().stopped );
            REQUIRE( s.session.state() == LiveCaptureSession::State::Stopping );
            const auto result = resultOf( ConversionResult::Status::Converted, log, 4 );
            s.runs.last().finish( result );

            THEN( "the tab shows the final summary and index, and nobody is told" )
            {
                REQUIRE_FALSE( s.session.isBusy() );
                REQUIRE( s.session.outcome()->status == LiveOutcome::Status::Captured );
                REQUIRE( s.session.outcome()->files == QStringList{ log } );
                const auto& entry = s.adapters.catalog.at( log );
                REQUIRE( entry.summary.packets == 4 );
                REQUIRE( entry.index == result.index );
                REQUIRE( entry.fileSize == 64 );
                REQUIRE( entry.error.isEmpty() );
                REQUIRE( s.adapters.notifications.isEmpty() );
            }
        }
    }
}

SCENARIO( "A live capture that fails after packets keeps them, with the error and the Guidance",
          "[live_session]" )
{
    Session s;
    QTemporaryDir dir;
    REQUIRE( s.session.start( kChoice ) );
    const auto log = fileOf( dir, "fake0.log" );
    s.runs.last().open( log, fileOf( dir, "fake0.pcap", 10 ) );
    auto result = resultOf( ConversionResult::Status::Failed, log, 2 );
    result.error = "tcpdump: permission denied";
    s.runs.last().finish( result );

    THEN( "its tab keeps the capture and the error, and the user is told what to do" )
    {
        const auto& outcome = *s.session.outcome();
        REQUIRE( outcome.status == LiveOutcome::Status::Failed );
        REQUIRE( outcome.error == "tcpdump: permission denied" );
        REQUIRE( outcome.guidance == "Ask for capture permissions." );
        REQUIRE( outcome.files == QStringList{ log } );
        const auto& entry = s.adapters.catalog.at( log );
        REQUIRE( entry.error == "tcpdump: permission denied" );
        REQUIRE( entry.summary.packets == 2 );
        REQUIRE( s.adapters.notifications
                 == QStringList{ "Capture fake0 failed: tcpdump: permission denied" } );
        REQUIRE( QFileInfo::exists( log ) );
    }
}

SCENARIO( "A failed live capture gets its kind's Guidance however it was started",
          "[live_session]" )
{
    Session s;
    auto failed = resultOf( ConversionResult::Status::Failed );
    failed.error = "permission denied";

    WHEN( "it was started from a choice" )
    {
        REQUIRE( s.session.start( kChoice ) );
        s.runs.last().finish( failed );

        THEN( "the Guidance is the kind's" )
        {
            REQUIRE( s.session.outcome()->guidance == "Ask for capture permissions." );
            REQUIRE( s.session.outcome()->files.isEmpty() );
        }
    }

    WHEN( "it was started by name, with its kind" )
    {
        REQUIRE( s.session.start( "usb0", s.kind->makeSource( kChoice ), {}, s.kind ) );
        s.runs.last().finish( failed );

        THEN( "the Guidance is the kind's too" )
        {
            REQUIRE( s.session.outcome()->guidance == "Ask for capture permissions." );
        }
    }

    WHEN( "it was started by name without a kind" )
    {
        REQUIRE( s.session.start( "usb0", s.kind->makeSource( kChoice ) ) );
        s.runs.last().finish( failed );

        THEN( "there is no Guidance, only the error" )
        {
            REQUIRE( s.session.outcome()->guidance.isEmpty() );
            REQUIRE( s.session.outcome()->error == "permission denied" );
        }
    }

    WHEN( "the next one started by name fails with an error the kind knows nothing of" )
    {
        REQUIRE( s.session.start( "usb0", s.kind->makeSource( kChoice ), {}, s.kind ) );
        auto other = failed;
        other.error = "the device went away";
        s.runs.last().finish( other );

        THEN( "there is no Guidance" )
        {
            REQUIRE( s.session.outcome()->guidance.isEmpty() );
        }
    }
}

SCENARIO( "A live capture that ends without packets leaves nothing behind", "[live_session]" )
{
    Session s;
    QTemporaryDir root;
    s.session.setOutputRoot( root.path() );
    REQUIRE( s.session.start( kChoice ) );
    REQUIRE( s.runs.last().request.outputRoot == root.path() );
    REQUIRE( QDir( root.path() ).mkpath( "capture-1" ) );
    QFile header( root.filePath( "capture-1/fake0.log" ) );
    REQUIRE( header.open( QIODevice::WriteOnly ) );
    header.close();
    s.runs.last().finish(
        resultOf( ConversionResult::Status::Converted, root.filePath( "capture-1/fake0.log" ) ) );

    THEN( "no tab opened, its directory is removed, and the user is told" )
    {
        REQUIRE( s.session.outcome()->status == LiveOutcome::Status::Empty );
        REQUIRE( s.adapters.openedTabs.isEmpty() );
        REQUIRE( s.adapters.catalog.empty() );
        REQUIRE_FALSE( QFileInfo::exists( root.filePath( "capture-1" ) ) );
        REQUIRE( s.adapters.notifications
                 == QStringList{ "The capture fake0 ended without packets." } );
    }
}

SCENARIO( "A live capture stopped before its header came is not a failure", "[live_session]" )
{
    Session s;
    REQUIRE( s.session.start( kChoice ) );
    s.session.stop();
    s.runs.last().finish( resultOf( ConversionResult::Status::Stopped ) );

    THEN( "it says it stopped, opens nothing and tells nobody" )
    {
        REQUIRE( s.session.outcome()->status == LiveOutcome::Status::Stopped );
        REQUIRE( s.session.outcome()->error.isEmpty() );
        REQUIRE( s.adapters.openedTabs.isEmpty() );
        REQUIRE( s.adapters.notifications.isEmpty() );
        REQUIRE_FALSE( s.session.isBusy() );
    }
}

SCENARIO( "A live capture that a stop condition ended tells the user which", "[live_session]" )
{
    Session s;
    QTemporaryDir dir;
    auto choice = kChoice;
    choice.limits.packets = 2;
    REQUIRE( s.session.start( choice ) );
    REQUIRE( s.runs.last().request.limits == choice.limits );
    const auto log = fileOf( dir, "fake0.log" );
    s.runs.last().open( log, fileOf( dir, "fake0.pcap" ) );
    auto result = resultOf( ConversionResult::Status::Converted, log, 2 );
    result.stoppedBy = StopCondition::Packets;
    s.runs.last().finish( result );

    THEN( "the notice names the condition, and the capture is kept" )
    {
        REQUIRE( s.session.outcome()->status == LiveOutcome::Status::Captured );
        REQUIRE( s.session.outcome()->stoppedBy == StopCondition::Packets );
        REQUIRE( s.adapters.notifications
                 == QStringList{ liveStopText( "fake0", StopCondition::Packets, choice.limits ) } );
        REQUIRE( s.adapters.notifications.first().contains( "stopped after 2 packets" ) );
        REQUIRE( s.adapters.catalog.at( log ).summary.packets == 2 );
    }
}

SCENARIO( "A ring buffer's live capture has a text, index and summary per file", "[live_session]" )
{
    Session s;
    QTemporaryDir dir;
    auto choice = kChoice;
    choice.limits.ringFiles = 2;
    choice.limits.fileBytes = 100;
    REQUIRE( s.session.start( choice ) );
    auto& run = s.runs.last();
    const auto log1 = fileOf( dir, "fake0_00001.log" );
    const auto raw1 = fileOf( dir, "fake0_00001.pcap", 90 );
    const auto log2 = fileOf( dir, "fake0_00002.log" );
    const auto raw2 = fileOf( dir, "fake0_00002.pcap", 40 );
    run.open( log1, raw1 );
    run.open( log2, raw2 );
    LiveSnapshot snapshot;
    snapshot.summary = summaryOf( 5 );
    snapshot.rawBytes = 500;
    snapshot.rawFile = 2;
    snapshot.index = std::make_shared<CaptureIndex>();
    run.snapshot( snapshot );

    THEN( "each file opened a tab of its own, in order, and each shows the summary so far" )
    {
        REQUIRE( s.adapters.openedTabs == QStringList{ log1, log2 } );
        REQUIRE( s.session.progress().rawFile == 2 );
        for ( const auto& log : { log1, log2 } ) {
            REQUIRE( s.adapters.catalog.at( log ).summary.packets == 5 );
            REQUIRE( s.adapters.catalog.at( log ).index == snapshot.index );
        }
    }

    WHEN( "it ends" )
    {
        const auto result = resultOf( ConversionResult::Status::Converted, log2, 6 );
        run.finish( result );

        THEN( "each file's tab shows the final summary and index, and its own raw file's size" )
        {
            REQUIRE( s.session.outcome()->files == QStringList{ log1, log2 } );
            const auto& first = s.adapters.catalog.at( log1 );
            const auto& second = s.adapters.catalog.at( log2 );
            REQUIRE( first.summary.packets == 6 );
            REQUIRE( second.summary.packets == 6 );
            REQUIRE( first.index == result.index );
            REQUIRE( second.index == result.index );
            REQUIRE( first.fileSize == 90 );
            REQUIRE( second.fileSize == 40 );
            REQUIRE( first.rawPath == raw1 );
            REQUIRE( second.rawPath == raw2 );
        }
    }
}

SCENARIO( "A start asked for while a capture runs waits until its program has ended",
          "[live_session]" )
{
    Session s;
    REQUIRE( s.session.start( kChoice ) );
    auto first = s.runs.runs.back();
    auto next = kChoice;
    next.networkInterface = "fake1";

    WHEN( "a capture runs" )
    {
        THEN( "starting another is refused, and says so" )
        {
            REQUIRE_FALSE( s.session.start( next ) );
            REQUIRE( s.adapters.notifications
                     == QStringList{ "A live capture is still running: stop it first." } );
            REQUIRE( s.runs.runs.size() == 1 );
        }
    }

    WHEN( "another is started once it is idle" )
    {
        s.session.startWhenIdle( next );

        THEN( "the running one is stopped, and the next waits" )
        {
            REQUIRE( first->stopped );
            REQUIRE( s.session.hasPendingStart() );
            REQUIRE( s.session.state() == LiveCaptureSession::State::Stopping );
            REQUIRE( s.runs.runs.size() == 1 );
        }

        AND_WHEN( "the running one ends, but its program has not" )
        {
            first->finish( resultOf( ConversionResult::Status::Stopped ) );

            THEN( "the next still waits" )
            {
                REQUIRE_FALSE( s.session.isBusy() );
                REQUIRE( s.session.hasPendingStart() );
                REQUIRE( s.runs.runs.size() == 1 );
            }

            AND_WHEN( "its program has ended" )
            {
                first->end();

                THEN( "the next starts" )
                {
                    REQUIRE_FALSE( s.session.hasPendingStart() );
                    REQUIRE( s.runs.runs.size() == 2 );
                    REQUIRE( s.runs.last().request.name == "fake1" );
                    REQUIRE( s.session.choice() == next );
                    REQUIRE( s.session.state() == LiveCaptureSession::State::Capturing );
                }

                THEN( "what the last one tells now is ignored" )
                {
                    first->finish( resultOf( ConversionResult::Status::Stopped ) );
                    REQUIRE( s.session.isBusy() );
                    REQUIRE_FALSE( s.session.outcome() );
                }
            }
        }
    }

    WHEN( "it has ended and its program too, and another is started once idle" )
    {
        first->finish( resultOf( ConversionResult::Status::Stopped ) );
        first->end();
        s.session.startWhenIdle( next );

        THEN( "it starts at once" )
        {
            REQUIRE_FALSE( s.session.hasPendingStart() );
            REQUIRE( s.runs.runs.size() == 2 );
        }
    }
}

SCENARIO( "A live capture is refused with why it cannot start", "[live_session]" )
{
    Session s;

    WHEN( "the choice has a problem" )
    {
        auto choice = kChoice;
        choice.options.insert( "note", "bad" );

        THEN( "it is refused with the message liveChoiceProblem() gives" )
        {
            REQUIRE_FALSE( s.session.start( choice ) );
            REQUIRE( s.adapters.notifications
                     == QStringList{ "Cannot start the live capture: The note is bad." } );
            REQUIRE( s.runs.runs.empty() );
            REQUIRE_FALSE( s.session.isBusy() );
        }
    }

    WHEN( "something else is busy" )
    {
        s.adapters.busy = "A capture is still being read.";

        THEN( "neither a choice nor a capture by name starts" )
        {
            REQUIRE_FALSE( s.session.start( kChoice ) );
            REQUIRE_FALSE( s.session.start( "usb0", s.kind->makeSource( kChoice ) ) );
            REQUIRE( s.adapters.notifications
                     == QStringList{ "A capture is still being read.",
                                     "A capture is still being read." } );
            REQUIRE( s.runs.runs.empty() );
        }
    }
}
