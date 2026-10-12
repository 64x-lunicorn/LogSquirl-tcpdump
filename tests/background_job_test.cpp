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
 * @file background_job_test.cpp
 * @brief BDD tests for the Background Job the sidebar converts and exports
 *        with: a cancel requested while the job finishes wins over its
 *        result, also when the job is destroyed, without a sidebar.
 */

#include <catch2/catch.hpp>

#include "background_job.h"
#include "fakehost.h"

#include <QSemaphore>

#include <optional>
#include <stdexcept>
#include <vector>

using namespace tcpdump;
using tcpdump_test::waitFor;

namespace {

/// What a job of the tests comes to: what it wrote, or why it failed.
struct Outcome {
    enum class Status { Done, Failed, Cancelled };
    Status status = Status::Failed;
    QString error;
    QString written; ///< What the job left behind, when Done.
};

using Job = BackgroundJob<Outcome>;

/// A job that waits for @p go and is then done, writing "output", without
/// looking at its cancel flag again: as a conversion or an export past
/// its last packet.  It reports half its progress before it waits.
Job::Work doneAfter( QSemaphore& go )
{
    return [ &go ]( const std::atomic_bool*, const Job::Progress& progress ) {
        progress( 500 );
        go.acquire();
        Outcome outcome;
        outcome.status = Outcome::Status::Done;
        outcome.written = "output";
        return outcome;
    };
}

/// Records what a job left behind and was removed, and what it came to.
struct Recorder {
    std::vector<QString> discarded;
    std::optional<Outcome> delivered;
    std::vector<int> progress;
    bool takesBack = true; ///< Whether what the job wrote can be taken back.
    int asked = 0;         ///< How often it was asked to take it back.

    Job::Discard discard()
    {
        return [ this ]( const Outcome& outcome ) {
            ++asked;
            if ( takesBack ) {
                discarded.push_back( outcome.written );
            }
            return takesBack;
        };
    }
    Job::Done done()
    {
        return [ this ]( Outcome outcome ) { delivered = std::move( outcome ); };
    }
    Job::Progress shown()
    {
        return [ this ]( int permille ) { progress.push_back( permille ); };
    }
};

} // namespace

SCENARIO( "A cancel requested while a background job finishes wins over its result",
          "[background_job]" )
{
    GIVEN( "a job that runs past its last look at the cancel flag" )
    {
        QSemaphore go;
        Recorder recorder;
        Job job( "test" );
        job.start( doneAfter( go ), recorder.discard(), recorder.done(), recorder.shown() );
        REQUIRE( job.isRunning() );

        WHEN( "the user cancels it before it is done" )
        {
            job.cancel();
            go.release();
            REQUIRE( waitFor( [ & ] { return recorder.delivered.has_value(); } ) );

            THEN( "its result is Cancelled, and what it wrote is removed" )
            {
                REQUIRE( recorder.delivered->status == Outcome::Status::Cancelled );
                REQUIRE( recorder.delivered->written.isEmpty() );
                REQUIRE( recorder.discarded == std::vector<QString>{ "output" } );
                REQUIRE_FALSE( job.isRunning() );
            }
        }

        WHEN( "nobody cancels it" )
        {
            go.release();
            REQUIRE( waitFor( [ & ] { return recorder.delivered.has_value(); } ) );

            THEN( "its result is delivered as it is, with its progress" )
            {
                REQUIRE( recorder.delivered->status == Outcome::Status::Done );
                REQUIRE( recorder.delivered->written == "output" );
                REQUIRE( recorder.discarded.empty() );
                REQUIRE_FALSE( recorder.progress.empty() );
                REQUIRE( recorder.progress.back() == 500 );
                REQUIRE_FALSE( job.isRunning() );
            }
        }

        WHEN( "it is cancelled and waited for, as when the sidebar is destroyed" )
        {
            go.release();
            job.cancelAndWait();
            QCoreApplication::processEvents();

            THEN( "what it wrote is removed, and nothing is delivered" )
            {
                REQUIRE( recorder.discarded == std::vector<QString>{ "output" } );
                REQUIRE_FALSE( recorder.delivered.has_value() );
                REQUIRE_FALSE( job.isRunning() );
            }
        }
    }

    GIVEN( "a job that ends without a result" )
    {
        Recorder recorder;
        Job job( "test" );
        job.start( []( const std::atomic_bool*,
                       const Job::Progress& ) -> Outcome { throw std::runtime_error( "gone" ); },
                   recorder.discard(), recorder.done() );
        REQUIRE( waitFor( [ & ] { return recorder.delivered.has_value(); } ) );

        THEN( "it failed, and says so" )
        {
            REQUIRE( recorder.delivered->status == Outcome::Status::Failed );
            REQUIRE( recorder.delivered->error == "The test ended without a result" );
            REQUIRE( recorder.discarded.empty() );
        }
    }

    GIVEN( "a job cancelled after its result was delivered" )
    {
        QSemaphore go;
        Recorder recorder;
        Job job( "test" );
        job.start( doneAfter( go ), recorder.discard(), recorder.done() );
        go.release();
        REQUIRE( waitFor( [ & ] { return recorder.delivered.has_value(); } ) );
        job.cancel();
        job.cancelAndWait();

        THEN( "its result stands" )
        {
            REQUIRE( recorder.delivered->status == Outcome::Status::Done );
            REQUIRE( recorder.discarded.empty() );
        }
    }
}

SCENARIO( "A cancel cannot take back what a background job wrote for good", "[background_job]" )
{
    GIVEN( "a job whose output cannot be taken back once it is done, as a file it replaced" )
    {
        QSemaphore go;
        Recorder recorder;
        recorder.takesBack = false;
        Job job( "test" );
        job.start( doneAfter( go ), recorder.discard(), recorder.done() );

        WHEN( "the user cancels it while it finishes" )
        {
            job.cancel();
            go.release();
            REQUIRE( waitFor( [ & ] { return recorder.delivered.has_value(); } ) );

            THEN( "the cancel came too late: its result stands" )
            {
                REQUIRE( recorder.asked == 1 );
                REQUIRE( recorder.delivered->status == Outcome::Status::Done );
                REQUIRE( recorder.delivered->written == "output" );
            }
        }

        WHEN( "it is cancelled and waited for, as when the sidebar is destroyed" )
        {
            go.release();
            job.cancelAndWait();
            QCoreApplication::processEvents();

            THEN( "what it wrote stays" )
            {
                REQUIRE( recorder.asked == 1 );
                REQUIRE( recorder.discarded.empty() );
                REQUIRE_FALSE( job.isRunning() );
            }
        }
    }
}
