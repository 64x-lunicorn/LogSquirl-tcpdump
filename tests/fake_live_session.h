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
 * @file fake_live_session.h
 * @brief Fakes around a Live Capture Session: its host, captures the test
 *        scripts, and captures run for real.
 *
 * FakeLiveHost is the host of a LiveCaptureSession and of its catalog, a
 * FakeSessionHost (fake_session_host.h): it records the tabs opened and the
 * notifications, and can say what else runs, which the Activity rule
 * weighs.  The session keeps what each tab
 * shows in a real CaptureCatalog, which opens the tabs and which the tests
 * read.  ScriptedRuns makes the session's runs (setRunFactory()): each a
 * ScriptedRun that records what it was asked to run and whether it was told
 * to stop, and tells the session what the test says, when the test says it,
 * on the test's thread, so that no event loop is needed.  WorkerSession is
 * a session whose captures run on a worker, as in the app (runOnWorker()),
 * for a source kind's tests with its fake programs: it runs the event loop
 * until the session told what the test waits for.
 */

#pragma once

#include "capture_catalog.h"
#include "fake_session_host.h"
#include "live_capture_session.h"

#include <QEventLoop>
#include <QString>
#include <QStringList>
#include <QTemporaryDir>
#include <QTimer>

#include <functional>
#include <memory>
#include <vector>

namespace tcpdump_test {

/// A Live Capture Session's host, and its catalog's tab host, recording.
using FakeLiveHost = FakeSessionHost;

/// A capture the test scripts: what the session asked for, and what it is told.
class ScriptedRun {
public:
    tcpdump::LiveRunRequest request; ///< What the session asked to run.
    bool started = false;            ///< The session started it.
    bool stopped = false;            ///< The session told it to stop.
    bool done = false;               ///< Its source is gone (end()).

    /// Its text file @p logPath, of the raw file @p rawPath, has a packet line.
    void open( const QString& logPath, const QString& rawPath )
    {
        const auto tell = listener_.readyToOpen;
        tell( logPath, rawPath );
    }
    /// A snapshot of what it captured so far.
    void snapshot( const tcpdump::LiveSnapshot& snapshot )
    {
        const auto tell = listener_.snapshot;
        tell( snapshot );
    }
    /// Its program wrote @p line to stderr.
    void stderrLine( const QString& line )
    {
        const auto tell = listener_.stderrLine;
        tell( line );
    }
    /// It ended with @p result.
    void finish( const tcpdump::ConversionResult& result )
    {
        const auto tell = listener_.finished;
        tell( result );
    }
    /// Its source is gone, its program ended.  The session may let go of
    /// it meanwhile (a pending start): the test's ScriptedRun stays.
    void end()
    {
        done = true;
        const auto tell = listener_.done;
        tell();
    }

private:
    friend class ScriptedRuns;
    tcpdump::LiveRun::Listener listener_;
};

/// Makes a Live Capture Session's runs as ScriptedRuns, kept for the test.
class ScriptedRuns {
public:
    /// What LiveCaptureSession::setRunFactory() takes.
    tcpdump::LiveRunFactory factory()
    {
        return [ this ]( tcpdump::LiveRunRequest request ) -> std::unique_ptr<tcpdump::LiveRun> {
            auto run = std::make_shared<ScriptedRun>();
            run->request = std::move( request );
            runs.push_back( run );
            return std::make_unique<Handle>( run );
        };
    }

    /// The last run made.
    ScriptedRun& last()
    {
        return *runs.back();
    }

    std::vector<std::shared_ptr<ScriptedRun>> runs; ///< Every run made, in order.

private:
    /// The session's handle on a ScriptedRun.
    class Handle : public tcpdump::LiveRun {
    public:
        explicit Handle( std::shared_ptr<ScriptedRun> run )
            : run_( std::move( run ) )
        {
        }
        ~Handle() override
        {
            // Let go of: it tells nothing more, as a retired LiveCapture.
            run_->listener_ = {};
            run_->listener_.readyToOpen = []( const QString&, const QString& ) {};
            run_->listener_.snapshot = []( const tcpdump::LiveSnapshot& ) {};
            run_->listener_.stderrLine = []( const QString& ) {};
            run_->listener_.finished = []( const tcpdump::ConversionResult& ) {};
            run_->listener_.done = [] {};
        }
        void start( Listener listener ) override
        {
            run_->started = true;
            run_->listener_ = std::move( listener );
        }
        void stop() override
        {
            run_->stopped = true;
        }
        bool isDone() const override
        {
            return run_->done;
        }

    private:
        std::shared_ptr<ScriptedRun> run_;
    };
};

/**
 * A Live Capture Session that runs its captures on a worker, as in the app,
 * with the kinds of a registry, writing below a temporary directory of its
 * own, on a FakeLiveHost and a CaptureCatalog; it records the lines its programs wrote to
 * stderr.  What a run tells comes through the event loop, which the waits
 * run until the session told it: the deadline only guards against a hang.
 */
class WorkerSession {
public:
    static constexpr int kHangGuardMs = 120000;

    explicit WorkerSession( std::shared_ptr<const tcpdump::LiveSourceRegistry> sources )
    {
        session.setSources( std::move( sources ) );
        session.setOutputRoot( outputRoot.path() );
        QObject::connect( &session, &tcpdump::LiveCaptureSession::stderrLine, &session,
                          [ this ]( const QString& line ) { stderrLines << line; } );
    }

    /// Run the event loop until the capture has ended: outcome() is its.
    bool waitForOutcome( int hangGuardMs = kHangGuardMs )
    {
        return waitUntil( [ this ] { return session.outcome().has_value(); }, hangGuardMs );
    }

    /// Run the event loop until the capture opened its first text file in a tab.
    bool waitForFile( int hangGuardMs = kHangGuardMs )
    {
        return waitUntil( [ this ] { return !host.openedTabs.isEmpty(); }, hangGuardMs );
    }

    /// Run the event loop until @p met holds, checked each time the session
    /// tells something: a file opened, its state, its outcome.
    bool waitUntil( const std::function<bool()>& met, int hangGuardMs = kHangGuardMs )
    {
        if ( met() ) {
            return true;
        }
        QEventLoop loop;
        const auto check = [ & ] {
            if ( met() ) {
                loop.quit();
            }
        };
        QObject::connect( &session, &tcpdump::LiveCaptureSession::fileOpened, &loop, check );
        QObject::connect( &session, &tcpdump::LiveCaptureSession::finished, &loop, check );
        QObject::connect( &session, &tcpdump::LiveCaptureSession::stateChanged, &loop, check );
        QTimer::singleShot( hangGuardMs, &loop, &QEventLoop::quit );
        loop.exec();
        return met();
    }

    /// What the last capture came to; it must have ended (waitForOutcome()).
    const tcpdump::LiveOutcome& outcome() const
    {
        return *session.outcome();
    }

    /// The lines its programs wrote to stderr, one text.
    QString stderrText() const
    {
        return stderrLines.join( '\n' );
    }

    FakeLiveHost host;
    tcpdump::CaptureCatalog catalog{ host };
    QTemporaryDir outputRoot; ///< Outlives the session, which writes below it.
    tcpdump::LiveCaptureSession session{ host, catalog };
    QStringList stderrLines; ///< What its capture programs wrote to stderr, in order.
};

} // namespace tcpdump_test
