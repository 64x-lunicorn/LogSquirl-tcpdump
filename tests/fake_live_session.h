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
 * @brief Fakes around a Live Capture Session: its host and capture catalog,
 *        and captures the test scripts.
 *
 * FakeLiveHost is both adapters of a LiveCaptureSession: it records the
 * tabs opened, the notifications, and what the catalog keeps per text file
 * (its raw file, summary, index, size and error), and can say something
 * else is busy.  ScriptedRuns makes the session's runs (setRunFactory()):
 * each a ScriptedRun that records what it was asked to run and whether it
 * was told to stop, and tells the session what the test says, when the
 * test says it, on the test's thread, so that no event loop is needed.
 */

#pragma once

#include "live_capture_session.h"

#include <QString>
#include <QStringList>

#include <map>
#include <memory>
#include <vector>

namespace tcpdump_test {

/// A Live Capture Session's host and capture catalog, recording.
class FakeLiveHost : public tcpdump::LiveCaptureHost, public tcpdump::LiveCaptureCatalog {
public:
    /// What the catalog keeps of a text file.
    struct Entry {
        QString rawPath;
        QString name;
        tcpdump::CaptureSummary summary;
        std::shared_ptr<const tcpdump::CaptureIndex> index;
        qint64 fileSize = 0;
        QString error;
        int updates = 0; ///< How often its summary was replaced.
    };

    void openTab( const QString& logPath ) override
    {
        openedTabs << logPath;
    }
    void notify( const QString& message ) override
    {
        notifications << message;
    }
    QString busyElsewhere() const override
    {
        return busy;
    }
    void addFile( const QString& logPath, const QString& rawPath, const QString& name ) override
    {
        catalog[ logPath ] = Entry{ rawPath, name, {}, {}, 0, {}, 0 };
    }
    void updateFile( const QString& logPath, const tcpdump::CaptureSummary& summary,
                     std::shared_ptr<const tcpdump::CaptureIndex> index, qint64 fileSize ) override
    {
        auto& entry = catalog.at( logPath );
        entry.summary = summary;
        if ( index ) {
            entry.index = std::move( index );
        }
        entry.fileSize = fileSize;
        ++entry.updates;
    }
    void setFileError( const QString& logPath, const QString& error ) override
    {
        catalog.at( logPath ).error = error;
    }

    QStringList openedTabs;    ///< The text files opened in tabs, in order.
    QStringList notifications; ///< What the user was told, in order.
    QString busy;              ///< Set: something else is busy, and this says so.
    std::map<QString, Entry> catalog;
};

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

} // namespace tcpdump_test
