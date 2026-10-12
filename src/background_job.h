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
 * @file background_job.h
 * @brief The Background Job: work that writes a file on a worker thread of
 *        its own, with progress and Cancel, whose result is delivered on
 *        the thread that started it.
 *
 * The sidebar converts a capture file and exports packets as one.  A job
 * checks its cancel flag as it goes, but may be done before it sees a
 * cancel the user asked for: the cancel wins all the same.  The result
 * delivered is then Cancelled, and what the job wrote is removed.  That
 * rule is applied here, once, for every kind of job, when the result is
 * delivered and when the job is cancelled and waited for (cancelAndWait(),
 * as the sidebar does when it is destroyed), when nothing is delivered.
 */

#pragma once

#include <QFutureWatcher>
#include <QPromise>
#include <QString>
#include <QThreadPool>
#include <QtConcurrent/QtConcurrentRun>

#include <atomic>
#include <functional>
#include <memory>

namespace tcpdump {

/**
 * One kind of work, run in the background one at a time.  @p Result has a
 * `Status` with `Failed` and `Cancelled`, `Failed` the default, and an
 * `error`, as ConversionResult and ExportResult have.
 *
 * Not thread-safe: it is started, cancelled and destroyed on one thread,
 * which runs an event loop to be delivered the results.
 */
template <typename Result>
class BackgroundJob {
public:
    /// Reports the share of the work done, in permille.
    using Progress = std::function<void( int permille )>;
    /// The work, run on the worker thread: checks @p cancel as it goes and
    /// reports to @p progress.
    using Work = std::function<Result( const std::atomic_bool* cancel, const Progress& progress )>;
    /// Removes what the work left behind for @p result, when a cancel came
    /// while it finished.
    using Discard = std::function<void( const Result& result )>;
    /// Takes the result, on the thread that started the job.
    using Done = std::function<void( Result result )>;

    /// A job of the kind @p name ("conversion"), as a result says it.
    explicit BackgroundJob( QString name )
        : name_( std::move( name ) )
    {
        pool_.setMaxThreadCount( 1 );
    }

    /// Cancels the running job and waits for it (cancelAndWait()).
    ~BackgroundJob()
    {
        cancelAndWait();
    }

    BackgroundJob( const BackgroundJob& ) = delete;
    BackgroundJob& operator=( const BackgroundJob& ) = delete;

    /// Whether a job runs: started, and its result not delivered yet.
    bool isRunning() const
    {
        return watcher_ != nullptr;
    }

    /**
     * Run @p work on the worker thread; its progress goes to @p shown, its
     * result to @p done, here, once.  A job cancelled before its result is
     * delivered comes to Cancelled, whatever the work returned, and
     * @p discard removes what it wrote.  One job at a time: does nothing
     * while one runs.
     */
    void start( Work work, Discard discard, Done done, Progress shown = {} )
    {
        if ( isRunning() ) {
            return;
        }
        auto cancelled = std::make_shared<std::atomic_bool>( false );
        cancel_ = cancelled;
        discard_ = std::move( discard );

        // The watcher lives on this thread, so its signals are delivered here.
        watcher_ = new QFutureWatcher<Result>;
        if ( shown ) {
            QObject::connect( watcher_, &QFutureWatcher<Result>::progressValueChanged, watcher_,
                              std::move( shown ) );
        }
        QObject::connect( watcher_, &QFutureWatcher<Result>::finished, watcher_,
                          [ this, done = std::move( done ) ] {
                              auto result = settle( takeResult() );
                              finish();
                              done( std::move( result ) );
                          } );
        watcher_->setFuture( QtConcurrent::run(
            &pool_, [ work = std::move( work ), cancelled ]( QPromise<Result>& promise ) {
                promise.setProgressRange( 0, kPermille );
                promise.addResult( work( cancelled.get(), [ &promise ]( int permille ) {
                    promise.setProgressValue( permille );
                } ) );
            } ) );
    }

    /// Ask the running job to stop; it comes to Cancelled.
    void cancel()
    {
        if ( cancel_ ) {
            cancel_->store( true );
        }
    }

    /**
     * Cancel the running job and wait for its worker: no code of the job
     * runs afterwards, and the host may unload the library.  A job that was
     * done when the cancel came loses what it wrote, as on cancel(), but its
     * result is delivered to no one.
     */
    void cancelAndWait()
    {
        cancel();
        pool_.waitForDone();
        if ( !watcher_ ) {
            return;
        }
        settle( takeResult() );
        // Its finished signal, posted to the watcher, goes with it.
        delete watcher_;
        watcher_ = nullptr;
        cancel_.reset();
        discard_ = {};
    }

private:
    /// The progress range a job reports in.
    static constexpr int kPermille = 1000;

    /// The running job's result, or that it ended without one (it threw).
    Result takeResult() const
    {
        if ( watcher_->future().resultCount() > 0 ) {
            return watcher_->result();
        }
        Result result;
        result.error = QString( "The %1 ended without a result" ).arg( name_ );
        return result;
    }

    /// The rule that a cancel wins, even over a job that was done when it
    /// came: @p result becomes Cancelled, and what it wrote is removed.
    Result settle( Result result ) const
    {
        if ( !cancel_ || !cancel_->load() ) {
            return result;
        }
        if ( discard_ ) {
            discard_( result );
        }
        Result cancelled;
        cancelled.status = Result::Status::Cancelled;
        return cancelled;
    }

    /// The job is over: forget it, and its watcher once its signal returns.
    void finish()
    {
        watcher_->deleteLater();
        watcher_ = nullptr;
        cancel_.reset();
        discard_ = {};
    }

    QString name_; ///< The kind of job, as a result says it.
    /// Cancels the running job; shared with its worker.
    std::shared_ptr<std::atomic_bool> cancel_;
    Discard discard_; ///< Removes what the running job wrote.
    /// The running job's progress and result; null while none runs.
    QFutureWatcher<Result>* watcher_ = nullptr;
    /// One worker thread, owned here so that it can be waited for.
    QThreadPool pool_;
};

} // namespace tcpdump
