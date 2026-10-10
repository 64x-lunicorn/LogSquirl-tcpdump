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
 * @file live_capture_session.cpp
 * @brief A live capture from its start to its outcome.
 */

#include "live_capture_session.h"

#include "plugin.h"
#include "settings.h"

#include <QDir>
#include <QFileInfo>
#include <QLocale>
#include <QMetaObject>

#include <algorithm>

namespace tcpdump {

QString formatBytes( uint64_t bytes )
{
    if ( bytes >= 1024 * 1024 ) {
        return QString::number( static_cast<double>( bytes ) / ( 1024.0 * 1024.0 ), 'f', 1 )
               + " MB";
    }
    if ( bytes >= 1024 ) {
        return QString::number( static_cast<double>( bytes ) / 1024.0, 'f', 1 ) + " KB";
    }
    return QString::number( bytes ) + " B";
}

QString clockTime( qint64 seconds )
{
    seconds = std::max<qint64>( seconds, 0 );
    return seconds >= 3600
               ? QString( "%1:%2:%3" )
                     .arg( seconds / 3600 )
                     .arg( seconds / 60 % 60, 2, 10, QChar( '0' ) )
                     .arg( seconds % 60, 2, 10, QChar( '0' ) )
               : QString( "%1:%2" ).arg( seconds / 60 ).arg( seconds % 60, 2, 10, QChar( '0' ) );
}

QString liveStopText( const QString& name, StopCondition condition, const LiveLimits& limits )
{
    switch ( condition ) {
    case StopCondition::Duration:
        return QString( "The capture %1 stopped after %2, as set." )
            .arg( name, clockTime( limits.duration.count() ) );
    case StopCondition::Packets:
        return QString( "The capture %1 stopped after %2 packets, as set." )
            .arg( name, QLocale().toString( static_cast<qulonglong>( limits.packets ) ) );
    case StopCondition::Bytes:
        return QString( "The capture %1 stopped at %2 captured, as set." )
            .arg( name, formatBytes( limits.bytes ) );
    case StopCondition::PacketNumbers:
        return QString( "The capture %1 stopped at packet %2, the last one the No. column can "
                        "number." )
            .arg( name, QLocale().toString( static_cast<qulonglong>( kMaxPacketNumber ) ) );
    case StopCondition::None:
        break;
    }
    return QString( "The capture %1 stopped." ).arg( name );
}

QString liveOutcomeText( const LiveOutcome& outcome )
{
    switch ( outcome.status ) {
    case LiveOutcome::Status::Stopped:
        return QString( "The capture %1 was stopped before anything was captured." )
            .arg( outcome.name );
    case LiveOutcome::Status::Empty:
        return QString( "The capture %1 ended without packets." ).arg( outcome.name );
    case LiveOutcome::Status::Captured:
    case LiveOutcome::Status::Failed:
        break;
    }
    return {};
}

namespace {

/// A LiveCapture run on its worker thread, retired when let go of.
class WorkerRun : public LiveRun {
public:
    explicit WorkerRun( LiveRunRequest request )
        : capture_( std::make_unique<LiveCapture>(
              request.name, request.outputRoot, request.options, std::move( request.makeSource ) ) )
    {
        capture_->setLimits( request.limits );
        if ( request.clock ) {
            capture_->setClock( std::move( request.clock ) );
        }
    }

    ~WorkerRun() override
    {
        // Its worker may still be ending the capture program: it ends on its
        // own, never waited for here.
        retireLiveCapture( std::move( capture_ ) );
    }

    void start( Listener listener ) override
    {
        auto* capture = capture_.get();
        QObject::connect( capture, &LiveCapture::readyToOpen, capture, listener.readyToOpen );
        QObject::connect( capture, &LiveCapture::snapshotTaken, capture, listener.snapshot );
        QObject::connect( capture, &LiveCapture::stderrLine, capture, listener.stderrLine );
        QObject::connect( capture, &LiveCapture::finished, capture, listener.finished );
        QObject::connect( capture, &LiveCapture::done, capture, listener.done );
        capture->start();
    }

    void stop() override
    {
        capture_->stop();
    }

    bool isDone() const override
    {
        return capture_->isDone();
    }

private:
    std::unique_ptr<LiveCapture> capture_;
};

} // namespace

std::unique_ptr<LiveRun> runOnWorker( LiveRunRequest request )
{
    return std::make_unique<WorkerRun>( std::move( request ) );
}

LiveCaptureSession::LiveCaptureSession( LiveCaptureHost& host, LiveCaptureCatalog& catalog,
                                        QObject* parent )
    : QObject( parent )
    , host_( host )
    , catalog_( catalog )
    , makeRun_( &runOnWorker )
{
    checkPool_.setMaxThreadCount( 1 );
}

LiveCaptureSession::~LiveCaptureSession()
{
    // First: the check's worker posts to this session (start()).  Its
    // listing is killed, not waited for to its timeout.
    if ( cancelCheck_ ) {
        cancelCheck_->store( true );
    }
    checkPool_.waitForDone();
    // A capture is stopped, not cancelled: its tab may stay open after a
    // runtime disable.  The plugin's shutdown joins its worker.
    run_.reset();
}

bool LiveCaptureSession::refuseWhileBusy()
{
    if ( const auto elsewhere = host_.busyElsewhere(); !elsewhere.isEmpty() ) {
        host_.notify( elsewhere );
        return true;
    }
    if ( isBusy() ) {
        host_.notify( "A live capture is still running: stop it first." );
        return true;
    }
    return false;
}

bool LiveCaptureSession::start( const LiveChoice& choice )
{
    if ( refuseWhileBusy() ) {
        return false;
    }
    if ( const auto problem = liveChoiceProblem( sources_.get(), choice ); !problem.isEmpty() ) {
        host_.notify( "Cannot start the live capture: " + problem );
        return false;
    }
    const auto kind = sources_->find( choice.source );
    if ( !kind->validationNeedsAsking( choice ) ) {
        return startChecked( choice );
    }

    // A saved extcap choice, say, whose arguments the form never asked for:
    // they are asked now, as a listing, and the choice checked by them.
    const auto check = ++checks_;
    auto cancel = std::make_shared<std::atomic_bool>( false );
    cancelCheck_ = cancel;
    choice_ = choice;
    setState( State::Checking );
    checkPool_.start( [ this, kind, choice, check, cancel ] {
        {
            const ListingCancelScope scope( cancel );
            kind->askForValidation( choice, LiveSourceKind::kListTimeout );
        }
        // Dropped if the session is gone by then; its destructor waits for
        // this worker, so it is not gone before the call is queued.
        QMetaObject::invokeMethod(
            this, [ this, choice, check ] { checked( choice, check ); }, Qt::QueuedConnection );
    } );
    return true;
}

void LiveCaptureSession::checked( const LiveChoice& choice, unsigned check )
{
    if ( check != checks_ || state_ != State::Checking ) {
        return; // Stopped, or another choice is checked.
    }
    setState( State::Idle );
    if ( const auto problem = liveChoiceProblem( sources_.get(), choice ); !problem.isEmpty() ) {
        host_.notify( "Cannot start the live capture: " + problem );
        return;
    }
    startChecked( choice );
}

bool LiveCaptureSession::startChecked( const LiveChoice& choice )
{
    if ( refuseWhileBusy() ) {
        return false;
    }
    const auto kind = sources_->find( choice.source );

    // The last choice started is the one shown after a restart.
    if ( !saveLiveChoice( hostConfigDir(), choice ) ) {
        hostLog( LOGSQUIRL_LOG_WARNING, "The live capture choice could not be saved in "
                                            + settingsFilePath( hostConfigDir() ) );
    }
    LiveRunRequest request;
    request.name = liveCaptureName( choice );
    request.makeSource = kind->makeSource( choice );
    request.limits = choice.limits;
    choice_ = choice;
    run( std::move( request ), kind );
    hostLog( LOGSQUIRL_LOG_INFO,
             QString( "Live capture from %1, interface %2, filter \"%3\", "
                      "snaplen %4" )
                 .arg( kind->displayName(),
                       choice.networkInterface.isEmpty() ? "(default)" : choice.networkInterface,
                       choice.filter )
                 .arg( choice.snaplen ) );
    return true;
}

bool LiveCaptureSession::start( const QString& name, LiveCapture::SourceFactory makeSource,
                                const LiveLimits& limits,
                                std::shared_ptr<const LiveSourceKind> kind )
{
    if ( refuseWhileBusy() ) {
        return false;
    }
    LiveRunRequest request;
    request.name = name;
    request.makeSource = std::move( makeSource );
    request.limits = limits;
    choice_.reset();
    run( std::move( request ), std::move( kind ) );
    return true;
}

void LiveCaptureSession::run( LiveRunRequest request, std::shared_ptr<const LiveSourceKind> kind )
{
    hostLog( LOGSQUIRL_LOG_INFO, "Capturing live: " + request.name );
    request.outputRoot = outputRoot_;
    request.options = loadConversionOptions( hostConfigDir() );
    request.clock = clock_;

    // The last run may still be ending its program: it is let go of, and
    // tells nothing more.
    run_.reset();
    const auto number = ++runs_;
    kind_ = std::move( kind );
    name_ = request.name;
    limits_ = request.limits;
    progress_ = {};
    files_.clear();
    rawFiles_.clear();
    outcome_.reset();
    clockStarted_.start();
    run_ = makeRun_( std::move( request ) );

    setState( State::Capturing );
    emit started();

    LiveRun::Listener listener;
    listener.readyToOpen = [ this, number ]( const QString& logPath, const QString& rawPath ) {
        openFile( number, logPath, rawPath );
    };
    listener.snapshot
        = [ this, number ]( const LiveSnapshot& snapshot ) { takeSnapshot( number, snapshot ); };
    listener.stderrLine = [ this, number ]( const QString& line ) {
        if ( number == runs_ ) {
            hostLog( LOGSQUIRL_LOG_INFO, name_ + ": " + line );
            emit stderrLine( line );
        }
    };
    listener.finished
        = [ this, number ]( const ConversionResult& result ) { finish( number, result ); };
    listener.done = [ this, number ] { runDone( number ); };
    run_->start( std::move( listener ) );
}

void LiveCaptureSession::startWhenIdle( const LiveChoice& choice )
{
    switch ( state_ ) {
    case State::Capturing:
    case State::Stopping:
        // Started once the running one is done (runDone()).
        pending_ = choice;
        if ( state_ == State::Capturing ) {
            stop();
        }
        emit stateChanged();
        return;
    case State::Checking:
        stop();
        break;
    case State::Idle:
        break;
    }
    if ( run_ && !run_->isDone() ) {
        // Ended, but its program is still ending.
        pending_ = choice;
        emit stateChanged();
        return;
    }
    start( choice );
}

void LiveCaptureSession::stop()
{
    switch ( state_ ) {
    case State::Idle:
    case State::Stopping:
        return;
    case State::Checking:
        ++checks_;
        if ( cancelCheck_ ) {
            cancelCheck_->store( true );
        }
        setState( State::Idle );
        return;
    case State::Capturing:
        run_->stop();
        setState( State::Stopping );
        return;
    }
}

void LiveCaptureSession::setState( State state )
{
    if ( state_ == state ) {
        return;
    }
    state_ = state;
    emit stateChanged();
}

void LiveCaptureSession::openFile( unsigned run, const QString& logPath, const QString& rawPath )
{
    if ( run != runs_ ) {
        return;
    }
    // Kept before the tab is opened: the host may report it in front at
    // once.  A ring buffer's next file opens a tab of its own; the tabs
    // before stay.
    files_ << logPath;
    rawFiles_.push_back( rawPath );
    catalog_.addFile( logPath, rawPath, name_ );
    host_.openTab( logPath );
    emit fileOpened( logPath );
}

void LiveCaptureSession::takeSnapshot( unsigned run, const LiveSnapshot& snapshot )
{
    if ( run != runs_ ) {
        return;
    }
    // The progress needs the counts only; the summary is kept once, with
    // each text file.
    progress_.elapsed = snapshot.elapsed;
    progress_.rawBytes = snapshot.rawBytes;
    progress_.rawFile = snapshot.rawFile;
    progress_.summary.packets = snapshot.summary.packets;
    progress_.summary.bytes = snapshot.summary.bytes;
    // Every tab of the capture shows its summary so far, and reads packets
    // through its latest index: one of a ring buffer's files deleted since
    // says its packets were rotated away.
    for ( const auto& file : files_ ) {
        catalog_.updateFile( file, snapshot.summary, snapshot.index,
                             static_cast<qint64>( snapshot.rawBytes ) );
    }
    emit progressed();
}

void LiveCaptureSession::finish( unsigned run, const ConversionResult& result )
{
    if ( run != runs_ ) {
        return;
    }
    LiveOutcome outcome;
    outcome.name = name_;
    outcome.files = files_;
    outcome.stoppedBy = result.stoppedBy;
    setState( State::Idle );
    const bool opened = !files_.isEmpty();

    switch ( result.status ) {
    case ConversionResult::Status::Cancelled:
        // Never comes: LiveCapture has no cancel, its finished() is never
        // Cancelled.  The status is the conversion's, shared with a file's;
        // listed only for the switch to name every status.
    case ConversionResult::Status::Stopped: {
        // Stopped before the header came: nothing went wrong, and nothing
        // was written, so there is nothing to open or remove.
        outcome.status = LiveOutcome::Status::Stopped;
        outcome.files.clear();
        hostLog( LOGSQUIRL_LOG_INFO, liveOutcomeText( outcome ) );
        break;
    }

    case ConversionResult::Status::Failed:
        outcome.status = LiveOutcome::Status::Failed;
        outcome.error = result.error;
        if ( kind_ ) {
            outcome.guidance = kind_->explainFailure( result.error );
        }
        hostLog( LOGSQUIRL_LOG_ERROR, "Capture " + name_ + " failed: " + result.error );
        host_.notify( "Capture " + name_ + " failed: " + result.error );
        if ( !opened || result.outputPath.isEmpty() ) {
            outcome.files.clear();
            break;
        }
        for ( const auto& file : files_ ) {
            catalog_.setFileError( file, result.error );
        }
        break;

    case ConversionResult::Status::Converted:
        if ( !opened ) {
            // No tab shows it: its files go now.
            outcome.status = LiveOutcome::Status::Empty;
            if ( !result.outputPath.isEmpty() ) {
                QDir( QFileInfo( result.outputPath ).absolutePath() ).removeRecursively();
            }
            const auto message = liveOutcomeText( outcome );
            hostLog( LOGSQUIRL_LOG_INFO, message );
            host_.notify( message );
            break;
        }
        outcome.status = LiveOutcome::Status::Captured;
        hostLog(
            LOGSQUIRL_LOG_INFO,
            QString( "Captured %1 packets from %2" ).arg( result.summary.packets ).arg( name_ ) );
        if ( result.stoppedBy != StopCondition::None ) {
            // Nobody pressed Stop: whoever left it running is told.
            const auto message = liveStopText( name_, result.stoppedBy, limits_ );
            hostLog( LOGSQUIRL_LOG_INFO, message );
            host_.notify( message );
        }
        break;
    }

    // The final summary and index, which the tabs of the capture show from
    // now on.
    if ( !outcome.files.isEmpty() ) {
        for ( qsizetype i = 0; i < files_.size(); ++i ) {
            catalog_.updateFile( files_[ i ], result.summary, result.index,
                                 QFileInfo( rawFiles_[ static_cast<size_t>( i ) ] ).size() );
        }
    }
    outcome_ = outcome;
    emit finished( outcome );
}

void LiveCaptureSession::runDone( unsigned run )
{
    // Start live capture… asked for another one: once the last one is done,
    // its program ended too, so that two never capture at once.  Starting
    // it lets go of the run that tells this, which goes on living.
    if ( run != runs_ || !pending_ ) {
        return;
    }
    const auto choice = *pending_;
    pending_.reset();
    emit stateChanged();
    start( choice );
}

} // namespace tcpdump
