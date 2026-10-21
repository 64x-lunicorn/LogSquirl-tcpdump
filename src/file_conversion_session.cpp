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
 * @file file_conversion_session.cpp
 * @brief Opening a capture file from its start to its outcome.
 */

#include "file_conversion_session.h"

#include "plugin.h"
#include "settings.h"

#include <QFileInfo>

namespace tcpdump {

FileConversionSession::FileConversionSession( SessionHost& host, CaptureCatalog& catalog,
                                              QObject* parent )
    : QObject( parent )
    , host_( host )
    , catalog_( catalog )
    , convert_( []( const QString& filePath, const QString& outputRoot,
                    const std::atomic_bool* cancel, const std::function<void( int )>& progress,
                    const ConversionOptions& options ) {
        return convertPcap( filePath, outputRoot, cancel, progress, options );
    } )
{
}

FileConversionSession::~FileConversionSession()
{
    // The host unloads the library right after the plugin is shut down:
    // the worker must be done with it before.  It checks the cancel flag
    // between packets, and convertPcap() reads regular files only, so it
    // cannot block on a FIFO or device; a regular file on a network share
    // that stalls can still hold it up until the system gives up on it.
    // A conversion that finished before the cancel reached it wrote a file
    // no tab will show: the cancel wins, and the file goes.
    job_.cancelAndWait();
}

QString FileConversionSession::refusal() const
{
    auto running = host_.running();
    running.converting = isBusy();
    return activityRefusalMessage( Activity::OpenFile, running );
}

bool FileConversionSession::start( const QString& filePath )
{
    if ( const auto why = refusal(); !why.isEmpty() ) {
        host_.notify( why );
        return false;
    }
    hostLog( LOGSQUIRL_LOG_INFO, "Opening pcap file: " + filePath );

    // The Converter writes into a new private directory below the output
    // root, kept for its tab until LogSquirl quits, and reports every
    // failure as a result: nothing is caught here.  It converts with the
    // options saved when it starts: a change of them in the configuration
    // dialog applies to the next capture, the tab of this one keeps its own.
    // A cancel wins over a conversion that was done when it came: its
    // directory goes.
    filePath_ = filePath;
    progress_ = 0;
    outcome_.reset();
    const auto outputRoot = outputRoot_;
    const auto options = loadConversionOptions( hostConfigDir() );
    job_.start(
        [ convert = convert_, filePath, outputRoot,
          options ]( const std::atomic_bool* cancel,
                     const BackgroundJob<ConversionResult>::Progress& progress ) {
            return convert( filePath, outputRoot, cancel, progress, options );
        },
        []( const ConversionResult& result ) {
            removeOutput( result );
            return true;
        },
        [ this ]( ConversionResult result ) { finish( std::move( result ) ); },
        [ this ]( int permille ) {
            progress_ = permille;
            emit progressed( permille );
        } );
    setState( State::Converting );
    return true;
}

void FileConversionSession::cancel()
{
    if ( state_ != State::Converting ) {
        return;
    }
    job_.cancel();
    setState( State::Cancelling );
}

QString FileConversionSession::label() const
{
    switch ( state_ ) {
    case State::Converting:
        return QString( "Reading %1\xe2\x80\xa6" )
            .arg( QFileInfo( filePath_ ).fileName().toHtmlEscaped() );
    case State::Cancelling:
        return "Cancelling\xe2\x80\xa6";
    case State::Idle:
        break;
    }
    return outcome_ ? outcome_->label : QString();
}

void FileConversionSession::finish( ConversionResult result )
{
    // Idle before the catalog announces the capture in front, so that it is
    // drawn as the one opened, not as one still being read.
    setState( State::Idle );

    FileConversionOutcome outcome;
    outcome.filePath = filePath_;
    switch ( result.status ) {
    case ConversionResult::Status::Cancelled:
    case ConversionResult::Status::Stopped: // only a stream is stopped
        outcome.status = FileConversionOutcome::Status::Cancelled;
        outcome.label = "Cancelled.";
        outcome.log = "Cancelled opening " + filePath_;
        hostLog( LOGSQUIRL_LOG_INFO, outcome.log );
        break;

    case ConversionResult::Status::Failed:
        outcome.status = FileConversionOutcome::Status::Failed;
        outcome.error = result.error;
        outcome.label = "Error: " + result.error.toHtmlEscaped();
        outcome.log = "pcap parse error: " + result.error;
        outcome.notification = "Failed to open pcap: " + result.error;
        hostLog( LOGSQUIRL_LOG_ERROR, outcome.log );
        host_.notify( outcome.notification );
        break;

    case ConversionResult::Status::Converted: {
        // Its tab opens in the LogSquirl viewer, and is the one in front;
        // the file stays until LogSquirl quits.
        outcome.status = FileConversionOutcome::Status::Opened;
        outcome.textPath = result.outputPath;
        outcome.log
            = QString( "Opened %1 packets from %2" ).arg( result.summary.packets ).arg( filePath_ );
        catalog_.openConverted( result.outputPath, filePath_, std::move( result.summary ),
                                std::move( result.index ) );
        catalog_.setFront( outcome.textPath );
        hostLog( LOGSQUIRL_LOG_INFO, outcome.log );
        break;
    }
    }

    outcome_ = outcome;
    emit finished( outcome );
}

void FileConversionSession::setState( State state )
{
    if ( state_ == state ) {
        return;
    }
    state_ = state;
    emit stateChanged();
}

} // namespace tcpdump
