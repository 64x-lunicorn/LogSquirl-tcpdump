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
 * @file live_capture.cpp
 * @brief Running a live conversion on a worker thread, told on the UI thread.
 */

#include "live_capture.h"

#include <QMetaObject>

#include <algorithm>
#include <exception>
#include <vector>

namespace tcpdump {

LiveCapture::SourceFactory LiveCapture::processSource( const ProcessCommand& command )
{
    return [ command ]( const std::atomic_bool* stop,
                        std::function<void( const QString& )> onStderrLine ) {
        return std::make_unique<ProcessSource>( command, stop, std::move( onStderrLine ) );
    };
}

LiveCapture::LiveCapture( const QString& name, const QString& outputRoot,
                          const ConversionOptions& options, SourceFactory makeSource,
                          QObject* parent )
    : QObject( parent )
    , name_( name )
    , outputRoot_( outputRoot )
    , options_( options )
    , makeSource_( std::move( makeSource ) )
{
    pool_.setMaxThreadCount( 1 );
}

LiveCapture::~LiveCapture()
{
    // Stopped, not cancelled: a tab may show the file already, and after a
    // runtime disable of the plugin it stays open.
    stop_->store( true );
    pool_.waitForDone();
}

void LiveCapture::post( std::function<void()> work )
{
    // Queued to this object: dropped if it is destroyed before it runs.
    QMetaObject::invokeMethod( this, std::move( work ), Qt::QueuedConnection );
}

void LiveCapture::start()
{
    if ( started_ ) {
        return;
    }
    started_ = true;
    running_ = true;

    // The worker uses copies and the flags it shares; this object only to
    // post to, which outlives the worker (the destructor waits for it).
    pool_.start( [ this, name = name_, outputRoot = outputRoot_, options = options_,
                   makeSource = makeSource_, limits = limits_, clock = clock_, stop = stop_ ] {
        ConversionResult result;
        std::unique_ptr<ByteSource> source;
        try {
            source = makeSource( stop.get(), [ this ]( const QString& line ) {
                post( [ this, line ] { emit stderrLine( line ); } );
            } );
        } catch ( const std::exception& e ) {
            result.error = QString::fromUtf8( e.what() );
        }
        if ( source ) {
            LiveObserver observer;
            observer.firstPacket = [ this ]( const QString& logPath, const QString& rawPath ) {
                post( [ this, logPath, rawPath ] { emit readyToOpen( logPath, rawPath ); } );
            };
            observer.snapshot = [ this ]( LiveSnapshot&& snapshot ) {
                post( [ this, snapshot = std::move( snapshot ) ] {
                    emit snapshotTaken( snapshot );
                } );
            };
            result = convertStream( *source, name, outputRoot, nullptr, options, observer, limits,
                                    clock );
        }
        else if ( result.error.isEmpty() ) {
            result.error = QStringLiteral( "The capture source could not be opened" );
        }
        post( [ this, result ] {
            running_ = false;
            emit finished( result );
        } );
        // May take a while: a capture program is ended here.
        source.reset();
        post( [ this ] {
            done_ = true;
            emit done();
        } );
    } );
}

void LiveCapture::stop()
{
    stop_->store( true );
}

namespace {

/// The retired captures, on the UI thread.
std::vector<std::unique_ptr<LiveCapture>>& retired()
{
    static std::vector<std::unique_ptr<LiveCapture>> captures;
    return captures;
}

/// Let go of the retired captures that are done: destroying them waits for
/// nothing (or for a worker's last moments, after done()).
void sweep()
{
    auto& captures = retired();
    captures.erase( std::remove_if( captures.begin(), captures.end(),
                                    []( const auto& capture ) { return capture->isDone(); } ),
                    captures.end() );
}

} // namespace

void retireLiveCapture( std::unique_ptr<LiveCapture> capture )
{
    sweep();
    if ( !capture ) {
        return;
    }
    capture->disconnect();
    capture->stop();
    if ( !capture->isDone() ) {
        retired().push_back( std::move( capture ) );
    }
}

void joinLiveCaptures()
{
    auto& captures = retired();
    for ( auto& capture : captures ) {
        capture->stop();
    }
    // Each destructor waits for its worker.
    captures.clear();
}

size_t retiredLiveCaptures()
{
    sweep();
    return retired().size();
}

} // namespace tcpdump
