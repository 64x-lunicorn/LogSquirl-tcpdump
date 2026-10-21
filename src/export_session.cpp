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
 * @file export_session.cpp
 * @brief Exporting the selected packets from its start to its outcome.
 */

#include "export_session.h"

#include "plugin.h"
#include "selected_packet_line.h"

#include <QDir>
#include <QPointer>

namespace tcpdump {

ExportSession::ExportSession( SessionHost& host, const CaptureCatalog& catalog, QObject* parent )
    : QObject( parent )
    , host_( host )
    , catalog_( catalog )
    , confirm_( []( ExportRequest& ) { return false; } )
    , chooseFile_( []( const ExportRequest& ) { return QString(); } )
    , export_( []( std::shared_ptr<const CaptureIndex> index, const PacketNumbers& numbers,
                   const QString& outputPath, const std::atomic_bool* cancel,
                   const std::function<void( int )>& progress ) {
        return exportPackets( std::move( index ), numbers, outputPath, cancel, progress );
    } )
{
}

ExportSession::~ExportSession()
{
    // An export stops between two packets and leaves nothing behind; one
    // that was done when the cancel came keeps its file, as on Cancel.
    job_.cancelAndWait();
}

QString ExportSession::refusal() const
{
    auto running = host_.runningElsewhere();
    running.exporting = isBusy();
    return activityRefusalMessage( Activity::Export, running );
}

bool ExportSession::start()
{
    // The menu entry stays enabled while an export runs.
    if ( const auto why = refusal(); !why.isEmpty() ) {
        host_.notify( why );
        return false;
    }
    const auto* front = catalog_.front();
    if ( !front ) {
        host_.notify( "Export packets: the tab in front shows no capture opened by the tcpdump "
                      "plugin." );
        return false;
    }
    const auto& st = g_state;
    if ( !st.api || !st.handle || !st.hostCapabilities.selectedLogLines ) {
        host_.notify( "Export packets needs LogSquirl 26.11 or later, which tells the selected "
                      "lines." );
        return false;
    }
    const auto index = front->index;
    ExportRequest request;
    request.captureName = front->fileName;
    request.packets = index->packets();
    request.format = captureFormatOf( index->capturePath() );

    // Without a selection, the user may still name or paste the packets.
    const auto selected = selectedPackets( readSelectedLines(), request.packets );
    if ( !selected.reason.isEmpty() ) {
        host_.notify( "Export packets: " + selected.reason );
        return false;
    }
    request.numbers = selected.set.numbers;
    request.selectedLines = selected.lineCount;
    request.truncated = selected.truncated;
    if ( request.truncated ) {
        hostLog( LOGSQUIRL_LOG_INFO,
                 QString( "Export packets: LogSquirl told only the first %1 selected lines" )
                     .arg( request.selectedLines ) );
    }
    const auto ofSelection = request.numbers;

    // The dialogs run their own event loops, in which this session may be
    // destroyed (the sidebar closed), or the menu entry chosen again.  They
    // are called as copies: the session's own go with it.
    const QPointer<ExportSession> self( this );
    const auto confirm = confirm_;
    const bool confirmed = confirm( request );
    if ( !self || !confirmed || request.numbers.empty() ) {
        return false;
    }
    const auto chooseFile = chooseFile_;
    request.outputPath = chooseFile( request );
    if ( !self || request.outputPath.isEmpty() ) {
        return false;
    }
    if ( const auto why = refusal(); !why.isEmpty() ) {
        host_.notify( why );
        return false;
    }
    // Only when the selection's packets are exported does its truncation matter.
    request.truncated = request.truncated && request.numbers == ofSelection;
    hostLog( LOGSQUIRL_LOG_INFO, QString( "Exporting %1 packets of %2 to %3" )
                                     .arg( request.numbers.count() )
                                     .arg( request.captureName, request.outputPath ) );

    request_ = request;
    progress_ = 0;
    outcome_.reset();

    // An export stops at a cancel, before its file replaces the one chosen
    // (exportPackets()).  Once it has, a cancel comes too late: the file
    // that was there is gone, and removing the export would lose both.
    // The export stands, and is reported.
    job_.start(
        [ exporter = export_, index, numbers = request.numbers,
          path = request.outputPath ]( const std::atomic_bool* cancel,
                                       const BackgroundJob<ExportResult>::Progress& progress ) {
            return exporter( index, numbers, path, cancel, progress );
        },
        // A cancelled or failed export left nothing behind to take back;
        // one that wrote its file cannot be taken back.
        []( const ExportResult& result ) {
            return result.status != ExportResult::Status::Exported;
        },
        [ this ]( ExportResult result ) { finish( std::move( result ) ); },
        [ this ]( int permille ) {
            progress_ = permille;
            emit progressed( permille );
        } );
    setState( State::Exporting );
    return true;
}

void ExportSession::cancel()
{
    if ( state_ != State::Exporting ) {
        return;
    }
    job_.cancel();
    setState( State::Cancelling );
}

QString ExportSession::label() const
{
    switch ( state_ ) {
    case State::Exporting:
        return QString( "Exporting %1 packets\xe2\x80\xa6" ).arg( request_.numbers.count() );
    case State::Cancelling:
        return "Cancelling\xe2\x80\xa6";
    case State::Idle:
        break;
    }
    return outcome_ ? outcome_->label : QString();
}

void ExportSession::finish( ExportResult result )
{
    // Idle before anything is told, so that the next export may start.
    setState( State::Idle );

    ExportOutcome outcome;
    outcome.request = request_;
    outcome.packets = result.packets;
    const auto fileName = QDir::toNativeSeparators( request_.outputPath );
    switch ( result.status ) {
    case ExportResult::Status::Cancelled:
        outcome.status = ExportOutcome::Status::Cancelled;
        outcome.label = "Cancelled.";
        outcome.log = "Cancelled exporting packets to " + fileName;
        hostLog( LOGSQUIRL_LOG_INFO, outcome.log );
        break;

    case ExportResult::Status::Failed:
        outcome.status = ExportOutcome::Status::Failed;
        outcome.error = result.error;
        outcome.label = "Error: " + result.error;
        outcome.log = "Exporting packets failed: " + result.error;
        outcome.notification = outcome.log;
        hostLog( LOGSQUIRL_LOG_ERROR, outcome.log );
        host_.notify( outcome.notification );
        break;

    case ExportResult::Status::Exported: {
        outcome.status = ExportOutcome::Status::Exported;
        auto message = QString( "Exported %1 packets of %2 to %3." )
                           .arg( result.packets )
                           .arg( request_.captureName, fileName );
        if ( request_.truncated ) {
            message += QString( " LogSquirl told only the first %1 selected lines: to export the "
                                "packets of more, copy their lines and paste them in the Export "
                                "dialog." )
                           .arg( request_.selectedLines );
        }
        outcome.label = message;
        outcome.log = message;
        outcome.notification = message;
        hostLog( LOGSQUIRL_LOG_INFO, outcome.log );
        host_.notify( outcome.notification );
        break;
    }
    }

    outcome_ = outcome;
    emit finished( outcome );
}

void ExportSession::setState( State state )
{
    if ( state_ == state ) {
        return;
    }
    state_ = state;
    emit stateChanged();
}

} // namespace tcpdump
