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
 * @file capture_sessions.cpp
 * @brief The plugin's sessions, and the actions that start them.
 */

#include "capture_sessions.h"

#include "capture_file.h"
#include "export_dialog.h"
#include "live_capture_form.h"
#include "plugin.h"
#include "raw_capture.h"
#include "settings.h"
#include "tempdirs.h"

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QMessageBox>
#include <QStandardPaths>

#include <exception>

namespace tcpdump {

namespace {

/// What setDefaultLiveSources() set; null: builtInLiveSources().
std::shared_ptr<const LiveSourceRegistry>& defaultLiveSources()
{
    static std::shared_ptr<const LiveSourceRegistry> sources;
    return sources;
}

} // namespace

void CaptureSessions::setDefaultLiveSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    defaultLiveSources() = std::move( sources );
}

CaptureSessions::CaptureSessions( QObject* parent )
    : QObject( parent )
    , chooseFile_( []( QWidget* parent, const QString& dir ) {
        return QFileDialog::getOpenFileName(
            parent, "Open pcap Capture File", dir,
            "Capture files (*.pcap *.pcapng *.cap *.dmp *.pcap.gz *.pcapng.gz *.cap.gz);;"
            "All files (*)" );
    } )
    , chooseSaveFile_( []( QWidget* parent, const QString& suggested ) {
        return QFileDialog::getSaveFileName( parent, "Save Capture", suggested,
                                             "Capture files (*.pcap *.pcapng);;All files (*)" );
    } )
    , confirmStop_( []( QWidget* parent, const QString& running ) {
        return QMessageBox::question(
                   parent, "Start Live Capture",
                   QString( "The live capture %1 is running: only one runs at a time. Stop it?" )
                       .arg( running ),
                   QMessageBox::Yes | QMessageBox::No, QMessageBox::No )
               == QMessageBox::Yes;
    } )
    , tempRoot_( tcpdump::tempRoot() )
{
    listingPool_.setMaxThreadCount( 4 );
    askLiveChoice_ = [ this ]( QWidget* parent, LiveChoice& choice ) {
        // Neither these sessions nor their members are used after the
        // dialog: they may be gone when it returns (their pool waits for
        // the listings).
        const auto dialog = makeLiveCaptureDialog( parent, choice );
        if ( dialog->exec() != QDialog::Accepted ) {
            return false;
        }
        choice = dialog->choice();
        return true;
    };

    SessionHost& host = *this;
    conversion_ = std::make_unique<FileConversionSession>( host, catalog_ );
    conversion_->setOutputRoot( tempRoot_ );
    live_ = std::make_unique<LiveCaptureSession>( host, catalog_ );
    live_->setOutputRoot( tempRoot_ );

    // The Export session asks with the Export dialog and a save dialog, and
    // tells the outcome itself.
    export_ = std::make_unique<ExportSession>( host, catalog_ );
    export_->setConfirmer( [ this ]( ExportRequest& request ) {
        // Neither these sessions nor their members are used after the
        // dialog: they may be gone when it returns.
        ExportDialog dialog( request, dialogParent() );
        if ( dialog.exec() != QDialog::Accepted ) {
            return false;
        }
        request.numbers = dialog.packetSet().numbers;
        return true;
    } );
    export_->setFileChooser( [ this ]( const ExportRequest& request ) {
        const auto dir = browseDir();
        const bool pcapng = request.format == CaptureFormat::Pcapng;
        const auto suggested
            = QDir( dir ).filePath( tcpdump::captureBaseName( request.captureName ) + "-packets."
                                    + ( pcapng ? "pcapng" : "pcap" ) );
        // Neither these sessions nor their members are used after the dialog.
        return QFileDialog::getSaveFileName( dialogParent(), "Export Packets", suggested,
                                             pcapng ? "pcapng captures (*.pcapng);;All files (*)"
                                                    : "pcap captures (*.pcap);;All files (*)" );
    } );

    setLiveSources( defaultLiveSources() ? defaultLiveSources() : builtInLiveSources() );
}

CaptureSessions::~CaptureSessions()
{
    // The listings of the Start live capture dialog are waited for by
    // listingPool_, as the host unloads the library next: their programs
    // are killed first, so that this takes moments, not a listing's timeout.
    // First, as a live capture's worker may be listing too.
    cancelListings();

    // A live capture is stopped, not cancelled: its tab may stay open after
    // a runtime disable.  Its worker is not waited for here: the plugin's
    // shutdown joins it (joinLiveCaptures()), with its program ended.
    live_.reset();

    // The host unloads the library right after the plugin is shut down:
    // the session cancels its conversion and waits for its worker.
    conversion_.reset();

    // The session cancels its export and waits for its worker: an export
    // stops between two packets and leaves nothing behind; one that was
    // done when the cancel came keeps its file, as on Cancel.
    export_.reset();
}

RunningActivities CaptureSessions::runningActivities() const
{
    RunningActivities running;
    running.converting = conversion_->isBusy();
    running.capturing = live_->isBusy();
    running.exporting = export_->isBusy();
    return running;
}

void CaptureSessions::setTempRoot( const QString& dir )
{
    tempRoot_ = dir;
    conversion_->setOutputRoot( dir );
    live_->setOutputRoot( dir );
}

void CaptureSessions::setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    liveSources_ = std::move( sources );
    live_->setSources( liveSources_ );
}

QString CaptureSessions::browseDir()
{
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }
    return lastDir_;
}

void CaptureSessions::chooseAndOpen()
{
    // The Open button is disabled meanwhile, but the menu entry is not.
    if ( const auto why = conversion_->refusal(); !why.isEmpty() ) {
        hostNotify( why );
        return;
    }

    // The dialog runs its own event loop, in which these sessions may be
    // deleted, as the plugin is shut down: then there is nothing left to
    // open the file for.  This does not help if the plugin is unloaded while
    // the dialog is open: the code this call returns into is gone then, and
    // only the host can prevent that.
    const QPointer<CaptureSessions> self( this );
    const auto filePath = chooseFile_( dialogParent(), browseDir() );
    if ( !self || filePath.isEmpty() ) {
        return;
    }

    lastDir_ = QFileInfo( filePath ).absolutePath();
    try {
        // The session refuses, converts, and tells its state and outcome.
        conversion_->start( filePath );
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog(
            LOGSQUIRL_LOG_ERROR,
            QString( "Opening %1 failed: %2" ).arg( filePath, QString::fromUtf8( e.what() ) ) );
    }
}

void CaptureSessions::chooseAndStartLiveCapture()
{
    // A capture that runs is not refused: the user is offered to stop it.
    const auto refusal = activityRefusal( Activity::LiveCapture, runningActivities() );
    if ( refusal && *refusal != ActivityRefusal::Capturing ) {
        hostNotify( refusalMessage( *refusal ) );
        return;
    }
    if ( live_->hasPendingStart() ) {
        hostNotify( "A live capture is still stopping: the next one starts when it has ended." );
        return;
    }
    // The dialogs run their own event loops, in which these sessions may be
    // deleted, or the capture end by itself.
    const QPointer<CaptureSessions> self( this );
    if ( refusal ) {
        const auto running
            = live_->state() == LiveCaptureSession::State::Checking && live_->choice()
                  ? liveCaptureName( *live_->choice() )
                  : live_->name();
        if ( !confirmStop_( dialogParent(), running ) || !self ) {
            return;
        }
    }
    auto choice = loadLiveChoice( hostConfigDir() );
    if ( !askLiveChoice_( dialogParent(), choice ) || !self ) {
        return;
    }
    // Once the running one, if any, has ended and its program too.
    live_->startWhenIdle( choice );
}

std::unique_ptr<LiveCaptureDialog> CaptureSessions::makeLiveCaptureDialog( QWidget* parent )
{
    return makeLiveCaptureDialog( parent, loadLiveChoice( hostConfigDir() ) );
}

std::unique_ptr<LiveCaptureDialog>
CaptureSessions::makeLiveCaptureDialog( QWidget* parent, const LiveChoice& choice )
{
    auto dialog
        = std::make_unique<LiveCaptureDialog>( liveSources_, choice, parent, &listingPool_ );
    // Another source chosen there starts with the options saved for it.
    if ( liveSources_ ) {
        for ( const auto& kind : liveSources_->kinds() ) {
            if ( kind->id() != choice.source ) {
                dialog->form()->setSourceOptions( kind->id(),
                                                  loadLiveOptions( hostConfigDir(), kind->id() ) );
            }
        }
    }
    return dialog;
}

void CaptureSessions::stopLiveCapture()
{
    // The sidebar's Stop shows only while one runs, but the menu entry is
    // always there.
    if ( !live_->isBusy() ) {
        hostNotify( "No live capture is running." );
        return;
    }
    live_->stop();
}

void CaptureSessions::exportSelectedPackets()
{
    // The session refuses, asks, exports, and tells its state and outcome.
    export_->start();
}

void CaptureSessions::saveCapture()
{
    const auto parts = catalog_.partsToSave();
    if ( parts.empty() ) {
        return;
    }
    const auto suggested = catalog_.saveName();
    // The dialog runs its own event loop, as in chooseAndOpen().
    const QPointer<CaptureSessions> self( this );
    const auto target
        = chooseSaveFile_( dialogParent(), QDir( browseDir() ).filePath( suggested ) );
    if ( !self || target.isEmpty() ) {
        return;
    }
    lastDir_ = QFileInfo( target ).absolutePath();

    // The dialog asked before replacing a file; it is replaced when the
    // capture is complete.
    QString error;
    if ( !saveCaptureParts( parts, target, error ) ) {
        const auto message = QString( "The capture could not be saved as %1: %2" )
                                 .arg( QDir::toNativeSeparators( target ), error );
        hostLog( LOGSQUIRL_LOG_ERROR, message );
        hostNotify( message );
        return;
    }
    hostLog( LOGSQUIRL_LOG_INFO, parts.size() > 1
                                     ? QString( "Saved the %1 files of the ring buffer as %2" )
                                           .arg( parts.size() )
                                           .arg( target )
                                     : "Saved the capture as " + target );
}

void CaptureSessions::openTab( const QString& logPath, bool follow )
{
    // On this, the UI thread.  The header and a packet line are in it, so
    // the host recognises the Log Format; a live capture's grows.
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, logPath.toUtf8().constData(), follow ? 1 : 0 );
    }
}

void CaptureSessions::notify( const QString& message )
{
    hostNotify( message );
}

RunningActivities CaptureSessions::runningElsewhere() const
{
    // Each session puts in its own, converting, capturing or exporting.
    return runningActivities();
}

} // namespace tcpdump
