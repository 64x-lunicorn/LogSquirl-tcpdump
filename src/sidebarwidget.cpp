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
 * @file sidebarwidget.cpp
 * @brief Implementation of the tcpdump sidebar panel.
 *
 * When the user clicks "Open pcap…", the widget:
 *   1. Opens a file dialog for .pcap / .cap / .dmp files
 *   2. Converts the pcap packet by packet with pcap_converter: parses each
 *      packet, formats it into a human-readable line, and writes the line
 *      to a temporary .log file
 *   3. Opens the .log file in LogSquirl's main viewer
 *
 * Its Follow stream button, on a host that offers it, opens the Regex Lab on
 * the conversation of the selected packet line (see follow_stream.h).
 *
 * The endpoints and protocols its summary lists are links, on a host that
 * has the Regex Lab: a click opens the Lab with the pattern of their lines
 * (see regex_lab.h).  The tunnel endpoints are not: the addresses of the
 * packets that carried a tunnelled one show in no column, so no pattern
 * could pick their lines.
 *
 * It keeps each converted capture's summary and CaptureIndex under the path
 * of its .log file and shows the one of the tab in front, as the host
 * reports tab switches; its Packet Panel shows the packets of that capture.
 *
 * A live capture (startLiveCapture()) runs in a LiveCapture: its tab is
 * opened, following the file, on the UI thread once the first packet line is
 * there, and its summary follows the snapshots until Stop finalises it.  The
 * Live capture section, and the Start live capture… dialog, choose what to
 * capture from the Live Source Kinds (live_source.h): the kind chosen makes
 * the stream, and explains a failure.
 *
 * Export packets… reads the selected lines, lets the user confirm or change
 * their packets in the ExportDialog, asks where to write them, and writes
 * them with exportPackets() on a worker thread of its own, so that an
 * export and a conversion can run side by side.
 */

#include "sidebarwidget.h"

#include "capture_file.h"
#include "conversation_table.h"
#include "display_filter_dialog.h"
#include "follow_stream.h"
#include "live_capture_form.h"
#include "packet_export.h"
#include "packet_panel.h"
#include "pcap_converter.h"
#include "plugin.h"
#include "raw_capture.h"
#include "regex_lab.h"
#include "settings.h"
#include "tempdirs.h"

#include <QDesktopServices>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QGroupBox>
#include <QLocale>
#include <QMessageBox>
#include <QPointer>
#include <QPromise>
#include <QStandardPaths>
#include <QStringList>
#include <QUrl>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <exception>
#include <map>
#include <vector>

namespace tcpdump {

namespace {

/// The README section on installing the Log Format and what it unlocks.
const char* const kLogFormatHelpUrl
    = "https://github.com/64x-lunicorn/LogSquirl-tcpdump#log-format";

/// What the summary says for a tab that shows no capture of the plugin.
const char* const kNoCaptureText = "No capture in this tab.";

/// The links of the summary that open a filter: this, then "endpoint/" or
/// "protocol/" and the percent-encoded name.
const char* const kFilterScheme = "tcpdump-filter:";
const char* const kEndpointFilter = "endpoint/";
const char* const kProtocolFilter = "protocol/";

/// The pattern of the filter @p link opens; empty for any other link.
QString filterPattern( const QString& link )
{
    if ( !link.startsWith( kFilterScheme ) ) {
        return {};
    }
    const auto filter = link.mid( static_cast<qsizetype>( qstrlen( kFilterScheme ) ) );
    const auto nameOf = []( const QString& rest, const char* kind ) {
        return QString::fromUtf8(
            QByteArray::fromPercentEncoding( rest.mid( qstrlen( kind ) ).toUtf8() ) );
    };
    if ( filter.startsWith( kEndpointFilter ) ) {
        return endpointPattern( nameOf( filter, kEndpointFilter ) );
    }
    if ( filter.startsWith( kProtocolFilter ) ) {
        return protocolPattern( nameOf( filter, kProtocolFilter ) );
    }
    return {};
}

/// One spelling of @p filePath, so that the path the host reports for a tab
/// finds the file the plugin wrote: e.g. on macOS the temporary directory
/// /var/folders/... is a link to /private/var/folders/....
QString fileKey( const QString& filePath )
{
    if ( filePath.isEmpty() ) {
        return {};
    }
    const QFileInfo info( filePath );
    const auto canonical = info.canonicalFilePath();
    return canonical.isEmpty() ? info.absoluteFilePath() : canonical;
}

/// What setDefaultLiveSources() set; null: builtInLiveSources().
std::shared_ptr<const LiveSourceRegistry>& defaultLiveSources()
{
    static std::shared_ptr<const LiveSourceRegistry> sources;
    return sources;
}

} // namespace

void SidebarWidget::setDefaultLiveSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    defaultLiveSources() = std::move( sources );
}

SidebarWidget::SidebarWidget( QWidget* parent )
    : QWidget( parent )
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
    , tempRoot_( tcpdump::tempRoot() )
    , confirmExport_( [ this ]( QWidget* parent, ExportRequest& request ) {
        const auto dir = lastDir_.isEmpty()
                             ? QStandardPaths::writableLocation( QStandardPaths::HomeLocation )
                             : lastDir_;
        // Neither this widget nor its members are used after the dialogs:
        // it may be gone when they return.
        ExportDialog dialog( request, parent );
        if ( dialog.exec() != QDialog::Accepted ) {
            return false;
        }
        request.numbers = dialog.packetSet().numbers;
        const bool pcapng = request.format == CaptureFormat::Pcapng;
        const auto suggested
            = QDir( dir ).filePath( tcpdump::captureBaseName( request.captureName ) + "-packets."
                                    + ( pcapng ? "pcapng" : "pcap" ) );
        request.outputPath
            = QFileDialog::getSaveFileName( parent, "Export Packets", suggested,
                                            pcapng ? "pcapng captures (*.pcapng);;All files (*)"
                                                   : "pcap captures (*.pcap);;All files (*)" );
        return !request.outputPath.isEmpty();
    } )
{
    pool_.setMaxThreadCount( 1 );
    exportPool_.setMaxThreadCount( 1 );

    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 8, 8, 8, 8 );
    layout->setSpacing( 6 );

    // Title
    auto* title = new QLabel( "<b>tcpdump / pcap Viewer</b>" );
    layout->addWidget( title );

    // Open button
    openButton_ = new QPushButton( "Open pcap\xe2\x80\xa6" );
    openButton_->setObjectName( "openButton" );
    openButton_->setToolTip( "Open a pcap capture file and display it as text" );
    layout->addWidget( openButton_ );

    connect( openButton_, &QPushButton::clicked, this, &SidebarWidget::chooseAndOpen );

    // Follow stream, as in the Plugins menu: only a host that has the Regex
    // Lab and tells the selected lines gets it.
    if ( g_state.hostCapabilities.regexLab && g_state.hostCapabilities.selectedLogLines ) {
        auto* followButton = new QPushButton( "Follow stream" );
        followButton->setObjectName( "followStreamButton" );
        followButton->setToolTip( "Filter the conversation of the selected packet line in the "
                                  "Regex Lab" );
        layout->addWidget( followButton );
        connect( followButton, &QPushButton::clicked, this, [] {
            try {
                followSelectedStream();
            } catch ( const std::exception& e ) {
                // An exception must not escape into Qt or the host.
                hostLog( LOGSQUIRL_LOG_ERROR,
                         "Follow stream failed: " + QString::fromUtf8( e.what() ) );
            }
        } );
    }

    // A display filter, as Plugins > tcpdump > Display filter… asks for it:
    // only a host that has the Regex Lab gets it.
    if ( g_state.hostCapabilities.regexLab ) {
        layout->addWidget( new DisplayFilterField );
    }

    // Progress of a running conversion, and a way to stop it
    progressBar_ = new QProgressBar;
    progressBar_->setObjectName( "progress" );
    progressBar_->setRange( 0, 1000 );
    progressBar_->setTextVisible( false );
    layout->addWidget( progressBar_ );

    cancelButton_ = new QPushButton( "Cancel" );
    cancelButton_->setObjectName( "cancelButton" );
    cancelButton_->setToolTip( "Stop reading the capture" );
    layout->addWidget( cancelButton_ );
    connect( cancelButton_, &QPushButton::clicked, this, &SidebarWidget::cancel );

    // Live capture: what to capture, Start and Stop, the progress (no
    // percentage, a stream has no size) and what the capture program says.
    auto* liveSection = new QGroupBox( "Live capture" );
    liveSection->setObjectName( "liveSection" );
    auto* liveLayout = new QVBoxLayout( liveSection );
    liveLayout->setSpacing( 4 );

    listingPool_.setMaxThreadCount( 4 );
    liveForm_ = new LiveCaptureForm( &listingPool_ );
    liveForm_->setObjectName( "liveForm" );
    liveLayout->addWidget( liveForm_ );
    connect( liveForm_, &LiveCaptureForm::changed, this, &SidebarWidget::updateStartButton );

    startButton_ = new QPushButton( "Start" );
    startButton_->setObjectName( "liveStartButton" );
    liveLayout->addWidget( startButton_ );
    connect( startButton_, &QPushButton::clicked, this, [ this ] {
        try {
            startLiveCapture( liveForm_->choice() );
        } catch ( const std::exception& e ) {
            // An exception must not escape into Qt or the host.
            hostLog( LOGSQUIRL_LOG_ERROR,
                     "Starting a live capture failed: " + QString::fromUtf8( e.what() ) );
        }
    } );

    liveLabel_ = new QLabel;
    liveLabel_->setObjectName( "liveProgress" );
    liveLabel_->setWordWrap( true );
    liveLayout->addWidget( liveLabel_ );

    stopButton_ = new QPushButton( "Stop" );
    stopButton_->setObjectName( "stopButton" );
    stopButton_->setToolTip( "End the capture and keep what was captured" );
    liveLayout->addWidget( stopButton_ );
    connect( stopButton_, &QPushButton::clicked, this, &SidebarWidget::stopLiveCapture );

    liveError_ = new QLabel;
    liveError_->setObjectName( "liveError" );
    liveError_->setWordWrap( true );
    liveError_->setTextInteractionFlags( Qt::TextSelectableByMouse );
    liveError_->setHidden( true );
    liveLayout->addWidget( liveError_ );

    // The capture program's stderr, the latest lines; also in the host's log.
    liveStderr_ = new QPlainTextEdit;
    liveStderr_->setObjectName( "liveStderr" );
    liveStderr_->setReadOnly( true );
    liveStderr_->setMaximumBlockCount( 200 );
    liveStderr_->setLineWrapMode( QPlainTextEdit::NoWrap );
    liveStderr_->setMaximumHeight( 5 * fontMetrics().lineSpacing() + 12 );
    liveStderr_->setToolTip( "What the capture program wrote to stderr" );
    liveStderr_->setHidden( true );
    liveLayout->addWidget( liveStderr_ );

    layout->addWidget( liveSection );

    liveTicker_.setInterval( 1000 );
    connect( &liveTicker_, &QTimer::timeout, this, &SidebarWidget::showLiveProgress );

    // Summary label
    summaryLabel_ = new QLabel( "No capture loaded." );
    summaryLabel_->setObjectName( "summary" );
    summaryLabel_->setTextFormat( Qt::RichText );
    summaryLabel_->setWordWrap( true );
    // Its links are opened here: filters in the Regex Lab, pages outside.
    summaryLabel_->setTextInteractionFlags( Qt::LinksAccessibleByMouse );
    connect( summaryLabel_, &QLabel::linkActivated, this, &SidebarWidget::openLink );
    layout->addWidget( summaryLabel_ );

    // A live capture's raw file is in the temporary directory, which goes
    // when LogSquirl quits: this keeps it.
    saveButton_ = new QPushButton( "Save capture\xe2\x80\xa6" );
    saveButton_->setObjectName( "saveCaptureButton" );
    saveButton_->setToolTip( "Save the raw capture of this tab as a pcap file; a ring buffer's "
                             "files kept as one" );
    saveButton_->setHidden( true );
    layout->addWidget( saveButton_ );
    connect( saveButton_, &QPushButton::clicked, this, &SidebarWidget::saveCapture );

    // The packet of the selected line, below; it takes the room left.
    packetPanel_ = new PacketPanel;
    packetPanel_->setObjectName( "packetPanel" );
    layout->addWidget( packetPanel_, 1 );

    askLiveChoice_ = [ this ]( QWidget* parent, LiveChoice& choice ) {
        // Neither this widget nor its members are used after the dialog:
        // it may be gone when it returns (its pool waits for the listings).
        LiveCaptureDialog dialog( liveSources_, choice, parent, &listingPool_ );
        // Another source chosen there starts with the options saved for it.
        if ( liveSources_ ) {
            for ( const auto& kind : liveSources_->kinds() ) {
                if ( kind->id() != choice.source ) {
                    dialog.form()->setSourceOptions(
                        kind->id(), loadLiveOptions( hostConfigDir(), kind->id() ) );
                }
            }
        }
        if ( dialog.exec() != QDialog::Accepted ) {
            return false;
        }
        choice = dialog.choice();
        return true;
    };
    confirmStop_ = []( QWidget* parent, const QString& running ) {
        return QMessageBox::question(
                   parent, "Start Live Capture",
                   QString( "The live capture %1 is running: only one runs at a time. Stop it?" )
                       .arg( running ),
                   QMessageBox::Yes | QMessageBox::No, QMessageBox::No )
               == QMessageBox::Yes;
    };

    setConverting( false );
    setCapturing( false );
    setLiveSources( defaultLiveSources() ? defaultLiveSources() : builtInLiveSources() );
}

SidebarWidget::~SidebarWidget()
{
    // The listings of the form and the dialog are waited for by
    // listingPool_, as the host unloads the library next: their programs
    // are killed first, so that this takes moments, not a listing's timeout.
    // First, as a live capture's worker may be listing too.
    cancelListings();

    // A live capture is stopped, not cancelled: its tab may stay open after
    // a runtime disable.  Its worker is not waited for here: the plugin's
    // shutdown joins it (joinLiveCaptures()), with its program ended.
    retireLiveCapture( std::move( live_ ) );

    // The host unloads the library right after the plugin is shut down:
    // the worker must be done with it before.  It checks the cancel flag
    // between packets, and convertPcap() reads regular files only, so it
    // cannot block on a FIFO or device; a regular file on a network share
    // that stalls can still hold it up until the system gives up on it.
    if ( cancelRunning_ ) {
        cancelRunning_->store( true );
    }
    pool_.waitForDone();

    // A conversion that finished before the cancel reached it wrote a file
    // no tab will show: the cancel wins, and the file goes.
    if ( watcher_ && watcher_->future().resultCount() > 0 ) {
        applyCancelRequest( watcher_->result(), cancelRunning_.get() );
    }

    // An export stops between two packets and leaves nothing behind; one
    // that was done keeps its file.  Its progress dialog goes first, as
    // closing it would cancel through this half-destroyed widget.
    if ( cancelExport_ ) {
        cancelExport_->store( true );
    }
    if ( exportProgress_ ) {
        exportProgress_->disconnect( this );
        delete exportProgress_;
    }
    exportPool_.waitForDone();
}

bool SidebarWidget::refuseWhileBusy()
{
    if ( converting_ ) {
        hostNotify( "A capture is still being read: wait for it, or cancel it first." );
        return true;
    }
    if ( capturing_ ) {
        hostNotify( "A live capture is still running: stop it first." );
        return true;
    }
    return false;
}

void SidebarWidget::chooseAndOpen()
{
    // The Open button is disabled meanwhile, but the menu entry is not.
    if ( refuseWhileBusy() ) {
        return;
    }
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }

    // The dialog runs its own event loop, in which this widget may be
    // deleted, e.g. with a parent that is closed meanwhile: then there is
    // nothing left to open the file for.  This does not help if the plugin
    // is unloaded while the dialog is open: the code this call returns into
    // is gone then, and only the host can prevent that.
    const QPointer<SidebarWidget> self( this );
    const auto filePath = chooseFile_( this, lastDir_ );
    if ( !self ) {
        return;
    }

    if ( filePath.isEmpty() ) {
        return;
    }

    lastDir_ = QFileInfo( filePath ).absolutePath();
    try {
        openPcapFile( filePath );
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog(
            LOGSQUIRL_LOG_ERROR,
            QString( "Opening %1 failed: %2" ).arg( filePath, QString::fromUtf8( e.what() ) ) );
    }
}

void SidebarWidget::openPcapFile( const QString& filePath )
{
    // One conversion at a time (Open is disabled meanwhile), so the outcome
    // that arrives is always that of the running one.
    if ( converting_ || capturing_ ) {
        return;
    }
    hostLog( LOGSQUIRL_LOG_INFO, "Opening pcap file: " + filePath );

    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancelRunning_ = cancelled;
    setConverting( true );
    summaryLabel_->setText( QString( "Reading %1\xe2\x80\xa6" )
                                .arg( QFileInfo( filePath ).fileName().toHtmlEscaped() ) );

    // The watcher lives on this thread, so its signals are delivered here.
    watcher_ = new QFutureWatcher<ConversionResult>( this );
    connect( watcher_, &QFutureWatcher<ConversionResult>::progressValueChanged, progressBar_,
             &QProgressBar::setValue );
    connect( watcher_, &QFutureWatcher<ConversionResult>::finished, this,
             [ this, cancelled, filePath ] {
                 ConversionResult result;
                 if ( watcher_->future().resultCount() > 0 ) {
                     result = watcher_->result();
                 }
                 else {
                     result.error = "The conversion ended without a result";
                 }
                 finishConversion( filePath,
                                   applyCancelRequest( std::move( result ), cancelled.get() ) );
             } );

    // The Converter writes into a new private directory below the temporary
    // root, kept for its tab until LogSquirl quits, and reports every
    // failure as a result: nothing is caught here.  It converts with the
    // options saved when it starts: a change of them in the configuration
    // dialog applies to the next capture, the tab of this one keeps its own.
    const auto tempRoot = tempRoot_;
    const auto options = loadConversionOptions( hostConfigDir() );
    watcher_->setFuture( QtConcurrent::run(
        &pool_, [ filePath, tempRoot, cancelled, options ]( QPromise<ConversionResult>& promise ) {
            promise.setProgressRange( 0, 1000 );
            promise.addResult( convertPcap(
                filePath, tempRoot, cancelled.get(),
                [ &promise ]( int permille ) { promise.setProgressValue( permille ); }, options ) );
        } ) );
}

void SidebarWidget::cancel()
{
    if ( !converting_ || !cancelRunning_ ) {
        return;
    }
    cancelRunning_->store( true );
    cancelButton_->setEnabled( false );
    summaryLabel_->setText( "Cancelling\xe2\x80\xa6" );
}

void SidebarWidget::exportSelectedPackets()
{
    // The menu entry stays enabled while an export runs.
    if ( exportWatcher_ ) {
        hostNotify( "Packets are still being exported: wait for it, or cancel it first." );
        return;
    }
    const auto found = converted_.find( frontKey_ );
    if ( found == converted_.end() ) {
        hostNotify( "Export packets: the tab in front shows no capture opened by the tcpdump "
                    "plugin." );
        return;
    }
    const auto& st = g_state;
    if ( !st.api || !st.handle || !st.hostCapabilities.selectedLogLines ) {
        hostNotify( "Export packets needs LogSquirl 26.11 or later, which tells the selected "
                    "lines." );
        return;
    }
    const auto index = found->second.index;
    ExportRequest request;
    request.captureName = found->second.fileName;
    request.packets = index->packets();
    request.format = captureFormatOf( index->capturePath() );

    // Without a selection, the user may still name or paste the packets.
    const char* text = nullptr;
    size_t length = 0;
    size_t lineCount = 0;
    const int selected = st.api->get_selected_log_lines( st.handle, &text, &length, &lineCount );
    if ( selected >= 0 && text ) {
        request.numbers
            = packetLinesOf( QString::fromUtf8( text, static_cast<qsizetype>( length ) ),
                             request.packets )
                  .numbers;
        request.selectedLines = lineCount;
        request.truncated = selected == LOGSQUIRL_LOG_LINES_TRUNCATED;
    }
    else if ( selected != LOGSQUIRL_LOG_LINES_NO_SELECTION ) {
        hostNotify( QString( "Export packets: LogSquirl did not tell the selected lines (%1)." )
                        .arg( selected ) );
        return;
    }
    if ( request.truncated ) {
        hostLog( LOGSQUIRL_LOG_INFO,
                 QString( "Export packets: LogSquirl told only the first %1 selected lines" )
                     .arg( request.selectedLines ) );
    }
    const auto ofSelection = request.numbers;

    // The dialogs run their own event loops, in which this widget may be
    // deleted, or the menu entry chosen again.
    const QPointer<SidebarWidget> self( this );
    const bool confirmed = confirmExport_( this, request );
    if ( !self || !confirmed || request.numbers.empty() || request.outputPath.isEmpty() ) {
        return;
    }
    if ( exportWatcher_ ) {
        hostNotify( "Packets are still being exported: wait for it, or cancel it first." );
        return;
    }
    // Only when the selection's packets are exported does its truncation matter.
    request.truncated = request.truncated && request.numbers == ofSelection;
    hostLog( LOGSQUIRL_LOG_INFO, QString( "Exporting %1 packets of %2 to %3" )
                                     .arg( request.numbers.count() )
                                     .arg( request.captureName, request.outputPath ) );

    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancelExport_ = cancelled;
    exportProgress_ = new QProgressDialog(
        QString( "Exporting %1 packets\xe2\x80\xa6" ).arg( request.numbers.count() ), "Cancel", 0,
        1000, this );
    exportProgress_->setObjectName( "exportProgress" );
    exportProgress_->setWindowTitle( "Export Packets" );
    exportProgress_->setAutoClose( false );
    exportProgress_->setAutoReset( false );
    exportProgress_->setMinimumDuration( 500 );
    connect( exportProgress_, &QProgressDialog::canceled, this, &SidebarWidget::cancelExport );

    // The watcher lives on this thread, so its signals are delivered here.
    exportWatcher_ = new QFutureWatcher<ExportResult>( this );
    connect( exportWatcher_, &QFutureWatcher<ExportResult>::progressValueChanged,
             exportProgress_.data(), &QProgressDialog::setValue );
    connect( exportWatcher_, &QFutureWatcher<ExportResult>::finished, this,
             [ this, cancelled, request ] {
                 ExportResult result;
                 if ( exportWatcher_->future().resultCount() > 0 ) {
                     result = exportWatcher_->result();
                 }
                 else {
                     result.error = "The export ended without a result";
                 }
                 // An export that was done before the cancel reached it: the
                 // cancel wins, as it does for a conversion.
                 if ( cancelled->load() && result.status == ExportResult::Status::Exported ) {
                     QFile::remove( request.outputPath );
                     result.status = ExportResult::Status::Cancelled;
                 }
                 finishExport( request, std::move( result ) );
             } );
    const auto numbers = request.numbers;
    const auto path = request.outputPath;
    exportWatcher_->setFuture( QtConcurrent::run(
        &exportPool_, [ index, numbers, path, cancelled ]( QPromise<ExportResult>& promise ) {
            promise.setProgressRange( 0, 1000 );
            promise.addResult(
                exportPackets( index, numbers, path, cancelled.get(), [ &promise ]( int permille ) {
                    promise.setProgressValue( permille );
                } ) );
        } ) );
}

void SidebarWidget::cancelExport()
{
    if ( !cancelExport_ ) {
        return;
    }
    cancelExport_->store( true );
    if ( exportProgress_ ) {
        exportProgress_->setLabelText( "Cancelling\xe2\x80\xa6" );
    }
}

void SidebarWidget::finishExport( const ExportRequest& request, ExportResult result )
{
    cancelExport_.reset();
    exportWatcher_->deleteLater();
    exportWatcher_ = nullptr;
    if ( exportProgress_ ) {
        // Closing it would cancel the export that is over.
        exportProgress_->disconnect( this );
        exportProgress_->deleteLater();
        exportProgress_ = nullptr;
    }

    const auto fileName = QDir::toNativeSeparators( request.outputPath );
    switch ( result.status ) {
    case ExportResult::Status::Cancelled:
        hostLog( LOGSQUIRL_LOG_INFO, "Cancelled exporting packets to " + fileName );
        return;
    case ExportResult::Status::Failed:
        hostLog( LOGSQUIRL_LOG_ERROR, "Exporting packets failed: " + result.error );
        hostNotify( "Exporting packets failed: " + result.error );
        return;
    case ExportResult::Status::Exported:
        break;
    }
    auto message = QString( "Exported %1 packets of %2 to %3." )
                       .arg( result.packets )
                       .arg( request.captureName, fileName );
    if ( request.truncated ) {
        message += QString( " LogSquirl told only the first %1 selected lines: to export the "
                            "packets of more, copy their lines and paste them in the Export "
                            "dialog." )
                       .arg( request.selectedLines );
    }
    hostLog( LOGSQUIRL_LOG_INFO, message );
    hostNotify( message );
}

void SidebarWidget::showPacketDetails()
{
    // The packet is read on the panel's worker: what it shows is told once read.
    const QPointer<PacketPanel> panel( packetPanel_ );
    packetPanel_->refresh( [ panel ] {
        if ( !panel || panel->isVisible() ) {
            return;
        }
        // The sidebar tab is not in front: say what it would show.
        if ( panel->shownPacket() == 0 ) {
            hostNotify( "Packet details: " + panel->statusText() );
            return;
        }
        QStringList names;
        for ( const auto& layer : panel->layers() ) {
            names << QString::fromStdString( layer.name );
        }
        if ( !names.isEmpty() ) {
            names.removeFirst(); // the frame
        }
        hostNotify(
            QString( "Packet %1: %2. Open the tcpdump sidebar tab for its fields and bytes." )
                .arg( panel->shownPacket() )
                .arg( names.join( " / " ) ) );
    } );
}

void SidebarWidget::followStreamContent()
{
    packetPanel_->refresh();
    QString why;
    if ( !packetPanel_->followStreamContent( &why ) ) {
        hostNotify( "Follow stream content: " + why );
        return;
    }
    if ( !packetPanel_->isVisible() ) {
        hostNotify( QString( "Follow stream content: the stream of packet %1 is shown in the "
                             "tcpdump sidebar tab." )
                        .arg( packetPanel_->selectedPacket() ) );
    }
}

void SidebarWidget::openLink( const QString& link )
{
    try {
        const auto pattern = filterPattern( link );
        if ( pattern.isEmpty() ) {
            QDesktopServices::openUrl( QUrl( link ) );
            return;
        }
        openRegexLab( "Filter", pattern );
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog( LOGSQUIRL_LOG_ERROR,
                 "Opening " + link + " failed: " + QString::fromUtf8( e.what() ) );
    }
}

void SidebarWidget::setConverting( bool converting )
{
    converting_ = converting;
    openButton_->setEnabled( !converting );
    cancelButton_->setEnabled( converting );
    cancelButton_->setHidden( !converting );
    progressBar_->setHidden( !converting );
    progressBar_->setValue( 0 );
    updateStartButton();
}

void SidebarWidget::finishConversion( const QString& filePath, ConversionResult result )
{
    cancelRunning_.reset();
    watcher_->deleteLater();
    watcher_ = nullptr;
    setConverting( false );

    switch ( result.status ) {
    case ConversionResult::Status::Cancelled:
    case ConversionResult::Status::Stopped: // only a stream is stopped
        summaryLabel_->setText( "Cancelled." );
        hostLog( LOGSQUIRL_LOG_INFO, "Cancelled opening " + filePath );
        return;

    case ConversionResult::Status::Failed: {
        const auto& msg = result.error;
        summaryLabel_->setText( "Error: " + msg.toHtmlEscaped() );
        hostLog( LOGSQUIRL_LOG_ERROR, "pcap parse error: " + msg );
        hostNotify( "Failed to open pcap: " + msg );
        return;
    }

    case ConversionResult::Status::Converted:
        break;
    }

    // Whether LogSquirl has the Log Format installed is not known to the
    // plugin, so the hint is shown regardless, but only with the first
    // capture of a load.
    ConvertedCapture capture;
    capture.fileName = QFileInfo( filePath ).fileName();
    capture.fileSize = QFileInfo( filePath ).size();
    capture.summary = std::move( result.summary );
    capture.index = std::move( result.index );
    capture.withFormatHint = !formatHintShown_;
    formatHintShown_ = true;
    const auto packets = capture.summary.packets;

    // Kept before the tab is opened: the host may report it in front at once.
    const auto key = fileKey( result.outputPath );
    converted_.insert_or_assign( key, std::move( capture ) );
    showSummaryFor( key );

    // Open in LogSquirl viewer; the file stays until LogSquirl quits
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, result.outputPath.toUtf8().constData(), 0 );
    }

    hostLog( LOGSQUIRL_LOG_INFO,
             QString( "Opened %1 packets from %2" ).arg( packets ).arg( filePath ) );
}

void SidebarWidget::showSummaryFor( const QString& filePath )
{
    frontKey_ = fileKey( filePath );
    const auto found = converted_.find( frontKey_ );
    packetPanel_->setCapture( found == converted_.end() ? nullptr : found->second.index );
    packetPanel_->conversationTable()->setSummary(
        found == converted_.end() ? nullptr : &found->second.summary );

    // The capture being read is shown in a tab of its own when it is done.
    if ( converting_ ) {
        return;
    }
    saveButton_->setHidden( found == converted_.end() || found->second.rawPath.isEmpty() );
    if ( found == converted_.end() ) {
        summaryLabel_->setText( kNoCaptureText );
        return;
    }
    const auto& capture = found->second;
    QString html;
    if ( capturing_ && isLiveKey( frontKey_ ) ) {
        html += "<i>Capturing\xe2\x80\xa6 the summary so far:</i><br>";
    }
    if ( !capture.error.isEmpty() ) {
        html += QString( "<b>Error:</b> %1<br>The capture so far is kept.<br>" )
                    .arg( capture.error.toHtmlEscaped() );
    }
    html += summaryHtml( capture.fileName, capture.fileSize, capture.summary,
                         g_state.hostCapabilities.regexLab );
    if ( capture.withFormatHint ) {
        html += QString( "<br><i>Table view, \xce\x94t and Go to timestamp need the plugin's "
                         "Log Format: <a href=\"%1\">install it once</a>.</i>" )
                    .arg( kLogFormatHelpUrl );
    }
    summaryLabel_->setText( html );
}

bool SidebarWidget::startLiveCapture( const QString& name, LiveCapture::SourceFactory makeSource,
                                      const LiveLimits& limits )
{
    if ( refuseWhileBusy() ) {
        return false;
    }
    hostLog( LOGSQUIRL_LOG_INFO, "Capturing live: " + name );

    // The last capture's worker may still be ending its program: it ends
    // on its own, never waited for here.
    retireLiveCapture( std::move( live_ ) );
    live_ = std::make_unique<LiveCapture>(
        name, tempRoot_, loadConversionOptions( hostConfigDir() ), std::move( makeSource ) );
    live_->setLimits( limits );
    liveLimits_ = limits;
    connect( live_.get(), &LiveCapture::readyToOpen, this, &SidebarWidget::openLiveCapture );
    connect( live_.get(), &LiveCapture::snapshotTaken, this, &SidebarWidget::takeLiveSnapshot );
    connect( live_.get(), &LiveCapture::finished, this, &SidebarWidget::finishLiveCapture );
    connect( live_.get(), &LiveCapture::done, this, &SidebarWidget::startPendingLiveCapture );
    connect( live_.get(), &LiveCapture::stderrLine, this, [ this, name ]( const QString& line ) {
        hostLog( LOGSQUIRL_LOG_INFO, name + ": " + line );
        liveStderr_->appendPlainText( line );
        liveStderr_->setHidden( false );
    } );

    liveKind_.reset(); // startLiveCapture( LiveChoice ) sets it
    liveStderr_->clear();
    liveStderr_->setHidden( true );
    liveError_->clear();
    liveError_->setHidden( true );
    liveKey_.clear();
    liveKeys_.clear();
    liveSnapshot_ = {};
    liveClock_.start();
    setCapturing( true );
    summaryLabel_->setText( QString( "Capturing %1\xe2\x80\xa6 waiting for the first packet." )
                                .arg( name.toHtmlEscaped() ) );
    live_->start();
    return true;
}

bool SidebarWidget::startLiveCapture( const LiveChoice& choice )
{
    if ( refuseWhileBusy() ) {
        return false;
    }
    const auto kind = liveSources_ ? liveSources_->find( choice.source ) : nullptr;
    QString problem;
    if ( !kind ) {
        problem = QString( "There is no live capture source \"%1\"." ).arg( choice.source );
    }
    else if ( const auto availability = kind->availability(); !availability.available ) {
        problem = availability.reason;
    }
    else if ( choice.snaplen < 1 || choice.snaplen > kMaxSnaplen ) {
        problem = QString( "The snaplen must be 1 to %1 bytes." ).arg( kMaxSnaplen );
    }
    else {
        problem = captureFilterProblem( choice.filter );
        if ( problem.isEmpty() ) {
            problem = liveLimitsProblem( choice.limits );
        }
        if ( problem.isEmpty() ) {
            problem = kind->validate( choice );
        }
    }
    if ( !problem.isEmpty() ) {
        hostNotify( "Cannot start the live capture: " + problem );
        return false;
    }

    // The last choice started is the one shown after a restart.
    if ( !saveLiveChoice( hostConfigDir(), choice ) ) {
        hostLog( LOGSQUIRL_LOG_WARNING, "The live capture choice could not be saved in "
                                            + settingsFilePath( hostConfigDir() ) );
    }
    if ( liveForm_->choice() != choice ) {
        liveForm_->setChoice( choice );
    }
    const auto source = kind->makeSource( choice );
    if ( !startLiveCapture( liveCaptureName( choice ), source, choice.limits ) ) {
        return false;
    }
    liveKind_ = kind;
    hostLog( LOGSQUIRL_LOG_INFO,
             QString( "Live capture from %1, interface %2, filter \"%3\", "
                      "snaplen %4" )
                 .arg( kind->displayName(),
                       choice.networkInterface.isEmpty() ? "(default)" : choice.networkInterface,
                       choice.filter )
                 .arg( choice.snaplen ) );
    return true;
}

void SidebarWidget::chooseAndStartLiveCapture()
{
    if ( converting_ ) {
        refuseWhileBusy();
        return;
    }
    if ( pendingStart_ ) {
        hostNotify( "A live capture is still stopping: the next one starts when it has ended." );
        return;
    }
    // The dialogs run their own event loops, in which this widget may be
    // deleted, or the capture end by itself.
    const QPointer<SidebarWidget> self( this );
    if ( capturing_ && live_ ) {
        const auto running = live_->name();
        if ( !confirmStop_( this, running ) || !self ) {
            return;
        }
    }
    auto choice = liveForm_->choice();
    if ( !askLiveChoice_( this, choice ) || !self ) {
        return;
    }
    if ( capturing_ ) {
        // Started once the running one is done (startPendingLiveCapture()).
        pendingStart_ = choice;
        stopLiveCapture();
        return;
    }
    if ( live_ && !live_->isDone() ) {
        // Finished, but its program is still ending.
        pendingStart_ = choice;
        return;
    }
    startLiveCapture( choice );
}

void SidebarWidget::setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    liveSources_ = std::move( sources );
    liveForm_->setSources( liveSources_ );
    if ( liveSources_ ) {
        for ( const auto& kind : liveSources_->kinds() ) {
            liveForm_->setSourceOptions( kind->id(),
                                         loadLiveOptions( hostConfigDir(), kind->id() ) );
        }
    }
    liveForm_->setChoice( loadLiveChoice( hostConfigDir() ) );
    updateStartButton();
}

void SidebarWidget::updateStartButton()
{
    if ( !startButton_ || !liveForm_ ) {
        return;
    }
    QString why;
    if ( converting_ ) {
        why = "A capture is being read.";
    }
    else if ( capturing_ ) {
        why = "A live capture is running.";
    }
    else {
        why = liveForm_->problem();
    }
    startButton_->setEnabled( why.isEmpty() );
    startButton_->setToolTip( why.isEmpty() ? "Start capturing live" : why );
    liveForm_->setEnabled( !capturing_ );
}

void SidebarWidget::showLiveError( const QString& error )
{
    auto text = "Error: " + error.toHtmlEscaped();
    if ( liveKind_ ) {
        if ( const auto hint = liveKind_->explainFailure( error ); !hint.isEmpty() ) {
            text += "<br>" + hint.toHtmlEscaped();
        }
    }
    liveError_->setText( text.replace( '\n', "<br>" ) );
    liveError_->setHidden( false );
}

void SidebarWidget::stopLiveCapture()
{
    if ( !capturing_ || !live_ ) {
        return;
    }
    live_->stop();
    stopButton_->setEnabled( false );
    liveLabel_->setText( liveLabel_->text() + " \xe2\x80\x94 stopping\xe2\x80\xa6" );
}

void SidebarWidget::setCapturing( bool capturing )
{
    capturing_ = capturing;
    openButton_->setEnabled( !capturing && !converting_ );
    stopButton_->setEnabled( capturing );
    stopButton_->setHidden( !capturing );
    liveLabel_->setHidden( !capturing );
    startButton_->setHidden( capturing );
    updateStartButton();
    if ( capturing ) {
        showLiveProgress();
        liveTicker_.start();
    }
    else {
        liveTicker_.stop();
    }
}

void SidebarWidget::showLiveProgress()
{
    liveLabel_->setText( liveProgressText( liveSnapshot_, liveClock_.elapsed(), liveLimits_ ) );
}

void SidebarWidget::openLiveCapture( const QString& logPath, const QString& rawPath )
{
    ConvertedCapture capture;
    capture.fileName = QFileInfo( rawPath ).fileName();
    capture.fileSize = QFileInfo( rawPath ).size();
    capture.rawPath = rawPath;
    capture.captureName = live_ ? live_->name() : QString();
    capture.withFormatHint = !formatHintShown_;
    formatHintShown_ = true;

    // Kept before the tab is opened: the host may report it in front at once.
    // A ring buffer's next file opens a tab of its own; the tabs before stay.
    liveKey_ = fileKey( logPath );
    liveKeys_.push_back( liveKey_ );
    converted_.insert_or_assign( liveKey_, std::move( capture ) );
    summaryLabel_->setText( QString( "Capturing %1\xe2\x80\xa6" )
                                .arg( live_ ? live_->name().toHtmlEscaped() : QString() ) );

    // On this, the UI thread; following the file, which grows.  The header
    // and a packet line are in it, so the host recognises the Log Format.
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, logPath.toUtf8().constData(), 1 );
    }
}

void SidebarWidget::takeLiveSnapshot( const LiveSnapshot& snapshot )
{
    // The progress line needs the counts only; the summary is kept once,
    // with its capture.
    liveSnapshot_.elapsed = snapshot.elapsed;
    liveSnapshot_.rawBytes = snapshot.rawBytes;
    liveSnapshot_.rawFile = snapshot.rawFile;
    liveSnapshot_.summary.packets = snapshot.summary.packets;
    liveSnapshot_.summary.bytes = snapshot.summary.bytes;
    showLiveProgress();
    // Every tab of the capture shows its summary so far, and reads packets
    // through its latest index: one of a ring buffer's files deleted since
    // says its packets were rotated away.
    for ( const auto& key : liveKeys_ ) {
        const auto found = converted_.find( key );
        if ( found == converted_.end() ) {
            continue;
        }
        found->second.fileSize = static_cast<qint64>( snapshot.rawBytes );
        if ( snapshot.index ) {
            found->second.index = snapshot.index;
        }
        updateSummary( key, snapshot.summary );
    }
}

bool SidebarWidget::isLiveKey( const QString& key ) const
{
    return !key.isEmpty()
           && std::find( liveKeys_.begin(), liveKeys_.end(), key ) != liveKeys_.end();
}

void SidebarWidget::updateSummary( const QString& textPath, CaptureSummary summary )
{
    const auto key = fileKey( textPath );
    const auto found = converted_.find( key );
    if ( found == converted_.end() ) {
        return;
    }
    // showSummaryFor() redraws the summary and the Conversations table.
    found->second.summary = std::move( summary );
    if ( frontKey_ == key ) {
        showSummaryFor( key );
    }
}

void SidebarWidget::finishLiveCapture( const ConversionResult& result )
{
    reportLiveOutcome( result );
}

void SidebarWidget::startPendingLiveCapture()
{
    // Start live capture… asked for another one: once the last one is done,
    // its program ended too, so that two never capture at once.  Starting
    // it retires the LiveCapture that sends this, which goes on living.
    if ( !pendingStart_ ) {
        return;
    }
    const auto choice = *pendingStart_;
    pendingStart_.reset();
    startLiveCapture( choice );
}

void SidebarWidget::reportLiveOutcome( const ConversionResult& result )
{
    const auto name = live_ ? live_->name() : QString();
    setCapturing( false );
    const auto found = liveKey_.isEmpty() ? converted_.end() : converted_.find( liveKey_ );
    const bool opened = found != converted_.end();

    switch ( result.status ) {
    case ConversionResult::Status::Cancelled:
        for ( const auto& key : liveKeys_ ) {
            converted_.erase( key );
        }
        summaryLabel_->setText( "Cancelled." );
        hostLog( LOGSQUIRL_LOG_INFO, "Cancelled capturing " + name );
        return;

    case ConversionResult::Status::Stopped: {
        // Stopped before the header came: nothing went wrong, and nothing
        // was written, so there is nothing to open or remove.
        const auto message
            = QString( "The capture %1 was stopped before anything was captured." ).arg( name );
        summaryLabel_->setText( message.toHtmlEscaped() );
        hostLog( LOGSQUIRL_LOG_INFO, message );
        return;
    }

    case ConversionResult::Status::Failed:
        showLiveError( result.error );
        hostLog( LOGSQUIRL_LOG_ERROR, "Capture " + name + " failed: " + result.error );
        hostNotify( "Capture " + name + " failed: " + result.error );
        if ( !opened || result.outputPath.isEmpty() ) {
            summaryLabel_->setText( "Error: " + result.error.toHtmlEscaped() );
            return;
        }
        for ( const auto& key : liveKeys_ ) {
            if ( const auto each = converted_.find( key ); each != converted_.end() ) {
                each->second.error = result.error;
            }
        }
        break;

    case ConversionResult::Status::Converted:
        if ( !opened ) {
            // No tab shows it: its files go now.
            if ( !result.outputPath.isEmpty() ) {
                QDir( QFileInfo( result.outputPath ).absolutePath() ).removeRecursively();
            }
            const auto message = QString( "The capture %1 ended without packets." ).arg( name );
            summaryLabel_->setText( message.toHtmlEscaped() );
            hostLog( LOGSQUIRL_LOG_INFO, message );
            hostNotify( message );
            return;
        }
        hostLog(
            LOGSQUIRL_LOG_INFO,
            QString( "Captured %1 packets from %2" ).arg( result.summary.packets ).arg( name ) );
        if ( result.stoppedBy != StopCondition::None ) {
            // Nobody pressed Stop: whoever left it running is told.
            const auto message = liveStopText( name, result.stoppedBy, liveLimits_ );
            hostLog( LOGSQUIRL_LOG_INFO, message );
            hostNotify( message );
        }
        break;
    }

    // The final summary and index, which the tabs of the capture show from
    // now on.
    for ( const auto& key : liveKeys_ ) {
        const auto each = converted_.find( key );
        if ( each == converted_.end() ) {
            continue;
        }
        each->second.fileSize = QFileInfo( each->second.rawPath ).size();
        if ( result.index ) {
            each->second.index = result.index;
        }
        updateSummary( key, result.summary );
    }
    if ( !isLiveKey( frontKey_ ) ) {
        summaryLabel_->setText( QString( "The capture %1 has ended: its tab shows its summary." )
                                    .arg( name.toHtmlEscaped() ) );
    }
}

void SidebarWidget::saveCapture()
{
    const auto found = converted_.find( frontKey_ );
    if ( found == converted_.end() || found->second.rawPath.isEmpty() ) {
        return;
    }
    // The files of the capture, those a ring buffer keeps, as the latest
    // index has them; before the first one, the raw file.
    std::vector<CapturePart> parts;
    if ( found->second.index ) {
        parts = found->second.index->parts();
    }
    if ( parts.empty() ) {
        CapturePart part;
        part.path = found->second.rawPath;
        parts.push_back( part );
    }
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }

    // Named after the capture, <name>.pcap: a ring buffer's files are numbered.
    const auto name = found->second.captureName.isEmpty()
                          ? QFileInfo( frontKey_ ).completeBaseName()
                          : found->second.captureName;
    const auto suggested = name + "." + QFileInfo( found->second.rawPath ).suffix();
    // The dialog runs its own event loop, as in chooseAndOpen().
    const QPointer<SidebarWidget> self( this );
    const auto target = chooseSaveFile_( this, QDir( lastDir_ ).filePath( suggested ) );
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

namespace {

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

/// @p name as text, or, with @p link, as a link to the filter of @p kind.
QString filterName( const std::string& name, const char* kind, bool link )
{
    const auto text = QString::fromStdString( name ).toHtmlEscaped();
    if ( !link ) {
        return text;
    }
    return QString( "<a href=\"%1%2%3\">%4</a>" )
        .arg( QString( kFilterScheme ), QString( kind ),
              QString::fromUtf8( QUrl::toPercentEncoding( QString::fromStdString( name ) ) ),
              text );
}

/// Entries of @p counts by count, highest first.
std::vector<std::pair<std::string, uint64_t>>
byCount( const std::map<std::string, uint64_t>& counts )
{
    std::vector<std::pair<std::string, uint64_t>> sorted( counts.begin(), counts.end() );
    std::stable_sort( sorted.begin(), sorted.end(),
                      []( const auto& a, const auto& b ) { return a.second > b.second; } );
    return sorted;
}

} // namespace

QString summaryHtml( const QString& fileName, qint64 fileSize, const CaptureSummary& summary,
                     bool filterLinks )
{
    const double duration = summary.durationSeconds;

    // Packets per second
    QString ppsStr = "-";
    if ( duration > 0.0 ) {
        auto pps = static_cast<double>( summary.packets ) / duration;
        ppsStr = QString::number( pps, 'f', 0 );
    }

    // Build summary HTML; anything from the file or its name is escaped,
    // since the label renders markup
    QString html;
    html += QString( "<b>%1</b><br>" ).arg( fileName.toHtmlEscaped() );
    html += QString( "<hr>" );

    // General stats
    html += QString( "<b>Overview</b><br>" );
    html += QString( "Packets: <b>%1</b><br>" )
                .arg( QLocale().toString( static_cast<qulonglong>( summary.packets ) ) );
    if ( summary.cutPackets > 0 ) {
        html += QString( "Cut packets: <b>%1</b> (captured shorter than on the wire)<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( summary.cutPackets ) ) );
    }
    html += QString( "File size: %1<br>" ).arg( formatBytes( static_cast<uint64_t>( fileSize ) ) );
    if ( !summary.firstTimeUtc.empty() ) {
        html += QString( "First packet: %1<br>" )
                    .arg( QString::fromStdString( summary.firstTimeUtc ) );
        html += QString( "Last packet: %1<br>" )
                    .arg( QString::fromStdString( summary.lastTimeUtc ) );
    }
    html += QString( "Duration: <b>%1 s</b><br>" ).arg( duration, 0, 'f', 3 );
    html += QString( "Packets/s: %1<br>" ).arg( ppsStr );
    QStringList linkTypes;
    for ( const auto& name : summary.linkTypeNames ) {
        linkTypes << QString::fromStdString( name ).toHtmlEscaped();
    }
    html += QString( "%1: %2<br>" )
                .arg( linkTypes.size() > 1 ? "Link types" : "Link type" )
                .arg( linkTypes.join( ", " ) );
    if ( !summary.compressionProblem.empty() ) {
        html += QString( "<i>The capture was cut off: %1.</i><br>" )
                    .arg( QString::fromStdString( summary.compressionProblem ).toHtmlEscaped() );
    }
    else if ( summary.endsInsideRecord ) {
        html += "<i>The capture was cut off in the middle of a packet.</i><br>";
    }
    if ( summary.packetNumbersUsedUp ) {
        html += QString( "<i>Stopped at packet %1, the last one the No. column can number; the "
                         "rest was not converted.</i><br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( summary.packets ) ) );
    }
    html += "<br>";

    // Protocol breakdown
    html += "<b>Protocols</b><br>";
    for ( const auto& [ proto, count ] : byCount( summary.protocolPackets ) ) {
        const auto bytes = summary.protocolBytes.at( proto );
        const auto pct
            = static_cast<double>( count ) / static_cast<double>( summary.packets ) * 100.0;
        // The name is not put in with arg(), which would read a '%' in it.
        html += filterName( proto, kProtocolFilter, filterLinks );
        html += QString( ": %1 (%2%, %3)<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) )
                    .arg( pct, 0, 'f', 1 )
                    .arg( formatBytes( bytes ) );
    }
    html += "<br>";

    // TCP analysis markers, and the handshakes' round-trip time
    if ( !summary.tcpMarkers.empty() || summary.medianInitialRttNs ) {
        html += "<b>Analysis</b><br>";
        if ( summary.medianInitialRttNs ) {
            html += QString( "Median iRTT: %1 ms (%2 %3)<br>" )
                        .arg( static_cast<double>( *summary.medianInitialRttNs ) / 1e6, 0, 'f', 3 )
                        .arg( QLocale().toString( static_cast<qulonglong>( summary.handshakes ) ) )
                        .arg( summary.handshakes == 1 ? "handshake" : "handshakes" );
        }
        for ( const auto& [ marker, count ] : summary.tcpMarkers ) {
            html += QString( "%1: %2<br>" )
                        .arg( QString::fromStdString( marker ).toHtmlEscaped() )
                        .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        }
        html += "<br>";
    }

    // TLS decryption, with a key log: what it decrypted, or why it could not
    if ( summary.tlsSessionsDecrypted ) {
        html += "<b>TLS decryption</b><br>";
        if ( !summary.keyLogError.empty() ) {
            html += QString( "<i>%1</i><br>" )
                        .arg( QString::fromStdString( summary.keyLogError ).toHtmlEscaped() );
        }
        html += QString( "Sessions decrypted: %1<br><br>" )
                    .arg( QLocale().toString(
                        static_cast<qulonglong>( *summary.tlsSessionsDecrypted ) ) );
    }

    // Top IPs
    html += QString( "<b>Endpoints</b> (%1%2 unique)<br>" )
                .arg( summary.otherEndpointPackets ? "more than " : "" )
                .arg( summary.endpointPackets.size() );
    int shown = 0;
    for ( const auto& [ ip, count ] : byCount( summary.endpointPackets ) ) {
        if ( shown >= 8 )
            break;
        html += filterName( ip, kEndpointFilter, filterLinks );
        // The name a DNS answer gave it, with host names shown: plain
        // text, the filter is the address's.
        const auto name = summary.endpointNames.find( ip );
        if ( name != summary.endpointNames.end() ) {
            html += " (" + QString::fromStdString( name->second ).toHtmlEscaped() + ")";
        }
        html += QString( ": %1 pkts<br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
        shown++;
    }
    if ( summary.otherEndpointPackets ) {
        html += QString( "Other endpoints: %1 pkts<br>" )
                    .arg( QLocale().toString(
                        static_cast<qulonglong>( *summary.otherEndpointPackets ) ) );
    }

    // The tunnels' endpoints, which no line shows: plain text, no filter
    if ( !summary.tunnelEndpointPackets.empty() ) {
        html += QString( "<br><b>Tunnel endpoints</b> (%1 unique)<br>" )
                    .arg( summary.tunnelEndpointPackets.size() );
        int shownTunnel = 0;
        for ( const auto& [ ip, count ] : byCount( summary.tunnelEndpointPackets ) ) {
            if ( shownTunnel >= 8 )
                break;
            html += QString::fromStdString( ip ).toHtmlEscaped();
            html += QString( ": %1 pkts<br>" )
                        .arg( QLocale().toString( static_cast<qulonglong>( count ) ) );
            shownTunnel++;
        }
    }
    if ( summary.streamCap ) {
        html += QString( "<br><i>More than %1 conversations: later ones show stream ? in the "
                         "log.</i><br>" )
                    .arg( QLocale().toString( static_cast<qulonglong>( *summary.streamCap ) ) );
    }

    return html;
}

namespace {

/// @p seconds as m:ss, or h:mm:ss from an hour on.
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

/// How far @p done is to @p limit, in percent, at most 100.
int percentOf( uint64_t done, uint64_t limit )
{
    return static_cast<int>(
        std::min<uint64_t>( done * 100 / std::max<uint64_t>( limit, 1 ), 100 ) );
}

} // namespace

QString liveProgressText( const LiveSnapshot& snapshot, qint64 elapsedMs, const LiveLimits& limits )
{
    const auto packets = snapshot.summary.packets;
    QString rate = "-";
    if ( snapshot.elapsed.count() > 0 ) {
        rate = QString::number( static_cast<double>( packets ) * 1000.0
                                    / static_cast<double>( snapshot.elapsed.count() ),
                                'f', 1 );
    }
    const auto seconds = std::max<qint64>( elapsedMs, 0 ) / 1000;
    auto text
        = QString( "Packets: %1 \xc2\xb7 Bytes: %2 \xc2\xb7 %3 packets/s \xc2\xb7 Elapsed %4" )
              .arg( QLocale().toString( static_cast<qulonglong>( packets ) ),
                    formatBytes( snapshot.summary.bytes ), rate, clockTime( seconds ) );

    // Each stop condition, and how far the capture is to it: the one
    // furthest on stops it first, unless the traffic changes.
    QStringList stops;
    if ( limits.duration.count() > 0 ) {
        stops << QString( "after %1 (%2%)" )
                     .arg( clockTime( limits.duration.count() ) )
                     .arg( percentOf( static_cast<uint64_t>( seconds ),
                                      static_cast<uint64_t>( limits.duration.count() ) ) );
    }
    if ( limits.packets > 0 ) {
        stops << QString( "at %1 packets (%2%)" )
                     .arg( QLocale().toString( static_cast<qulonglong>( limits.packets ) ) )
                     .arg( percentOf( packets, limits.packets ) );
    }
    if ( limits.bytes > 0 ) {
        stops << QString( "at %1 (%2%)" )
                     .arg( formatBytes( limits.bytes ) )
                     .arg( percentOf( snapshot.rawBytes, limits.bytes ) );
    }
    if ( !stops.isEmpty() ) {
        text += "\nStops " + stops.join( ", or " );
    }
    if ( limits.ringBuffer() ) {
        text += QString( "\nRing buffer: file %1, keeping the last %2" )
                    .arg( snapshot.rawFile )
                    .arg( limits.ringFiles );
    }
    return text;
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

} // namespace tcpdump
