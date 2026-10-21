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
 *   2. Hands it to its File Conversion session, which converts the pcap
 *      packet by packet with pcap_converter: parses each packet, formats it
 *      into a human-readable line, and writes the line to a temporary .log
 *      file
 *   3. The session opens the .log file in LogSquirl's main viewer, through
 *      the capture catalog
 *
 * Its Stream lines in Regex Lab button, on a host that offers it, opens the
 * Regex Lab on the conversation of the selected packet line (see
 * follow_stream.h); it is enabled only while the Packet Panel finds a
 * packet line of a numbered stream selected in a capture's tab.
 *
 * The endpoints and protocols its summary lists are links, on a host that
 * has the Regex Lab: a click opens the Lab with the pattern of their lines
 * (see regex_lab.h).  The tunnel endpoints are not: the addresses of the
 * packets that carried a tunnelled one show in no column, so no pattern
 * could pick their lines.
 *
 * Its CaptureCatalog keeps each converted capture's summary and CaptureIndex
 * under the path of its .log file, opens its tab and says which is in the
 * tab in front, as the host reports tab switches; the sidebar shows that
 * one's summary, and its Packet Panel the packets of that capture.  The
 * sidebar is the catalog's tab host: it opens a tab on the UI thread.
 *
 * A live capture (startLiveCapture()) is its LiveCaptureSession's, which
 * decides what it does: the sidebar is the session's host (a notification),
 * and the session keeps the summaries of its text files in the catalog,
 * which opens each one's tab once the first packet line is there; the
 * summaries follow the snapshots until the capture ends.  The sidebar shows the
 * session's state, progress, stderr lines and outcome.  The Live capture section, and the Start
 * live capture… dialog, choose what to capture from the Live Source Kinds (live_source.h): the kind
 * chosen makes the stream, and explains a failure.
 *
 * Opening a capture file is its FileConversionSession's, which converts it
 * and keeps it in the catalog: the sidebar forwards Open and Cancel to it,
 * and shows its progress, label and outcome.
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
#include "selected_packet_line.h"
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
#include <QResizeEvent>
#include <QScrollArea>
#include <QStandardPaths>
#include <QStringList>
#include <QUrl>

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

/// What setDefaultLiveSources() set; null: builtInLiveSources().
std::shared_ptr<const LiveSourceRegistry>& defaultLiveSources()
{
    static std::shared_ptr<const LiveSourceRegistry> sources;
    return sources;
}

/// How far the line under the capture's name is from the window's colour
/// to the text's: one part in this many.
constexpr int kSeparatorShare = 3;

/// The line under the capture's name.  A rule is drawn in the text's
/// colour, stark on a dark window: this one a third of the way from the
/// window's colour to the text's.
QString separatorHtml( const QPalette& palette )
{
    const auto window = palette.color( QPalette::Window );
    const auto text = palette.color( QPalette::WindowText );
    const auto mix = []( int from, int to ) { return from + ( to - from ) / kSeparatorShare; };
    const QColor line( mix( window.red(), text.red() ), mix( window.green(), text.green() ),
                       mix( window.blue(), text.blue() ) );
    return QString( "<hr style=\"background-color:%1\">" ).arg( line.name() );
}

/// The summary, scrolled when the sidebar is too short for all of it.  It
/// asks for the height of its text at its width, up to
/// SidebarWidget::kSummaryMaxLines (as a QScrollArea does), so that a long
/// summary leaves the Packet panel room in a tall sidebar; in a short one it
/// gives in down to SidebarWidget::kSummaryMinLines.
class SummaryArea : public QScrollArea {
public:
    explicit SummaryArea( QLabel* summary )
    {
        setFrameShape( QFrame::NoFrame );
        setHorizontalScrollBarPolicy( Qt::ScrollBarAlwaysOff );
        setWidgetResizable( true );
        setWidget( summary );
    }

    QSize sizeHint() const override
    {
        const auto width = viewport()->width();
        const auto text
            = widget()->heightForWidth( width > 0 ? width : widget()->sizeHint().width() );
        return { QScrollArea::sizeHint().width(),
                 std::min( text, SidebarWidget::kSummaryMaxLines * fontMetrics().lineSpacing() ) };
    }

    QSize minimumSizeHint() const override
    {
        return { QScrollArea::minimumSizeHint().width(),
                 SidebarWidget::kSummaryMinLines * fontMetrics().lineSpacing() };
    }

protected:
    bool event( QEvent* event ) override
    {
        // A new text in the summary asks for another height.
        if ( event->type() == QEvent::LayoutRequest ) {
            updateGeometry();
        }
        return QScrollArea::event( event );
    }

    void resizeEvent( QResizeEvent* event ) override
    {
        QScrollArea::resizeEvent( event );
        // So does a new width.
        if ( event->size().width() != event->oldSize().width() ) {
            updateGeometry();
        }
    }
};

/// The sidebar's content, scrolled as a whole only when the sidebar is
/// shorter than the content's minimum: the summary's and the Packet panel's
/// minimums and the widgets above them.  Down to that minimum the content is
/// as tall as the sidebar, and only the summary scrolls, in itself; below
/// it the content keeps its minimum height and scrolls, so that no widget is
/// squeezed over another or cut off.  It is not widgetResizable: a
/// QScrollArea that is would make the content as tall as its word-wrapped
/// labels prefer, not as tall as they need at least.
class ContentArea : public QScrollArea {
public:
    explicit ContentArea( QWidget* content )
    {
        setFrameShape( QFrame::NoFrame );
        setHorizontalScrollBarPolicy( Qt::ScrollBarAlwaysOff );
        setWidget( content );
        content->installEventFilter( this );
    }

    QSize sizeHint() const override
    {
        return widget()->sizeHint();
    }

protected:
    bool eventFilter( QObject* watched, QEvent* event ) override
    {
        // A widget of the content shown, hidden or of another size.
        if ( watched == widget() && event->type() == QEvent::LayoutRequest ) {
            fit();
        }
        return QScrollArea::eventFilter( watched, event );
    }

    bool viewportEvent( QEvent* event ) override
    {
        // The sidebar resized, or the scroll bar came or went.
        if ( event->type() == QEvent::Resize ) {
            fit();
        }
        return QScrollArea::viewportEvent( event );
    }

private:
    void fit()
    {
        const auto width = viewport()->width();
        const auto* layout = widget()->layout();
        auto minimum = layout->totalMinimumSize().height();
        if ( layout->hasHeightForWidth() ) {
            minimum = std::max( minimum, layout->totalMinimumHeightForWidth( width ) );
        }
        widget()->resize( width, std::max( viewport()->height(), minimum ) );
    }
};

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
    // All of it scrolls when the sidebar is shorter than its minimum.
    auto* content = new QWidget;
    auto* layout = new QVBoxLayout( content );
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

    // Stream lines in Regex Lab, as in the Plugins menu: only a host that
    // has the Regex Lab and tells the selected lines gets it.  It is enabled
    // as the Packet Panel finds the selected line, below.
    if ( g_state.hostCapabilities.regexLab && g_state.hostCapabilities.selectedLogLines ) {
        streamLinesButton_ = new QPushButton( "Stream lines in Regex Lab" );
        streamLinesButton_->setObjectName( "streamLinesButton" );
        layout->addWidget( streamLinesButton_ );
        connect( streamLinesButton_, &QPushButton::clicked, this, [ this ] {
            try {
                openStreamLines();
            } catch ( const std::exception& e ) {
                // An exception must not escape into Qt or the host.
                hostLog( LOGSQUIRL_LOG_ERROR,
                         "Stream lines in Regex Lab failed: " + QString::fromUtf8( e.what() ) );
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

    // Live capture: Start live capture… asks what to capture in its dialog;
    // while one runs, its progress (no percentage, a stream has no size),
    // Stop and what the capture program says.
    auto* liveSection = new QGroupBox( "Live capture" );
    liveSection->setObjectName( "liveSection" );
    auto* liveLayout = new QVBoxLayout( liveSection );
    liveLayout->setSpacing( 4 );

    listingPool_.setMaxThreadCount( 4 );
    startButton_ = new QPushButton( "Start live capture\u2026" );
    startButton_->setObjectName( "liveCaptureButton" );
    liveLayout->addWidget( startButton_ );
    connect( startButton_, &QPushButton::clicked, this, [ this ] {
        try {
            chooseAndStartLiveCapture();
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
    liveError_->setTextFormat( Qt::RichText );
    liveError_->setTextInteractionFlags( Qt::TextBrowserInteraction );
    liveError_->setOpenExternalLinks( true );
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
    summaryLabel_->setAlignment( Qt::AlignLeft | Qt::AlignTop );
    // Its links are opened here: filters in the Regex Lab, pages outside.
    summaryLabel_->setTextInteractionFlags( Qt::LinksAccessibleByMouse );
    connect( summaryLabel_, &QLabel::linkActivated, this, &SidebarWidget::openLink );
    auto* summaryArea = new SummaryArea( summaryLabel_ );
    summaryArea->setObjectName( "summaryArea" );
    layout->addWidget( summaryArea );

    // A live capture's raw file is in the temporary directory, which goes
    // when LogSquirl quits: this keeps it.
    saveButton_ = new QPushButton( "Save capture\xe2\x80\xa6" );
    saveButton_->setObjectName( "saveCaptureButton" );
    saveButton_->setToolTip( "Save the raw capture of this tab as a pcap file; a ring buffer's "
                             "files kept as one" );
    saveButton_->setHidden( true );
    layout->addWidget( saveButton_ );
    connect( saveButton_, &QPushButton::clicked, this, &SidebarWidget::saveCapture );

    // The packet of the selected line, below; it takes the room left, and
    // keeps room for its tabs and the Conversations however long the summary.
    packetPanel_ = new PacketPanel;
    packetPanel_->setObjectName( "packetPanel" );
    packetPanel_->setMinimumHeight( kPacketPanelMinLines * fontMetrics().lineSpacing() );
    layout->addWidget( packetPanel_, 1 );
    auto* contentArea = new ContentArea( content );
    contentArea->setObjectName( "sidebarScroll" );
    auto* outer = new QVBoxLayout( this );
    outer->setContentsMargins( 0, 0, 0, 0 );
    outer->addWidget( contentArea );
    if ( streamLinesButton_ ) {
        connect( packetPanel_, &PacketPanel::streamActionsChanged, this,
                 &SidebarWidget::updateStreamLinesButton );
        updateStreamLinesButton();
    }

    askLiveChoice_ = [ this ]( QWidget* parent, LiveChoice& choice ) {
        // Neither this widget nor its members are used after the dialog:
        // it may be gone when it returns (its pool waits for the listings).
        const auto dialog = makeLiveCaptureDialog( parent, choice );
        if ( dialog->exec() != QDialog::Accepted ) {
            return false;
        }
        choice = dialog->choice();
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

    // This widget is the sessions' host; the sessions keep their captures'
    // summaries in the catalog, and the sidebar shows the one in front,
    // anew whenever the catalog announces that it changed.
    catalog_.observeFront( [ this ] { showFront(); } );
    SessionHost& host = *this;
    conversion_ = std::make_unique<FileConversionSession>( host, catalog_ );
    conversion_->setOutputRoot( tempRoot_ );
    connect( conversion_.get(), &FileConversionSession::stateChanged, this,
             &SidebarWidget::showConversionState );
    connect( conversion_.get(), &FileConversionSession::progressed, this,
             [ this ]( int permille ) { progressBar_->setValue( permille ); } );
    connect( conversion_.get(), &FileConversionSession::finished, this,
             &SidebarWidget::showConversionOutcome );

    live_ = std::make_unique<LiveCaptureSession>( host, catalog_ );
    live_->setOutputRoot( tempRoot_ );
    connect( live_.get(), &LiveCaptureSession::stateChanged, this, &SidebarWidget::showLiveState );
    connect( live_.get(), &LiveCaptureSession::started, this, &SidebarWidget::showLiveStart );
    connect( live_.get(), &LiveCaptureSession::fileOpened, this, &SidebarWidget::showLiveFile );
    // The catalog's snapshot of the tab in front redraws its summary.
    connect( live_.get(), &LiveCaptureSession::progressed, this, &SidebarWidget::showLiveProgress );
    connect( live_.get(), &LiveCaptureSession::stderrLine, this, [ this ]( const QString& line ) {
        liveStderr_->appendPlainText( line );
        liveStderr_->setHidden( false );
    } );
    connect( live_.get(), &LiveCaptureSession::finished, this, &SidebarWidget::showLiveOutcome );

    showConversionState();
    showLiveState();
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
    // shutdown joins it (joinLiveCaptures()), with its program ended.  The
    // session tells this widget nothing more.
    live_->disconnect( this );
    live_.reset();

    // The host unloads the library right after the plugin is shut down:
    // the session cancels its conversion and waits for its worker, and
    // tells this widget nothing more.
    conversion_->disconnect( this );
    conversion_.reset();

    // An export stops between two packets and leaves nothing behind; one
    // that was done when the cancel came keeps its file, as on Cancel.  Its
    // progress dialog goes first, as closing it would cancel through this
    // half-destroyed widget.
    if ( exportProgress_ ) {
        exportProgress_->disconnect( this );
        delete exportProgress_;
    }
    export_.cancelAndWait();
}

bool SidebarWidget::refuse( Activity activity )
{
    const auto why = activityRefusalMessage( activity, runningActivities() );
    if ( why.isEmpty() ) {
        return false;
    }
    hostNotify( why );
    return true;
}

void SidebarWidget::chooseAndOpen()
{
    // The Open button is disabled meanwhile, but the menu entry is not.
    if ( const auto why = conversion_->refusal(); !why.isEmpty() ) {
        hostNotify( why );
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
    // The session refuses, converts, and tells its state and outcome.
    conversion_->start( filePath );
}

void SidebarWidget::cancel()
{
    conversion_->cancel();
}

void SidebarWidget::exportSelectedPackets()
{
    // The menu entry stays enabled while an export runs.
    if ( refuse( Activity::Export ) ) {
        return;
    }
    const auto* front = catalog_.front();
    if ( !front ) {
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
    const auto index = front->index;
    ExportRequest request;
    request.captureName = front->fileName;
    request.packets = index->packets();
    request.format = captureFormatOf( index->capturePath() );

    // Without a selection, the user may still name or paste the packets.
    const auto selected = selectedPackets( readSelectedLines(), request.packets );
    if ( !selected.reason.isEmpty() ) {
        hostNotify( "Export packets: " + selected.reason );
        return;
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

    // The dialogs run their own event loops, in which this widget may be
    // deleted, or the menu entry chosen again.
    const QPointer<SidebarWidget> self( this );
    const bool confirmed = confirmExport_( this, request );
    if ( !self || !confirmed || request.numbers.empty() || request.outputPath.isEmpty() ) {
        return;
    }
    if ( refuse( Activity::Export ) ) {
        return;
    }
    // Only when the selection's packets are exported does its truncation matter.
    request.truncated = request.truncated && request.numbers == ofSelection;
    hostLog( LOGSQUIRL_LOG_INFO, QString( "Exporting %1 packets of %2 to %3" )
                                     .arg( request.numbers.count() )
                                     .arg( request.captureName, request.outputPath ) );

    exportProgress_ = new QProgressDialog(
        QString( "Exporting %1 packets\xe2\x80\xa6" ).arg( request.numbers.count() ), "Cancel", 0,
        1000, this );
    exportProgress_->setObjectName( "exportProgress" );
    exportProgress_->setWindowTitle( "Export Packets" );
    exportProgress_->setAutoClose( false );
    exportProgress_->setAutoReset( false );
    exportProgress_->setMinimumDuration( 500 );
    connect( exportProgress_, &QProgressDialog::canceled, this, &SidebarWidget::cancelExport );

    // An export stops at a cancel, before its file replaces the one chosen
    // (exportPackets()).  Once it has, a cancel comes too late: the file
    // that was there is gone, and removing the export would lose both.
    // The export stands, and is reported.
    const auto numbers = request.numbers;
    const auto path = request.outputPath;
    export_.start(
        [ index, numbers, path ]( const std::atomic_bool* cancel,
                                  const BackgroundJob<ExportResult>::Progress& progress ) {
            return exportPackets( index, numbers, path, cancel, progress );
        },
        // A cancelled or failed export left nothing behind to take back;
        // one that wrote its file cannot be taken back.
        []( const ExportResult& result ) {
            return result.status != ExportResult::Status::Exported;
        },
        [ this, request ]( ExportResult result ) { finishExport( request, std::move( result ) ); },
        [ progress = exportProgress_ ]( int permille ) {
            if ( progress ) {
                progress->setValue( permille );
            }
        } );
}

void SidebarWidget::cancelExport()
{
    if ( !isExporting() ) {
        return;
    }
    export_.cancel();
    if ( exportProgress_ ) {
        exportProgress_->setLabelText( "Cancelling\xe2\x80\xa6" );
    }
}

void SidebarWidget::finishExport( const ExportRequest& request, ExportResult result )
{
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
        hostNotify( "Show stream content: " + why );
        return;
    }
    if ( !packetPanel_->isVisible() ) {
        hostNotify( QString( "Show stream content: the stream of packet %1 is shown in the "
                             "tcpdump sidebar tab." )
                        .arg( packetPanel_->selectedPacket() ) );
    }
}

void SidebarWidget::openStreamLines()
{
    // The panel reads the selection now, not at its next poll; the stream
    // followed is that of the line it read, which its problem is about.
    packetPanel_->refresh();
    if ( const auto problem = packetPanel_->streamLinesProblem(); !problem.isEmpty() ) {
        hostNotify( "Stream lines in Regex Lab: " + problem );
        return;
    }
    if ( const auto line = packetPanel_->selectedLine() ) {
        followStream( *line );
    }
}

void SidebarWidget::updateStreamLinesButton()
{
    enableUnlessProblem( streamLinesButton_, packetPanel_->streamLinesProblem(),
                         QStringLiteral( "Open the Regex Lab with the pattern of the lines of "
                                         "this packet's conversation" ) );
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

void SidebarWidget::showConversionState()
{
    const auto state = conversion_->state();
    const bool converting = state != FileConversionSession::State::Idle;
    openButton_->setEnabled( !activityRefusal( Activity::OpenFile, runningActivities() ) );
    cancelButton_->setEnabled( state == FileConversionSession::State::Converting );
    cancelButton_->setHidden( !converting );
    progressBar_->setHidden( !converting );
    progressBar_->setValue( conversion_->progress() );
    updateStartButton();
    // Once it is over, the outcome, or the tab it opened, says what it came to.
    if ( converting ) {
        summaryLabel_->setText( conversion_->label() );
    }
}

void SidebarWidget::showConversionOutcome( const FileConversionOutcome& outcome )
{
    // A capture opened is in front: the catalog announced it, and its
    // summary is drawn already.
    if ( !outcome.label.isEmpty() ) {
        summaryLabel_->setText( outcome.label );
    }
}

void SidebarWidget::showSummaryFor( const QString& filePath )
{
    // Another tab in front is announced: showFront() draws it.
    catalog_.setFront( filePath );
}

void SidebarWidget::showFront()
{
    const auto* front = catalog_.front();
    packetPanel_->setCapture( front ? front->index : nullptr );
    packetPanel_->conversationTable()->setSummary( front ? &front->summary : nullptr );

    // The capture being read is shown in a tab of its own when it is done.
    if ( isConverting() ) {
        return;
    }
    saveButton_->setHidden( catalog_.partsToSave().empty() );
    shownSummary_ = frontSummaryHtml();
    summaryLabel_->setText( shownSummary_ );
}

QString SidebarWidget::frontSummaryHtml() const
{
    const auto* front = catalog_.front();
    if ( !front ) {
        return kNoCaptureText;
    }
    const auto& capture = *front;
    QString html;
    if ( catalog_.isCapturing( catalog_.frontFile() ) ) {
        html += "<i>Capturing\xe2\x80\xa6 the summary so far:</i><br>";
    }
    if ( !capture.error.isEmpty() ) {
        html += QString( "<b>Error:</b> %1<br>The capture so far is kept.<br>" )
                    .arg( capture.error.toHtmlEscaped() );
    }
    html += summaryHtml( capture.fileName, capture.fileSize, capture.summary,
                         g_state.hostCapabilities.regexLab, palette() );
    if ( capture.withFormatHint ) {
        html += QString( "<br><i>Table view, \xce\x94t and Go to timestamp need the plugin's "
                         "Log Format: <a href=\"%1\">install it once</a>.</i>" )
                    .arg( kLogFormatHelpUrl );
    }
    return html;
}

void SidebarWidget::changeEvent( QEvent* event )
{
    QWidget::changeEvent( event );
    // A switch between light and dark mode: the summary is made again, so
    // that the line under the capture's name takes the new colours.  Not
    // while the label says something else, a conversion's progress or end.
    if ( event->type() == QEvent::PaletteChange && summaryLabel_
         && summaryLabel_->text() == shownSummary_ ) {
        shownSummary_ = frontSummaryHtml();
        summaryLabel_->setText( shownSummary_ );
    }
}

bool SidebarWidget::startLiveCapture( const QString& name, LiveCapture::SourceFactory makeSource,
                                      const LiveLimits& limits,
                                      std::shared_ptr<const LiveSourceKind> kind )
{
    return live_->start( name, std::move( makeSource ), limits, std::move( kind ) );
}

bool SidebarWidget::startLiveCapture( const LiveChoice& choice )
{
    return live_->start( choice );
}

void SidebarWidget::chooseAndStartLiveCapture()
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
    // The dialogs run their own event loops, in which this widget may be
    // deleted, or the capture end by itself.
    const QPointer<SidebarWidget> self( this );
    if ( refusal ) {
        const auto running
            = live_->state() == LiveCaptureSession::State::Checking && live_->choice()
                  ? liveCaptureName( *live_->choice() )
                  : live_->name();
        if ( !confirmStop_( this, running ) || !self ) {
            return;
        }
    }
    auto choice = loadLiveChoice( hostConfigDir() );
    if ( !askLiveChoice_( this, choice ) || !self ) {
        return;
    }
    // Once the running one, if any, has ended and its program too.
    live_->startWhenIdle( choice );
}

void SidebarWidget::setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    liveSources_ = std::move( sources );
    live_->setSources( liveSources_ );
}

std::unique_ptr<LiveCaptureDialog> SidebarWidget::makeLiveCaptureDialog( QWidget* parent )
{
    return makeLiveCaptureDialog( parent, loadLiveChoice( hostConfigDir() ) );
}

std::unique_ptr<LiveCaptureDialog> SidebarWidget::makeLiveCaptureDialog( QWidget* parent,
                                                                         const LiveChoice& choice )
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

void SidebarWidget::updateStartButton()
{
    if ( !startButton_ ) {
        return;
    }
    // As in chooseAndStartLiveCapture(), a capture that runs is no reason:
    // the button is hidden meanwhile.
    const auto refusal = activityRefusal( Activity::LiveCapture, runningActivities() );
    const auto why = refusal && *refusal != ActivityRefusal::Capturing ? refusalMessage( *refusal )
                                                                       : QString();
    startButton_->setEnabled( why.isEmpty() );
    startButton_->setToolTip( why.isEmpty() ? "Choose what to capture, and start capturing" : why );
}

void SidebarWidget::showLiveError( const LiveOutcome& outcome )
{
    auto text = "Error: " + guidanceHtml( outcome.error );
    if ( !outcome.guidance.isEmpty() ) {
        text += "<br>" + guidanceHtml( outcome.guidance );
    }
    liveError_->setText( text );
    liveError_->setHidden( false );
}

void SidebarWidget::stopLiveCapture()
{
    live_->stop();
}

void SidebarWidget::showLiveStart()
{
    liveStderr_->clear();
    liveStderr_->setHidden( true );
    liveError_->clear();
    liveError_->setHidden( true );
    summaryLabel_->setText( QString( "Capturing %1\xe2\x80\xa6 waiting for the first packet." )
                                .arg( live_->name().toHtmlEscaped() ) );
}

void SidebarWidget::showLiveState()
{
    const bool capturing = isCapturing();
    openButton_->setEnabled( !activityRefusal( Activity::OpenFile, runningActivities() ) );
    stopButton_->setEnabled( capturing && live_->state() != LiveCaptureSession::State::Stopping );
    stopButton_->setHidden( !capturing );
    liveLabel_->setHidden( !capturing );
    startButton_->setHidden( capturing );
    updateStartButton();
    if ( capturing ) {
        showLiveProgress();
        if ( !liveTicker_.isActive() ) {
            liveTicker_.start();
        }
    }
    else {
        liveTicker_.stop();
    }
}

void SidebarWidget::showLiveProgress()
{
    switch ( live_->state() ) {
    case LiveCaptureSession::State::Idle:
        return;
    case LiveCaptureSession::State::Checking:
        liveLabel_->setText( "Asking the source about the choice before it starts\xe2\x80\xa6" );
        return;
    case LiveCaptureSession::State::Capturing:
        liveLabel_->setText(
            liveProgressText( live_->progress(), live_->elapsedMs(), live_->limits() ) );
        return;
    case LiveCaptureSession::State::Stopping:
        liveLabel_->setText(
            liveProgressText( live_->progress(), live_->elapsedMs(), live_->limits() )
            + " \xe2\x80\x94 stopping\xe2\x80\xa6" );
        return;
    }
}

void SidebarWidget::openTab( const QString& logPath, bool follow )
{
    // On this, the UI thread.  The header and a packet line are in it, so
    // the host recognises the Log Format; a live capture's grows.
    if ( g_state.api && g_state.handle ) {
        g_state.api->open_file( g_state.handle, logPath.toUtf8().constData(), follow ? 1 : 0 );
    }
}

void SidebarWidget::notify( const QString& message )
{
    hostNotify( message );
}

RunningActivities SidebarWidget::runningElsewhere() const
{
    // Each session puts in its own, converting or capturing.
    return runningActivities();
}

void SidebarWidget::showLiveFile( const QString& logPath )
{
    // The host may have brought its tab to the front at once, showing its
    // summary; otherwise the label says the capture goes on.
    if ( !catalog_.isFront( logPath ) ) {
        summaryLabel_->setText(
            QString( "Capturing %1\xe2\x80\xa6" ).arg( live_->name().toHtmlEscaped() ) );
    }
}

void SidebarWidget::updateSummary( const QString& textPath, CaptureSummary summary )
{
    // The catalog announces it if its tab is in front.
    catalog_.updateSummary( textPath, std::move( summary ) );
}

void SidebarWidget::showLiveOutcome( const LiveOutcome& outcome )
{
    switch ( outcome.status ) {
    case LiveOutcome::Status::Stopped:
    case LiveOutcome::Status::Empty:
        summaryLabel_->setText( liveOutcomeText( outcome ).toHtmlEscaped() );
        return;
    case LiveOutcome::Status::Failed:
        showLiveError( outcome );
        if ( outcome.files.isEmpty() ) {
            summaryLabel_->setText( "Error: " + outcome.error.toHtmlEscaped() );
            return;
        }
        break;
    case LiveOutcome::Status::Captured:
        break;
    }
    // Its tabs show the final summary: the catalog announced it for the one
    // in front.  With another tab in front, the label says where it is.
    if ( !catalog_.isLive( catalog_.frontFile() ) ) {
        summaryLabel_->setText( QString( "The capture %1 has ended: its tab shows its summary." )
                                    .arg( outcome.name.toHtmlEscaped() ) );
    }
}

void SidebarWidget::saveCapture()
{
    const auto parts = catalog_.partsToSave();
    if ( parts.empty() ) {
        return;
    }
    if ( lastDir_.isEmpty() ) {
        lastDir_ = QStandardPaths::writableLocation( QStandardPaths::HomeLocation );
    }
    const auto suggested = catalog_.saveName();
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
                     bool filterLinks, const QPalette& palette )
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
    html += separatorHtml( palette );

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

} // namespace tcpdump
