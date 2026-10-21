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
 * The sidebar is a view of the plugin's CaptureSessions: its buttons
 * forward to them, and it shows what they tell.  When the user clicks
 * "Open pcap…", the sessions:
 *   1. Open a file dialog for .pcap / .cap / .dmp files, over the sidebar
 *   2. Hand it to the File Conversion session, which converts the pcap
 *      packet by packet with pcap_converter: parses each packet, formats it
 *      into a human-readable line, and writes the line to a temporary .log
 *      file
 *   3. The session opens the .log file in LogSquirl's main viewer, through
 *      the capture catalog
 * and the sidebar shows the session's progress, label and outcome.
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
 * The sessions' CaptureCatalog keeps each capture's summary and CaptureIndex
 * under the path of its .log file and says which is in the tab in front, as
 * the host reports tab switches; the sidebar shows that one's summary, and
 * its Packet Panel the packets of that capture, whenever the catalog
 * announces a change.
 *
 * A live capture is the Live Capture Session's, which keeps the summaries
 * of its text files in the catalog; the sidebar shows the session's state,
 * progress, stderr lines and outcome.  Start live capture… asks, through
 * the sessions, in the Start live capture dialog, which chooses what to
 * capture from the Live Source Kinds (live_source.h).
 *
 * Export packets… is the Export session's; the sidebar shows its progress
 * dialog, whose Cancel forwards to it.
 */

#include "sidebarwidget.h"

#include "conversation_table.h"
#include "display_filter_dialog.h"
#include "follow_stream.h"
#include "live_capture_form.h"
#include "packet_panel.h"
#include "pcap_converter.h"
#include "plugin.h"
#include "regex_lab.h"

#include <QDesktopServices>
#include <QGroupBox>
#include <QLocale>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollArea>
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

SidebarWidget::SidebarWidget( CaptureSessions& sessions, QWidget* parent )
    : QWidget( parent )
    , sessions_( sessions )
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

    connect( openButton_, &QPushButton::clicked, this,
             [ this ] { forward( "Opening a capture", &CaptureSessions::chooseAndOpen ); } );

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
    connect( cancelButton_, &QPushButton::clicked, this,
             [ this ] { sessions_.conversionSession().cancel(); } );

    // Live capture: Start live capture… asks what to capture in its dialog;
    // while one runs, its progress (no percentage, a stream has no size),
    // Stop and what the capture program says.
    auto* liveSection = new QGroupBox( "Live capture" );
    liveSection->setObjectName( "liveSection" );
    auto* liveLayout = new QVBoxLayout( liveSection );
    liveLayout->setSpacing( 4 );

    startButton_ = new QPushButton( "Start live capture…" );
    startButton_->setObjectName( "liveCaptureButton" );
    liveLayout->addWidget( startButton_ );
    connect( startButton_, &QPushButton::clicked, this, [ this ] {
        forward( "Starting a live capture", &CaptureSessions::chooseAndStartLiveCapture );
    } );

    liveLabel_ = new QLabel;
    liveLabel_->setObjectName( "liveProgress" );
    liveLabel_->setWordWrap( true );
    liveLayout->addWidget( liveLabel_ );

    stopButton_ = new QPushButton( "Stop" );
    stopButton_->setObjectName( "stopButton" );
    stopButton_->setToolTip( "End the capture and keep what was captured" );
    liveLayout->addWidget( stopButton_ );
    connect( stopButton_, &QPushButton::clicked, this,
             [ this ] { sessions_.liveSession().stop(); } );

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

    // Summary label, which says what summaryText() decides
    summaryLabel_ = new QLabel;
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
    connect( saveButton_, &QPushButton::clicked, this,
             [ this ] { forward( "Saving a capture", &CaptureSessions::saveCapture ); } );

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

    // The sessions ask the user over this sidebar, and it shows what they
    // tell: the capture in front anew whenever the catalog announces that it
    // changed, each session's state, progress and outcome.
    sessions_.setDialogParent( this );
    sessions_.catalog().observeFront( [ self = QPointer<SidebarWidget>( this ) ] {
        if ( self ) {
            self->showFront();
        }
    } );
    auto* conversion = &sessions_.conversionSession();
    connect( conversion, &FileConversionSession::stateChanged, this,
             &SidebarWidget::showConversionState );
    connect( conversion, &FileConversionSession::progressed, this,
             [ this ]( int permille ) { progressBar_->setValue( permille ); } );
    connect( conversion, &FileConversionSession::finished, this,
             &SidebarWidget::showConversionOutcome );

    auto* live = &sessions_.liveSession();
    connect( live, &LiveCaptureSession::stateChanged, this, &SidebarWidget::showLiveState );
    connect( live, &LiveCaptureSession::started, this, &SidebarWidget::showLiveStart );
    connect( live, &LiveCaptureSession::fileOpened, this, &SidebarWidget::showLiveFile );
    // The catalog's snapshot of the tab in front redraws its summary.
    connect( live, &LiveCaptureSession::progressed, this, &SidebarWidget::showLiveProgress );
    connect( live, &LiveCaptureSession::stderrLine, this, [ this ]( const QString& line ) {
        liveStderr_->appendPlainText( line );
        liveStderr_->setHidden( false );
    } );
    connect( live, &LiveCaptureSession::finished, this, &SidebarWidget::showLiveOutcome );

    // The Export session asks and tells the outcome itself; the sidebar
    // shows its progress dialog.
    auto* exporting = &sessions_.exportSession();
    connect( exporting, &ExportSession::stateChanged, this, &SidebarWidget::showExportState );
    connect( exporting, &ExportSession::progressed, this, [ this ]( int permille ) {
        if ( exportProgress_ ) {
            exportProgress_->setValue( permille );
        }
    } );

    showSummary( SummaryStatus::NothingLoaded );
    showConversionState();
    showLiveState();
    showExportState();
}

SidebarWidget::~SidebarWidget()
{
    // The sessions run on, and tell this widget nothing more.  The export's
    // progress dialog goes first, as closing it would cancel the export
    // through this half-destroyed widget.
    sessions_.conversionSession().disconnect( this );
    sessions_.liveSession().disconnect( this );
    sessions_.exportSession().disconnect( this );
    if ( exportProgress_ ) {
        exportProgress_->disconnect( this );
        delete exportProgress_;
    }
}

void SidebarWidget::forward( const char* what, void ( CaptureSessions::*action )() )
{
    try {
        ( sessions_.*action )();
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog( LOGSQUIRL_LOG_ERROR,
                 QString( "%1 failed: %2" ).arg( what, QString::fromUtf8( e.what() ) ) );
    }
}

void SidebarWidget::showExportState()
{
    auto& session = sessions_.exportSession();
    switch ( session.state() ) {
    case ExportSession::State::Exporting:
        if ( !exportProgress_ ) {
            exportProgress_ = new QProgressDialog( session.label(), "Cancel", 0, 1000, this );
            exportProgress_->setObjectName( "exportProgress" );
            exportProgress_->setWindowTitle( "Export Packets" );
            exportProgress_->setAutoClose( false );
            exportProgress_->setAutoReset( false );
            exportProgress_->setMinimumDuration( 500 );
            connect( exportProgress_, &QProgressDialog::canceled, this,
                     [ this ] { sessions_.exportSession().cancel(); } );
        }
        return;
    case ExportSession::State::Cancelling:
        if ( exportProgress_ ) {
            exportProgress_->setLabelText( session.label() );
        }
        return;
    case ExportSession::State::Idle:
        if ( exportProgress_ ) {
            // Closing it would cancel the export that is over.
            exportProgress_->disconnect( this );
            exportProgress_->deleteLater();
            exportProgress_ = nullptr;
        }
        return;
    }
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

void SidebarWidget::updateOpenButton()
{
    openButton_->setEnabled(
        !activityRefusal( Activity::OpenFile, sessions_.runningActivities() ) );
}

void SidebarWidget::showConversionState()
{
    const auto& session = sessions_.conversionSession();
    const auto state = session.state();
    const bool converting = state != FileConversionSession::State::Idle;
    updateOpenButton();
    cancelButton_->setEnabled( state == FileConversionSession::State::Converting );
    cancelButton_->setHidden( !converting );
    progressBar_->setHidden( !converting );
    progressBar_->setValue( session.progress() );
    updateStartButton();
    // Once it is over, the outcome, or the tab it opened, says what it came to.
    if ( converting ) {
        showSummary( SummaryStatus::Conversion );
    }
}

void SidebarWidget::showConversionOutcome( const FileConversionOutcome& outcome )
{
    // A capture opened is in front: the catalog announced it, and its
    // summary is drawn already.
    if ( !outcome.label.isEmpty() ) {
        showSummary( SummaryStatus::Conversion );
    }
}

void SidebarWidget::showFront()
{
    const auto& catalog = sessions_.catalog();
    const auto* front = catalog.front();
    packetPanel_->setCapture( front ? front->index : nullptr );
    packetPanel_->conversationTable()->setSummary( front ? &front->summary : nullptr );

    // The capture being read is shown in a tab of its own when it is done.
    if ( !sessions_.conversionSession().isBusy() ) {
        saveButton_->setHidden( catalog.partsToSave().empty() );
    }
    showSummary( SummaryStatus::Front );
}

void SidebarWidget::showSummary( SummaryStatus status )
{
    summaryStatus_ = status;
    summaryLabel_->setText( summaryText() );
}

QString SidebarWidget::summaryText() const
{
    const auto& conversion = sessions_.conversionSession();
    const auto& live = sessions_.liveSession();
    const auto& catalog = sessions_.catalog();
    // The capture being read is shown in a tab of its own when it is done:
    // until then, whatever comes to the front, the label says it is read.
    if ( conversion.isBusy() ) {
        return conversion.label();
    }
    switch ( summaryStatus_ ) {
    case SummaryStatus::NothingLoaded:
        return "No capture loaded.";
    case SummaryStatus::Front:
        break;
    case SummaryStatus::Conversion:
        // Its outcome's label, "Cancelled." or the error; a capture opened
        // is in front.
        if ( const auto label = conversion.label(); !label.isEmpty() ) {
            return label;
        }
        break;
    case SummaryStatus::LiveStarted:
        return QString( "Capturing %1\xe2\x80\xa6 waiting for the first packet." )
            .arg( live.name().toHtmlEscaped() );
    case SummaryStatus::LiveFile:
        // The host may have brought its tab to the front at once, showing
        // its summary; otherwise the label says the capture goes on.
        if ( !live.files().isEmpty() && catalog.isFront( live.files().last() ) ) {
            break;
        }
        return QString( "Capturing %1\xe2\x80\xa6" ).arg( live.name().toHtmlEscaped() );
    case SummaryStatus::LiveOutcome: {
        // Its tab in front shows its final summary: the catalog announced it.
        const auto& outcome = live.outcome();
        if ( !outcome || ( !outcome->files.isEmpty() && catalog.isLive( catalog.frontFile() ) ) ) {
            break;
        }
        switch ( outcome->status ) {
        case LiveOutcome::Status::Stopped:
        case LiveOutcome::Status::Empty:
            return liveOutcomeText( *outcome ).toHtmlEscaped();
        case LiveOutcome::Status::Failed:
            if ( outcome->files.isEmpty() ) {
                return "Error: " + outcome->error.toHtmlEscaped();
            }
            break;
        case LiveOutcome::Status::Captured:
            break;
        }
        // Its tabs show the final summary; another tab is in front, or none.
        return QString( "The capture %1 has ended: its tab shows its summary." )
            .arg( outcome->name.toHtmlEscaped() );
    }
    }
    return frontSummaryHtml();
}

QString SidebarWidget::frontSummaryHtml() const
{
    const auto& catalog = sessions_.catalog();
    const auto* front = catalog.front();
    if ( !front ) {
        return kNoCaptureText;
    }
    const auto& capture = *front;
    QString html;
    if ( catalog.isCapturing( catalog.frontFile() ) ) {
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
    // A switch between light and dark mode: the label says its status again,
    // so that the line under a capture's name takes the new colours.
    if ( event->type() == QEvent::PaletteChange && summaryLabel_ ) {
        showSummary( summaryStatus_ );
    }
}

void SidebarWidget::updateStartButton()
{
    if ( !startButton_ ) {
        return;
    }
    // As in CaptureSessions::chooseAndStartLiveCapture(), a capture that
    // runs is no reason: the button is hidden meanwhile.
    const auto refusal = activityRefusal( Activity::LiveCapture, sessions_.runningActivities() );
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

void SidebarWidget::showLiveStart()
{
    liveStderr_->clear();
    liveStderr_->setHidden( true );
    liveError_->clear();
    liveError_->setHidden( true );
    showSummary( SummaryStatus::LiveStarted );
}

void SidebarWidget::showLiveState()
{
    const auto& live = sessions_.liveSession();
    const bool capturing = live.isBusy();
    updateOpenButton();
    stopButton_->setEnabled( capturing && live.state() != LiveCaptureSession::State::Stopping );
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
    const auto& live = sessions_.liveSession();
    switch ( live.state() ) {
    case LiveCaptureSession::State::Idle:
        return;
    case LiveCaptureSession::State::Checking:
        liveLabel_->setText( "Asking the source about the choice before it starts\xe2\x80\xa6" );
        return;
    case LiveCaptureSession::State::Capturing:
        liveLabel_->setText( liveProgressText( live.progress(), live.elapsedMs(), live.limits() ) );
        return;
    case LiveCaptureSession::State::Stopping:
        liveLabel_->setText( liveProgressText( live.progress(), live.elapsedMs(), live.limits() )
                             + " \xe2\x80\x94 stopping\xe2\x80\xa6" );
        return;
    }
}

void SidebarWidget::showLiveFile()
{
    showSummary( SummaryStatus::LiveFile );
}

void SidebarWidget::showLiveOutcome( const LiveOutcome& outcome )
{
    if ( outcome.status == LiveOutcome::Status::Failed ) {
        showLiveError( outcome );
    }
    showSummary( SummaryStatus::LiveOutcome );
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
