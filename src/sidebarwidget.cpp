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
 * Its Filter stream in Regex Lab button, on a host that offers it, opens the
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
#include "plugin.h"
#include "regex_lab.h"
#include "settings.h"

#include <QDesktopServices>
#include <QGroupBox>
#include <QLocale>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollArea>
#include <QSplitter>
#include <QStringList>
#include <QStyle>
#include <QUrl>

#include <algorithm>
#include <exception>

namespace tcpdump {

namespace {

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

/// The splitter between the summary and the Packet panel.  Until the user
/// drags its handle, or a position is restored, it is at the default split:
/// the summary as tall as it asks (SummaryArea, up to
/// SidebarWidget::kSummaryMaxLines), the Packet panel the rest, as a new
/// summary or a resize ask anew.  Neither pane can be dragged below its
/// minimum, and on a resize the Packet panel takes what is gained or lost.
class SummarySplitter : public QSplitter {
public:
    SummarySplitter( QWidget* summary, QWidget* panel )
        : QSplitter( Qt::Vertical )
    {
        setChildrenCollapsible( false );
        addWidget( summary );
        addWidget( panel );
        setStretchFactor( 0, 0 );
        setStretchFactor( 1, 1 );
        // Only the user's drag moves the splitter, not setSizes().
        connect( this, &QSplitter::splitterMoved, this, [ this ] { atDefault_ = false; } );
    }

    /// Put the panes at @p sizes, as saved; the default split if they are
    /// not one size per pane.
    void restore( const QList<int>& sizes )
    {
        if ( sizes.size() == count() ) {
            atDefault_ = false;
            setSizes( sizes );
        }
    }

protected:
    bool event( QEvent* event ) override
    {
        const auto handled = QSplitter::event( event );
        // A pane asks for another height: a new summary, Save capture… shown.
        if ( event->type() == QEvent::LayoutRequest ) {
            fitSummary();
        }
        return handled;
    }

    void resizeEvent( QResizeEvent* event ) override
    {
        QSplitter::resizeEvent( event );
        fitSummary();
    }

private:
    /// At the default split, give the summary the height it asks for.
    void fitSummary()
    {
        const auto room = height() - handleWidth();
        if ( !atDefault_ || room <= 0 ) {
            return;
        }
        const auto* summary = widget( 0 );
        const auto least = summary->minimumSizeHint().height();
        const auto most = std::max( least, room - widget( 1 )->minimumHeight() );
        const auto top = std::clamp( summary->sizeHint().height(), least, most );
        if ( sizes().value( 0 ) != top ) {
            setSizes( { top, room - top } );
        }
    }

    bool atDefault_ = true;
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

    // Filter stream in Regex Lab, as in the Plugins menu: only a host that
    // has the Regex Lab and tells the selected lines gets it.  It is enabled
    // as the Packet Panel finds the selected line, below.
    if ( g_state.hostCapabilities.regexLab && g_state.hostCapabilities.selectedLogLines ) {
        streamLinesButton_ = new QPushButton( "Filter stream in Regex Lab" );
        streamLinesButton_->setObjectName( "streamLinesButton" );
        layout->addWidget( streamLinesButton_ );
        connect( streamLinesButton_, &QPushButton::clicked, this, [ this ] {
            try {
                openStreamLines();
            } catch ( const std::exception& e ) {
                // An exception must not escape into Qt or the host.
                hostLog( LOGSQUIRL_LOG_ERROR,
                         "Filter stream in Regex Lab failed: " + QString::fromUtf8( e.what() ) );
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
    // Shown only while a capture runs, so Stop live capture never says none
    // does.
    connect( stopButton_, &QPushButton::clicked, this, [ this ] {
        forward( "Stopping a live capture", &CaptureSessions::stopLiveCapture );
    } );

    liveError_ = new GuidanceLabel( "liveError" );
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
    liveStderrDropped_ = new QLabel;
    liveStderrDropped_->setObjectName( "liveStderrDropped" );
    liveStderrDropped_->setHidden( true );
    liveLayout->addWidget( liveStderrDropped_ );

    layout->addWidget( liveSection );

    liveTicker_.setInterval( 1000 );
    connect( &liveTicker_, &QTimer::timeout, this, &SidebarWidget::showLiveProgress );

    // Summary label, which says what summaryLabelText() decides
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
    // The summary's pane of the splitter below: the summary and Save capture….
    auto* summaryPane = new QWidget;
    summaryPane->setObjectName( "summaryPane" );
    auto* summaryLayout = new QVBoxLayout( summaryPane );
    summaryLayout->setContentsMargins( 0, 0, 0, 0 );
    summaryLayout->setSpacing( layout->spacing() );
    summaryLayout->addWidget( summaryArea, 1 );

    // A live capture's raw file is in the temporary directory, which goes
    // when LogSquirl quits: this keeps it.
    saveButton_ = new QPushButton( "Save capture\xe2\x80\xa6" );
    saveButton_->setObjectName( "saveCaptureButton" );
    saveButton_->setToolTip( "Save the raw capture of this tab as a pcap file; a ring buffer's "
                             "files kept as one" );
    saveButton_->setHidden( true );
    summaryLayout->addWidget( saveButton_ );
    connect( saveButton_, &QPushButton::clicked, this,
             [ this ] { forward( "Saving a capture", &CaptureSessions::saveCapture ); } );

    // The packet of the selected line, below; it takes the room left, and
    // keeps room for its tabs and the Conversations however long the summary.
    packetPanel_ = new PacketPanel;
    packetPanel_->setObjectName( "packetPanel" );
    packetPanel_->setMinimumHeight( kPacketPanelMinLines * fontMetrics().lineSpacing() );

    // The user drags the handle between the two; where it and the panel's
    // own handles were left is restored from settings.ini, and saved there.
    auto* summarySplitter = new SummarySplitter( summaryPane, packetPanel_ );
    summarySplitter->setObjectName( "summarySplitter" );
    layout->addWidget( summarySplitter, 1 );
    splitters_ = { { kSummarySplitName, summarySplitter },
                   { kLayersSplitName, packetPanel_->layersSplitter() },
                   { kConversationsSplitName, packetPanel_->conversationsSplitter() } };
    const auto configDir = hostConfigDir();
    summarySplitter->restore( loadSplitterSizes( configDir, kSummarySplitName ) );
    for ( const auto& [ name, splitter ] : splitters_ ) {
        if ( splitter != summarySplitter ) {
            if ( const auto sizes = loadSplitterSizes( configDir, name );
                 sizes.size() == splitter->count() ) {
                splitter->setSizes( sizes );
            }
        }
        // A drag sends many moves: the sizes are saved once it rests.
        connect( splitter, &QSplitter::splitterMoved, this, [ this, name = name ] {
            movedSplitters_.insert( name );
            layoutSaver_.start();
        } );
    }
    layoutSaver_.setSingleShot( true );
    layoutSaver_.setInterval( kLayoutSaveDelayMs );
    connect( &layoutSaver_, &QTimer::timeout, this, &SidebarWidget::saveLayout );

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
    // The destructor stops observing.
    frontObserver_ = sessions_.catalog().observeFront( [ this ] { showFront(); } );
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
    connect( live, &LiveCaptureSession::stderrLines, this,
             [ this ]( const QStringList& lines, quint64 dropped ) {
                 // The view keeps the latest lines (its block count) and says
                 // how many came before them.
                 liveStderr_->appendPlainText( lines.join( QLatin1Char( '\n' ) ) );
                 liveStderr_->setHidden( false );
                 liveStderrLines_ += dropped + static_cast<quint64>( lines.size() );
                 const auto shown = static_cast<quint64>( liveStderr_->maximumBlockCount() );
                 if ( liveStderrLines_ > shown ) {
                     liveStderrDropped_->setText(
                         QString( "%1 earlier lines dropped" )
                             .arg( QLocale().toString(
                                 static_cast<qulonglong>( liveStderrLines_ - shown ) ) ) );
                     liveStderrDropped_->setHidden( false );
                 }
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
    sessions_.catalog().stopObserving( frontObserver_ );
    sessions_.conversionSession().disconnect( this );
    sessions_.liveSession().disconnect( this );
    sessions_.exportSession().disconnect( this );
    if ( exportProgress_ ) {
        exportProgress_->disconnect( this );
        delete exportProgress_;
    }
    // A drag not saved yet is saved now, while the splitters are still here.
    if ( layoutSaver_.isActive() ) {
        layoutSaver_.stop();
        saveLayout();
    }
}

void SidebarWidget::saveLayout()
{
    const auto configDir = hostConfigDir();
    for ( const auto& [ name, splitter ] : splitters_ ) {
        if ( movedSplitters_.contains( name )
             && !saveSplitterSizes( configDir, name, splitter->sizes() ) ) {
            hostLog( LOGSQUIRL_LOG_WARNING, "The sidebar's layout could not be saved in "
                                                + settingsFilePath( configDir ) );
            return;
        }
    }
    movedSplitters_.clear();
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
            exportProgress_ = new QProgressDialog( this );
            exportProgress_->setObjectName( "exportProgress" );
            // The session's label() is plain text, which a QLabel would
            // take for markup if it looked like it: an error or a path with
            // a '<' in it.  Aligned as the dialog's own label.
            auto* label = new QLabel;
            label->setTextFormat( Qt::PlainText );
            label->setAlignment( Qt::Alignment( exportProgress_->style()->styleHint(
                QStyle::SH_ProgressDialog_TextLabelAlignment, nullptr, exportProgress_ ) ) );
            exportProgress_->setLabel( label );
            exportProgress_->setLabelText( session.label() );
            exportProgress_->setCancelButtonText( "Cancel" );
            exportProgress_->setRange( 0, 1000 );
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
        hostNotify( "Follow stream content: " + why );
        return;
    }
    if ( !packetPanel_->isVisible() ) {
        hostNotify( QString( "Follow stream content: the stream of packet %1 is shown in the "
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
        hostNotify( "Filter stream in Regex Lab: " + problem );
        return;
    }
    if ( const auto line = packetPanel_->selectedLine() ) {
        followStream( *line );
    }
}

void SidebarWidget::updateStreamLinesButton()
{
    enableUnlessProblem( streamLinesButton_, packetPanel_->streamLinesProblem(),
                         QStringLiteral( "Filter this packet's conversation in the Regex Lab: "
                                         "open it with the pattern of the stream's lines" ) );
}

void SidebarWidget::openLink( const QString& link )
{
    try {
        const auto pattern = summaryLinkPattern( link );
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
    summaryLabel_->setText(
        summaryLabelText( status, sessions_, g_state.hostCapabilities.regexLab, palette() ) );
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
    liveError_->setText( liveErrorHtml( outcome ) );
    liveError_->setHidden( false );
}

void SidebarWidget::showLiveStart()
{
    liveStderr_->clear();
    liveStderr_->setHidden( true );
    liveStderrLines_ = 0;
    liveStderrDropped_->clear();
    liveStderrDropped_->setHidden( true );
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
    // Hidden while idle, with what it said last.
    if ( const auto text = liveStateText( sessions_.liveSession() ); !text.isEmpty() ) {
        liveLabel_->setText( text );
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

} // namespace tcpdump
