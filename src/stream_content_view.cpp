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
 * @file stream_content_view.cpp
 * @brief The Stream tab: reading in the background, rendering, export.
 */

#include "stream_content_view.h"

#include "plugin.h"

#include <QComboBox>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QTextCursor>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrent>

#include <exception>

namespace tcpdump {

namespace {

/// "1.5 MB", "812 bytes".
QString sizeText( uint64_t bytes )
{
    if ( bytes < 1024 ) {
        return QStringLiteral( "%1 bytes" ).arg( bytes );
    }
    if ( bytes < 1024 * 1024 ) {
        return QStringLiteral( "%1 KB" ).arg( static_cast<double>( bytes ) / 1024, 0, 'f', 1 );
    }
    return QStringLiteral( "%1 MB" ).arg( static_cast<double>( bytes ) / ( 1024 * 1024 ), 0, 'f',
                                          1 );
}

/// The colour of a direction's bytes, as Wireshark's: the client's red,
/// the server's blue; dark enough on a light background, light enough on a
/// dark one.
QTextCharFormat directionFormat( unsigned direction, const QPalette& palette )
{
    const bool dark = palette.color( QPalette::Base ).lightness() < 128;
    QTextCharFormat format;
    if ( direction == 0 ) {
        format.setForeground( dark ? QColor( 0xff, 0x8a, 0x8a ) : QColor( 0xa0, 0x10, 0x10 ) );
    }
    else {
        format.setForeground( dark ? QColor( 0x8a, 0xb4, 0xff ) : QColor( 0x10, 0x30, 0xa0 ) );
    }
    return format;
}

QTextCharFormat gapFormat( const QPalette& palette )
{
    QTextCharFormat format;
    format.setForeground( palette.color( QPalette::PlaceholderText ) );
    format.setFontItalic( true );
    return format;
}

} // namespace

StreamContentView::StreamContentView( QWidget* parent )
    : QWidget( parent )
{
    // One task at a time: a read or an export of the stream shown.
    pool_.setMaxThreadCount( 1 );

    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    layout->setSpacing( 4 );

    status_ = new QLabel;
    status_->setObjectName( "streamStatus" );
    status_->setWordWrap( true );
    status_->setTextFormat( Qt::PlainText );
    layout->addWidget( status_ );

    auto* choices = new QHBoxLayout;
    directionBox_ = new QComboBox;
    directionBox_->setObjectName( "streamDirection" );
    directionBox_->setToolTip( "Show both directions, or the bytes one side sent" );
    directionBox_->addItem( "Both directions", static_cast<uint>( kBothDirections ) );
    directionBox_->addItem( "Client \xe2\x86\x92 server", static_cast<uint>( kClientToServer ) );
    directionBox_->addItem( "Server \xe2\x86\x92 client", static_cast<uint>( kServerToClient ) );
    choices->addWidget( directionBox_, 1 );
    formatBox_ = new QComboBox;
    formatBox_->setObjectName( "streamFormat" );
    formatBox_->setToolTip( "Show the bytes as text or as a hex dump" );
    formatBox_->addItem( "Text", static_cast<int>( StreamFormat::Text ) );
    formatBox_->addItem( "Hex", static_cast<int>( StreamFormat::Hex ) );
    choices->addWidget( formatBox_ );
    layout->addLayout( choices );

    content_ = new QPlainTextEdit;
    content_->setObjectName( "streamText" );
    content_->setReadOnly( true );
    content_->setFont( QFontDatabase::systemFont( QFontDatabase::FixedFont ) );
    content_->setLineWrapMode( QPlainTextEdit::WidgetWidth );
    layout->addWidget( content_, 1 );

    note_ = new QLabel;
    note_->setObjectName( "streamNote" );
    note_->setWordWrap( true );
    note_->setTextFormat( Qt::PlainText );
    layout->addWidget( note_ );

    progress_ = new QProgressBar;
    progress_->setObjectName( "streamProgress" );
    progress_->setRange( 0, 1000 );
    progress_->setTextVisible( false );
    layout->addWidget( progress_ );

    auto* buttons = new QHBoxLayout;
    moreButton_ = new QPushButton( "Show more" );
    moreButton_->setObjectName( "streamMore" );
    moreButton_->setToolTip( "Read more of the stream" );
    buttons->addWidget( moreButton_ );
    cancelButton_ = new QPushButton( "Cancel" );
    cancelButton_->setObjectName( "streamCancel" );
    cancelButton_->setToolTip( "Stop reading the stream" );
    buttons->addWidget( cancelButton_ );
    exportButton_ = new QPushButton( "Export\xe2\x80\xa6" );
    exportButton_->setObjectName( "streamExport" );
    exportButton_->setToolTip( "Write the whole stream to a file" );
    auto* exportMenu = new QMenu( exportButton_ );
    exportMenu->addAction( "Raw bytes of the directions shown\xe2\x80\xa6", this,
                           [ this ] { chooseExport( true ); } );
    exportMenu->addAction( "Text as shown\xe2\x80\xa6", this, [ this ] { chooseExport( false ); } );
    exportButton_->setMenu( exportMenu );
    buttons->addWidget( exportButton_ );
    buttons->addStretch( 1 );
    layout->addLayout( buttons );

    connect( moreButton_, &QPushButton::clicked, this, &StreamContentView::showMore );
    connect( cancelButton_, &QPushButton::clicked, this, &StreamContentView::cancel );
    connect( directionBox_, qOverload<int>( &QComboBox::currentIndexChanged ), this,
             [ this ]( int ) { setDirections( directionBox_->currentData().toUInt() ); } );
    connect( formatBox_, qOverload<int>( &QComboBox::currentIndexChanged ), this, [ this ]( int ) {
        setFormat( static_cast<StreamFormat>( formatBox_->currentData().toInt() ) );
    } );

    clear( QStringLiteral( "Select a packet line and choose Follow stream content." ) );
}

StreamContentView::~StreamContentView()
{
    // The reader checks the flag between packets.
    if ( cancel_ ) {
        cancel_->store( true );
    }
    pool_.waitForDone();
}

QString StreamContentView::statusText() const
{
    return status_->text();
}

QString StreamContentView::noteText() const
{
    return note_->text();
}

QString StreamContentView::contentText() const
{
    return content_->toPlainText();
}

void StreamContentView::clear( const QString& reason )
{
    cancel();
    ++generation_;
    index_.reset();
    reader_.reset();
    chunks_.clear();
    rerenderPending_ = false;
    shownBytes_ = 0;
    more_ = false;
    lastError_.clear();
    content_->clear();
    setBusy( false );
    status_->setText( reason );
    note_->clear();
    note_->hide();
    exportButton_->setEnabled( false );
    moreButton_->setEnabled( false );
}

void StreamContentView::follow( std::shared_ptr<const CaptureIndex> index, uint32_t number,
                                int streamId )
{
    clear( QString() );
    index_ = std::move( index );
    number_ = number;
    streamId_ = streamId;
    reader_ = std::make_shared<StreamContentReader>( index_, number, streamId );
    renderer_ = std::make_unique<StreamRenderer>( format_, directions_, Transport::Tcp );
    startRead( kShowBytes );
}

void StreamContentView::showMore()
{
    if ( busy_ || !more_ || !reader_ || shownBytes_ >= kMaxShownBytes ) {
        return;
    }
    startRead( std::min( kShowBytes, kMaxShownBytes - shownBytes_ ) );
}

void StreamContentView::cancel()
{
    if ( cancel_ ) {
        cancel_->store( true );
    }
}

void StreamContentView::setBusy( bool busy, const QString& status )
{
    busy_ = busy;
    progress_->setVisible( busy );
    progress_->setValue( 0 );
    cancelButton_->setVisible( busy );
    if ( busy ) {
        status_->setText( status );
        moreButton_->setEnabled( false );
        exportButton_->setEnabled( false );
    }
}

void StreamContentView::startRead( uint64_t budget )
{
    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancel_ = cancelled;
    const auto generation = generation_;
    setBusy( true, QStringLiteral( "Reading the stream of packet %1\u2026" ).arg( number_ ) );

    // The watcher lives on this thread, so its signals are delivered here.
    auto* watcher = new QFutureWatcher<std::shared_ptr<Batch>>( this );
    connect( watcher, &QFutureWatcher<std::shared_ptr<Batch>>::progressValueChanged, progress_,
             &QProgressBar::setValue );
    connect( watcher, &QFutureWatcher<std::shared_ptr<Batch>>::finished, this,
             [ this, watcher, generation ] {
                 watcher->deleteLater();
                 if ( generation != generation_ ) {
                     return; // a stream followed before this one
                 }
                 auto batch = watcher->future().resultCount() > 0 ? watcher->result() : nullptr;
                 if ( !batch ) {
                     batch = std::make_shared<Batch>();
                     batch->status = StreamContentReader::Status::Failed;
                     batch->error = QStringLiteral( "The read ended without a result." );
                 }
                 try {
                     finishRead( batch );
                 } catch ( const std::exception& e ) {
                     // An exception must not escape into Qt or the host.
                     hostLog( LOGSQUIRL_LOG_ERROR,
                              "Follow stream content failed: " + QString::fromUtf8( e.what() ) );
                 }
             } );
    const auto reader = reader_;
    watcher->setFuture( QtConcurrent::run( &pool_, [ reader, cancelled, budget ](
                                                       QPromise<std::shared_ptr<Batch>>& promise ) {
        promise.setProgressRange( 0, 1000 );
        auto batch = std::make_shared<Batch>();
        try {
            batch->status = reader->read(
                [ &batch ]( StreamChunk&& chunk ) {
                    batch->chunks.push_back( std::move( chunk ) );
                },
                budget, cancelled.get(),
                [ &promise ]( uint32_t done, uint32_t total ) {
                    promise.setProgressValue( static_cast<int>( uint64_t{ done } * 1000 / total ) );
                } );
            batch->error = reader->error();
        } catch ( const std::exception& e ) {
            batch->status = StreamContentReader::Status::Failed;
            batch->error = QString::fromUtf8( e.what() );
        }
        promise.addResult( std::move( batch ) );
    } ) );
}

void StreamContentView::finishRead( const std::shared_ptr<Batch>& batch )
{
    using Status = StreamContentReader::Status;
    setBusy( false );
    lastError_.clear();
    if ( batch->status == Status::Failed && chunks_.empty() && batch->chunks.empty() ) {
        status_->setText( batch->error );
        reader_.reset();
        more_ = false;
        note_->hide();
        return;
    }
    if ( chunks_.empty() ) {
        // The reader knows the stream's ends now.
        renderer_
            = std::make_unique<StreamRenderer>( format_, directions_, reader_->ends().transport );
    }
    const auto from = chunks_.size();
    for ( auto& chunk : batch->chunks ) {
        shownBytes_ += chunk.bytes.size();
        chunks_.push_back( std::move( chunk ) );
    }
    if ( rerenderPending_ ) {
        // The format or directions changed while it read: all of it anew.
        rerender();
    }
    else {
        appendChunks( chunks_, from );
    }
    // A cancelled read can go on where it stopped.
    more_ = batch->status == Status::More || batch->status == Status::Cancelled;
    if ( batch->status == Status::Failed ) {
        lastError_ = batch->error;
    }
    else if ( batch->status == Status::Cancelled ) {
        lastError_ = QStringLiteral( "Cancelled." );
    }
    updateLabels();
}

void StreamContentView::appendChunks( const std::vector<StreamChunk>& chunks, size_t from )
{
    QTextCursor cursor( content_->document() );
    cursor.movePosition( QTextCursor::End );
    cursor.beginEditBlock();
    // Runs of one direction go in at once.
    QString run;
    QTextCharFormat runFormat;
    const auto flush = [ & ] {
        if ( !run.isEmpty() ) {
            cursor.insertText( run, runFormat );
            run.clear();
        }
    };
    for ( size_t i = from; i < chunks.size(); ++i ) {
        const auto& chunk = chunks[ i ];
        const auto text = renderer_->render( chunk );
        if ( text.isEmpty() ) {
            continue;
        }
        const auto format = chunk.missing > 0 ? gapFormat( palette() )
                                              : directionFormat( chunk.direction, palette() );
        if ( format != runFormat ) {
            flush();
            runFormat = format;
        }
        run += text;
    }
    flush();
    cursor.endEditBlock();
}

void StreamContentView::rerender()
{
    rerenderPending_ = false;
    if ( !reader_ ) {
        return;
    }
    content_->clear();
    renderer_ = std::make_unique<StreamRenderer>( format_, directions_, reader_->ends().transport );
    appendChunks( chunks_, 0 );
    content_->moveCursor( QTextCursor::Start );
}

void StreamContentView::setFormat( StreamFormat format )
{
    if ( format == format_ ) {
        return;
    }
    format_ = format;
    formatBox_->setCurrentIndex( formatBox_->findData( static_cast<int>( format ) ) );
    content_->setLineWrapMode( format == StreamFormat::Hex ? QPlainTextEdit::NoWrap
                                                           : QPlainTextEdit::WidgetWidth );
    if ( busy_ ) {
        rerenderPending_ = true; // when the read or export ends
    }
    else {
        rerender();
    }
}

void StreamContentView::setDirections( unsigned directions )
{
    if ( directions == directions_ ) {
        return;
    }
    directions_ = directions;
    directionBox_->setCurrentIndex( directionBox_->findData( static_cast<uint>( directions ) ) );
    if ( busy_ ) {
        rerenderPending_ = true; // when the read or export ends
    }
    else {
        rerender();
    }
}

void StreamContentView::updateLabels()
{
    if ( !reader_ ) {
        return;
    }
    const auto& ends = reader_->ends();
    const auto client = ends.name( 0 ), server = ends.name( 1 );
    const auto transport = ends.transport == Transport::Tcp ? "TCP" : "UDP";
    const auto stream = streamId_ >= 0
                            ? QStringLiteral( "%1 stream %2" ).arg( transport ).arg( streamId_ )
                            : QStringLiteral( "%1 stream" ).arg( transport );
    const auto more = more_ ? QStringLiteral( "+" ) : QString();
    auto status = QStringLiteral( "%1: %2 \u2192 %3 %4%6, %3 \u2192 %2 %5%6" )
                      .arg( stream, client, server, sizeText( reader_->bytesSent( 0 ) ),
                            sizeText( reader_->bytesSent( 1 ) ), more );
    if ( !lastError_.isEmpty() ) {
        status += QStringLiteral( " (%1)" ).arg( lastError_ );
    }
    status_->setText( status );
    directionBox_->setItemText( 1, QStringLiteral( "%1 \u2192 %2" ).arg( client, server ) );
    directionBox_->setItemText( 2, QStringLiteral( "%1 \u2192 %2" ).arg( server, client ) );

    if ( more_ && shownBytes_ >= kMaxShownBytes ) {
        note_->setText( QStringLiteral( "Showing the first %1 of the stream: export it for all "
                                        "of it." )
                            .arg( sizeText( shownBytes_ ) ) );
    }
    else if ( more_ ) {
        note_->setText( QStringLiteral( "Showing the first %1 of the stream: Show more reads "
                                        "on, Export writes all of it." )
                            .arg( sizeText( shownBytes_ ) ) );
    }
    else if ( chunks_.empty() ) {
        note_->setText( QStringLiteral( "The stream carries no payload." ) );
    }
    else {
        note_->clear();
    }
    note_->setVisible( !note_->text().isEmpty() );
    moreButton_->setEnabled( more_ && shownBytes_ < kMaxShownBytes );
    exportButton_->setEnabled( true );
}

void StreamContentView::chooseExport( bool raw )
{
    if ( !reader_ || busy_ ) {
        return;
    }
    const auto path = QFileDialog::getSaveFileName(
        this, raw ? "Export the stream's raw bytes" : "Export the stream as shown", QString(),
        raw ? "All files (*)" : "Text files (*.txt);;All files (*)" );
    if ( !path.isEmpty() ) {
        exportTo( path, raw );
    }
}

void StreamContentView::exportTo( const QString& path, bool raw )
{
    if ( !reader_ || busy_ ) {
        return;
    }
    auto cancelled = std::make_shared<std::atomic_bool>( false );
    cancel_ = cancelled;
    const auto generation = generation_;
    setBusy(
        true,
        QStringLiteral( "Exporting the stream to %1\u2026" ).arg( QFileInfo( path ).fileName() ) );

    auto* watcher = new QFutureWatcher<StreamExport>( this );
    connect( watcher, &QFutureWatcher<StreamExport>::progressValueChanged, progress_,
             &QProgressBar::setValue );
    connect( watcher, &QFutureWatcher<StreamExport>::finished, this,
             [ this, watcher, generation, path ] {
                 watcher->deleteLater();
                 if ( generation != generation_ ) {
                     return;
                 }
                 setBusy( false );
                 if ( rerenderPending_ ) {
                     rerender();
                 }
                 StreamExport result;
                 if ( watcher->future().resultCount() > 0 ) {
                     result = watcher->result();
                 }
                 else {
                     result.status = StreamContentReader::Status::Failed;
                     result.error = QStringLiteral( "The export ended without a result." );
                 }
                 switch ( result.status ) {
                 case StreamContentReader::Status::Done:
                     lastError_
                         = QStringLiteral( "exported %1 to %2" )
                               .arg( sizeText( result.bytes ), QFileInfo( path ).fileName() );
                     break;
                 case StreamContentReader::Status::Cancelled:
                     lastError_ = QStringLiteral( "export cancelled" );
                     break;
                 default:
                     lastError_ = QStringLiteral( "export failed: %1" ).arg( result.error );
                     hostLog( LOGSQUIRL_LOG_WARNING, "Follow stream content: " + lastError_ );
                     break;
                 }
                 updateLabels();
             } );
    // A reader of its own, from the start of the stream: the one shown keeps its place.
    const auto index = index_;
    const auto number = number_;
    const auto streamId = streamId_;
    const auto format = format_;
    const auto directions = directions_;
    watcher->setFuture( QtConcurrent::run( &pool_, [ index, number, streamId, path, raw, format,
                                                     directions, cancelled ](
                                                       QPromise<StreamExport>& promise ) {
        promise.setProgressRange( 0, 1000 );
        StreamExport result;
        try {
            StreamContentReader reader( index, number, streamId );
            result = exportStreamContent(
                reader, path, raw, format, directions, cancelled.get(),
                [ &promise ]( uint32_t done, uint32_t total ) {
                    promise.setProgressValue( static_cast<int>( uint64_t{ done } * 1000 / total ) );
                } );
        } catch ( const std::exception& e ) {
            result.status = StreamContentReader::Status::Failed;
            result.error = QString::fromUtf8( e.what() );
        }
        promise.addResult( result );
    } ) );
}

} // namespace tcpdump
