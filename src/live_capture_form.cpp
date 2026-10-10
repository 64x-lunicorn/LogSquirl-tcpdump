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
 * @file live_capture_form.cpp
 * @brief The live capture UI's fields, and the Start live capture… dialog.
 */

#include "live_capture_form.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <chrono>
#include <exception>
#include <limits>

namespace tcpdump {

namespace {

/// What a target's item says: its id, and its description or problem.
QString targetText( const LiveTarget& target )
{
    const auto& more = target.problem.isEmpty() ? target.description : target.problem;
    return more.isEmpty() ? target.id : target.id + QString::fromUtf8( " \xe2\x80\x94 " ) + more;
}

} // namespace

LiveCaptureForm::LiveCaptureForm( QThreadPool* pool, QWidget* parent )
    : QWidget( parent )
    , pool_( pool )
{
    if ( !pool_ ) {
        ownPool_ = std::make_unique<QThreadPool>();
        // A listing that hangs until its timeout does not hold up the next.
        ownPool_->setMaxThreadCount( 4 );
        pool_ = ownPool_.get();
    }

    auto* layout = new QFormLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    layout->setFieldGrowthPolicy( QFormLayout::AllNonFixedFieldsGrow );

    source_ = new QComboBox;
    source_->setObjectName( "liveSource" );
    source_->setToolTip( "Where to capture" );
    layout->addRow( "Source:", source_ );

    status_ = new QLabel;
    status_->setObjectName( "liveSourceStatus" );
    status_->setWordWrap( true );
    status_->setTextInteractionFlags( Qt::TextSelectableByMouse );
    status_->setHidden( true );
    layout->addRow( status_ );

    deviceLabel_ = new QLabel( "Device:" );
    device_ = new QComboBox;
    device_->setObjectName( "liveDevice" );
    layout->addRow( deviceLabel_, device_ );

    interface_ = new QComboBox;
    interface_->setObjectName( "liveInterface" );
    interface_->setEditable( true );
    interface_->setInsertPolicy( QComboBox::NoInsert );
    interface_->setToolTip( "The interface to capture on; one the source does not list can be "
                            "typed" );
    refresh_ = new QPushButton( "Refresh" );
    refresh_->setObjectName( "liveRefresh" );
    refresh_->setToolTip( "List the devices and interfaces anew" );
    auto* interfaceRow = new QHBoxLayout;
    interfaceRow->setContentsMargins( 0, 0, 0, 0 );
    interfaceRow->addWidget( interface_, 1 );
    interfaceRow->addWidget( refresh_ );
    layout->addRow( "Interface:", interfaceRow );

    filter_ = new QLineEdit;
    filter_->setObjectName( "liveFilter" );
    filter_->setPlaceholderText( "BPF, e.g. host 10.0.0.1 and tcp port 443" );
    filter_->setToolTip( "Capture filter in BPF syntax, passed to the capture program; empty "
                         "captures everything" );
    filter_->setClearButtonEnabled( true );
    layout->addRow( "Capture filter:", filter_ );

    filterHint_ = new QLabel;
    filterHint_->setObjectName( "liveFilterHint" );
    filterHint_->setWordWrap( true );
    filterHint_->setHidden( true );
    layout->addRow( filterHint_ );

    snaplen_ = new QSpinBox;
    snaplen_->setObjectName( "liveSnaplen" );
    snaplen_->setRange( 1, kMaxSnaplen );
    snaplen_->setValue( kDefaultSnaplen );
    snaplen_->setSuffix( " bytes" );
    snaplen_->setToolTip( "The bytes kept of each packet; a packet cut shorter is marked "
                          "[cut to N bytes]" );
    layout->addRow( "Snaplen:", snaplen_ );

    connect( source_, &QComboBox::activated, this, [ this ] { sourceChanged(); } );
    // A device chosen, or typed (a host): its interfaces.
    connect( device_, &QComboBox::activated, this, [ this ] {
        ++generation_;
        listInterfaces();
    } );
    connect( interface_, &QComboBox::currentTextChanged, this, [ this ] {
        tellTarget();
        emit changed();
    } );
    connect( device_, &QComboBox::currentTextChanged, this, &LiveCaptureForm::tellTarget );
    connect( refresh_, &QPushButton::clicked, this, &LiveCaptureForm::refresh );
    connect( filter_, &QLineEdit::textChanged, this, [ this ] {
        checkFilter();
        emit changed();
    } );
    connect( snaplen_, &QSpinBox::valueChanged, this, &LiveCaptureForm::changed );

    addLimitFields( layout );

    sourceChanged();
}

void LiveCaptureForm::addLimitFields( QFormLayout* layout )
{
    // A spin box of 0 to @p max, 0 shown as @p none.
    auto spin = [ this ]( const char* name, int max, const QString& suffix, const QString& none,
                          const QString& tip ) {
        auto* box = new QSpinBox;
        box->setObjectName( name );
        box->setRange( 0, max );
        box->setSuffix( suffix );
        box->setSpecialValueText( none );
        box->setToolTip( tip );
        box->setAccelerated( true );
        connect( box, &QSpinBox::valueChanged, this, &LiveCaptureForm::changed );
        return box;
    };
    const auto noLimit = QStringLiteral( "no limit" );
    stopSeconds_ = spin( "liveStopSeconds", kMaxLimitSeconds, " s", noLimit,
                         "Stop the capture after this many seconds" );
    layout->addRow( "Stop after time:", stopSeconds_ );
    stopPackets_ = spin( "liveStopPackets", std::numeric_limits<int>::max(), " packets", noLimit,
                         "Stop the capture after this many packets" );
    layout->addRow( "Stop after packets:", stopPackets_ );
    stopMegabytes_ = spin( "liveStopMegabytes", kMaxLimitMegabytes, " MB", noLimit,
                           "Stop the capture once this much was captured (the raw capture's "
                           "size, 1 MB = 1024 \xc3\x97 1024 bytes)" );
    layout->addRow( "Stop after size:", stopMegabytes_ );

    ringFiles_ = spin( "liveRingFiles", kMaxRingFiles, " files", "off",
                       "Keep the raw capture in this many files, starting a new one at the size "
                       "or duration below and deleting the oldest; the tab keeps the packets of "
                       "the files kept" );
    layout->addRow( "Ring buffer:", ringFiles_ );
    ringMegabytes_ = spin( "liveRingMegabytes", kMaxLimitMegabytes, " MB", "any size",
                           "Start a new file once one is this big" );
    ringSeconds_ = spin( "liveRingSeconds", kMaxLimitSeconds, " s", "any time",
                         "Start a new file once one is this old" );
    auto* fileRow = new QHBoxLayout;
    fileRow->setContentsMargins( 0, 0, 0, 0 );
    fileRow->addWidget( ringMegabytes_, 1 );
    fileRow->addWidget( ringSeconds_, 1 );
    layout->addRow( "New file after:", fileRow );
    connect( ringFiles_, &QSpinBox::valueChanged, this, &LiveCaptureForm::enableRingFields );
    enableRingFields();
}

void LiveCaptureForm::enableRingFields()
{
    const bool ring = ringFiles_->value() > 0;
    ringMegabytes_->setEnabled( ring );
    ringSeconds_->setEnabled( ring );
}

LiveCaptureForm::~LiveCaptureForm()
{
    // Its listings' programs are killed, rather than waited for.
    cancel_->store( true );
    if ( ownPool_ ) {
        ownPool_->waitForDone();
    }
}

void LiveCaptureForm::setSources( std::shared_ptr<const LiveSourceRegistry> sources )
{
    const auto current = choice();
    sources_ = std::move( sources );
    source_->clear();
    if ( sources_ ) {
        for ( const auto& kind : sources_->kinds() ) {
            source_->addItem( kind->displayName(), kind->id() );
        }
    }
    setChoice( current );
}

void LiveCaptureForm::setSourceOptions( const QString& source, const LiveOptions& options )
{
    if ( options_ && optionsSource_ == source ) {
        options_->setOptions( options );
    }
    optionsBySource_[ source ] = options;
}

void LiveCaptureForm::setChoice( const LiveChoice& choice )
{
    dropOptionsWidget();
    optionsBySource_[ choice.source ] = choice.options;
    wanted_ = choice;
    const auto index = source_->findData( choice.source );
    source_->setCurrentIndex( index >= 0 ? index : ( source_->count() > 0 ? 0 : -1 ) );
    filter_->setText( choice.filter );
    snaplen_->setValue( choice.snaplen );
    // Clamped, as settings.ini may hold more than a field shows.
    auto clamped = []( uint64_t value, int max ) {
        return static_cast<int>( std::min<uint64_t>( value, static_cast<uint64_t>( max ) ) );
    };
    const auto& limits = choice.limits;
    stopSeconds_->setValue(
        clamped( static_cast<uint64_t>( limits.duration.count() ), stopSeconds_->maximum() ) );
    stopPackets_->setValue( clamped( limits.packets, stopPackets_->maximum() ) );
    stopMegabytes_->setValue(
        clamped( ( limits.bytes + kMegabyte - 1 ) / kMegabyte, stopMegabytes_->maximum() ) );
    ringFiles_->setValue( clamped( limits.ringFiles, ringFiles_->maximum() ) );
    ringMegabytes_->setValue(
        clamped( ( limits.fileBytes + kMegabyte - 1 ) / kMegabyte, ringMegabytes_->maximum() ) );
    ringSeconds_->setValue(
        clamped( static_cast<uint64_t>( limits.fileDuration.count() ), ringSeconds_->maximum() ) );
    checkFilter();
    sourceChanged();
}

LiveChoice LiveCaptureForm::choice() const
{
    LiveChoice choice;
    choice.source = source_->currentData().toString();
    if ( const auto kind = currentKind();
         kind && kind->devices() != LiveSourceKind::Devices::None ) {
        choice.device = currentId( device_ );
    }
    choice.networkInterface = currentId( interface_ );
    choice.filter = filter_->text().trimmed();
    choice.snaplen = snaplen_->value();
    auto& limits = choice.limits;
    limits.duration = std::chrono::seconds( stopSeconds_->value() );
    limits.packets = static_cast<uint64_t>( stopPackets_->value() );
    limits.bytes = static_cast<uint64_t>( stopMegabytes_->value() ) * kMegabyte;
    limits.ringFiles = static_cast<uint32_t>( ringFiles_->value() );
    limits.fileBytes = static_cast<uint64_t>( ringMegabytes_->value() ) * kMegabyte;
    limits.fileDuration = std::chrono::seconds( ringSeconds_->value() );
    if ( options_ ) {
        choice.options = options_->options();
    }
    else if ( const auto kept = optionsBySource_.find( choice.source );
              kept != optionsBySource_.end() ) {
        choice.options = kept->second;
    }
    return choice;
}

std::shared_ptr<const LiveSourceKind> LiveCaptureForm::currentKind() const
{
    return sources_ ? sources_->find( source_->currentData().toString() ) : nullptr;
}

QString LiveCaptureForm::problem() const
{
    if ( auto invalid = liveChoiceProblem( sources_.get(), choice() ); !invalid.isEmpty() ) {
        return invalid;
    }
    // The form's own state: an options widget still asking (an extcap for
    // its arguments) cannot tell yet.
    return options_ ? options_->problem() : QString();
}

void LiveCaptureForm::refresh()
{
    const auto kind = currentKind();
    if ( !kind || !kind->availability().available ) {
        sourceChanged(); // it may have become available
        return;
    }
    // What is chosen now stays chosen, if it is still listed.
    wanted_ = choice();
    ++generation_;
    if ( kind->devices() == LiveSourceKind::Devices::None ) {
        listInterfaces();
    }
    else {
        listDevices();
    }
}

void LiveCaptureForm::sourceChanged()
{
    ++generation_;
    dropOptionsWidget();
    showOptionsWidget();
    device_->clear();
    interface_->clear();
    const auto kind = currentKind();
    const auto devices = kind ? kind->devices() : LiveSourceKind::Devices::None;
    deviceLabel_->setHidden( devices == LiveSourceKind::Devices::None );
    device_->setHidden( devices == LiveSourceKind::Devices::None );
    device_->setEditable( devices == LiveSourceKind::Devices::Typed );
    if ( kind ) {
        deviceLabel_->setText( kind->deviceLabel() + QLatin1Char( ':' ) );
    }
    if ( kind && wanted_.source == kind->id() && devices == LiveSourceKind::Devices::Typed ) {
        device_->setEditText( wanted_.device );
    }
    if ( kind && wanted_.source == kind->id() ) {
        interface_->setEditText( wanted_.networkInterface );
    }

    const auto availability = kind ? kind->availability() : LiveAvailability{};
    const bool usable = kind && availability.available;
    device_->setEnabled( usable );
    interface_->setEnabled( usable );
    refresh_->setEnabled( usable );
    if ( !kind ) {
        showStatus( QStringLiteral( "No live capture source is available." ) );
    }
    else if ( !usable ) {
        showStatus( availability.reason );
    }
    else {
        showStatus( {} );
        if ( devices == LiveSourceKind::Devices::None ) {
            listInterfaces();
        }
        else {
            listDevices();
        }
    }
    emit changed();
}

void LiveCaptureForm::listDevices()
{
    const auto kind = currentKind();
    if ( !kind ) {
        return;
    }
    showStatus( QStringLiteral( "Listing %1s\xe2\x80\xa6" ).arg( kind->deviceLabel().toLower() ) );
    runListing( [ kind ] { return kind->listDevices( LiveSourceKind::kListTimeout ); },
                [ this, kind ]( const LiveListing& listing ) {
                    const auto wanted = wanted_.source == kind->id() ? wanted_.device : QString();
                    if ( kind->devices() == LiveSourceKind::Devices::Typed ) {
                        // Suggestions: what is typed stays.
                        const auto typed = device_->currentText();
                        fill( device_, listing, {} );
                        device_->setEditText( typed.isEmpty() ? wanted : typed );
                    }
                    else {
                        fill( device_, listing, wanted );
                    }
                    if ( !listing.error.isEmpty() ) {
                        showStatus( listing.error );
                        return;
                    }
                    if ( currentId( device_ ).isEmpty() ) {
                        showStatus(
                            QStringLiteral( "No %1 found." ).arg( kind->deviceLabel().toLower() ) );
                        return;
                    }
                    listInterfaces();
                } );
}

void LiveCaptureForm::listInterfaces()
{
    const auto kind = currentKind();
    if ( !kind ) {
        return;
    }
    const auto device
        = kind->devices() == LiveSourceKind::Devices::None ? QString() : currentId( device_ );
    const auto options = choice().options;
    showStatus( QStringLiteral( "Listing interfaces\xe2\x80\xa6" ) );
    runListing(
        [ kind, device, options ] {
            return kind->listInterfacesWith( device, options, LiveSourceKind::kListTimeout );
        },
        [ this, kind ]( const LiveListing& listing ) {
            const auto typed = interface_->currentText();
            const auto wanted = wanted_.source == kind->id() ? wanted_.networkInterface : QString();
            fill( interface_, listing, wanted );
            // An interface typed, or remembered, that is not listed stays.
            if ( interface_->findData( wanted ) < 0 && !wanted.isEmpty() ) {
                interface_->setEditText( wanted );
            }
            else if ( listing.targets.empty() && !typed.isEmpty() ) {
                interface_->setEditText( typed );
            }
            if ( !listing.error.isEmpty() ) {
                showStatus( listing.error );
            }
            else if ( listing.targets.empty() ) {
                showStatus( QStringLiteral( "No interfaces found." ) );
            }
            else {
                showStatus( {} );
            }
            emit changed();
        } );
}

void LiveCaptureForm::runListing( std::function<LiveListing()> listing,
                                  std::function<void( const LiveListing& )> done )
{
    const auto generation = generation_;
    ++listing_;
    auto* watcher = new QFutureWatcher<LiveListing>( this );
    connect( watcher, &QFutureWatcher<LiveListing>::finished, this,
             [ this, watcher, generation, done ] {
                 --listing_;
                 watcher->deleteLater();
                 if ( generation != generation_ ) {
                     return; // for a source or device no longer chosen
                 }
                 LiveListing result;
                 if ( watcher->future().resultCount() > 0 ) {
                     result = watcher->result();
                 }
                 else {
                     result.error = QStringLiteral( "The listing ended without a result" );
                 }
                 done( result );
             } );
    // The listing holds its kind, never the form: it may outlive it.
    watcher->setFuture( QtConcurrent::run( pool_, [ listing, cancel = cancel_ ] {
        const ListingCancelScope scope( cancel );
        try {
            return listing();
        } catch ( const std::exception& e ) {
            // An exception must not escape into Qt.
            LiveListing failed;
            failed.error
                = QStringLiteral( "Listing failed: %1" ).arg( QString::fromUtf8( e.what() ) );
            return failed;
        }
    } ) );
}

void LiveCaptureForm::fill( QComboBox* box, const LiveListing& listing, const QString& wanted )
{
    const auto before = currentId( box );
    box->clear();
    auto* model = qobject_cast<QStandardItemModel*>( box->model() );
    int firstUsable = -1;
    for ( const auto& target : listing.targets ) {
        box->addItem( targetText( target ), target.id );
        const int row = box->count() - 1;
        box->setItemData( row, target.description.isEmpty() ? target.problem : target.description,
                          Qt::ToolTipRole );
        if ( !target.problem.isEmpty() ) {
            if ( model ) {
                model->item( row )->setEnabled( false );
            }
        }
        else if ( firstUsable < 0 ) {
            firstUsable = row;
        }
    }
    auto index = box->findData( wanted );
    if ( index < 0 ) {
        index = box->findData( before );
    }
    if ( index < 0 ) {
        index = firstUsable;
    }
    box->setCurrentIndex( index );
    if ( index < 0 && box->isEditable() ) {
        box->setEditText( QString() );
    }
}

QString LiveCaptureForm::currentId( const QComboBox* box )
{
    const auto index = box->currentIndex();
    if ( index >= 0 && box->itemText( index ) == box->currentText() ) {
        return box->itemData( index ).toString();
    }
    return box->isEditable() ? box->currentText().trimmed() : QString();
}

void LiveCaptureForm::showStatus( const QString& text )
{
    status_->setText( text );
    status_->setHidden( text.isEmpty() );
}

void LiveCaptureForm::dropOptionsWidget()
{
    if ( !options_ ) {
        return;
    }
    optionsBySource_[ optionsSource_ ] = options_->options();
    // Deleted now, not later: its object name must not be found any more.
    delete options_;
    options_ = nullptr;
    optionsSource_.clear();
}

void LiveCaptureForm::showOptionsWidget()
{
    const auto kind = currentKind();
    options_ = kind ? kind->makeOptionsWidget() : nullptr;
    if ( !options_ ) {
        return;
    }
    optionsSource_ = kind->id();
    if ( const auto kept = optionsBySource_.find( optionsSource_ );
         kept != optionsBySource_.end() ) {
        options_->setOptions( kept->second );
    }
    auto* layout = static_cast<QFormLayout*>( this->layout() );
    layout->addRow( options_ );
    options_->setEnabled( kind->availability().available );
    connect( options_, &LiveOptionsWidget::changed, this, &LiveCaptureForm::changed );
    connect( options_, &LiveOptionsWidget::listingChanged, this, [ this ] {
        const auto kind = currentKind();
        if ( kind
             && ( kind->devices() == LiveSourceKind::Devices::None
                  || !currentId( device_ ).isEmpty() ) ) {
            listInterfaces();
        }
    } );
    tellTarget();
}

void LiveCaptureForm::tellTarget()
{
    if ( !options_ ) {
        return;
    }
    const auto kind = currentKind();
    const auto device = kind && kind->devices() != LiveSourceKind::Devices::None
                            ? currentId( device_ )
                            : QString();
    options_->setTarget( device, currentId( interface_ ) );
}

void LiveCaptureForm::checkFilter()
{
    const auto problem = captureFilterProblem( filter_->text() );
    filterHint_->setText( problem );
    filterHint_->setHidden( problem.isEmpty() );
}

// ── LiveCaptureDialog ────────────────────────────────────────────────────

LiveCaptureDialog::LiveCaptureDialog( std::shared_ptr<const LiveSourceRegistry> sources,
                                      const LiveChoice& choice, QWidget* parent, QThreadPool* pool )
    : QDialog( parent )
{
    setWindowTitle( "Start Live Capture" );
    setObjectName( "liveCaptureDialog" );
    auto* layout = new QVBoxLayout( this );

    form_ = new LiveCaptureForm( pool );
    form_->setSources( std::move( sources ) );
    form_->setChoice( choice );
    layout->addWidget( form_ );

    auto* buttons = new QDialogButtonBox( QDialogButtonBox::Cancel );
    auto* start = buttons->addButton( "Start", QDialogButtonBox::AcceptRole );
    start->setObjectName( "liveStartButton" );
    start->setDefault( true );
    layout->addWidget( buttons );
    connect( buttons, &QDialogButtonBox::accepted, this, &QDialog::accept );
    connect( buttons, &QDialogButtonBox::rejected, this, &QDialog::reject );

    // The form shows why a source is unavailable or a filter is wrong; the
    // button tells the rest.
    const auto check = [ this, start ] {
        const auto why = form_->problem();
        start->setEnabled( why.isEmpty() );
        start->setToolTip( why.isEmpty() ? QStringLiteral( "Start capturing" ) : why );
    };
    connect( form_, &LiveCaptureForm::changed, this, check );
    check();
}

LiveChoice LiveCaptureDialog::choice() const
{
    return form_->choice();
}

} // namespace tcpdump
