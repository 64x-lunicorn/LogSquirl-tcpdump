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
 * @file extcap_options.cpp
 * @brief An extcap interface's arguments as a form.
 */

#include "extcap_options.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QPushButton>
#include <QRadioButton>
#include <QSet>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include <exception>

namespace tcpdump {

namespace {

/// The object name of @p arg's field, for tests: extcapArg--remote-host.
QString fieldName( const ExtcapArg& arg )
{
    return QStringLiteral( "extcapArg" ) + arg.call;
}

bool isNumber( ExtcapArgType type )
{
    return type == ExtcapArgType::Integer || type == ExtcapArgType::Unsigned
           || type == ExtcapArgType::Long || type == ExtcapArgType::Double;
}

/// The values of a multicheck, a child after its parent, indented.
QString indented( const ExtcapArg& arg, const ExtcapValue& value )
{
    int depth = 0;
    auto parent = value.parent;
    // Bounded: a parent chain may loop.
    while ( !parent.isEmpty() && depth < 8 ) {
        ++depth;
        QString next;
        for ( const auto& other : arg.values ) {
            if ( other.value == parent ) {
                next = other.parent;
                break;
            }
        }
        parent = next;
    }
    return QString( depth * 2, QLatin1Char( ' ' ) ) + value.display;
}

} // namespace

ExtcapOptionsWidget::ExtcapOptionsWidget( std::shared_ptr<const ExtcapSourceKind> kind,
                                          QWidget* parent )
    : LiveOptionsWidget( parent )
    , kind_( std::move( kind ) )
{
    setObjectName( QStringLiteral( "extcapOptions" ) );
    pool_.setMaxThreadCount( 2 );
    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    status_ = new QLabel;
    status_->setObjectName( QStringLiteral( "extcapStatus" ) );
    status_->setWordWrap( true );
    status_->setTextInteractionFlags( Qt::TextSelectableByMouse );
    status_->setHidden( true );
    layout->addWidget( status_ );

    settle_ = new QTimer( this );
    settle_->setSingleShot( true );
    settle_->setInterval( kSettleMs );
    connect( settle_, &QTimer::timeout, this, [ this ] {
        settling_ = false;
        list();
    } );
}

ExtcapOptionsWidget::~ExtcapOptionsWidget()
{
    if ( cancel_ ) {
        cancel_->store( true );
    }
    pool_.waitForDone();
}

void ExtcapOptionsWidget::setOptions( const LiveOptions& options )
{
    options_ = options;
    if ( !shownInterface_.isEmpty() ) {
        const QSignalBlocker quiet( this );
        show( config_ );
    }
}

LiveOptions ExtcapOptionsWidget::options() const
{
    return options_;
}

void ExtcapOptionsWidget::setTarget( const QString& device, const QString& networkInterface )
{
    if ( device == device_ && networkInterface == interface_ ) {
        return;
    }
    device_ = device;
    interface_ = networkInterface;
    ++generation_;
    if ( cancel_ ) {
        cancel_->store( true ); // for an interface no longer chosen
        cancel_.reset();
    }
    listing_ = false;
    settling_ = true;
    settle_->start();
    emit changed();
}

void ExtcapOptionsWidget::list()
{
    if ( device_.isEmpty() || interface_.isEmpty() ) {
        config_ = {};
        shownDevice_ = device_;
        shownInterface_.clear();
        delete fields_;
        fields_ = nullptr;
        showStatus( {} );
        emit changed();
        return;
    }
    const auto generation = generation_;
    cancel_ = std::make_shared<std::atomic_bool>( false );
    listing_ = true;
    showStatus( QStringLiteral( "Asking %1 for the arguments of %2\xe2\x80\xa6" )
                    .arg( device_, interface_ ) );
    auto* watcher = new QFutureWatcher<ExtcapConfig>( this );
    connect( watcher, &QFutureWatcher<ExtcapConfig>::finished, this,
             [ this, watcher, generation, device = device_, networkInterface = interface_ ] {
                 watcher->deleteLater();
                 if ( generation != generation_ ) {
                     return; // for an interface no longer chosen
                 }
                 listing_ = false;
                 ExtcapConfig config;
                 if ( watcher->future().resultCount() > 0 ) {
                     config = watcher->result();
                 }
                 else {
                     config.error = QStringLiteral( "The listing ended without a result" );
                 }
                 shownDevice_ = device;
                 shownInterface_ = networkInterface;
                 show( config );
             } );
    // The listing holds the kind and its flag, never the widget.
    watcher->setFuture(
        QtConcurrent::run( &pool_, [ kind = kind_, cancel = cancel_, device = device_,
                                     networkInterface = interface_ ] {
            const ListingCancelScope scope( cancel );
            try {
                return kind->config( device, networkInterface, LiveSourceKind::kListTimeout );
            } catch ( const std::exception& e ) {
                ExtcapConfig failed;
                failed.error = QString::fromUtf8( e.what() );
                return failed;
            }
        } ) );
    emit changed();
}

void ExtcapOptionsWidget::show( const ExtcapConfig& config )
{
    config_ = config;
    // Deleted now: the old fields' names must not be found any more.
    delete fields_;
    fields_ = new QWidget;
    auto* form = new QFormLayout( fields_ );
    form->setContentsMargins( 0, 0, 0, 0 );
    form->setFieldGrowthPolicy( QFormLayout::AllNonFixedFieldsGrow );
    layout()->addWidget( fields_ );

    if ( !config.error.isEmpty() ) {
        showStatus( QStringLiteral( "Cannot ask %1 for its arguments: %2" )
                        .arg( shownDevice_, config.error ) );
    }
    else {
        QStringList dlts;
        for ( const auto& dlt : config.dlts ) {
            dlts << ( dlt.display.isEmpty()
                          ? dlt.name
                          : QStringLiteral( "%1 (%2)" ).arg( dlt.name, dlt.display ) );
        }
        showStatus( dlts.isEmpty() ? QString()
                                   : QStringLiteral( "Link type: " ) + dlts.join( ", " ) );
    }

    // This interface's options are what the fields hold now.
    const auto prefix = QString::fromLatin1( QUrl::toPercentEncoding( shownInterface_ ) );
    QSet<QString> current;
    for ( const auto& arg : config.args ) {
        current.insert( extcapOptionName( shownInterface_, arg ) );
    }
    if ( config.error.isEmpty() ) {
        for ( auto option = options_.begin(); option != options_.end(); ) {
            auto name = option.key();
            if ( isSecretLiveOption( name ) ) {
                name.remove( 0, 1 );
            }
            const bool ours = name.size() > prefix.size() && name.startsWith( prefix )
                              && ( name[ prefix.size() ] == QLatin1Char( ':' )
                                   || name[ prefix.size() ] == QLatin1Char( '?' ) );
            option = ours && !current.contains( option.key() ) ? options_.erase( option )
                                                               : std::next( option );
        }
    }
    for ( const auto& arg : config.args ) {
        const auto value = initialValue( arg );
        options_.insert( extcapOptionName( shownInterface_, arg ), value );
        auto* field = makeField( arg, value );
        auto* label = new QLabel(
            arg.display + ( arg.required ? QStringLiteral( " *:" ) : QStringLiteral( ":" ) ) );
        label->setToolTip( arg.tooltip );
        field->setToolTip( arg.tooltip );
        form->addRow( label, field );
    }
    emit changed();
}

QString ExtcapOptionsWidget::initialValue( const ExtcapArg& arg ) const
{
    const auto kept = options_.constFind( extcapOptionName( shownInterface_, arg ) );
    if ( kept != options_.constEnd() ) {
        return kept.value();
    }
    switch ( arg.type ) {
    case ExtcapArgType::Boolean:
    case ExtcapArgType::BoolFlag:
        return liveOptionValue(
            arg.defaultValue.compare( QLatin1String( "true" ), Qt::CaseInsensitive ) == 0 );
    case ExtcapArgType::Selector:
    case ExtcapArgType::Radio:
    case ExtcapArgType::EditSelector: {
        for ( const auto& value : arg.values ) {
            if ( value.isDefault ) {
                return value.value;
            }
        }
        if ( !arg.defaultValue.isEmpty() || arg.type == ExtcapArgType::EditSelector ) {
            return arg.defaultValue;
        }
        for ( const auto& value : arg.values ) {
            if ( value.enabled ) {
                return value.value;
            }
        }
        return {};
    }
    case ExtcapArgType::Multicheck: {
        QStringList checked;
        for ( const auto& value : arg.values ) {
            if ( value.isDefault ) {
                checked << value.value;
            }
        }
        return checked.isEmpty() ? arg.defaultValue : checked.join( QLatin1Char( ',' ) );
    }
    default:
        return arg.defaultValue;
    }
}

QWidget* ExtcapOptionsWidget::makeField( const ExtcapArg& arg, const QString& value )
{
    QWidget* field = nullptr;
    switch ( arg.type ) {
    case ExtcapArgType::Boolean:
    case ExtcapArgType::BoolFlag: {
        auto* box = new QCheckBox;
        box->setChecked( value == QLatin1String( "true" ) );
        connect( box, &QCheckBox::toggled, this,
                 [ this, arg ]( bool on ) { store( arg, liveOptionValue( on ) ); } );
        field = box;
        break;
    }
    case ExtcapArgType::Selector:
    case ExtcapArgType::EditSelector: {
        auto* box = new QComboBox;
        box->setEditable( arg.type == ExtcapArgType::EditSelector );
        for ( const auto& choice : arg.values ) {
            box->addItem( choice.display, choice.value );
        }
        const auto index = box->findData( value );
        if ( index >= 0 ) {
            box->setCurrentIndex( index );
        }
        else if ( box->isEditable() ) {
            box->setEditText( value );
        }
        if ( box->isEditable() ) {
            connect( box, &QComboBox::currentTextChanged, this, [ this, arg, box ] {
                const auto at = box->currentIndex();
                store( arg, at >= 0 && box->itemText( at ) == box->currentText()
                                ? box->itemData( at ).toString()
                                : box->currentText() );
            } );
        }
        else {
            connect( box, &QComboBox::currentIndexChanged, this,
                     [ this, arg, box ] { store( arg, box->currentData().toString() ); } );
        }
        field = box;
        break;
    }
    case ExtcapArgType::Radio: {
        auto* group = new QWidget;
        auto* column = new QVBoxLayout( group );
        column->setContentsMargins( 0, 0, 0, 0 );
        auto* buttons = new QButtonGroup( group );
        for ( const auto& choice : arg.values ) {
            auto* button = new QRadioButton( choice.display );
            button->setObjectName( fieldName( arg ) + QLatin1Char( '=' ) + choice.value );
            button->setEnabled( choice.enabled );
            button->setChecked( choice.value == value );
            buttons->addButton( button );
            column->addWidget( button );
            connect( button, &QRadioButton::toggled, this,
                     [ this, arg, choice = choice.value ]( bool on ) {
                         if ( on ) {
                             store( arg, choice );
                         }
                     } );
        }
        field = group;
        break;
    }
    case ExtcapArgType::Multicheck: {
        auto* list = new QListWidget;
        const auto checked = value.split( QLatin1Char( ',' ), Qt::SkipEmptyParts );
        for ( const auto& choice : arg.values ) {
            auto* item = new QListWidgetItem( indented( arg, choice ), list );
            item->setData( Qt::UserRole, choice.value );
            item->setFlags( choice.enabled ? Qt::ItemIsEnabled | Qt::ItemIsUserCheckable
                                           : Qt::ItemIsUserCheckable );
            item->setCheckState( checked.contains( choice.value ) ? Qt::Checked : Qt::Unchecked );
        }
        list->setMaximumHeight( 120 );
        connect( list, &QListWidget::itemChanged, this, [ this, arg, list ] {
            QStringList on;
            for ( int row = 0; row < list->count(); ++row ) {
                if ( list->item( row )->checkState() == Qt::Checked ) {
                    on << list->item( row )->data( Qt::UserRole ).toString();
                }
            }
            store( arg, on.join( QLatin1Char( ',' ) ) );
        } );
        field = list;
        break;
    }
    case ExtcapArgType::FileSelect: {
        auto* row = new QWidget;
        auto* line = new QHBoxLayout( row );
        line->setContentsMargins( 0, 0, 0, 0 );
        auto* path = new QLineEdit( value );
        path->setObjectName( fieldName( arg ) + QStringLiteral( "Path" ) );
        path->setPlaceholderText( arg.placeholder );
        auto* browse = new QPushButton( QStringLiteral( "Browse\xe2\x80\xa6" ) );
        line->addWidget( path, 1 );
        line->addWidget( browse );
        connect( path, &QLineEdit::textChanged, this,
                 [ this, arg ]( const QString& text ) { store( arg, text ); } );
        connect( browse, &QPushButton::clicked, this, [ this, arg, path ] {
            const auto chosen = arg.mustExist
                                    ? QFileDialog::getOpenFileName( this, arg.display, path->text(),
                                                                    arg.fileExtension )
                                    : QFileDialog::getSaveFileName( this, arg.display, path->text(),
                                                                    arg.fileExtension );
            if ( !chosen.isEmpty() ) {
                path->setText( chosen );
            }
        } );
        field = row;
        break;
    }
    default: {
        auto* edit = new QLineEdit( value );
        if ( arg.type == ExtcapArgType::Password ) {
            edit->setEchoMode( QLineEdit::Password );
        }
        auto placeholder = arg.placeholder;
        if ( placeholder.isEmpty() && isNumber( arg.type ) && !arg.rangeMin.isEmpty() ) {
            placeholder = QStringLiteral( "%1 to %2" ).arg( arg.rangeMin, arg.rangeMax );
        }
        edit->setPlaceholderText( placeholder );
        connect( edit, &QLineEdit::textChanged, this,
                 [ this, arg ]( const QString& text ) { store( arg, text ); } );
        field = edit;
        break;
    }
    }
    if ( field->objectName().isEmpty() ) {
        field->setObjectName( fieldName( arg ) );
    }
    return field;
}

void ExtcapOptionsWidget::store( const ExtcapArg& arg, const QString& value )
{
    options_.insert( extcapOptionName( shownInterface_, arg ), value );
    emit changed();
}

QString ExtcapOptionsWidget::problem() const
{
    // The arguments' rules are the kind's validate(): what is left is
    // whether this widget knows them yet.
    if ( isListing() && !device_.isEmpty() && !interface_.isEmpty() ) {
        return QStringLiteral( "Asking %1 for the arguments of %2\xe2\x80\xa6" )
            .arg( device_, interface_ );
    }
    return {};
}

void ExtcapOptionsWidget::showStatus( const QString& text )
{
    status_->setText( text );
    status_->setHidden( text.isEmpty() );
}

} // namespace tcpdump
