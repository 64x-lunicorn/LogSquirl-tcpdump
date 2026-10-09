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
 * @file display_filter_dialog.cpp
 * @brief The display filter dialog, and the Regex Lab it opens.
 */

#include "display_filter_dialog.h"

#include "plugin.h"
#include "regex_lab.h"

#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

#include <exception>

namespace tcpdump {

namespace {

/// What is wrong with @p text, translated to @p translated, for the user:
/// "Column 19: …"; nothing for a filter of the subset, or an empty one,
/// which is no mistake yet, only cannot be opened.
QString errorText( const QString& text, const DisplayFilterPattern& translated )
{
    return translated.error.isEmpty() || text.trimmed().isEmpty()
               ? QString()
               : QStringLiteral( "Column %1: %2" )
                     .arg( translated.errorPosition + 1 )
                     .arg( translated.error );
}

/// The filter opened last, from the dialog or the sidebar.
QString& lastFilter()
{
    static QString filter;
    return filter;
}

/// Open the Regex Lab with @p pattern, @p filter's, logging the filter and
/// keeping it to offer again.
void openFilter( const QString& filter, const QString& pattern )
{
    lastFilter() = filter;
    hostLog( LOGSQUIRL_LOG_INFO, "Display filter: " + filter );
    openRegexLab( "Display filter", pattern );
}

} // namespace

DisplayFilterDialog::DisplayFilterDialog( const QString& filter, QWidget* parent )
    : QDialog( parent )
{
    setWindowTitle( QStringLiteral( "Display Filter" ) );
    auto* layout = new QVBoxLayout( this );

    auto* intro = new QLabel( QStringLiteral(
        "A display filter as in Wireshark: the Regex Lab opens with the pattern of the packet "
        "lines it selects. Fields: ip.addr, ip.src, ip.dst, ipv6.addr, ipv6.src, ipv6.dst, "
        "tcp.port, tcp.srcport, tcp.dstport, tcp.stream, the same of udp, and frame.len, "
        "compared with ==, !=, <, >, <= or >=; protocol names as in the Protocol column; "
        "!, &&, || and parentheses." ) );
    intro->setTextFormat( Qt::PlainText );
    intro->setWordWrap( true );
    layout->addWidget( intro );

    edit_ = new QLineEdit( filter );
    edit_->setObjectName( "filter" );
    edit_->setPlaceholderText( QStringLiteral( "ip.addr == 10.0.0.1 && tcp.port == 443" ) );
    edit_->setClearButtonEnabled( true );
    layout->addWidget( edit_ );

    error_ = new QLabel;
    error_->setObjectName( "filterError" );
    error_->setTextFormat( Qt::PlainText );
    error_->setWordWrap( true );
    layout->addWidget( error_ );

    auto* buttons = new QDialogButtonBox( QDialogButtonBox::Cancel );
    openButton_
        = buttons->addButton( QStringLiteral( "Open in Regex Lab" ), QDialogButtonBox::AcceptRole );
    openButton_->setObjectName( "openButton" );
    openButton_->setDefault( true );
    layout->addWidget( buttons );
    connect( buttons, &QDialogButtonBox::accepted, this, &QDialog::accept );
    connect( buttons, &QDialogButtonBox::rejected, this, &QDialog::reject );
    connect( edit_, &QLineEdit::textChanged, this, &DisplayFilterDialog::update );

    resize( 560, sizeHint().height() );
    update();
}

QString DisplayFilterDialog::filter() const
{
    return edit_->text();
}

QString DisplayFilterDialog::pattern() const
{
    return translated_.pattern;
}

void DisplayFilterDialog::update()
{
    const auto text = edit_->text();
    translated_ = displayFilterPattern( text );
    error_->setText( errorText( text, translated_ ) );
    openButton_->setEnabled( !translated_.pattern.isEmpty() );
}

void openDisplayFilter( QWidget* parent )
{
    if ( !g_state.hostCapabilities.regexLab ) {
        return;
    }
    // The filter accepted last, offered again to refine it.
    DisplayFilterDialog dialog( lastFilter(), parent );
    if ( dialog.exec() != QDialog::Accepted || dialog.pattern().isEmpty() ) {
        return;
    }
    openFilter( dialog.filter(), dialog.pattern() );
}

// ── DisplayFilterField ───────────────────────────────────────────────────

DisplayFilterField::DisplayFilterField( QWidget* parent )
    : QWidget( parent )
{
    auto* layout = new QVBoxLayout( this );
    layout->setContentsMargins( 0, 0, 0, 0 );
    auto* row = new QHBoxLayout;
    edit_ = new QLineEdit;
    edit_->setObjectName( "displayFilter" );
    edit_->setPlaceholderText( QStringLiteral( "Display filter: ip.addr == 10.0.0.1 && tcp" ) );
    edit_->setToolTip( QStringLiteral(
        "A display filter as in Wireshark (see Plugins > tcpdump > Display filter\u2026): the "
        "Regex Lab opens with the pattern of the packet lines it selects" ) );
    edit_->setClearButtonEnabled( true );
    row->addWidget( edit_, 1 );
    openButton_ = new QPushButton( QStringLiteral( "Open in Regex Lab" ) );
    openButton_->setObjectName( "openDisplayFilter" );
    row->addWidget( openButton_ );
    layout->addLayout( row );

    error_ = new QLabel;
    error_->setObjectName( "displayFilterError" );
    error_->setTextFormat( Qt::PlainText );
    error_->setWordWrap( true );
    error_->setHidden( true );
    layout->addWidget( error_ );

    connect( edit_, &QLineEdit::textChanged, this, &DisplayFilterField::update );
    connect( edit_, &QLineEdit::returnPressed, this, &DisplayFilterField::open );
    connect( openButton_, &QPushButton::clicked, this, &DisplayFilterField::open );
    update();
}

void DisplayFilterField::update()
{
    const auto text = edit_->text();
    translated_ = displayFilterPattern( text );
    error_->setText( errorText( text, translated_ ) );
    error_->setHidden( error_->text().isEmpty() );
    openButton_->setEnabled( !translated_.pattern.isEmpty() );
}

void DisplayFilterField::open()
{
    if ( translated_.pattern.isEmpty() || !g_state.hostCapabilities.regexLab ) {
        return;
    }
    try {
        openFilter( edit_->text(), translated_.pattern );
    } catch ( const std::exception& e ) {
        // An exception must not escape into Qt or the host.
        hostLog( LOGSQUIRL_LOG_ERROR, "Display filter failed: " + QString::fromUtf8( e.what() ) );
    }
}

} // namespace tcpdump
