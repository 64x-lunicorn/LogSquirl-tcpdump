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
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>

namespace tcpdump {

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
    // An empty field is no mistake yet: it only cannot be opened.
    error_->setText( translated_.error.isEmpty() || text.trimmed().isEmpty()
                         ? QString()
                         : QStringLiteral( "Column %1: %2" )
                               .arg( translated_.errorPosition + 1 )
                               .arg( translated_.error ) );
    openButton_->setEnabled( !translated_.pattern.isEmpty() );
}

void openDisplayFilter( QWidget* parent )
{
    if ( !g_state.hostCapabilities.regexLab ) {
        return;
    }
    // The filter accepted last, offered again to refine it.
    static QString lastFilter;
    DisplayFilterDialog dialog( lastFilter, parent );
    if ( dialog.exec() != QDialog::Accepted || dialog.pattern().isEmpty() ) {
        return;
    }
    lastFilter = dialog.filter();
    hostLog( LOGSQUIRL_LOG_INFO, "Display filter: " + lastFilter );
    openRegexLab( "Display filter", dialog.pattern() );
}

} // namespace tcpdump
