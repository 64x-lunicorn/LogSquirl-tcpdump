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
 * @file configdialog_test.cpp
 * @brief BDD tests for the configuration dialog and Configure… entry point.
 */

#include <catch2/catch.hpp>

#include "configdialog.h"
#include "fakehost.h"
#include "settings.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QLabel>
#include <QPushButton>
#include <QSpinBox>
#include <QTimer>

#include <functional>

using namespace tcpdump;
using tcpdump_test::FakeHost;

extern "C" void logsquirl_plugin_configure( void* parent_widget );

namespace {

template <typename T>
T* child( const QWidget& dialog, const char* name )
{
    auto* found = dialog.findChild<T*>( name );
    REQUIRE( found );
    return found;
}

/// Run @p work on the dialog the next call opens, once it is shown.
void whenDialogOpens( std::function<void( ConfigDialog& )> work )
{
    QTimer::singleShot( 0, [ work = std::move( work ) ] {
        auto* dialog = qobject_cast<ConfigDialog*>( QApplication::activeModalWidget() );
        if ( !dialog ) {
            // Look among the top-level widgets, for a platform without focus.
            for ( auto* widget : QApplication::topLevelWidgets() ) {
                if ( auto* found = qobject_cast<ConfigDialog*>( widget );
                     found && found->isVisible() ) {
                    dialog = found;
                }
            }
        }
        CHECK( dialog ); // no exception may leave the event loop
        if ( dialog ) {
            work( *dialog );
        }
    } );
}

} // namespace

SCENARIO( "The configuration dialog shows and edits the conversion options", "[configdialog]" )
{
    GIVEN( "a dialog for options other than the defaults" )
    {
        ConversionOptions options;
        options.layout = { TimeColumns::AbsoluteOnly, true };
        options.preview = false;
        options.previewChars = 50;
        options.maxStreams = 1234;
        options.maxEndpoints = 567;
        options.reassemblyMegabytes = 8;
        ConfigDialog dialog( options );

        THEN( "its controls show them" )
        {
            REQUIRE( child<QComboBox>( dialog, "timeColumns" )->currentData().toInt()
                     == static_cast<int>( TimeColumns::AbsoluteOnly ) );
            REQUIRE( child<QCheckBox>( dialog, "macColumns" )->isChecked() );
            REQUIRE_FALSE( child<QCheckBox>( dialog, "preview" )->isChecked() );
            REQUIRE( child<QSpinBox>( dialog, "previewChars" )->value() == 50 );
            REQUIRE_FALSE( child<QSpinBox>( dialog, "previewChars" )->isEnabled() );
            REQUIRE( child<QSpinBox>( dialog, "maxStreams" )->value() == 1234 );
            REQUIRE( child<QSpinBox>( dialog, "maxEndpoints" )->value() == 567 );
            REQUIRE( child<QSpinBox>( dialog, "reassemblyMegabytes" )->value() == 8 );
            REQUIRE( dialog.options().layout.timeColumns == TimeColumns::AbsoluteOnly );
            REQUIRE( dialog.options().previewChars == 50 );
        }

        THEN( "it says that an open capture keeps the options it was converted with" )
        {
            REQUIRE( child<QLabel>( dialog, "note" )->text().contains( "open capture keeps" ) );
        }

        WHEN( "the controls are changed" )
        {
            auto* timeColumns = child<QComboBox>( dialog, "timeColumns" );
            timeColumns->setCurrentIndex(
                timeColumns->findData( static_cast<int>( TimeColumns::RelativeOnly ) ) );
            child<QCheckBox>( dialog, "macColumns" )->setChecked( false );
            child<QCheckBox>( dialog, "preview" )->setChecked( true );
            child<QSpinBox>( dialog, "previewChars" )->setValue( 80 );
            child<QSpinBox>( dialog, "maxStreams" )->setValue( 2000 );
            child<QSpinBox>( dialog, "maxEndpoints" )->setValue( 3000 );
            child<QSpinBox>( dialog, "reassemblyMegabytes" )->setValue( 128 );

            THEN( "the dialog's options are the new ones" )
            {
                const auto edited = dialog.options();
                REQUIRE( edited.layout.timeColumns == TimeColumns::RelativeOnly );
                REQUIRE_FALSE( edited.layout.macColumns );
                REQUIRE( edited.preview );
                REQUIRE( child<QSpinBox>( dialog, "previewChars" )->isEnabled() );
                REQUIRE( edited.previewChars == 80 );
                REQUIRE( edited.maxStreams == 2000 );
                REQUIRE( edited.maxEndpoints == 3000 );
                REQUIRE( edited.reassemblyMegabytes == 128 );
            }
        }

        WHEN( "Restore Defaults is clicked" )
        {
            child<QDialogButtonBox>( dialog, "buttons" )
                ->button( QDialogButtonBox::RestoreDefaults )
                ->click();

            THEN( "the controls show the defaults" )
            {
                const auto restored = dialog.options();
                const ConversionOptions defaults;
                REQUIRE( restored.layout.timeColumns == defaults.layout.timeColumns );
                REQUIRE( restored.layout.macColumns == defaults.layout.macColumns );
                REQUIRE( restored.preview == defaults.preview );
                REQUIRE( restored.previewChars == defaults.previewChars );
                REQUIRE( restored.maxStreams == defaults.maxStreams );
                REQUIRE( restored.maxEndpoints == defaults.maxEndpoints );
                REQUIRE( restored.reassemblyMegabytes == defaults.reassemblyMegabytes );
            }
        }
    }

    GIVEN( "a dialog for the defaults" )
    {
        ConfigDialog dialog( ConversionOptions{} );

        THEN( "the controls reach the largest values allowed" )
        {
            REQUIRE( child<QSpinBox>( dialog, "previewChars" )->maximum()
                     == static_cast<int>( kMaxPreviewChars ) );
            REQUIRE( child<QSpinBox>( dialog, "maxStreams" )->maximum()
                     == static_cast<int>( kMaxStreamCap ) );
            REQUIRE( child<QSpinBox>( dialog, "maxEndpoints" )->maximum()
                     == static_cast<int>( kMaxEndpointCap ) );
            REQUIRE( child<QSpinBox>( dialog, "reassemblyMegabytes" )->maximum()
                     == static_cast<int>( kMaxReassemblyMegabytes ) );
        }
    }
}

SCENARIO( "Configure… saves the options in the plugin's configuration directory",
          "[configdialog][plugin]" )
{
    GIVEN( "the plugin in a host with an empty configuration directory" )
    {
        FakeHost host;

        WHEN( "the dialog is opened, changed and accepted" )
        {
            whenDialogOpens( []( ConfigDialog& dialog ) {
                auto* timeColumns = dialog.findChild<QComboBox*>( "timeColumns" );
                timeColumns->setCurrentIndex(
                    timeColumns->findData( static_cast<int>( TimeColumns::RelativeOnly ) ) );
                dialog.findChild<QCheckBox*>( "preview" )->setChecked( false );
                dialog.accept();
            } );
            logsquirl_plugin_configure( nullptr );

            THEN( "the settings file holds the new options" )
            {
                const auto saved = loadConversionOptions( host.configDir() );
                REQUIRE( saved.layout.timeColumns == TimeColumns::RelativeOnly );
                REQUIRE_FALSE( saved.preview );
            }

            AND_WHEN( "it is opened again" )
            {
                ConversionOptions shown;
                whenDialogOpens( [ &shown ]( ConfigDialog& dialog ) {
                    shown = dialog.options();
                    dialog.reject();
                } );
                logsquirl_plugin_configure( nullptr );

                THEN( "it shows the saved options" )
                {
                    REQUIRE( shown.layout.timeColumns == TimeColumns::RelativeOnly );
                    REQUIRE_FALSE( shown.preview );
                }
            }
        }

        WHEN( "the dialog is changed and cancelled" )
        {
            whenDialogOpens( []( ConfigDialog& dialog ) {
                dialog.findChild<QCheckBox*>( "macColumns" )->setChecked( true );
                dialog.reject();
            } );
            logsquirl_plugin_configure( nullptr );

            THEN( "nothing is saved" )
            {
                REQUIRE_FALSE( QFile::exists( settingsFilePath( host.configDir() ) ) );
            }
        }
    }
}
