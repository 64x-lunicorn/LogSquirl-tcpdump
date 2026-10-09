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
 * @file conversion_options_test.cpp
 * @brief The corpus converted with other ConversionOptions than the defaults.
 *
 * The expected text of each option is not committed: it is derived here
 * from the conversion with the defaults, which corpus_test.cpp checks
 * against tests/corpus.  A time column left out is that column's text cut
 * from each line, as every column is written on its own; a preview left out
 * is the preview, and its separator, cut from the end of a packet's Info.
 */

#include <catch2/catch.hpp>

#include "pcap_converter.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QTemporaryDir>

using namespace tcpdump;

namespace {

/// The committed captures with an expected text, and the real captures of
/// the local corpus if there are any.
QFileInfoList corpusCaptures()
{
    const QStringList patterns{ "*.pcap", "*.pcapng" };
    const QDir committed( QStringLiteral( TCPDUMP_CORPUS_DIR ) );
    auto captures = committed.entryInfoList( patterns, QDir::Files, QDir::Name );
    if ( const QDir local( committed.filePath( "local" ) ); local.exists() ) {
        captures += local.entryInfoList( patterns, QDir::Files, QDir::Name );
    }
    QFileInfoList withText;
    for ( const auto& capture : captures ) {
        if ( QFile::exists( capture.dir().filePath( capture.completeBaseName() + ".txt" ) ) ) {
            withText << capture;
        }
    }
    return withText;
}

/// The lines @p capture converts to with @p options.
QStringList convert( const QFileInfo& capture, const ConversionOptions& options )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const auto result = convertPcap( capture.filePath(), out.path(), nullptr, {}, options );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    QFile file( result.outputPath );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    REQUIRE( lines.last().isEmpty() );
    lines.removeLast();
    return lines;
}

/// Where the column at @p index starts in @p line, splitting it at runs of
/// spaces: No. is 0, Stream 1, UTC Time 2 and 3 (date and time of day, or
/// "UTC" and "Time" in the header), Time 4, Source 5.
qsizetype columnStart( const QString& line, int index )
{
    qsizetype pos = 0;
    for ( int i = 0; i < index; ++i ) {
        pos = line.indexOf( ' ', pos );
        REQUIRE( pos >= 0 );
        while ( line[ pos ] == ' ' ) {
            ++pos;
        }
    }
    return pos;
}

/// @p line without the columns from @p first up to @p end.
QString withoutColumns( const QString& line, int first, int end )
{
    const auto from = columnStart( line, first );
    return QString( line ).remove( from, columnStart( line, end ) - from );
}

} // namespace

SCENARIO( "The corpus converts with each choice of time columns", "[converter][corpus]" )
{
    const auto captures = corpusCaptures();
    REQUIRE( captures.size() >= 3 );

    for ( const auto& capture : captures ) {
        GIVEN( "the capture " + capture.fileName().toStdString() )
        {
            const auto defaults = convert( capture, {} );

            WHEN( "both time columns are chosen" )
            {
                ConversionOptions options;
                options.layout.timeColumns = TimeColumns::Both;

                THEN( "the text is the default one" )
                {
                    REQUIRE( convert( capture, options ) == defaults );
                }
            }

            WHEN( "only the absolute time is chosen" )
            {
                ConversionOptions options;
                options.layout.timeColumns = TimeColumns::AbsoluteOnly;
                const auto lines = convert( capture, options );

                THEN( "each line is the default one without its Time column" )
                {
                    REQUIRE( lines.size() == defaults.size() );
                    for ( qsizetype i = 0; i < lines.size(); ++i ) {
                        INFO( "line " << i + 1 );
                        REQUIRE( lines[ i ].toStdString()
                                 == withoutColumns( defaults[ i ], 4, 5 ).toStdString() );
                    }
                }
            }

            WHEN( "only the relative time is chosen" )
            {
                ConversionOptions options;
                options.layout.timeColumns = TimeColumns::RelativeOnly;
                const auto lines = convert( capture, options );

                THEN( "each line is the default one without its UTC Time column" )
                {
                    REQUIRE( lines.size() == defaults.size() );
                    for ( qsizetype i = 0; i < lines.size(); ++i ) {
                        INFO( "line " << i + 1 );
                        REQUIRE( lines[ i ].toStdString()
                                 == withoutColumns( defaults[ i ], 2, 4 ).toStdString() );
                    }
                }
            }
        }
    }
}

SCENARIO( "The corpus converts without payload previews", "[converter][corpus]" )
{
    const auto captures = corpusCaptures();
    REQUIRE( captures.size() >= 3 );
    // A packet cut at the snaplen says so after its Info, so after its preview.
    static const QRegularExpression cutNote( R"( \[cut to \d+ bytes\]$)" );
    const auto separator = QString::fromUtf8( kDescriptionSeparator );
    const auto continuation = separator + "Continuation";
    qsizetype previewsLeftOut = 0;

    for ( const auto& capture : captures ) {
        const auto defaults = convert( capture, {} );
        ConversionOptions options;
        options.preview = false;
        const auto lines = convert( capture, options );

        INFO( "capture " << capture.fileName().toStdString() );
        REQUIRE( lines.size() == defaults.size() );
        for ( qsizetype i = 0; i < lines.size(); ++i ) {
            INFO( "line " << i + 1 << ": " << defaults[ i ].toStdString() );
            auto line = lines[ i ];
            auto expected = defaults[ i ];
            const auto note = cutNote.match( expected );
            if ( note.hasMatch() ) {
                REQUIRE( line.endsWith( note.captured() ) );
                line.chop( note.capturedLength() );
                expected.chop( note.capturedLength() );
            }
            if ( line == expected ) {
                continue;
            }
            // The preview is what follows the line: after the separator, or
            // after "Continuation: " in a stream whose protocol it continues.
            REQUIRE( expected.startsWith( line ) );
            const auto preview = expected.mid( line.size() );
            REQUIRE( ( preview.startsWith( separator )
                       || ( line.endsWith( continuation ) && preview.startsWith( ": " ) ) ) );
            REQUIRE_FALSE( preview.mid( 2 ).contains( separator ) );
            ++previewsLeftOut;
        }
    }
    REQUIRE( previewsLeftOut > 0 );
}

SCENARIO( "The corpus converts with shorter payload previews", "[converter][corpus]" )
{
    const auto captures = corpusCaptures();
    static const QRegularExpression cutNote( R"( \[cut to \d+ bytes\]$)" );
    const auto ellipsis = QString::fromUtf8( "\xe2\x80\xa6" );
    qsizetype previewsCut = 0;

    for ( const auto& capture : captures ) {
        const auto defaults = convert( capture, {} );
        ConversionOptions options;
        options.previewChars = 8;
        const auto lines = convert( capture, options );

        INFO( "capture " << capture.fileName().toStdString() );
        REQUIRE( lines.size() == defaults.size() );
        for ( qsizetype i = 0; i < lines.size(); ++i ) {
            if ( lines[ i ] == defaults[ i ] ) {
                continue;
            }
            INFO( "line " << i + 1 << ": " << defaults[ i ].toStdString() );
            auto line = lines[ i ];
            auto expected = defaults[ i ];
            const auto note = cutNote.match( expected );
            if ( note.hasMatch() ) {
                line.chop( note.capturedLength() );
                expected.chop( note.capturedLength() );
            }
            // The same line up to the preview's 8th character, then an ellipsis.
            REQUIRE( line.endsWith( ellipsis ) );
            line.chop( ellipsis.size() );
            REQUIRE( expected.startsWith( line ) );
            REQUIRE( expected.size() > line.size() + 1 );
            const auto separator = line.lastIndexOf( QString::fromUtf8( kDescriptionSeparator ) );
            REQUIRE( separator >= 0 );
            REQUIRE( line.size() - separator >= 8 );
            ++previewsCut;
        }
    }
    REQUIRE( previewsCut > 0 );
}
