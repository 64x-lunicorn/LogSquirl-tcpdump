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
 * @file corpus_test.cpp
 * @brief Regression tests converting the captures in tests/corpus.
 *
 * Each <name>.pcap with a <name>.txt beside it must convert to exactly
 * that text.  The captures cover the link layers, byte orders, timestamp
 * precisions and protocols the parser handles, including malformed and
 * cut-off records.  After an intended change of the output, run the tests
 * with TCPDUMP_UPDATE_CORPUS=1 to rewrite the .txt files, and review the
 * difference.  The malformed-*.pcap files, mutated captures from fuzzing,
 * must merely be read to their end.
 */

#include <catch2/catch.hpp>

#include "pcap_converter.h"

#include <QDir>
#include <QFile>
#include <QTemporaryDir>

using namespace tcpdump;

namespace {

QString corpusDir()
{
    return QStringLiteral( TCPDUMP_CORPUS_DIR );
}

QByteArray readText( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    return file.readAll();
}

} // namespace

SCENARIO( "The corpus captures convert to their expected text", "[corpus]" )
{
    const QDir dir( corpusDir() );
    const auto captures = dir.entryList( { "*.pcap" }, QDir::Files, QDir::Name );
    REQUIRE( captures.size() >= 2 );

    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const bool update = qEnvironmentVariableIsSet( "TCPDUMP_UPDATE_CORPUS" );

    for ( const auto& capture : captures ) {
        const auto name = capture.chopped( 5 );
        const auto expectedPath = dir.filePath( name + ".txt" );
        if ( name.startsWith( "malformed-" ) || ( !QFile::exists( expectedPath ) && !update ) ) {
            continue;
        }

        GIVEN( "the capture " + name.toStdString() )
        {
            const auto outPath = out.filePath( name + ".log" );
            const auto result = convertPcap( dir.filePath( capture ), outPath );
            REQUIRE( result.status == ConversionResult::Status::Converted );

            if ( update ) {
                QFile expected( expectedPath );
                REQUIRE( expected.open( QIODevice::WriteOnly | QIODevice::Truncate ) );
                expected.write( readText( outPath ) );
            }

            THEN( "the text matches the expected one line for line" )
            {
                const auto actual = readText( outPath ).split( '\n' );
                const auto expected = readText( expectedPath ).split( '\n' );
                REQUIRE( actual.size() == expected.size() );
                for ( int i = 0; i < actual.size(); ++i ) {
                    INFO( "line " << i + 1 );
                    REQUIRE( actual[ i ].toStdString() == expected[ i ].toStdString() );
                }
            }
        }
    }
}

SCENARIO( "Malformed captures are read to their end", "[corpus]" )
{
    const QDir dir( corpusDir() );
    const auto captures = dir.entryList( { "malformed-*.pcap" }, QDir::Files, QDir::Name );
    REQUIRE_FALSE( captures.isEmpty() );

    QTemporaryDir out;
    REQUIRE( out.isValid() );

    for ( const auto& capture : captures ) {
        GIVEN( "the capture " + capture.toStdString() )
        {
            const auto result
                = convertPcap( dir.filePath( capture ), out.filePath( capture + ".log" ) );

            THEN( "it converts, as far as its records go" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( ( result.stats.packets > 0 || result.truncated ) );
            }
        }
    }
}
