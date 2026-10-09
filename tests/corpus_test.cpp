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
 * Each <name>.pcap or <name>.pcapng with a <name>.txt beside it must
 * convert to exactly that text.  The captures cover the link layers, byte orders, timestamp
 * precisions and protocols the parser handles, including malformed and
 * cut-off records.  After an intended change of the output, run the tests
 * with TCPDUMP_UPDATE_CORPUS=1 to rewrite the .txt files, and review the
 * difference.  interfaces.pcapng is written by tests/make_pcapng_corpus.py,
 * tls.pcap by tests/make_tls_corpus.py, dns.pcap by tests/make_dns_corpus.py,
 * tcp-analysis.pcap by tests/make_tcp_analysis_corpus.py, stream-labels.pcap
 * by tests/make_stream_labels_corpus.py, icmp.pcap by tests/make_icmp_corpus.py,
 * dhcp-ntp.pcap by tests/make_dhcp_ntp_corpus.py, tunnels.pcap by
 * tests/make_tunnels_corpus.py, wifi.pcap and ppp.pcapng by
 * tests/make_link_layers_corpus.py, reassembly.pcap by
 * tests/make_reassembly_corpus.py, mqtt.pcap by tests/make_mqtt_corpus.py,
 * sip.pcap by tests/make_sip_corpus.py, someip.pcap by
 * tests/make_someip_corpus.py, doip.pcap by tests/make_doip_corpus.py,
 * ssh.pcap by tests/make_ssh_corpus.py, websocket.pcap by
 * tests/make_websocket_corpus.py, smb.pcap by tests/make_smb_corpus.py.
 * Captures of real loopback traffic, recorded by tests/make_real_corpus.sh,
 * stay uncommitted in tests/corpus/local and are converted too when present.
 * The malformed-*.pcap files, mutated captures from fuzzing,
 * must merely be read to their end.
 */

#include <catch2/catch.hpp>

#include "pcap_converter.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>

using namespace tcpdump;

namespace {

QString corpusDir()
{
    return QStringLiteral( TCPDUMP_CORPUS_DIR );
}

// The committed captures, then those in the local corpus of real captures
// if there is one.
QFileInfoList corpusCaptures()
{
    const QStringList patterns{ "*.pcap", "*.pcapng" };
    auto captures = QDir( corpusDir() ).entryInfoList( patterns, QDir::Files, QDir::Name );
    const QDir local( corpusDir() + QStringLiteral( "/local" ) );
    if ( local.exists() ) {
        captures += local.entryInfoList( patterns, QDir::Files, QDir::Name );
    }
    return captures;
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
    REQUIRE( QDir( corpusDir() ).entryList( { "*.pcap", "*.pcapng" }, QDir::Files ).size() >= 3 );

    QTemporaryDir out;
    REQUIRE( out.isValid() );
    const bool update = qEnvironmentVariableIsSet( "TCPDUMP_UPDATE_CORPUS" );

    for ( const auto& capture : corpusCaptures() ) {
        const auto name = capture.completeBaseName();
        const auto expectedPath = capture.dir().filePath( name + ".txt" );
        if ( name.startsWith( "malformed-" ) || ( !QFile::exists( expectedPath ) && !update ) ) {
            continue;
        }

        GIVEN( "the capture " + name.toStdString() )
        {
            const auto result = convertPcap( capture.filePath(), out.path() );
            REQUIRE( result.status == ConversionResult::Status::Converted );
            const auto outPath = result.outputPath;

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
            const auto result = convertPcap( dir.filePath( capture ), out.path() );

            THEN( "it converts, as far as its records go" )
            {
                REQUIRE( result.status == ConversionResult::Status::Converted );
                REQUIRE( ( result.summary.packets > 0 || result.summary.endsInsideRecord ) );
            }
        }
    }
}
