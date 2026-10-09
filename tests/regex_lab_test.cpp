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
 * @file regex_lab_test.cpp
 * @brief BDD tests for the summary's filters: the Regex Lab patterns that
 *        match the lines of an endpoint or a protocol.
 */

#include <catch2/catch.hpp>

#include "corpus_layouts.h"
#include "fakehost.h"
#include "pcap_converter.h"
#include "regex_lab.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QStringList>
#include <QTemporaryDir>

#include <set>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

const QString kArrow = QString::fromUtf8( "\xe2\x86\x92" );

/// The lines @p pattern matches, by their number, as the Regex Lab does with
/// Match case.
std::set<int> matched( const QString& pattern, const QStringList& lines )
{
    const QRegularExpression regex( pattern );
    INFO( pattern.toStdString() );
    REQUIRE( regex.isValid() );
    std::set<int> numbers;
    for ( int i = 0; i < lines.size(); ++i ) {
        if ( regex.match( lines[ i ] ).hasMatch() ) {
            numbers.insert( i + 1 );
        }
    }
    return numbers;
}

/// The lines with @p value in one of @p columns, by their number; in Source
/// and Destination also with the name host names put behind it.
std::set<int> withColumn( const QStringList& lines, const QStringList& columns,
                          const QString& value )
{
    std::set<int> numbers;
    for ( int i = 0; i < lines.size(); ++i ) {
        const auto match = packetLineRegex().match( lines[ i ] );
        for ( const auto& column : columns ) {
            const auto text = match.captured( column );
            const bool named
                = column != "protocol" && text.startsWith( value + "(" ) && text.endsWith( ")" );
            if ( match.hasMatch() && ( text == value || named ) ) {
                numbers.insert( i + 1 );
            }
        }
    }
    return numbers;
}

/// A packet line with the given columns.
QString packetLine( const QString& source, const QString& destination, const QString& protocol,
                    const QString& info )
{
    return QString(
               "1      0       2023-11-14 22:13:20.000000Z  0.000000       %1 %2 %3 54     %4" )
        .arg( source.leftJustified( 39 ), destination.leftJustified( 39 ),
              protocol.leftJustified( 9 ), info );
}

} // namespace

SCENARIO( "The summary's filters match the lines of an endpoint or a protocol", "[regexlab]" )
{
    GIVEN( "lines between similar addresses, and addresses inside Info" )
    {
        const QStringList lines{
            packetLine( "10.0.0.1", "10.0.0.2", "TCP", "50000 " + kArrow + " 80 [SYN]" ),
            packetLine( "10.0.0.2", "10.0.0.1", "TCP", "80 " + kArrow + " 50000 [SYN, ACK]" ),
            packetLine( "10.0.0.11", "10.0.0.2", "UDP", "53 " + kArrow + " 53 Len=0" ),
            packetLine( "10x0x0x1", "110.0.0.1", "UDP", "53 " + kArrow + " 53 Len=0" ),
            packetLine( "10.0.0.3", "10.0.0.4", "DNS", "| Query 10.0.0.1 TCP 54 PTR" ),
            packetLine( "fe80::1", "fe80::10", "ICMPv6", "Type=135" ),
            packetLine( "fe80::10", "ff02::1", "ICMPv6", "Type=136" ),
            packetLine( "2001:db8::1", "fe80::1", "ETH(0x88CC)", "TCP" ),
            "2026-10-09 12:00:00 INFO 10.0.0.1 TCP",
        };

        THEN( "an IPv4 address matches its lines in Source or Destination, dots literally" )
        {
            REQUIRE( matched( endpointPattern( "10.0.0.1" ), lines ) == std::set<int>{ 1, 2 } );
            REQUIRE( matched( endpointPattern( "10.0.0.2" ), lines ) == std::set<int>{ 1, 2, 3 } );
        }

        THEN( "an IPv6 address matches its lines, not a longer one it starts or ends" )
        {
            REQUIRE( matched( endpointPattern( "fe80::1" ), lines ) == std::set<int>{ 6, 8 } );
            REQUIRE( matched( endpointPattern( "fe80::10" ), lines ) == std::set<int>{ 6, 7 } );
            REQUIRE( matched( endpointPattern( "ff02::1" ), lines ) == std::set<int>{ 7 } );
        }

        THEN( "an address matches its lines with the name a DNS answer gave it, too" )
        {
            const QStringList named{
                packetLine( "10.0.0.1(host.example)", "10.0.0.2", "TCP", "50000 " ),
                packetLine( "10.0.0.2", "10.0.0.1(host.example)", "TCP", "80 " ),
                packetLine( "10.0.0.11(other.example)", "10.0.0.2", "UDP", "53 " ),
                packetLine( "fe80::1(router.local)", "fe80::10", "ICMPv6", "Type=135" ),
            };
            REQUIRE( matched( endpointPattern( "10.0.0.1" ), named ) == std::set<int>{ 1, 2 } );
            REQUIRE( matched( endpointPattern( "10.0.0.2" ), named ) == std::set<int>{ 1, 2, 3 } );
            REQUIRE( matched( endpointPattern( "fe80::1" ), named ) == std::set<int>{ 4 } );
            REQUIRE( matched( endpointPattern( "fe80::10" ), named ) == std::set<int>{ 4 } );
        }

        THEN( "a protocol matches the lines of its Protocol column only" )
        {
            REQUIRE( matched( protocolPattern( "TCP" ), lines ) == std::set<int>{ 1, 2 } );
            REQUIRE( matched( protocolPattern( "ICMPv6" ), lines ) == std::set<int>{ 6, 7 } );
            REQUIRE( matched( protocolPattern( "ETH(0x88CC)" ), lines ) == std::set<int>{ 8 } );
        }
    }

    QTemporaryDir out;
    REQUIRE( out.isValid() );

    for ( const auto& capture : committedCaptures() ) {
        for ( const auto& layout : allLineLayouts() ) {
            GIVEN( "the corpus capture " + QFileInfo( capture ).fileName().toStdString()
                   + ", converted with " + describeLayout( layout ) )
            {
                ConversionOptions options;
                options.layout = layout;
                const auto result = convertPcap( capture, out.path(), nullptr, {}, options );
                REQUIRE( result.status == ConversionResult::Status::Converted );
                QFile text( result.outputPath );
                REQUIRE( text.open( QIODevice::ReadOnly ) );
                auto lines = QString::fromUtf8( text.readAll() ).split( '\n', Qt::SkipEmptyParts );
                const auto& summary = result.summary;
                REQUIRE_FALSE( summary.endpointPackets.empty() );

                THEN( "each endpoint of its summary matches the lines with it as Source or "
                      "Destination" )
                {
                    for ( const auto& [ address, count ] : summary.endpointPackets ) {
                        const auto name = QString::fromStdString( address );
                        INFO( name.toStdString() );
                        const auto expected
                            = withColumn( lines, { "source", "destination" }, name );
                        REQUIRE( expected.size() > 0 );
                        REQUIRE( matched( endpointPattern( name ), lines ) == expected );
                    }
                }

                THEN( "each protocol of its summary matches its packets' lines" )
                {
                    for ( const auto& [ protocol, count ] : summary.protocolPackets ) {
                        const auto name = QString::fromStdString( protocol );
                        INFO( name.toStdString() );
                        const auto numbers = matched( protocolPattern( name ), lines );
                        REQUIRE( numbers == withColumn( lines, { "protocol" }, name ) );
                        REQUIRE( numbers.size() == count );
                    }
                }
            }
        }
    }
}

SCENARIO( "A column's address is read without the name behind it", "[regexlab]" )
{
    THEN( "a name in parentheses is left out, anything else is kept as it is" )
    {
        REQUIRE( columnAddress( "93.184.216.34(www.example.com)" ) == "93.184.216.34" );
        REQUIRE( columnAddress( "2001:db8::1(example.com)" ) == "2001:db8::1" );
        REQUIRE( columnAddress( "93.184.216.34" ) == "93.184.216.34" );
        REQUIRE( columnAddress( "00:11:22:33:44:55" ) == "00:11:22:33:44:55" );
        REQUIRE( columnAddress( "-" ) == "-" );
        REQUIRE( columnAddress( "10.0.0.1(not a name)" ) == "10.0.0.1(not a name)" );
    }

    THEN( "an address pattern matches the address with and without its name only" )
    {
        const QRegularExpression column( "^" + addressPattern( "10.0.0.1" ) + "$" );
        REQUIRE( column.match( "10.0.0.1" ).hasMatch() );
        REQUIRE( column.match( "10.0.0.1(host.example)" ).hasMatch() );
        REQUIRE_FALSE( column.match( "10.0.0.10" ).hasMatch() );
        REQUIRE_FALSE( column.match( "10.0.0.10(host.example)" ).hasMatch() );
        REQUIRE_FALSE( column.match( "10x0x0x1" ).hasMatch() );
    }
}

SCENARIO( "A filter opens in the Regex Lab, and what the user does is logged", "[regexlab]" )
{
    GIVEN( "a host with the Regex Lab" )
    {
        FakeHost host;

        WHEN( "a filter is opened" )
        {
            openRegexLab( "Filter", "^a\\.b" );

            THEN( "the Lab shows the pattern, matching case" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( host.regexLabs.first().pattern == "^a\\.b" );
                REQUIRE( host.regexLabs.first().flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( host.notifications.isEmpty() );
            }

            AND_WHEN( "the user applies a pattern" )
            {
                host.regexLabs.first().apply( "^a", LOGSQUIRL_REGEX_LAB_MATCH_CASE );

                THEN( "it is logged under the feature's name" )
                {
                    REQUIRE( host.logs.contains( "Filter: applied ^a" ) );
                }
            }

            AND_WHEN( "the user cancels" )
            {
                host.regexLabs.first().cancel();

                THEN( "the cancel is logged" )
                {
                    REQUIRE( host.logs.contains( "Filter: cancelled" ) );
                }
            }
        }
    }

    GIVEN( "a host older than LogSquirl 26.11" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );

        THEN( "nothing is opened" )
        {
            openRegexLab( "Filter", "^a" );
            REQUIRE( host.regexLabs.isEmpty() );
        }
    }
}
