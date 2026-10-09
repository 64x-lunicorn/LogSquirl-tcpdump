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
 * @file presets_test.cpp
 * @brief Tests of the highlighter set and the filter group in presets/.
 *
 * The two .conf files are read as LogSquirl's Import reads them: QSettings
 * in INI format, one HighlighterSetCollection or PredefinedFiltersCollection
 * holding one set (src/ui/src/highlighterset.cpp, predefinedfilters.cpp and
 * groupexchange.cpp in the host).  Their patterns are matched as a
 * highlighter matches, with QRegularExpression and its "Ignore case" off.
 *
 * Every pattern is applied to every line of every corpus text: the packet
 * numbers it matches in a committed text must be those listed below, and in
 * any text, the local real captures' included, those that the rule it
 * stands for picks out of the line's columns.
 */

#include <catch2/catch.hpp>

#include "corpus_layouts.h"
#include "packet_formatter.h"
#include "regex_lab.h"

#include <QColor>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSettings>
#include <QTemporaryDir>

#include <functional>
#include <map>
#include <set>
#include <vector>

using namespace tcpdump;

namespace {

// ── The files, as LogSquirl imports them ───────────────────────────────────

/// One highlighter or predefined filter: what it is called here, and its
/// pattern.  Highlighters have no name in the file; the test names them.
struct Rule {
    QString name;
    QString pattern;
    QColor fore;
    QColor back;
};

/// The host's versions of the settings it reads (HighlighterSetCollection_
/// VERSION and the others): a file of a newer one is not imported.
constexpr int kHighlighterSetCollectionVersion = 2;
constexpr int kHighlighterSetVersion = 3;
constexpr int kPredefinedFiltersCollectionVersion = 3;
constexpr int kPredefinedFilterSetVersion = 1;

QString presetFile( const char* name )
{
    return QDir( QStringLiteral( TCPDUMP_PRESETS_DIR ) ).filePath( QString::fromUtf8( name ) );
}

/// The names of the highlighters, top to bottom, in the order of the file.
const QStringList kHighlighterNames{ "TCP problems", "TCP RST",     "ICMP errors", "DNS NXDOMAIN",
                                     "HTTP 4xx/5xx", "TCP SYN/FIN", "TLS",         "ARP" };

/// The set's id and group's id: fixed, so that importing a newer file
/// offers to replace the one imported before.
const QString kHighlighterSetId = "7c1d2f9e4b3a4d5e8f60a1b2c3d4e5f6";
const QString kFilterGroupId = "3e8a5c7b9d0f4e1a8b2c6d4f0e9a7b5c";

std::vector<Rule> loadHighlighters()
{
    const auto path = presetFile( "tcpdump_highlighter.conf" );
    REQUIRE( QFile::exists( path ) );
    QSettings settings( path, QSettings::IniFormat );
    REQUIRE( settings.status() == QSettings::NoError );
    REQUIRE_FALSE( settings.contains( "kind" ) ); // or it is no highlighter file

    settings.beginGroup( "HighlighterSetCollection" );
    REQUIRE( settings.value( "version" ).toInt() == kHighlighterSetCollectionVersion );
    REQUIRE( settings.beginReadArray( "sets" ) == 1 );
    settings.setArrayIndex( 0 );
    settings.beginGroup( "HighlighterSet" );
    REQUIRE( settings.value( "version" ).toInt() == kHighlighterSetVersion );
    REQUIRE( settings.value( "name" ).toString() == "tcpdump" );
    REQUIRE( settings.value( "id" ).toString() == kHighlighterSetId );

    std::vector<Rule> rules;
    const int size = settings.beginReadArray( "highlighters" );
    REQUIRE( size == kHighlighterNames.size() );
    for ( int i = 0; i < size; ++i ) {
        settings.setArrayIndex( i );
        REQUIRE( settings.value( "use_regex" ).toBool() );
        REQUIRE_FALSE( settings.value( "ignore_case" ).toBool() );
        REQUIRE_FALSE( settings.value( "match_only" ).toBool() ); // the whole line
        REQUIRE_FALSE( settings.value( "variate_colors" ).toBool() );
        rules.push_back( { kHighlighterNames[ i ], settings.value( "regexp" ).toString(),
                           QColor( settings.value( "fore_colour" ).toString() ),
                           QColor( settings.value( "back_colour" ).toString() ) } );
    }
    settings.endArray();
    settings.endGroup();
    settings.endArray();
    settings.endGroup();
    return rules;
}

std::vector<Rule> loadFilters()
{
    const auto path = presetFile( "tcpdump_filter.conf" );
    REQUIRE( QFile::exists( path ) );
    QSettings settings( path, QSettings::IniFormat );
    REQUIRE( settings.status() == QSettings::NoError );
    REQUIRE_FALSE( settings.contains( "kind" ) );

    settings.beginGroup( "PredefinedFiltersCollection" );
    REQUIRE( settings.value( "version" ).toInt() == kPredefinedFiltersCollectionVersion );
    REQUIRE( settings.beginReadArray( "sets" ) == 1 );
    settings.setArrayIndex( 0 );
    settings.beginGroup( "PredefinedFilterSet" );
    REQUIRE( settings.value( "version" ).toInt() == kPredefinedFilterSetVersion );
    REQUIRE( settings.value( "name" ).toString() == "tcpdump" );
    REQUIRE( settings.value( "id" ).toString() == kFilterGroupId );

    std::vector<Rule> rules;
    const int size = settings.beginReadArray( "filters" );
    for ( int i = 0; i < size; ++i ) {
        settings.setArrayIndex( i );
        REQUIRE( settings.value( "regex" ).toBool() );
        rules.push_back( { settings.value( "name" ).toString(),
                           settings.value( "filter" ).toString(),
                           {},
                           {} } );
    }
    settings.endArray();
    settings.endGroup();
    settings.endArray();
    settings.endGroup();
    return rules;
}

bool matches( const Rule& rule, const QString& line )
{
    const QRegularExpression regex( rule.pattern );
    REQUIRE( regex.isValid() );
    return regex.match( line ).hasMatch();
}

/// The highlighter that colours @p line: the topmost that matches, as
/// LogSquirl tries them from the bottom up and the last match wins.
QString colouredBy( const std::vector<Rule>& highlighters, const QString& line )
{
    for ( const auto& rule : highlighters ) {
        if ( matches( rule, line ) ) {
            return rule.name;
        }
    }
    return {};
}

// ── What each rule stands for, read from the columns ──────────────────────

/// A packet line's columns, and what Info says of TCP.
struct Line {
    QString protocol;
    QString info;        ///< after the tunnels it may start with: the inner packet's
    QStringList markers; ///< "TCP Retransmission", … at the start of Info
    QStringList flags;   ///< SYN, ACK, …, for a TCP segment
    QString afterFlags;  ///< Info after the flags' bracket
    QString description; ///< Info after " | ", what the payload is
    bool tcp = false;
};

Line readLine( const QString& text )
{
    const auto match = packetLineRegex().match( text );
    REQUIRE( match.hasMatch() );
    Line line;
    line.protocol = match.captured( "protocol" );
    line.info = match.captured( "body" );
    // The tunnels the packet came through, as the Packet Formatter names
    // them before its Info (pcap_parser.cpp: enterTunnel's callers)
    static const QRegularExpression tunnel(
        R"(^(VXLAN(?: VNI \d+)?|GRE(?: key=0x[\dA-F]+)?|IPv[46]-in-IPv[46]) \| )" );
    for ( auto t = tunnel.match( line.info ); t.hasMatch(); t = tunnel.match( line.info ) ) {
        line.info = line.info.mid( t.capturedLength() );
    }

    auto rest = line.info;
    while ( rest.startsWith( "[TCP " ) && rest.contains( "] " ) ) {
        const auto end = rest.indexOf( "] " );
        line.markers << rest.mid( 1, end - 1 );
        rest = rest.mid( end + 2 );
    }
    // "50000 → 80 [ACK, PSH] Seq=…": a TCP segment, as UDP says Len= there
    const auto words = rest.split( ' ' );
    if ( words.size() >= 4 && words[ 1 ] == QString::fromUtf8( "\xe2\x86\x92" )
         && words[ 3 ].startsWith( '[' ) ) {
        const auto open = rest.indexOf( '[' );
        const auto close = rest.indexOf( ']', open );
        if ( close > open ) {
            line.tcp = true;
            line.flags = rest.mid( open + 1, close - open - 1 ).split( ", " );
            line.afterFlags = rest.mid( close + 1 );
        }
    }
    const auto separator = line.info.indexOf( " | " );
    if ( separator >= 0 ) {
        line.description = line.info.mid( separator + 3 );
    }
    return line;
}

/// The analysis markers that are no problem, as Wireshark's "Bad TCP"
/// colouring rule leaves them out.
const QStringList kHarmlessMarkers{ "TCP Window Update", "TCP Keep-Alive", "TCP Keep-Alive ACK" };

bool tcpProblem( const Line& l )
{
    for ( const auto& marker : l.markers ) {
        if ( !kHarmlessMarkers.contains( marker ) ) {
            return true;
        }
    }
    return l.tcp && l.afterFlags.contains( "[bogus TCP header length" );
}

bool tcpRst( const Line& l )
{
    return l.tcp && l.flags.contains( "RST" );
}

bool tcpSynFin( const Line& l )
{
    return l.tcp && ( l.flags.contains( "SYN" ) || l.flags.contains( "FIN" ) );
}

/// Wireshark's "ICMP errors": ICMP types 3, 4, 5 and 11, ICMPv6 types 1 to
/// 4, which the plugin names all.
bool icmpError( const Line& l )
{
    const auto named = [ &l ]( const QStringList& names ) {
        for ( const auto& name : names ) {
            if ( l.info == name || l.info.startsWith( name + ' ' ) ) {
                return true;
            }
        }
        return false;
    };
    if ( l.protocol == "ICMP" ) {
        return named( { "Destination unreachable", "Source quench", "Redirect", "Time exceeded" } );
    }
    if ( l.protocol == "ICMPv6" ) {
        return named(
            { "Destination unreachable", "Packet too big", "Time exceeded", "Parameter problem" } );
    }
    return false;
}

bool dns( const Line& l )
{
    return l.protocol == "DNS" || l.protocol == "mDNS";
}

bool dnsNxdomain( const Line& l )
{
    return dns( l ) && l.description.contains( "[NXDOMAIN]" );
}

bool http( const Line& l )
{
    static const QStringList methods{ "GET",     "HEAD",    "POST",  "PUT",  "DELETE",
                                      "CONNECT", "OPTIONS", "TRACE", "PATCH" };
    if ( !l.protocol.startsWith( "HTTP" ) ) {
        return false;
    }
    const auto words = l.description.split( ' ' );
    return ( words.size() >= 3 && methods.contains( words[ 0 ] )
             && words[ 2 ].startsWith( "HTTP/" ) )
           || ( l.description.startsWith( "HTTP/" ) && l.description.size() > 5
                && l.description[ 5 ].isDigit() );
}

bool httpError( const Line& l )
{
    if ( !http( l ) || !l.description.startsWith( "HTTP/" ) ) {
        return false;
    }
    // "HTTP/1.1 404 Not Found, Content-Type: …", or "HTTP/1.1 500, …"
    auto status = l.description.section( ' ', 1, 1 );
    if ( status.endsWith( ',' ) ) {
        status.chop( 1 );
    }
    return status.size() == 3 && ( status[ 0 ] == '4' || status[ 0 ] == '5' )
           && status[ 1 ].isDigit() && status[ 2 ].isDigit();
}

bool tls( const Line& l )
{
    return l.protocol.startsWith( "TLS" );
}

bool icmp( const Line& l )
{
    return l.protocol == "ICMP" || l.protocol == "ICMPv6";
}

bool arp( const Line& l )
{
    return l.protocol == "ARP";
}

using Predicate = std::function<bool( const Line& )>;

const std::map<QString, Predicate>& highlighterRules()
{
    static const std::map<QString, Predicate> rules{
        { "TCP problems", tcpProblem },
        { "TCP RST", tcpRst },
        { "ICMP errors", icmpError },
        { "DNS NXDOMAIN", dnsNxdomain },
        { "HTTP 4xx/5xx", httpError },
        { "TCP SYN/FIN", tcpSynFin },
        { "TLS", tls },
        { "ARP", arp },
    };
    return rules;
}

const std::map<QString, Predicate>& filterRules()
{
    static const std::map<QString, Predicate> rules{
        { "TCP handshakes", tcpSynFin },
        { "TCP errors", []( const Line& l ) { return tcpProblem( l ) || tcpRst( l ); } },
        { "DNS", dns },
        { "HTTP", http },
        { "TLS", tls },
        { "ICMP", icmp },
        { "ARP", arp },
    };
    return rules;
}

// ── The corpus ─────────────────────────────────────────────────────────────

using Numbers = std::set<int>;

/// The packets each rule matches in each committed corpus text; a rule not
/// listed matches none.  A corpus text that is not here fails the test, so
/// that a new one gets its list.
const std::map<QString, std::map<QString, Numbers>>& expectedMatches()
{
    static const std::map<QString, std::map<QString, Numbers>> expected{
        { "dhcp-ntp.txt", {} },
        { "dns.txt",
          {
              { "DNS NXDOMAIN", { 14 } },
              { "TCP SYN/FIN", { 17, 18 } }, // DNS over TCP
              { "TCP handshakes", { 17, 18 } },
              { "DNS", { 1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12,
                         13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24 } },
          } },
        { "icmp.txt",
          {
              // Unreachable, time exceeded, fragmentation needed, redirect,
              // unreachable without a quote; ICMPv6 unreachable, too big
              { "ICMP errors", { 3, 4, 5, 6, 7, 14, 15 } },
              { "ICMP", { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
          } },
        { "interfaces.txt",
          {
              { "TCP SYN/FIN", { 3, 5 } },
              { "TCP handshakes", { 3, 5 } },
              { "DNS", { 1, 6 } },
              { "ICMP", { 2, 4 } },
          } },
        { "loopback-be-ns.txt",
          {
              { "TCP SYN/FIN", { 2 } },
              { "TCP handshakes", { 2 } },
          } },
        { "mixed.txt",
          {
              { "TCP problems", { 14, 15, 16, 18, 19 } }, // retransmissions, bogus length
              { "TCP SYN/FIN", { 1 } },
              { "TLS", { 4 } },
              { "ARP", { 21 } },
              { "TCP handshakes", { 1 } },
              { "TCP errors", { 14, 15, 16, 18, 19 } },
              { "DNS", { 5, 8 } },
              { "HTTP", { 2, 3 } },
              { "ICMP", { 7, 20 } },
          } },
        { "mqtt.txt",
          {
              { "TCP SYN/FIN", { 1, 2, 21, 22, 31, 32 } },
              { "TCP handshakes", { 1, 2, 21, 22, 31, 32 } },
          } },
        { "sip.txt",
          {
              { "TCP SYN/FIN", { 17, 18 } },
              { "TCP handshakes", { 17, 18 } },
          } },
        { "stream-labels.txt",
          {
              { "TCP SYN/FIN", { 1, 2, 10, 11, 13, 14 } },
              { "TLS", { 16, 17, 18 } }, // a Continuation and a bare ACK too
              { "TCP handshakes", { 1, 2, 10, 11, 13, 14 } },
              { "HTTP", { 4, 6 } }, // not the Continuation of the body
          } },
        { "ppp.txt",
          {
              // LCP, PAP, IPCP and PPPoED are none of them
              { "ICMP", { 15, 16, 25, 26 } },
              { "DNS", { 27 } },
          } },
        { "tcp-analysis.txt",
          {
              { "TCP problems", { 5, 8, 9, 10, 12, 14, 16, 17, 18, 19, 20 } },
              { "TCP SYN/FIN", { 1, 2, 24, 25 } },
              { "TCP handshakes", { 1, 2, 24, 25 } },
              { "TCP errors", { 5, 8, 9, 10, 12, 14, 16, 17, 18, 19, 20 } },
          } },
        { "tls.txt",
          {
              { "TCP SYN/FIN", { 1, 2, 12, 13, 21, 22 } },
              { "TLS",
                { 4, 5, 6, 7, 8, 9, 10, 11, 15, 16, 17, 18, 19, 20, 24, 25 } }, // Continuations too
              { "TCP handshakes", { 1, 2, 12, 13, 21, 22 } },
          } },
        { "tunnels.txt",
          {
              // The packets inside the tunnels, as if they were not
              { "TCP SYN/FIN", { 1, 2, 8, 11 } },
              { "ARP", { 5 } },
              { "TCP handshakes", { 1, 2, 8, 11 } },
              { "DNS", { 7, 10, 13 } },
              { "HTTP", { 4 } },
              { "ICMP", { 6, 12, 14 } },
          } },
        { "wifi.txt",
          {
              // 802.11 frames and EAPOL are none of them
              { "ARP", { 10, 11 } },
              { "ICMP", { 14, 15 } },
          } },
    };
    return expected;
}

/// The packet lines of a corpus text, its header left out.
QStringList packetLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    if ( !lines.isEmpty() && lines.last().isEmpty() ) {
        lines.removeLast();
    }
    REQUIRE_FALSE( lines.isEmpty() );
    lines.removeFirst();
    return lines;
}

/// The packet numbers of the lines @p rule matches.
Numbers matchedNumbers( const Rule& rule, const QStringList& lines )
{
    Numbers numbers;
    for ( const auto& line : lines ) {
        if ( matches( rule, line ) ) {
            numbers.insert( line.section( ' ', 0, 0 ).toInt() );
        }
    }
    return numbers;
}

std::string describe( const Numbers& numbers )
{
    std::string text;
    for ( const auto n : numbers ) {
        text += ( text.empty() ? "" : " " ) + std::to_string( n );
    }
    return "{" + text + "}";
}

/// A packet line as the plugin formats it, with @p protocol and @p info,
/// carried through @p tunnels, outermost first.
QString packetLine( const char* protocol, const std::string& info, bool withPorts = true,
                    const std::vector<std::string>& tunnels = {} )
{
    PacketRecord pkt;
    pkt.number = 7;
    pkt.timestampSec = 1700000000;
    pkt.srcIp = "192.168.1.1";
    pkt.dstIp = "192.168.1.2";
    pkt.protocol = protocol;
    pkt.capturedLen = pkt.originalLen = 60;
    pkt.info = info;
    for ( const auto& name : tunnels ) {
        pkt.tunnels.push_back( { name, "192.0.2.1", "192.0.2.2" } );
    }
    return QString::fromStdString(
        formatPacketLine( pkt, pkt.timestampSec, 0, withPorts ? 3 : kNoStream ) );
}

const std::string kArrow = "\xe2\x86\x92";

} // namespace

SCENARIO( "The highlighter set and the filter group import into LogSquirl", "[presets]" )
{
    GIVEN( "the two files in presets/" )
    {
        const auto highlighters = loadHighlighters();
        const auto filters = loadFilters();

        THEN( "they hold the highlighters and filters the README lists, with valid patterns" )
        {
            QStringList filterNames;
            for ( const auto& filter : filters ) {
                filterNames << filter.name;
            }
            REQUIRE( filterNames
                     == QStringList{ "TCP handshakes", "TCP errors", "DNS", "HTTP", "TLS", "ICMP",
                                     "ARP" } );
            for ( const auto& rule : highlighters ) {
                INFO( rule.name.toStdString() );
                REQUIRE( QRegularExpression( rule.pattern ).isValid() );
                REQUIRE( rule.fore.isValid() );
                REQUIRE( rule.back.isValid() );
            }
            for ( const auto& rule : filters ) {
                INFO( rule.name.toStdString() );
                REQUIRE( QRegularExpression( rule.pattern ).isValid() );
            }
        }

        THEN( "no pattern has a capture group, so a highlighter colours its whole line" )
        {
            for ( const auto& rule : highlighters ) {
                INFO( rule.name.toStdString() );
                REQUIRE( QRegularExpression( rule.pattern ).captureCount() == 0 );
            }
        }

        THEN( "every pattern starts at the line's start, so that only a column decides" )
        {
            for ( const auto* rules : { &highlighters, &filters } ) {
                for ( const auto& rule : *rules ) {
                    INFO( rule.name.toStdString() );
                    REQUIRE( rule.pattern.startsWith( '^' ) );
                }
            }
        }
    }
}

SCENARIO( "The highlighters and filters match the corpus lines they are meant for",
          "[presets][corpus]" )
{
    const auto highlighters = loadHighlighters();
    const auto filters = loadFilters();
    const QDir dir( QStringLiteral( TCPDUMP_CORPUS_DIR ) );

    std::vector<std::pair<const std::vector<Rule>*, const std::map<QString, Predicate>*>> sets{
        { &highlighters, &highlighterRules() }, { &filters, &filterRules() }
    };

    GIVEN( "the committed corpus texts" )
    {
        const auto texts = dir.entryList( { "*.txt" }, QDir::Files, QDir::Name );
        REQUIRE( texts.size() >= 2 );

        THEN( "each pattern matches exactly the packets listed for it" )
        {
            for ( const auto& text : texts ) {
                INFO( "corpus text: " << text.toStdString() );
                const auto expected = expectedMatches().find( text );
                REQUIRE( expected != expectedMatches().end() );
                const auto lines = packetLines( dir.filePath( text ) );
                for ( const auto& [ rules, predicates ] : sets ) {
                    for ( const auto& rule : *rules ) {
                        INFO( "rule: " << rule.name.toStdString() );
                        const auto listed = expected->second.find( rule.name );
                        const auto want
                            = listed == expected->second.end() ? Numbers{} : listed->second;
                        REQUIRE( describe( matchedNumbers( rule, lines ) ) == describe( want ) );
                    }
                }
            }
        }
    }

    GIVEN( "every corpus text, the local real captures' included" )
    {
        auto paths = QStringList{};
        for ( const auto& text : dir.entryList( { "*.txt" }, QDir::Files, QDir::Name ) ) {
            paths << dir.filePath( text );
        }
        const QDir local( dir.filePath( "local" ) );
        for ( const auto& text : local.entryList( { "*.txt" }, QDir::Files, QDir::Name ) ) {
            paths << local.filePath( text );
        }

        THEN( "each pattern matches the lines whose columns its rule picks, and no other" )
        {
            for ( const auto& path : paths ) {
                for ( const auto& text : packetLines( path ) ) {
                    INFO( "line: " << text.toStdString() );
                    const auto line = readLine( text );
                    for ( const auto& [ rules, predicates ] : sets ) {
                        REQUIRE( rules->size() == predicates->size() );
                        for ( const auto& rule : *rules ) {
                            INFO( "rule: " << rule.name.toStdString() );
                            REQUIRE( matches( rule, text ) == predicates->at( rule.name )( line ) );
                        }
                    }
                }
            }
        }
    }
}

SCENARIO( "The highlighters and filters match the same packets in every Line Layout",
          "[presets][corpus]" )
{
    const auto highlighters = loadHighlighters();
    const auto filters = loadFilters();
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    GIVEN( "the committed corpus captures, converted with each choice of columns" )
    {
        THEN( "each pattern matches exactly the packets listed for it" )
        {
            for ( const auto& capture : tcpdump_test::committedCaptures() ) {
                const auto text = QFileInfo( capture ).completeBaseName() + ".txt";
                const auto expected = expectedMatches().find( text );
                REQUIRE( expected != expectedMatches().end() );
                for ( const auto& layout : tcpdump_test::allLineLayouts() ) {
                    INFO( "capture: " << QFileInfo( capture ).fileName().toStdString() << ", "
                                      << tcpdump_test::describeLayout( layout ) );
                    const auto lines = tcpdump_test::convertedLines( capture, layout, out.path() );
                    for ( const auto* rules : { &highlighters, &filters } ) {
                        for ( const auto& rule : *rules ) {
                            INFO( "rule: " << rule.name.toStdString() );
                            const auto listed = expected->second.find( rule.name );
                            const auto want
                                = listed == expected->second.end() ? Numbers{} : listed->second;
                            REQUIRE( describe( matchedNumbers( rule, lines ) )
                                     == describe( want ) );
                        }
                    }
                }
            }
        }
    }
}

SCENARIO( "The highlighters and filters read Info as the plugin writes it", "[presets]" )
{
    const auto highlighters = loadHighlighters();
    const auto filters = loadFilters();

    // Lines the corpus has none of, each with what colours it and the
    // filters that show it
    struct Case {
        QString line;
        QString colour;
        QStringList filters;
    };
    const std::vector<Case> cases{
        { packetLine( "TCP", "443 " + kArrow + " 50100 [ACK, RST] Seq=1 Ack=1 Win=0" ),
          "TCP RST",
          { "TCP errors" } },
        { packetLine( "TCP", "443 " + kArrow + " 50100 [RST] Seq=1 Win=0" ),
          "TCP RST",
          { "TCP errors" } },
        { packetLine( "HTTPS",
                      "[TCP Retransmission] 50100 " + kArrow + " 443 [SYN] Seq=0 Win=64240" ),
          "TCP problems",
          { "TCP handshakes", "TCP errors" } },
        { packetLine( "HTTP",
                      "[TCP Dup ACK 7#1] 80 " + kArrow + " 40000 [ACK] Seq=1 Ack=101 Win=1" ),
          "TCP problems",
          { "TCP errors" } },
        { packetLine( "HTTP",
                      "[TCP Window Update] 80 " + kArrow + " 40000 [ACK] Seq=1 Ack=1 Win=9" ),
          "",
          {} },
        { packetLine( "HTTP", "[TCP Keep-Alive] 40000 " + kArrow + " 80 [ACK] Seq=0 Ack=1 Win=9" ),
          "",
          {} },
        { packetLine( "HTTP",
                      "[TCP Keep-Alive ACK] 80 " + kArrow + " 40000 [ACK] Seq=1 Ack=1 Win=9" ),
          "",
          {} },
        { packetLine( "HTTP", "[TCP Keep-Alive] [TCP ZeroWindow] 80 " + kArrow
                                  + " 40000 [ACK] Seq=1 Ack=1 Win=0" ),
          "TCP problems",
          { "TCP errors" } },
        { packetLine( "HTTP",
                      "40000 " + kArrow + " 80 [ACK, FIN, PSH] Seq=1 Ack=1 Win=9 Len=1 | x" ),
          "TCP SYN/FIN",
          { "TCP handshakes" } },
        { packetLine( "HTTP", "[TCP Previous segment not captured] 80 " + kArrow
                                  + " 40000 [ACK, PSH] Seq=201 Ack=1 Win=9 Len=100" ),
          "TCP problems",
          { "TCP errors" } },
        { packetLine( "HTTP", "[TCP Spurious Retransmission] 80 " + kArrow
                                  + " 40000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=100" ),
          "TCP problems",
          { "TCP errors" } },
        { packetLine( "HTTP", "[TCP ZeroWindowProbeAck] [TCP ZeroWindow] 80 " + kArrow
                                  + " 40000 [ACK] Seq=1 Ack=1 Win=0" ),
          "TCP problems",
          { "TCP errors" } },
        { packetLine( "HTTPS-Alt", "50443 " + kArrow + " 8443 [SYN] Seq=0 Win=64240" ),
          "TCP SYN/FIN",
          { "TCP handshakes" } },
        { packetLine( "DNS", "53 " + kArrow
                                 + " 40000 Len=40 | Standard query response 0x1a2b A nope.example "
                                   "[NXDOMAIN]" ),
          "DNS NXDOMAIN",
          { "DNS" } },
        { packetLine( "mDNS", "5353 " + kArrow
                                  + " 5353 Len=40 | Standard query response 0x0000 A nope.local "
                                    "[NXDOMAIN]" ),
          "DNS NXDOMAIN",
          { "DNS" } },
        { packetLine( "DNS", "53 " + kArrow
                                 + " 40000 Len=40 | Standard query response 0x1a2b A example.org "
                                   "A 93.184.216.34" ),
          "",
          { "DNS" } },
        { packetLine( "DNS", "53 " + kArrow
                                 + " 40000 Len=40 | Standard query response 0x1a2b A example.org "
                                   "[SERVFAIL]" ),
          "",
          { "DNS" } },
        { packetLine( "HTTP", "80 " + kArrow
                                  + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | HTTP/1.1 404 "
                                    "Not Found, Content-Type: text/html, Content-Length: 9" ),
          "HTTP 4xx/5xx",
          { "HTTP" } },
        { packetLine( "HTTP", "80 " + kArrow
                                  + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | HTTP/1.1 503 "
                                    "Service Unavailable" ),
          "HTTP 4xx/5xx",
          { "HTTP" } },
        { packetLine( "HTTP", "80 " + kArrow
                                  + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | HTTP/1.1 500, "
                                    "Content-Length: 0" ),
          "HTTP 4xx/5xx",
          { "HTTP" } },
        { packetLine( "HTTP", "80 " + kArrow
                                  + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | HTTP/1.1 301 "
                                    "Moved Permanently, Content-Length: 404" ),
          "",
          { "HTTP" } },
        { packetLine( "HTTP", "50000 " + kArrow
                                  + " 80 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | POST "
                                    "example.com/api HTTP/1.1" ),
          "",
          { "HTTP" } },
        { packetLine( "HTTP", "80 " + kArrow
                                  + " 50000 [ACK, PSH] Seq=31 Ack=1 Win=9 Len=30 | Continuation: "
                                    "body | HTTP/1.1 404 Not Found" ),
          "",
          {} },
        { packetLine( "HTTP2", "50000 " + kArrow
                                   + " 80 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | Magic, "
                                     "SETTINGS[0], WINDOW_UPDATE[0]" ),
          "",
          {} },
        { packetLine( "HTTP-Alt", "8080 " + kArrow
                                      + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=9 | hello [RST]" ),
          "",
          {} },
        { packetLine( "SSDP", "1900 " + kArrow + " 1900 Len=90 | HTTP/1.1 404 Not Found" ),
          "",
          {} },
        { packetLine( "ICMP",
                      "Destination unreachable (Port unreachable) for 10.0.0.1:51234 " + kArrow
                          + " 192.168.1.5:53 UDP",
                      false ),
          "ICMP errors",
          { "ICMP" } },
        { packetLine( "ICMP", "Time exceeded (TTL exceeded in transit)", false ),
          "ICMP errors",
          { "ICMP" } },
        { packetLine( "ICMP", "Source quench", false ), "ICMP errors", { "ICMP" } },
        { packetLine( "ICMP", "Redirect (Redirect for host) gateway=192.168.1.254", false ),
          "ICMP errors",
          { "ICMP" } },
        { packetLine( "ICMP", "Parameter problem (Pointer indicates the error)", false ),
          "",
          { "ICMP" } },
        { packetLine( "ICMP", "Echo (ping) request id=0x1234, seq=7", false ), "", { "ICMP" } },
        { packetLine( "ICMP", "Type=42 Code=0", false ), "", { "ICMP" } },
        { packetLine( "ICMPv6", "Packet too big mtu=1280", false ), "ICMP errors", { "ICMP" } },
        { packetLine( "ICMPv6", "Parameter problem (Erroneous header field) pointer=6", false ),
          "ICMP errors",
          { "ICMP" } },
        { packetLine( "ICMPv6", "Redirect fe80::1 via fe80::2", false ), "", { "ICMP" } },
        { packetLine( "ICMPv6", "Neighbor solicitation for fe80::1", false ), "", { "ICMP" } },
        { packetLine( "QUIC", "50000 " + kArrow
                                  + " 443 Len=1200 | Initial, Version 1, DCID=0102, SCID=0a0b" ),
          "",
          {} },
        { packetLine( "TLS", "50443 " + kArrow
                                 + " 443 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=40 | Client Hello, "
                                   "SNI=example.com, TLS 1.3, ALPN=h2,http/1.1" ),
          "TLS",
          { "TLS" } },
        { packetLine( "ARP", "192.168.1.1 is at 00:11:22:33:44:55", false ), "ARP", { "ARP" } },
        { packetLine( "TCP", "443 " + kArrow + " 50100 [RST] Seq=1 Win=0", true,
                      { "VXLAN VNI 100" } ),
          "TCP RST",
          { "TCP errors" } },
        { packetLine( "HTTPS",
                      "[TCP Retransmission] 50100 " + kArrow + " 443 [SYN] Seq=0 Win=64240", true,
                      { "VXLAN VNI 100", "GRE key=0x0000002A" } ),
          "TCP problems",
          { "TCP handshakes", "TCP errors" } },
        { packetLine( "HTTP",
                      "80 " + kArrow
                          + " 50000 [ACK, PSH] Seq=1 Ack=1 Win=9 Len=30 | HTTP/1.1 404 "
                            "Not Found",
                      true, { "GRE" } ),
          "HTTP 4xx/5xx",
          { "HTTP" } },
        { packetLine( "DNS",
                      "53 " + kArrow
                          + " 40000 Len=40 | Standard query response 0x1a2b A nope.example "
                            "[NXDOMAIN]",
                      true, { "IPv6-in-IPv4" } ),
          "DNS NXDOMAIN",
          { "DNS" } },
        { packetLine( "ICMP", "Time exceeded (TTL exceeded in transit)", false,
                      { "IPv4-in-IPv6" } ),
          "ICMP errors",
          { "ICMP" } },
        { packetLine( "GRE", "GRE, protocol type 0x88BE", false ), "", {} },
    };

    for ( const auto& c : cases ) {
        GIVEN( "the line " + c.line.toStdString() )
        {
            THEN( "it is coloured by " + ( c.colour.isEmpty() ? "none" : c.colour.toStdString() ) )
            {
                REQUIRE( colouredBy( highlighters, c.line ) == c.colour );
            }

            THEN( "the filters that show it are those its rules pick" )
            {
                QStringList shown;
                for ( const auto& rule : filters ) {
                    if ( matches( rule, c.line ) ) {
                        shown << rule.name;
                    }
                }
                REQUIRE( shown == c.filters );

                const auto line = readLine( c.line );
                for ( const auto& rule : filters ) {
                    INFO( "filter: " << rule.name.toStdString() );
                    REQUIRE( filterRules().at( rule.name )( line ) == shown.contains( rule.name ) );
                }
                for ( const auto& rule : highlighters ) {
                    INFO( "highlighter: " << rule.name.toStdString() );
                    REQUIRE( highlighterRules().at( rule.name )( line )
                             == matches( rule, c.line ) );
                }
            }
        }
    }
}
