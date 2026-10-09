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
 * @file display_filter_test.cpp
 * @brief BDD tests for display filters: the parser of the supported subset,
 *        its errors, and the patterns, checked against a reference
 *        evaluation of the filter over each corpus line's columns.
 */

#include <catch2/catch.hpp>

#include "corpus_layouts.h"
#include "display_filter.h"
#include "display_filter_dialog.h"
#include "fakehost.h"
#include "plugin.h"
#include "regex_lab.h"
#include "sidebarwidget.h"

#include <QApplication>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QStringList>
#include <QTemporaryDir>
#include <QTimer>

#include <algorithm>
#include <functional>
#include <map>
#include <set>

using namespace tcpdump;
using namespace tcpdump_test;

extern "C" int logsquirl_plugin_init_ex( const LogSquirlHostApi* api, void* handle,
                                         size_t api_size );
extern "C" void logsquirl_plugin_shutdown( void );

namespace {

const QString kArrow = QString::fromUtf8( "\xe2\x86\x92" );

/// The lines @p pattern matches, by their number from 1, as the Regex Lab
/// does with Match case.
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

/// The lines @p filter selects, through its pattern.
std::set<int> selected( const QString& filter, const QStringList& lines )
{
    const auto translated = displayFilterPattern( filter );
    INFO( filter.toStdString() + ": " + translated.error.toStdString() );
    REQUIRE( translated.error.isEmpty() );
    return matched( translated.pattern, lines );
}

/// Run @p work on the display filter dialog the next call opens, once it is
/// shown.
void whenDialogOpens( std::function<void( DisplayFilterDialog& )> work )
{
    QTimer::singleShot( 0, [ work = std::move( work ) ] {
        auto* dialog = qobject_cast<DisplayFilterDialog*>( QApplication::activeModalWidget() );
        if ( !dialog ) {
            // Look among the top-level widgets, for a platform without focus.
            for ( auto* widget : QApplication::topLevelWidgets() ) {
                if ( auto* found = qobject_cast<DisplayFilterDialog*>( widget );
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

// ── The reference evaluation ─────────────────────────────────────────────

/// A packet line's columns, read without any pattern of the plugin but the
/// Log Format's, and the ports of its Info read word by word.
struct Columns {
    bool packet = false;
    QString stream;
    QString source;
    QString destination;
    QString protocol;
    uint64_t length = 0;
    enum class Transport { None, Tcp, Udp } transport = Transport::None;
    uint64_t sourcePort = 0;
    uint64_t destinationPort = 0;
};

bool isNumber( const QString& text )
{
    return !text.isEmpty()
           && std::all_of( text.begin(), text.end(), []( QChar c ) { return c.isDigit(); } );
}

/// @p text without its first word and the spaces after it.
QString afterWord( const QString& text )
{
    const auto space = text.indexOf( ' ' );
    if ( space < 0 ) {
        return {};
    }
    int next = space;
    while ( next < text.size() && text[ next ] == ' ' ) {
        ++next;
    }
    return text.mid( next );
}

/// The address of a Source or Destination column, without the name host
/// names put behind it in parentheses.
QString withoutName( const QString& column )
{
    const auto open = column.indexOf( '(' );
    return open > 0 && column.endsWith( ')' ) ? column.left( open ) : column;
}

/// The columns of @p line, converted with MAC columns if @p macColumns,
/// the addresses without their names.
Columns columnsOf( const QString& line, bool macColumns )
{
    Columns columns;
    const auto match = packetLineRegex().match( line );
    if ( !match.hasMatch() ) {
        return columns;
    }
    columns.packet = true;
    columns.stream = match.captured( "stream" );
    columns.source = withoutName( match.captured( "source" ) );
    columns.destination = withoutName( match.captured( "destination" ) );
    columns.protocol = match.captured( "protocol" );
    columns.length = match.captured( "length" ).toULongLong();

    auto info = match.captured( "body" );
    if ( macColumns ) {
        info = afterWord( afterWord( info ) );
    }
    // The tunnels, outermost first, then the TCP analysis markers
    const auto separator = QStringLiteral( " | " );
    while ( ( info.startsWith( "VXLAN" ) || info.startsWith( "GRE" )
              || info.startsWith( "IPv4-in-" ) || info.startsWith( "IPv6-in-" ) )
            && info.contains( separator ) ) {
        info = info.mid( info.indexOf( separator ) + separator.size() );
    }
    while ( info.startsWith( "[TCP " ) && info.contains( "] " ) ) {
        info = info.mid( info.indexOf( "] " ) + 2 );
    }
    const auto words = info.split( ' ' );
    if ( words.size() >= 4 && isNumber( words[ 0 ] ) && words[ 1 ] == kArrow
         && isNumber( words[ 2 ] ) ) {
        if ( words[ 3 ].startsWith( '[' ) ) {
            columns.transport = Columns::Transport::Tcp;
        }
        else if ( words[ 3 ].startsWith( "Len=" ) ) {
            columns.transport = Columns::Transport::Udp;
        }
        columns.sourcePort = words[ 0 ].toULongLong();
        columns.destinationPort = words[ 2 ].toULongLong();
    }
    return columns;
}

bool isIpv4Text( const QString& text, uint32_t* value = nullptr )
{
    const auto parts = text.split( '.' );
    if ( parts.size() != 4 ) {
        return false;
    }
    uint32_t address = 0;
    for ( const auto& part : parts ) {
        if ( !isNumber( part ) || part.toUInt() > 255 ) {
            return false;
        }
        address = address << 8 | part.toUInt();
    }
    if ( value ) {
        *value = address;
    }
    return true;
}

bool isIpv6Text( const QString& text )
{
    return text.contains( "::" ) || text.count( ':' ) == 7;
}

/// The values @p field has in @p columns: none when the packet lacks it.
std::vector<QString> valuesOf( FilterField field, const Columns& columns )
{
    using Transport = Columns::Transport;
    const bool ipv4 = isIpv4Text( columns.source ) && columns.protocol != "ARP";
    const bool ipv6 = isIpv6Text( columns.source );
    const bool tcp = columns.transport == Transport::Tcp;
    const bool udp = columns.transport == Transport::Udp;
    const auto source = QString::number( columns.sourcePort );
    const auto destination = QString::number( columns.destinationPort );
    switch ( field ) {
    case FilterField::IpAddr:
        return ipv4 ? std::vector{ columns.source, columns.destination } : std::vector<QString>{};
    case FilterField::IpSrc:
        return ipv4 ? std::vector{ columns.source } : std::vector<QString>{};
    case FilterField::IpDst:
        return ipv4 ? std::vector{ columns.destination } : std::vector<QString>{};
    case FilterField::Ipv6Addr:
        return ipv6 ? std::vector{ columns.source, columns.destination } : std::vector<QString>{};
    case FilterField::Ipv6Src:
        return ipv6 ? std::vector{ columns.source } : std::vector<QString>{};
    case FilterField::Ipv6Dst:
        return ipv6 ? std::vector{ columns.destination } : std::vector<QString>{};
    case FilterField::TcpPort:
        return tcp ? std::vector{ source, destination } : std::vector<QString>{};
    case FilterField::TcpSrcPort:
        return tcp ? std::vector{ source } : std::vector<QString>{};
    case FilterField::TcpDstPort:
        return tcp ? std::vector{ destination } : std::vector<QString>{};
    case FilterField::UdpPort:
        return udp ? std::vector{ source, destination } : std::vector<QString>{};
    case FilterField::UdpSrcPort:
        return udp ? std::vector{ source } : std::vector<QString>{};
    case FilterField::UdpDstPort:
        return udp ? std::vector{ destination } : std::vector<QString>{};
    case FilterField::TcpStream:
        return tcp && isNumber( columns.stream ) ? std::vector{ columns.stream }
                                                 : std::vector<QString>{};
    case FilterField::UdpStream:
        return udp && isNumber( columns.stream ) ? std::vector{ columns.stream }
                                                 : std::vector<QString>{};
    case FilterField::FrameLen:
        return { QString::number( columns.length ) };
    }
    return {};
}

/// Whether @p value, a value of @p test's field, is the one compared with.
bool equals( const FilterExpression& test, const QString& value )
{
    switch ( test.field ) {
    case FilterField::IpAddr:
    case FilterField::IpSrc:
    case FilterField::IpDst: {
        uint32_t address = 0;
        uint32_t compared = 0;
        REQUIRE( isIpv4Text( test.address, &compared ) );
        if ( !isIpv4Text( value, &address ) ) {
            return false;
        }
        const int prefix = test.prefixLength < 0 ? 32 : test.prefixLength;
        const uint32_t mask = prefix == 0 ? 0 : ~0u << ( 32 - prefix );
        return ( address & mask ) == compared;
    }
    case FilterField::Ipv6Addr:
    case FilterField::Ipv6Src:
    case FilterField::Ipv6Dst:
        return value == test.address;
    default:
        return value.toULongLong() == test.number;
    }
}

/// Whether @p value compares with @p test's number as @p test says.
bool compares( const FilterExpression& test, const QString& value )
{
    const auto number = value.toULongLong();
    switch ( test.op ) {
    case FilterOperator::Less:
        return number < test.number;
    case FilterOperator::Greater:
        return number > test.number;
    case FilterOperator::LessEqual:
        return number <= test.number;
    case FilterOperator::GreaterEqual:
        return number >= test.number;
    default:
        return equals( test, value );
    }
}

/// Whether @p expression selects the packet with @p columns.
bool evaluate( const FilterExpression& expression, const Columns& columns )
{
    using Kind = FilterExpression::Kind;
    const auto& operands = expression.operands;
    switch ( expression.kind ) {
    case Kind::And:
        return std::all_of( operands.begin(), operands.end(),
                            [ &columns ]( const auto& e ) { return evaluate( e, columns ); } );
    case Kind::Or:
        return std::any_of( operands.begin(), operands.end(),
                            [ &columns ]( const auto& e ) { return evaluate( e, columns ); } );
    case Kind::Not:
        return !evaluate( operands.front(), columns );
    case Kind::Protocol:
        return columns.protocol.compare( expression.protocol, Qt::CaseInsensitive ) == 0;
    case Kind::Comparison:
        break;
    }
    const auto values = valuesOf( expression.field, columns );
    switch ( expression.op ) {
    case FilterOperator::Present:
        return !values.empty();
    case FilterOperator::NotEqual:
        return !values.empty()
               && std::none_of( values.begin(), values.end(), [ &expression ]( const auto& v ) {
                      return equals( expression, v );
                  } );
    default:
        return std::any_of( values.begin(), values.end(), [ &expression ]( const auto& v ) {
            return compares( expression, v );
        } );
    }
}

/// The lines @p filter selects by the reference evaluation; a line that is
/// no packet line never.
std::set<int> evaluated( const QString& filter, const QStringList& lines, bool macColumns )
{
    const auto parsed = parseDisplayFilter( filter );
    REQUIRE( parsed.error.isEmpty() );
    std::set<int> numbers;
    for ( int i = 0; i < lines.size(); ++i ) {
        const auto columns = columnsOf( lines[ i ], macColumns );
        if ( columns.packet && evaluate( parsed.expression, columns ) ) {
            numbers.insert( i + 1 );
        }
    }
    return numbers;
}

/// Filters on the values @p lines have, a few of each field.
QStringList filtersFrom( const QStringList& lines, bool macColumns )
{
    std::set<QString> ipv4;
    std::set<QString> ipv6;
    std::set<uint64_t> tcpPorts;
    std::set<uint64_t> udpPorts;
    std::set<QString> streams;
    std::set<uint64_t> lengths;
    std::set<QString> protocols;
    for ( const auto& line : lines ) {
        const auto columns = columnsOf( line, macColumns );
        if ( !columns.packet ) {
            continue;
        }
        for ( const auto& address : { columns.source, columns.destination } ) {
            if ( isIpv4Text( address ) ) {
                ipv4.insert( address );
            }
            else if ( isIpv6Text( address ) ) {
                ipv6.insert( address );
            }
        }
        if ( columns.transport != Columns::Transport::None ) {
            auto& ports = columns.transport == Columns::Transport::Tcp ? tcpPorts : udpPorts;
            ports.insert( columns.sourcePort );
            ports.insert( columns.destinationPort );
        }
        streams.insert( columns.stream );
        lengths.insert( columns.length );
        if ( columns.protocol.front().isLetter()
             && std::all_of( columns.protocol.begin(), columns.protocol.end(), []( QChar c ) {
                    return c.isLetterOrNumber() || c == '-' || c == '_';
                } ) ) {
            protocols.insert( columns.protocol.toLower() );
        }
    }

    QStringList filters;
    const auto take = []( const auto& set ) {
        // At most eight values, spread over the set
        std::vector<typename std::decay_t<decltype( set )>::value_type> some;
        const auto step = std::max<size_t>( 1, set.size() / 8 );
        size_t i = 0;
        for ( const auto& value : set ) {
            if ( i++ % step == 0 ) {
                some.push_back( value );
            }
        }
        return some;
    };
    for ( const auto& address : take( ipv4 ) ) {
        filters << "ip.addr == " + address << "ip.src == " + address + " && !tcp"
                << "ip.dst eq " + address + " || udp" << "ip.addr != " + address
                << "ip.addr == " + address + "/24";
    }
    for ( const auto& address : take( ipv6 ) ) {
        filters << "ipv6.addr == " + address << "ipv6.src == " + address.toUpper()
                << "!(ipv6.dst != " + address + ")";
    }
    for ( const auto port : take( tcpPorts ) ) {
        filters << QString( "tcp.port == %1" ).arg( port )
                << QString( "tcp.srcport < %1 and tcp.dstport >= %1" ).arg( port )
                << QString( "tcp.port != %1" ).arg( port );
    }
    for ( const auto port : take( udpPorts ) ) {
        filters << QString( "udp.port == %1" ).arg( port )
                << QString( "udp.dstport > %1 || udp.srcport <= %1" ).arg( port )
                << QString( "not udp.port != %1" ).arg( port );
    }
    for ( const auto& stream : take( streams ) ) {
        if ( isNumber( stream ) ) {
            filters << "tcp.stream == " + stream << "udp.stream == " + stream
                    << "tcp.stream > " + stream << "!(udp.stream < " + stream + ")";
        }
    }
    for ( const auto length : take( lengths ) ) {
        filters << QString( "frame.len == %1" ).arg( length )
                << QString( "frame.len > %1" ).arg( length )
                << QString( "frame.len le %1 && ip" ).arg( length );
    }
    for ( const auto& protocol : protocols ) {
        filters << protocol << "!" + protocol + " && ipv6";
    }
    return filters;
}

/// Filters for every corpus text, one of each kind at least.
const QStringList kFilters{
    "tcp",
    "udp",
    "ip",
    "ipv6",
    "!tcp",
    "not ip and not ipv6",
    "arp",
    "dns",
    "DNS",
    "http || tls",
    "tcp && !http",
    "frame.len > 1000",
    "frame.len <= 60",
    "frame.len != 54",
    "frame.len >= 100 && frame.len < 200",
    "frame.len",
    "tcp.port == 443",
    "tcp.port == 80 or tcp.port == 8080",
    "udp.port == 53",
    "tcp.port < 1024",
    "tcp.port > 1023",
    "tcp.srcport >= 50000",
    "udp.dstport le 53",
    "udp.srcport == 53 || udp.dstport == 53",
    "tcp.port != 80",
    "udp.port != 53",
    "tcp.port",
    "udp.port",
    "tcp.stream == 0",
    "udp.stream == 0",
    "tcp.stream > 1",
    "!(tcp.stream == 0)",
    "tcp.stream != 0",
    "tcp.stream",
    "udp.stream",
    "ip.addr == 10.0.0.0/8",
    "ip.dst == 192.168.0.0/16",
    "ip.src == 0.0.0.0/0",
    "ip.addr",
    "ipv6.addr",
    "ipv6.src",
    "icmp || icmpv6",
    "!(ip || ipv6) || arp",
    "!(tcp || udp) && !(icmp or arp)",
    "(tcp.port == 443 || udp.port == 443) && !(frame.len < 100)",
};

} // namespace

SCENARIO( "A display filter selects the packet lines it means", "[displayfilter]" )
{
    GIVEN( "packet lines of several kinds, and lines that are none" )
    {
        const auto line = []( const QString& stream, const QString& source,
                              const QString& destination, const QString& protocol, int length,
                              const QString& info ) {
            return QString( "1      %1 2023-11-14 22:13:20.000000Z  0.000000       %2 %3 %4 %5 %6" )
                .arg( stream.leftJustified( 7 ), source.leftJustified( 39 ),
                      destination.leftJustified( 39 ), protocol.leftJustified( 9 ),
                      QString::number( length ).leftJustified( 6 ), info );
        };
        const QStringList lines{
            line( "0", "10.0.0.1", "10.0.0.2", "HTTP", 54, "50000 " + kArrow + " 80 [SYN] Seq=0" ),
            line( "0", "10.0.0.2", "10.0.0.1", "HTTP", 60, "80 " + kArrow + " 50000 [SYN, ACK]" ),
            line( "0", "10.0.0.1", "224.0.0.251", "DNS", 90,
                  "5353 " + kArrow + " 53 Len=48 | Standard query" ),
            line( "1", "fe80::1", "2001:db8::1", "TLS", 1514,
                  "[TCP Retransmission] 443 " + kArrow + " 51000 [ACK] Seq=1" ),
            line( "-", "10.0.0.1", "10.0.0.2", "ARP", 42, "Who has 10.0.0.2? Tell 10.0.0.1" ),
            line( "-", "10.0.0.3", "10.0.0.1", "ICMP", 70,
                  "Destination unreachable (Port unreachable) for 10.0.0.1:53 " + kArrow
                      + " 10.0.0.3:5000 UDP" ),
            line( "2", "10.1.0.10", "10.2.0.20", "HTTP-Alt", 104,
                  "VXLAN VNI 100 | 50000 " + kArrow + " 8080 [SYN] Seq=0" ),
            line( "-", "00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", "LLDP", 60, "Chassis" ),
            "No.    Stream  UTC Time                     Time           Source",
            "2026-10-09 12:00:00 INFO tcp.port == 80 10.0.0.1",
        };

        const std::vector<std::pair<QString, std::set<int>>> table{
            { "tcp", { 1, 2, 4, 7 } },
            { "udp", { 3 } },
            { "ip", { 1, 2, 3, 6, 7 } },
            { "ipv6", { 4 } },
            { "!tcp", { 3, 5, 6, 8 } },
            { "not (ip or ipv6)", { 5, 8 } },
            { "http", { 1, 2 } },
            { "http-alt || Tls", { 4, 7 } },
            { "arp", { 5 } },
            { "ip.addr == 10.0.0.1", { 1, 2, 3, 6 } },
            { "ip.addr != 10.0.0.1", { 7 } },
            { "!(ip.addr == 10.0.0.1)", { 4, 5, 7, 8 } },
            { "ip.src == 10.0.0.1", { 1, 3 } },
            { "ip.dst==10.0.0.1&&tcp", { 2 } },
            { "ip.addr == 10.0.0.0/8", { 1, 2, 3, 6, 7 } },
            { "ip.addr == 10.0.0.0/30", { 1, 2, 3, 6 } },
            { "ip.src == 10.1.0.0/16", { 7 } },
            { "ipv6.addr == 2001:DB8:0::1", { 4 } },
            { "ipv6.src == fe80::1", { 4 } },
            { "tcp.port == 80", { 1, 2 } },
            { "tcp.port == 53", {} },
            { "udp.port == 53", { 3 } },
            { "tcp.dstport == 8080", { 7 } },
            { "tcp.srcport > 1023", { 1, 7 } },
            { "tcp.port <= 80", { 1, 2 } },
            { "tcp.port != 80", { 4, 7 } },
            { "tcp.port gt 65535", {} },
            { "tcp.stream == 0", { 1, 2 } },
            { "udp.stream == 0", { 3 } },
            { "tcp.stream >= 1", { 4, 7 } },
            { "frame.len > 1000", { 4 } },
            { "frame.len < 60", { 1, 5 } },
            { "frame.len == 0x3c", { 2, 8 } },
            { "frame.len != 60 && !ip", { 4, 5 } },
            { "frame.len", { 1, 2, 3, 4, 5, 6, 7, 8 } },
            { "!frame.len", {} },
            { "tcp.port == 80 || udp.port == 53 && ip.dst == 10.0.0.2", { 1, 2 } },
            { "(tcp.port == 80 || udp.port == 53) && ip.dst == 10.0.0.2", { 1 } },
            { "!!tcp", { 1, 2, 4, 7 } },
        };

        for ( const auto& [ filter, expected ] : table ) {
            THEN( "\"" + filter.toStdString() + "\" selects its lines" )
            {
                REQUIRE( selected( filter, lines ) == expected );
                REQUIRE( evaluated( filter, lines, false ) == expected );
            }
        }
    }

    GIVEN( "simple filters" )
    {
        THEN( "a single condition is one pattern from the start of the line" )
        {
            REQUIRE( displayFilterPattern( "frame.len == 54" ).pattern
                     == upToSourcePattern() + R"(\S+ +\S+ +\S+ +54 )" );
            REQUIRE( displayFilterPattern( "dns" ).pattern
                     == upToSourcePattern() + R"(\S+ +\S+ +(?i:dns) +\d+ )" );
            REQUIRE( displayFilterPattern( "ip.src == 10.0.0.1" ).pattern
                     == upToSourcePattern() + R"((?:10\.0\.0\.1))" + nameSuffixPattern()
                            + R"( +\S+ +(?!ARP )\S+ +\d+ )" );
        }

        THEN( "conditions combine as lookaheads at the start of the line" )
        {
            const auto rest = upToSourcePattern().mid( 1 );
            REQUIRE( displayFilterPattern( "dns && frame.len > 99" ).pattern
                     == "^(?=" + rest + R"(\S+ +\S+ +(?i:dns) +\d+ )" + ")(?=" + rest
                            + R"(\S+ +\S+ +\S+ +(?:[1-9]\d{2}|[1-9]\d{3,}) )" + ")" );
            REQUIRE( displayFilterPattern( "!dns" ).pattern
                     == "^(?=" + rest + R"(\S+ +\S+ +\S+ +\d+ )" + ")(?!" + rest
                            + R"(\S+ +\S+ +(?i:dns) +\d+ )" + ")" );
        }
    }
}

SCENARIO( "A display filter outside the subset is rejected with its position", "[displayfilter]" )
{
    struct Rejected {
        QString filter;
        int position;
        QString reason;
    };
    const std::vector<Rejected> table{
        { "", 0, "Type a display filter" },
        { "   ", 0, "Type a display filter" },
        { "tcp.flags.syn == 1", 0, "The field tcp.flags.syn is not supported" },
        { "tcp && http.host == x", 7, "The field http.host is not supported" },
        { "ip.addr = 10.0.0.1", 8, "Compare with ==, not =" },
        { "ip.addr === 10.0.0.1", 8, "\"===\" is not supported" },
        { "tcp & udp", 4, "Combine with && or and" },
        { "tcp | udp", 4, "Combine with || or or" },
        { "tcp ^^ udp", 4, "\"^\" is not supported" },
        { "tcp xor udp", 4, "\"xor\" is not supported" },
        { "http contains \"GET\"", 5, "\"contains\" is not supported" },
        { "frame.len matches 1", 10, "\"matches\" is not supported" },
        { "tcp.port in {80 443}", 9, "\"in\" is not supported" },
        { "eth.src[0:3] == 00:11:22", 7, "Slices are not supported" },
        { "frame.len == \"54\"", 13, "Strings are not supported" },
        { "ip.addr > 10.0.0.1", 8, "ip.addr is compared with == or != only" },
        { "ip.addr == fe80::1", 11, "is an IPv6 address: compare it with ipv6.addr" },
        { "ipv6.src == 10.0.0.1", 12, "is an IPv4 address: compare it with ip.src" },
        { "ip.dst == 10.0.0", 10, "10.0.0 is not an IPv4 address" },
        { "ip.dst == 10.0.0.256", 10, "is not an IPv4 address" },
        { "ipv6.addr == fe80:::1", 13, "is not an IPv6 address" },
        { "ipv6.addr == fe80::/64", 19, "Address prefixes are supported for IPv4 only" },
        { "ip.addr == 10.0.0.0/33", 20, "Expected a prefix length from 0 to 32" },
        { "tcp.port == 70000", 12, "too big for a port" },
        { "tcp.port == http", 12, "http is not a number" },
        { "tcp.srcport == tcp.dstport", 15, "Comparing two fields is not supported" },
        { "tcp.port ==", 11, "Expected a value after ==" },
        { "dns == 1", 4, "dns is a protocol, which is not compared" },
        { "tcp ==", 4, "tcp is a protocol" },
        { "80", 0, "Expected a field or a protocol, not the value 80" },
        { "tcp udp", 4, "Expected && or || here" },
        { "(tcp", 4, "Expected ) to close the ( at column 1" },
        { "tcp)", 3, "This ) closes no (" },
        { "tcp &&", 6, "The filter ends where a field, a protocol or ( is expected" },
        { "!", 1, "The filter ends where" },
        { "tcp && || udp", 7, "Expected a field, a protocol or ( here" },
        { "tcp ; udp", 4, "\";\" is not part of a display filter" },
        { QString( 100000, '(' ) + "tcp" + QString( 100000, ')' ), 64, "nested more than 64 deep" },
        { QString( 100000, '!' ) + "tcp", 64, "nested more than 64 deep" },
        { QString( "not " ).repeated( 100 ) + "tcp", 256, "nested more than 64 deep" },
    };
    for ( const auto& rejected : table ) {
        THEN( "\"" + rejected.filter.toStdString() + "\" is rejected" )
        {
            const auto translated = displayFilterPattern( rejected.filter );
            INFO( translated.error.toStdString() );
            REQUIRE( translated.pattern.isEmpty() );
            REQUIRE( translated.error.contains( rejected.reason ) );
            REQUIRE( translated.errorPosition == rejected.position );
        }
    }
}

SCENARIO( "A number range is an exact pattern", "[displayfilter]" )
{
    const auto numbers = []( const QString& pattern ) {
        const QRegularExpression regex( "^(?:" + pattern + ")$" );
        REQUIRE( regex.isValid() );
        std::vector<uint64_t> found;
        for ( uint64_t n = 0; n < 30000; ++n ) {
            if ( regex.match( QString::number( n ) ).hasMatch() ) {
                found.push_back( n );
            }
        }
        // No number with a leading zero
        REQUIRE_FALSE( regex.match( "07" ).hasMatch() );
        REQUIRE_FALSE( regex.match( "007" ).hasMatch() );
        return found;
    };
    const std::vector<std::pair<uint64_t, uint64_t>> ranges{
        { 0, 0 },       { 0, 9 },     { 7, 7 },        { 3, 17 },    { 0, 99 },
        { 10, 99 },     { 1, 1023 },  { 1024, 65535 }, { 99, 101 },  { 120, 4567 },
        { 1000, 1999 }, { 555, 555 }, { 89, 2001 },    { 0, 29999 }, { 4321, 4329 },
    };
    for ( const auto& [ low, high ] : ranges ) {
        THEN( "from " + std::to_string( low ) + " to " + std::to_string( high ) )
        {
            std::vector<uint64_t> expected;
            for ( auto n = low; n <= high && n < 30000; ++n ) {
                expected.push_back( n );
            }
            REQUIRE( numbers( numberRangePattern( low, high ) ) == expected );
        }
    }

    THEN( "a range without an upper bound takes every longer number" )
    {
        const auto pattern = numberRangePattern( 1234, std::numeric_limits<uint64_t>::max() );
        const auto found = numbers( pattern );
        REQUIRE( found.front() == 1234 );
        REQUIRE( found.size() == 30000 - 1234 );
        REQUIRE( QRegularExpression( "^(?:" + pattern + ")$" )
                     .match( "123456789012345678901234" )
                     .hasMatch() );
    }

    THEN( "an empty range has no pattern" )
    {
        REQUIRE( numberRangePattern( 5, 4 ).isEmpty() );
    }
}

SCENARIO( "Display filters select exactly the corpus lines they mean, in every Line Layout",
          "[displayfilter]" )
{
    QTemporaryDir out;
    REQUIRE( out.isValid() );
    std::map<QString, size_t> selections;

    for ( const auto& capture : committedCaptures() ) {
        for ( const auto& layout : allLineLayouts() ) {
            INFO( QFileInfo( capture ).fileName().toStdString() + ", converted with "
                  + describeLayout( layout ) );
            auto lines = convertedLines( capture, layout, out.path() );
            // Lines that are no packet line, which no filter may select
            lines << "No.    Stream  Source  Destination  Protocol  Length Info"
                  << "2026-10-09 12:00:00 INFO tcp 10.0.0.1 54";
            for ( const auto& filter : kFilters + filtersFrom( lines, layout.macColumns ) ) {
                INFO( filter.toStdString() );
                const auto expected = evaluated( filter, lines, layout.macColumns );
                REQUIRE( selected( filter, lines ) == expected );
                selections[ filter ] += expected.size();
            }
        }
    }

    // Each filter of the list selects some line of the corpus, so that no
    // comparison above is one of two empty sets only.
    for ( const auto& filter : kFilters ) {
        INFO( filter.toStdString() );
        CHECK( selections[ filter ] > 0 );
    }
}

SCENARIO( "Display filter\xe2\x80\xa6 asks for a filter and opens its pattern in the Regex Lab",
          "[displayfilter]" )
{
    GIVEN( "the dialog" )
    {
        DisplayFilterDialog dialog;
        auto* edit = dialog.findChild<QLineEdit*>( "filter" );
        auto* error = dialog.findChild<QLabel*>( "filterError" );
        auto* open = dialog.findChild<QPushButton*>( "openButton" );
        REQUIRE( edit );
        REQUIRE( error );
        REQUIRE( open );

        THEN( "an empty filter cannot be opened, and is no error yet" )
        {
            REQUIRE_FALSE( open->isEnabled() );
            REQUIRE( error->text().isEmpty() );
        }

        WHEN( "a filter outside the subset is typed" )
        {
            edit->setText( "tcp.port == 80 && http.host" );

            THEN( "the column and the reason are shown, and it cannot be opened" )
            {
                REQUIRE( error->text().startsWith( "Column 19: The field http.host is not "
                                                   "supported" ) );
                REQUIRE_FALSE( open->isEnabled() );
                REQUIRE( dialog.pattern().isEmpty() );
            }

            AND_WHEN( "it is corrected" )
            {
                edit->setText( "tcp.port == 80 && http" );

                THEN( "the error goes, and its pattern can be opened" )
                {
                    REQUIRE( error->text().isEmpty() );
                    REQUIRE( open->isEnabled() );
                    REQUIRE( dialog.pattern()
                             == displayFilterPattern( "tcp.port == 80 && http" ).pattern );
                }
            }
        }
    }

    GIVEN( "a plugin loaded by a host with the Regex Lab" )
    {
        FakeHost host;
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        const auto entry = std::find_if(
            host.menuActions.begin(), host.menuActions.end(), []( const auto& action ) {
                return action.label == QString::fromUtf8( "Display filter\xe2\x80\xa6" );
            } );
        REQUIRE( entry != host.menuActions.end() );
        REQUIRE( entry->menuPath == "tcpdump" );

        WHEN( "the entry is chosen and a filter opened" )
        {
            whenDialogOpens( []( DisplayFilterDialog& dialog ) {
                dialog.findChild<QLineEdit*>( "filter" )->setText( "udp.port == 53" );
                dialog.findChild<QPushButton*>( "openButton" )->click();
            } );
            entry->trigger();

            THEN( "the Regex Lab opens with its pattern, matching case, and the filter is "
                  "logged" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( host.regexLabs.first().pattern
                         == displayFilterPattern( "udp.port == 53" ).pattern );
                REQUIRE( host.regexLabs.first().flags == LOGSQUIRL_REGEX_LAB_MATCH_CASE );
                REQUIRE( host.logs.contains( "Display filter: udp.port == 53" ) );
            }

            AND_WHEN( "the entry is chosen again" )
            {
                QString offered;
                whenDialogOpens( [ &offered ]( DisplayFilterDialog& dialog ) {
                    offered = dialog.filter();
                    dialog.reject();
                } );
                entry->trigger();

                THEN( "the filter is offered again, and a cancel opens nothing" )
                {
                    REQUIRE( offered == "udp.port == 53" );
                    REQUIRE( host.regexLabs.size() == 1 );
                }
            }
        }

        logsquirl_plugin_shutdown();
    }

    GIVEN( "a plugin loaded by a host older than LogSquirl 26.11" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

        THEN( "the entry is not offered" )
        {
            for ( const auto& action : host.menuActions ) {
                REQUIRE( action.label != QString::fromUtf8( "Display filter\xe2\x80\xa6" ) );
            }
        }

        logsquirl_plugin_shutdown();
    }
}

SCENARIO( "The sidebar's display filter field opens its pattern in the Regex Lab",
          "[displayfilter]" )
{
    GIVEN( "a plugin loaded by a host with the Regex Lab" )
    {
        FakeHost host;
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );
        auto* sidebar = tcpdump::g_state.sidebarWidget;
        REQUIRE( sidebar );
        auto* edit = sidebar->findChild<QLineEdit*>( "displayFilter" );
        auto* error = sidebar->findChild<QLabel*>( "displayFilterError" );
        auto* open = sidebar->findChild<QPushButton*>( "openDisplayFilter" );
        REQUIRE( edit );
        REQUIRE( error );
        REQUIRE( open );

        THEN( "an empty filter cannot be opened, and is no error yet" )
        {
            REQUIRE_FALSE( open->isEnabled() );
            REQUIRE( error->text().isEmpty() );
        }

        WHEN( "a filter outside the subset is typed" )
        {
            edit->setText( "tcp.port == 80 && http.host" );

            THEN( "the column and the reason are shown, as in the dialog, and nothing opens" )
            {
                REQUIRE( error->text().startsWith( "Column 19: The field http.host is not "
                                                   "supported" ) );
                REQUIRE_FALSE( open->isEnabled() );
                emit edit->returnPressed();
                REQUIRE( host.regexLabs.isEmpty() );
            }
        }

        WHEN( "a filter of the subset is typed and opened" )
        {
            edit->setText( "udp.port == 5353" );
            REQUIRE( open->isEnabled() );
            open->click();

            THEN( "the Regex Lab opens with its pattern, the filter logged and offered by the "
                  "dialog next time" )
            {
                REQUIRE( host.regexLabs.size() == 1 );
                REQUIRE( host.regexLabs.first().pattern
                         == displayFilterPattern( "udp.port == 5353" ).pattern );
                REQUIRE( host.logs.contains( "Display filter: udp.port == 5353" ) );
                QString offered;
                whenDialogOpens( [ &offered ]( DisplayFilterDialog& dialog ) {
                    offered = dialog.filter();
                    dialog.reject();
                } );
                openDisplayFilter( nullptr );
                REQUIRE( offered == "udp.port == 5353" );
            }

            AND_WHEN( "Enter is pressed in the field" )
            {
                emit edit->returnPressed();

                THEN( "it opens again" )
                {
                    REQUIRE( host.regexLabs.size() == 2 );
                }
            }
        }

        logsquirl_plugin_shutdown();
    }

    GIVEN( "a plugin loaded by a host older than LogSquirl 26.11" )
    {
        FakeHost host( LOGSQUIRL_HOST_API_BASE_SIZE );
        REQUIRE( logsquirl_plugin_init_ex( host.api(), &host, host.apiSize() ) == 0 );

        THEN( "the sidebar has no display filter field" )
        {
            REQUIRE_FALSE(
                tcpdump::g_state.sidebarWidget->findChild<QLineEdit*>( "displayFilter" ) );
        }

        logsquirl_plugin_shutdown();
    }
}
