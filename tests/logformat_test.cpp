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
 * @file logformat_test.cpp
 * @brief Tests of the Log Format definition, formats/tcpdump_log.json.
 *
 * The file is read as LogSquirl reads a user format: its regex compiled with
 * QRegularExpression and no options, its columns the named groups in pattern
 * order, and its timestamp read by the rules of LogSquirl's TimestampReader
 * (src/logformat/src/timestampreader.cpp), ported below for the directives
 * the format may use.  Every line of every corpus text, header excluded,
 * must match and yield the columns the line shows, also in the other Line
 * Layouts the configuration dialog offers: a time column a line does not
 * have is empty, and the MAC columns are read as the start of Info.
 */

#include <catch2/catch.hpp>

#include "packet_formatter.h"
#include "pcap_converter.h"
#include "regex_lab.h"

#include <QDate>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QTemporaryDir>
#include <QTime>
#include <QTimeZone>

#include <optional>
#include <vector>

using namespace tcpdump;

namespace {

/// The one format the file defines, as LogSquirl reads it.
struct LogFormat {
    QString name;
    QJsonObject definition;
    QStringList patterns;
    QString timestampField = "timestamp"; // lnav's defaults, as the host's
    QString bodyField = "body";
    QStringList timestampFormats;
};

LogFormat loadFormat()
{
    QFile file( QStringLiteral( TCPDUMP_FORMAT_FILE ) );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson( file.readAll(), &error );
    INFO( error.errorString().toStdString() );
    REQUIRE( document.isObject() );

    LogFormat format;
    const auto root = document.object();
    for ( auto it = root.begin(); it != root.end(); ++it ) {
        if ( !it.key().startsWith( '$' ) ) {
            REQUIRE( format.name.isEmpty() ); // one format in the file
            format.name = it.key();
            format.definition = it.value().toObject();
        }
    }
    REQUIRE_FALSE( format.name.isEmpty() );

    const auto& def = format.definition;
    const auto regex = def.value( "regex" ).toObject();
    for ( auto it = regex.begin(); it != regex.end(); ++it ) {
        format.patterns << it.value().toObject().value( "pattern" ).toString();
    }
    if ( def.contains( "timestamp-field" ) ) {
        format.timestampField = def.value( "timestamp-field" ).toString();
    }
    if ( def.contains( "body-field" ) ) {
        format.bodyField = def.value( "body-field" ).toString();
    }
    const auto tsFormat = def.value( "timestamp-format" );
    if ( tsFormat.isArray() ) {
        for ( const auto& f : tsFormat.toArray() ) {
            format.timestampFormats << f.toString();
        }
    }
    else if ( tsFormat.isString() ) {
        format.timestampFormats << tsFormat.toString();
    }
    return format;
}

// ── LogSquirl's TimestampReader, ported ────────────────────────────────────
//
// The same tokens and reading rules as the host's: a run of whitespace in
// the format matches one or more whitespace characters, %Y exactly four
// digits, %m %d %H %M %S one or two, %f and %L any number of digits of which
// the first three are the milliseconds, %z/%Z an optional zone ("Z", "UTC",
// "+02:00", ...) that makes the time the UTC instant it names; trailing
// whitespace is allowed, anything else left over is not.  A directive not
// ported here makes the format unreadable, so that a change of the format
// to one fails this test instead of passing unchecked.

enum class Kind { Literal, Space, Year4, Month, Day, Hour, Minute, Second, Fraction, Zone };

struct Token {
    Kind kind;
    QChar literal;
};

std::optional<std::vector<Token>> compileTimestampFormat( const QString& format )
{
    std::vector<Token> pattern;
    for ( qsizetype i = 0; i < format.size(); ++i ) {
        const auto c = format[ i ];
        if ( c.isSpace() ) {
            if ( pattern.empty() || pattern.back().kind != Kind::Space ) {
                pattern.push_back( { Kind::Space, {} } );
            }
            continue;
        }
        if ( c != '%' ) {
            pattern.push_back( { Kind::Literal, c } );
            continue;
        }
        if ( ++i >= format.size() ) {
            return std::nullopt;
        }
        switch ( format[ i ].unicode() ) {
        case 'Y':
            pattern.push_back( { Kind::Year4, {} } );
            break;
        case 'm':
            pattern.push_back( { Kind::Month, {} } );
            break;
        case 'd':
        case 'e':
            pattern.push_back( { Kind::Day, {} } );
            break;
        case 'H':
            pattern.push_back( { Kind::Hour, {} } );
            break;
        case 'M':
            pattern.push_back( { Kind::Minute, {} } );
            break;
        case 'S':
            pattern.push_back( { Kind::Second, {} } );
            break;
        case 'L':
        case 'f':
            pattern.push_back( { Kind::Fraction, {} } );
            break;
        case 'z':
        case 'Z':
            pattern.push_back( { Kind::Zone, {} } );
            break;
        case '%':
            pattern.push_back( { Kind::Literal, '%' } );
            break;
        default:
            return std::nullopt;
        }
    }
    return pattern;
}

bool isDigit( QChar c )
{
    return c >= '0' && c <= '9';
}

std::optional<int> readNumber( QStringView text, qsizetype& pos, int maxDigits )
{
    int value = 0;
    int digits = 0;
    while ( digits < maxDigits && pos < text.size() && isDigit( text[ pos ] ) ) {
        value = value * 10 + ( text[ pos ].unicode() - '0' );
        ++pos;
        ++digits;
    }
    return digits == 0 ? std::nullopt : std::optional<int>( value );
}

std::optional<int> readFraction( QStringView text, qsizetype& pos )
{
    int millis = 0;
    int digits = 0;
    for ( ; pos < text.size() && isDigit( text[ pos ] ); ++pos, ++digits ) {
        if ( digits < 3 ) {
            millis = millis * 10 + ( text[ pos ].unicode() - '0' );
        }
    }
    if ( digits == 0 ) {
        return std::nullopt;
    }
    for ( int d = digits; d < 3; ++d ) {
        millis *= 10;
    }
    return millis;
}

std::optional<int> readZone( QStringView text, qsizetype& pos )
{
    auto p = pos;
    while ( p < text.size() && text[ p ].isSpace() ) {
        ++p;
    }
    if ( p >= text.size() ) {
        return std::nullopt;
    }
    if ( text[ p ] == '+' || text[ p ] == '-' ) {
        const auto sign = text[ p ] == '-' ? -1 : 1;
        const auto digitsStart = ++p;
        QString digits;
        for ( ; p < text.size() && ( isDigit( text[ p ] ) || text[ p ] == ':' ); ++p ) {
            if ( text[ p ] != ':' ) {
                digits += text[ p ];
            }
        }
        if ( p - digitsStart < 2 ) {
            return std::nullopt;
        }
        pos = p;
        const auto hours = digits.left( 2 ).toInt();
        const auto minutes = digits.size() >= 4 ? digits.mid( 2, 2 ).toInt() : 0;
        if ( hours > 23 || minutes > 59 ) {
            return std::nullopt;
        }
        return sign * ( hours * 3600 + minutes * 60 );
    }
    const auto start = p;
    while ( p < text.size() && text[ p ].isLetter() ) {
        ++p;
    }
    pos = p;
    const auto name = text.mid( start, p - start ).toString().toUpper();
    if ( name == "Z" || name == "UTC" || name == "GMT" || name == "UT" ) {
        return 0;
    }
    return std::nullopt;
}

/// The Timestamp LogSquirl reads from the text of a timestamp field with the
/// format's timestamp formats, the first that fits winning.
std::optional<QDateTime> parseTimestamp( const QStringList& formats, QStringView text )
{
    for ( const auto& format : formats ) {
        const auto pattern = compileTimestampFormat( format );
        REQUIRE( pattern ); // a directive LogSquirl knows and this port has
        int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, millis = 0;
        std::optional<int> offset;
        qsizetype pos = 0;
        bool fits = true;
        for ( const auto& token : *pattern ) {
            std::optional<int> value = 0;
            switch ( token.kind ) {
            case Kind::Literal:
                fits = pos < text.size() && text[ pos ] == token.literal;
                ++pos;
                break;
            case Kind::Space:
                fits = pos < text.size() && text[ pos ].isSpace();
                while ( pos < text.size() && text[ pos ].isSpace() ) {
                    ++pos;
                }
                break;
            case Kind::Year4: {
                const auto start = pos;
                value = readNumber( text, pos, 4 );
                fits = value && pos - start == 4;
                year = value.value_or( 0 );
                break;
            }
            case Kind::Month:
                month = ( value = readNumber( text, pos, 2 ) ).value_or( 0 );
                break;
            case Kind::Day:
                day = ( value = readNumber( text, pos, 2 ) ).value_or( 0 );
                break;
            case Kind::Hour:
                hour = ( value = readNumber( text, pos, 2 ) ).value_or( 0 );
                break;
            case Kind::Minute:
                minute = ( value = readNumber( text, pos, 2 ) ).value_or( 0 );
                break;
            case Kind::Second:
                second = ( value = readNumber( text, pos, 2 ) ).value_or( 0 );
                break;
            case Kind::Fraction:
                millis = ( value = readFraction( text, pos ) ).value_or( 0 );
                break;
            case Kind::Zone:
                offset = readZone( text, pos );
                break;
            }
            if ( !fits || !value ) {
                fits = false;
                break;
            }
        }
        while ( fits && pos < text.size() && text[ pos ].isSpace() ) {
            ++pos;
        }
        if ( !fits || pos != text.size() ) {
            continue;
        }
        const QDate date( year, month, day );
        const QTime time( hour, minute, second, millis );
        if ( date.isValid() && time.isValid() ) {
            return QDateTime( date, time, QTimeZone::UTC ).addSecs( -offset.value_or( 0 ) );
        }
    }
    return std::nullopt;
}

// ── The columns of a packet line ───────────────────────────────────────────

/// A packet line's columns, split as a reader splits them, independently of
/// the format's regex: at runs of spaces, UTC Time being two of them (date
/// and time of day) and Info the rest of the line, the MAC columns of a
/// Line Layout with them included.  A time column the line's Line Layout
/// leaves out is empty.
struct Columns {
    QString number, stream, utcTime, time, source, destination, protocol, length, info;
};

std::optional<Columns> splitColumns( const QString& line, const LineLayout& layout = {} )
{
    const bool utc = layout.timeColumns != TimeColumns::RelativeOnly;
    const bool relative = layout.timeColumns != TimeColumns::AbsoluteOnly;
    const int count = 6 + ( utc ? 2 : 0 ) + ( relative ? 1 : 0 );
    QStringList parts;
    qsizetype pos = 0;
    for ( int i = 0; i < count; ++i ) {
        const auto end = line.indexOf( ' ', pos );
        if ( end < 0 ) {
            return std::nullopt;
        }
        parts << line.mid( pos, end - pos );
        pos = end;
        while ( pos < line.size() && line[ pos ] == ' ' ) {
            ++pos;
        }
    }
    Columns columns;
    columns.info = line.mid( pos );
    auto next = [ &parts ] { return parts.takeFirst(); };
    columns.number = next();
    columns.stream = next();
    if ( utc ) {
        columns.utcTime = next();
        columns.utcTime += ' ' + next();
    }
    if ( relative ) {
        columns.time = next();
    }
    columns.source = next();
    columns.destination = next();
    columns.protocol = next();
    columns.length = next();
    return columns;
}

/// The format's match of @p line, the first of its patterns that matches.
QRegularExpressionMatch matchLine( const LogFormat& format, const QString& line )
{
    for ( const auto& pattern : format.patterns ) {
        const QRegularExpression re( pattern ); // no options, as LogSquirl's
        auto match = re.match( line );
        if ( match.hasMatch() ) {
            return match;
        }
    }
    return {};
}

/// Checks that the format reads @p line, written in @p layout, into the
/// columns it shows.
void requireFields( const LogFormat& format, const QString& line, const LineLayout& layout = {} )
{
    INFO( "line: " << line.toStdString() );
    const auto match = matchLine( format, line );
    REQUIRE( match.hasMatch() );
    const auto columns = splitColumns( line, layout );
    REQUIRE( columns );
    REQUIRE( match.captured( "number" ) == columns->number );
    REQUIRE( match.captured( "stream" ) == columns->stream );
    REQUIRE( match.captured( format.timestampField ) == columns->utcTime );
    REQUIRE( match.captured( "time" ) == columns->time );
    REQUIRE( match.captured( "source" ) == columns->source );
    REQUIRE( match.captured( "destination" ) == columns->destination );
    REQUIRE( match.captured( "protocol" ) == columns->protocol );
    REQUIRE( match.captured( "length" ) == columns->length );
    REQUIRE( match.captured( format.bodyField ) == columns->info );
    if ( layout.macColumns ) {
        static const QRegularExpression macs(
            "^(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|-) +(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|-) " );
        REQUIRE( macs.match( columns->info ).hasMatch() );
    }
}

QStringList namedGroups( const QString& pattern )
{
    // The rule LogSquirl derives the column order with
    static const QRegularExpression namedGroupRe( R"(\(\?<([a-zA-Z_]\w*)>)" );
    QStringList names;
    auto it = namedGroupRe.globalMatch( pattern );
    while ( it.hasNext() ) {
        names << it.next().captured( 1 );
    }
    return names;
}

} // namespace

SCENARIO( "The Log Format defines one column per packet line field", "[logformat]" )
{
    const auto format = loadFormat();

    THEN( "its patterns compile as LogSquirl compiles them" )
    {
        REQUIRE_FALSE( format.patterns.isEmpty() );
        for ( const auto& pattern : format.patterns ) {
            const QRegularExpression re( pattern );
            INFO( re.errorString().toStdString() );
            REQUIRE( re.isValid() );
        }
    }

    THEN( "the columns are the packet line's fields, in its order" )
    {
        for ( const auto& pattern : format.patterns ) {
            REQUIRE( namedGroups( pattern )
                     == QStringList{ "number", "stream", "timestamp", "time", "source",
                                     "destination", "protocol", "length", "body" } );
        }
    }

    THEN( "it has a timestamp field with a format, which unlocks Δt and Go to timestamp" )
    {
        REQUIRE( format.timestampField == "timestamp" );
        REQUIRE( format.patterns.first().contains( "(?<" + format.timestampField + ">" ) );
        REQUIRE_FALSE( format.timestampFormats.isEmpty() );
        REQUIRE( format.bodyField == "body" );
    }

    THEN( "Length is its only numeric value, which the Chart Panel plots" )
    {
        const auto values = format.definition.value( "value" ).toObject();
        for ( const auto& name : namedGroups( format.patterns.first() ) ) {
            if ( name == format.timestampField || name == format.bodyField ) {
                continue;
            }
            INFO( "field " << name.toStdString() );
            REQUIRE( values.contains( name ) );
            const auto kind = values.value( name ).toObject().value( "kind" ).toString();
            REQUIRE( ( kind == "integer" || kind == "float" ) == ( name == "length" ) );
            REQUIRE_FALSE( values.value( name ).toObject().value( "hidden" ).toBool() );
        }
    }

    THEN( "the plugin reads packet lines with the same regex, for its Regex Lab patterns" )
    {
        REQUIRE( format.patterns.size() == 1 );
        REQUIRE( packetLineRegex().pattern() == format.patterns.first() );
    }

    THEN( "its sample lines match it" )
    {
        const auto samples = format.definition.value( "sample" ).toArray();
        REQUIRE_FALSE( samples.isEmpty() );
        for ( const auto& sample : samples ) {
            requireFields( format, sample.toObject().value( "line" ).toString() );
        }
    }
}

SCENARIO( "The Log Format reads every line of every corpus text", "[logformat][corpus]" )
{
    const auto format = loadFormat();
    const QDir committed( QStringLiteral( TCPDUMP_CORPUS_DIR ) );
    auto texts = committed.entryInfoList( { "*.txt" }, QDir::Files, QDir::Name );
    REQUIRE( texts.size() >= 2 );
    // Real captures stay uncommitted in tests/corpus/local; their text is read too when present.
    if ( const QDir local( committed.filePath( "local" ) ); local.exists() ) {
        texts += local.entryInfoList( { "*.txt" }, QDir::Files, QDir::Name );
    }

    for ( const auto& text : texts ) {
        GIVEN( "the corpus text " + text.fileName().toStdString() )
        {
            QFile file( text.filePath() );
            REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
            auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
            if ( lines.last().isEmpty() ) {
                lines.removeLast();
            }
            REQUIRE( lines.size() >= 2 );

            THEN( "the header line is no packet" )
            {
                REQUIRE_FALSE( matchLine( format, lines.first() ).hasMatch() );
            }

            THEN( "every packet line matches with the columns it shows" )
            {
                for ( qsizetype i = 1; i < lines.size(); ++i ) {
                    requireFields( format, lines[ i ] );
                    REQUIRE( matchLine( format, lines[ i ] ).captured( "number" )
                             == QString::number( i ) );
                }
            }

            THEN( "every timestamp is read, the time since the first one being Time" )
            {
                const auto first = parseTimestamp(
                    format.timestampFormats,
                    matchLine( format, lines[ 1 ] ).captured( format.timestampField ) );
                REQUIRE( first );
                for ( qsizetype i = 1; i < lines.size(); ++i ) {
                    INFO( "line: " << lines[ i ].toStdString() );
                    const auto match = matchLine( format, lines[ i ] );
                    const auto timestamp = parseTimestamp(
                        format.timestampFormats, match.captured( format.timestampField ) );
                    REQUIRE( timestamp );
                    REQUIRE( timestamp->timeSpec() == Qt::UTC );
                    // Both are cut to the millisecond: they differ by less than one
                    const auto elapsedMs = static_cast<double>( first->msecsTo( *timestamp ) );
                    REQUIRE( std::abs( elapsedMs - match.captured( "time" ).toDouble() * 1000.0 )
                             < 1.0 );
                }
            }
        }
    }
}

SCENARIO( "The Log Format reads the corpus in every Line Layout", "[logformat][corpus]" )
{
    const auto format = loadFormat();
    const QDir committed( QStringLiteral( TCPDUMP_CORPUS_DIR ) );
    const QStringList patterns{ "*.pcap", "*.pcapng" };
    auto captures = committed.entryInfoList( patterns, QDir::Files, QDir::Name );
    if ( const QDir local( committed.filePath( "local" ) ); local.exists() ) {
        captures += local.entryInfoList( patterns, QDir::Files, QDir::Name );
    }
    QTemporaryDir out;
    REQUIRE( out.isValid() );

    for ( const auto timeColumns :
          { TimeColumns::Both, TimeColumns::AbsoluteOnly, TimeColumns::RelativeOnly } ) {
        for ( const bool macColumns : { false, true } ) {
            ConversionOptions options;
            options.layout = { timeColumns, macColumns };
            for ( const auto& capture : captures ) {
                if ( capture.fileName().startsWith( "malformed-" ) ) {
                    continue;
                }
                INFO( "capture " << capture.fileName().toStdString() << ", time columns "
                                 << static_cast<int>( timeColumns ) << ", MAC columns "
                                 << macColumns );
                const auto result
                    = convertPcap( capture.filePath(), out.path(), nullptr, {}, options );
                REQUIRE( result.status == ConversionResult::Status::Converted );
                QFile file( result.outputPath );
                REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
                const auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
                REQUIRE_FALSE( matchLine( format, lines.first() ).hasMatch() );
                for ( qsizetype i = 1; i < lines.size() && !lines[ i ].isEmpty(); ++i ) {
                    requireFields( format, lines[ i ], options.layout );
                    if ( timeColumns != TimeColumns::RelativeOnly ) {
                        REQUIRE( parseTimestamp(
                            format.timestampFormats,
                            matchLine( format, lines[ i ] ).captured( format.timestampField ) ) );
                    }
                }
            }
        }
    }
}

SCENARIO( "The Log Format reads the UTC Time at 6 and 9 decimals", "[logformat]" )
{
    const auto format = loadFormat();
    // 2023-10-09 08:41:12.123456789 UTC
    const int64_t seconds = 1696840872;
    const uint32_t nanoseconds = 123456789;
    const QDateTime expected( QDate( 2023, 10, 9 ), QTime( 8, 41, 12, 123 ), QTimeZone::UTC );

    for ( const auto precision : { TimePrecision::Microseconds, TimePrecision::Nanoseconds } ) {
        const auto decimals = precision == TimePrecision::Nanoseconds ? 9 : 6;
        GIVEN( "a packet line with " + std::to_string( decimals ) + " decimals" )
        {
            PacketRecord pkt;
            pkt.number = 1;
            pkt.timestampSec = seconds;
            pkt.timestampNsec = nanoseconds;
            pkt.srcIp = "192.168.1.1";
            pkt.dstIp = "10.0.0.1";
            pkt.protocol = "UDP";
            pkt.originalLen = pkt.capturedLen = 60;
            pkt.info = "5000 \xe2\x86\x92 5001 Len=18";
            const auto line = QString::fromStdString(
                formatPacketLine( pkt, pkt.timestampSec, pkt.timestampNsec, 0, precision ) );

            THEN( "the timestamp field is the UTC Time, read to the millisecond in UTC" )
            {
                requireFields( format, line );
                const auto field = matchLine( format, line ).captured( format.timestampField );
                REQUIRE( field.toStdString() == formatUtcTime( seconds, nanoseconds, precision ) );
                REQUIRE( field.section( '.', 1 ).size() == decimals + 1 ); // and the Z
                REQUIRE( parseTimestamp( format.timestampFormats, field ) == expected );
            }
        }
    }
}

SCENARIO( "The Log Format reads lines with empty or overlong columns", "[logformat]" )
{
    const auto format = loadFormat();
    PacketRecord pkt;
    pkt.number = 1;
    pkt.capturedLen = pkt.originalLen = 60;

    GIVEN( "a packet without addresses and a protocol wider than its column" )
    {
        pkt.number = 1000000;
        pkt.protocol = "ETH(0x88CC)";
        pkt.info = "EtherType 0x88CC";
        const auto line = QString::fromStdString( formatPacketLine( pkt, 0, 0, kNoStream ) );

        THEN( "its fields are read" )
        {
            requireFields( format, line );
            REQUIRE( matchLine( format, line ).captured( "source" ) == "-" );
        }
    }

    GIVEN( "a packet without Info, as long as a million bytes" )
    {
        pkt.srcMac = "00:11:22:33:44:55";
        pkt.dstMac = "ff:ff:ff:ff:ff:ff";
        pkt.protocol = "ARP";
        pkt.capturedLen = pkt.originalLen = 1234567;
        const auto line = QString::fromStdString( formatPacketLine( pkt, 0, 0, kUnnumbered ) );

        THEN( "its body is empty" )
        {
            const auto match = matchLine( format, line );
            REQUIRE( match.hasMatch() );
            REQUIRE( match.captured( "length" ) == "1234567" );
            REQUIRE( match.captured( "body" ).isEmpty() );
        }
    }
}
