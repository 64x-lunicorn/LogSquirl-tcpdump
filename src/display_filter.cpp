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
 * @file display_filter.cpp
 * @brief The display filter parser, and the patterns it translates a filter
 *        into.
 *
 * A filter is read in two steps: the tokenizer cuts it into words,
 * operators and parentheses, rejecting what the subset has no use for
 * (strings, slices, sets, `contains`, ...), and a recursive-descent parser
 * builds the FilterExpression, checking each field's operator and value.
 * Each error is thrown as a FilterError with its position and caught by
 * parseDisplayFilter().
 */

#include "display_filter.h"

#include "regex_lab.h"
#include "wire_bytes.h"

#include <QStringList>

#include <algorithm>
#include <array>
#include <limits>
#include <string>

namespace tcpdump {

namespace {

// ── Errors ───────────────────────────────────────────────────────────────

/// Why the filter is rejected, and where.
struct FilterError {
    QString message;
    int position;
};

// ── Fields ───────────────────────────────────────────────────────────────

/// What a field's values are.
enum class ValueKind { Ipv4, Ipv6, Port, Stream, Length };

struct FieldInfo {
    const char* name;
    FilterField field;
    ValueKind kind;
};

constexpr std::array kFields{
    FieldInfo{ "ip.addr", FilterField::IpAddr, ValueKind::Ipv4 },
    FieldInfo{ "ip.src", FilterField::IpSrc, ValueKind::Ipv4 },
    FieldInfo{ "ip.dst", FilterField::IpDst, ValueKind::Ipv4 },
    FieldInfo{ "ipv6.addr", FilterField::Ipv6Addr, ValueKind::Ipv6 },
    FieldInfo{ "ipv6.src", FilterField::Ipv6Src, ValueKind::Ipv6 },
    FieldInfo{ "ipv6.dst", FilterField::Ipv6Dst, ValueKind::Ipv6 },
    FieldInfo{ "tcp.port", FilterField::TcpPort, ValueKind::Port },
    FieldInfo{ "tcp.srcport", FilterField::TcpSrcPort, ValueKind::Port },
    FieldInfo{ "tcp.dstport", FilterField::TcpDstPort, ValueKind::Port },
    FieldInfo{ "udp.port", FilterField::UdpPort, ValueKind::Port },
    FieldInfo{ "udp.srcport", FilterField::UdpSrcPort, ValueKind::Port },
    FieldInfo{ "udp.dstport", FilterField::UdpDstPort, ValueKind::Port },
    FieldInfo{ "tcp.stream", FilterField::TcpStream, ValueKind::Stream },
    FieldInfo{ "udp.stream", FilterField::UdpStream, ValueKind::Stream },
    FieldInfo{ "frame.len", FilterField::FrameLen, ValueKind::Length },
};

const FieldInfo* fieldNamed( const QString& name )
{
    for ( const auto& info : kFields ) {
        if ( name == QLatin1String( info.name ) ) {
            return &info;
        }
    }
    return nullptr;
}

const FieldInfo& infoOf( FilterField field )
{
    for ( const auto& info : kFields ) {
        if ( info.field == field ) {
            return info;
        }
    }
    return kFields.back();
}

QString supportedFields()
{
    QStringList names;
    for ( const auto& info : kFields ) {
        names << QString::fromLatin1( info.name );
    }
    return names.join( ", " );
}

/// The largest value of a field of @p kind; a stream or a length has none
/// worth a bound, so it is UINT64_MAX, which numberRangePattern() reads as
/// no bound.
uint64_t maximumOf( ValueKind kind )
{
    return kind == ValueKind::Port ? 65535 : std::numeric_limits<uint64_t>::max();
}

// ── Addresses ────────────────────────────────────────────────────────────

/// @p text as a dotted-decimal IPv4 address.
bool parseIpv4( const QString& text, uint32_t& address )
{
    const auto parts = text.split( '.' );
    if ( parts.size() != 4 ) {
        return false;
    }
    address = 0;
    for ( const auto& part : parts ) {
        if ( part.isEmpty() || part.size() > 3 ) {
            return false;
        }
        for ( const auto c : part ) {
            if ( c < '0' || c > '9' ) {
                return false;
            }
        }
        const auto octet = part.toUInt();
        if ( octet > 255 ) {
            return false;
        }
        address = ( address << 8 ) | octet;
    }
    return true;
}

bool isHexDigit( QChar c )
{
    const auto lower = c.toLower();
    return ( lower >= '0' && lower <= '9' ) || ( lower >= 'a' && lower <= 'f' );
}

/// The groups of @p part, an IPv6 address on one side of "::"; the last
/// may be an IPv4 address, two groups, when @p ipv4Last.
bool parseIpv6Groups( const QString& part, std::vector<uint16_t>& groups, bool ipv4Last )
{
    if ( part.isEmpty() ) {
        return true;
    }
    const auto items = part.split( ':' );
    for ( int i = 0; i < items.size(); ++i ) {
        const auto& item = items[ i ];
        if ( ipv4Last && i == items.size() - 1 && item.contains( '.' ) ) {
            uint32_t ipv4 = 0;
            if ( !parseIpv4( item, ipv4 ) ) {
                return false;
            }
            groups.push_back( static_cast<uint16_t>( ipv4 >> 16 ) );
            groups.push_back( static_cast<uint16_t>( ipv4 & 0xFFFF ) );
            continue;
        }
        if ( item.isEmpty() || item.size() > 4 ) {
            return false;
        }
        for ( const auto c : item ) {
            if ( !isHexDigit( c ) ) {
                return false;
            }
        }
        groups.push_back( static_cast<uint16_t>( item.toUInt( nullptr, 16 ) ) );
    }
    return true;
}

/// @p text as an IPv6 address, in any of the forms of RFC 4291.
bool parseIpv6( const QString& text, uint8_t ( &address )[ 16 ] )
{
    const auto gap = text.indexOf( QLatin1String( "::" ) );
    if ( gap >= 0 && text.indexOf( QLatin1String( "::" ), gap + 1 ) >= 0 ) {
        return false;
    }
    std::vector<uint16_t> head;
    std::vector<uint16_t> tail;
    if ( gap < 0 ) {
        if ( !parseIpv6Groups( text, head, true ) || head.size() != 8 ) {
            return false;
        }
    }
    else if ( !parseIpv6Groups( text.left( gap ), head, false )
              || !parseIpv6Groups( text.mid( gap + 2 ), tail, true )
              || head.size() + tail.size() > 7 ) {
        return false;
    }
    std::array<uint16_t, 8> groups{};
    std::copy( head.begin(), head.end(), groups.begin() );
    std::copy( tail.begin(), tail.end(),
               groups.end() - static_cast<std::ptrdiff_t>( tail.size() ) );
    for ( int i = 0; i < 8; ++i ) {
        address[ 2 * i ] = static_cast<uint8_t>( groups[ i ] >> 8 );
        address[ 2 * i + 1 ] = static_cast<uint8_t>( groups[ i ] & 0xFF );
    }
    return true;
}

QString ipv4Text( uint32_t address )
{
    const uint8_t bytes[ 4 ]
        = { static_cast<uint8_t>( address >> 24 ), static_cast<uint8_t>( address >> 16 ),
            static_cast<uint8_t>( address >> 8 ), static_cast<uint8_t>( address ) };
    return QString::fromStdString( formatIpv4( bytes ) );
}

// ── Tokens ───────────────────────────────────────────────────────────────

struct Token {
    enum class Type { Word, Open, Close, Not, And, Or, Compare, End };
    Type type = Type::End;
    QString text;
    int position = 0;
    FilterOperator op = FilterOperator::Present;
};

bool isWordCharacter( QChar c )
{
    return ( c.unicode() < 128 && c.isLetterOrNumber() ) || c == '_' || c == '.' || c == ':'
           || c == '-' || c == '/';
}

/// The operators the subset leaves out, as words, and why.
QString unsupportedWord( const QString& word )
{
    static const QStringList operators{ "contains", "matches", "in", "bitand", "any", "all" };
    if ( operators.contains( word ) ) {
        return QString( "\"%1\" is not supported: compare with ==, !=, <, >, <= or >=." )
            .arg( word );
    }
    if ( word == "xor" ) {
        return QStringLiteral( "\"xor\" is not supported: combine with &&, || and !." );
    }
    return {};
}

std::vector<Token> tokenize( const QString& filter )
{
    std::vector<Token> tokens;
    const auto at = [ &filter ]( int i ) { return i < filter.size() ? filter[ i ] : QChar(); };
    int i = 0;
    while ( i < filter.size() ) {
        const auto c = filter[ i ];
        Token token;
        token.position = i;
        if ( c.isSpace() ) {
            ++i;
            continue;
        }
        if ( c == '(' || c == ')' ) {
            token.type = c == '(' ? Token::Type::Open : Token::Type::Close;
            token.text = c;
            ++i;
        }
        else if ( c == '!' && at( i + 1 ) == '=' ) {
            if ( at( i + 2 ) == '=' ) {
                throw FilterError{ "\"!==\" is not supported: use !=.", i };
            }
            token.type = Token::Type::Compare;
            token.op = FilterOperator::NotEqual;
            token.text = "!=";
            i += 2;
        }
        else if ( c == '!' ) {
            token.type = Token::Type::Not;
            token.text = c;
            ++i;
        }
        else if ( c == '=' ) {
            if ( at( i + 1 ) != '=' ) {
                throw FilterError{ "Compare with ==, not =.", i };
            }
            if ( at( i + 2 ) == '=' ) {
                throw FilterError{ "\"===\" is not supported: use ==.", i };
            }
            token.type = Token::Type::Compare;
            token.op = FilterOperator::Equal;
            token.text = "==";
            i += 2;
        }
        else if ( c == '<' || c == '>' ) {
            const bool orEqual = at( i + 1 ) == '=';
            token.type = Token::Type::Compare;
            token.op = c == '<'
                           ? ( orEqual ? FilterOperator::LessEqual : FilterOperator::Less )
                           : ( orEqual ? FilterOperator::GreaterEqual : FilterOperator::Greater );
            token.text = filter.mid( i, orEqual ? 2 : 1 );
            i += orEqual ? 2 : 1;
        }
        else if ( c == '&' || c == '|' ) {
            if ( at( i + 1 ) != c ) {
                throw FilterError{ c == '&' ? QStringLiteral( "Combine with && or and, not &." )
                                            : QStringLiteral( "Combine with || or or, not |." ),
                                   i };
            }
            token.type = c == '&' ? Token::Type::And : Token::Type::Or;
            token.text = filter.mid( i, 2 );
            i += 2;
        }
        else if ( c == '"' || c == '\'' ) {
            throw FilterError{ "Strings are not supported: compare addresses, ports, streams or "
                               "lengths.",
                               i };
        }
        else if ( c == '[' ) {
            throw FilterError{ "Slices are not supported.", i };
        }
        else if ( c == '{' ) {
            throw FilterError{ "Sets are not supported: combine comparisons with ||.", i };
        }
        else if ( c == '~' || c == '^' ) {
            throw FilterError{ QString( "\"%1\" is not supported: compare with ==, !=, <, >, <= "
                                        "or >=, and combine with &&, || and !." )
                                   .arg( c ),
                               i };
        }
        else if ( isWordCharacter( c ) ) {
            int end = i;
            while ( end < filter.size() && isWordCharacter( filter[ end ] ) ) {
                ++end;
            }
            token.text = filter.mid( i, end - i );
            i = end;
            const auto word = token.text.toLower();
            static const QStringList comparisons{ "eq", "ne", "lt", "gt", "le", "ge" };
            static const FilterOperator comparisonOps[] = {
                FilterOperator::Equal,   FilterOperator::NotEqual,  FilterOperator::Less,
                FilterOperator::Greater, FilterOperator::LessEqual, FilterOperator::GreaterEqual
            };
            if ( word == "and" ) {
                token.type = Token::Type::And;
            }
            else if ( word == "or" ) {
                token.type = Token::Type::Or;
            }
            else if ( word == "not" ) {
                token.type = Token::Type::Not;
            }
            else if ( comparisons.contains( word ) ) {
                token.type = Token::Type::Compare;
                token.op = comparisonOps[ comparisons.indexOf( word ) ];
            }
            else if ( const auto why = unsupportedWord( word ); !why.isEmpty() ) {
                throw FilterError{ why, token.position };
            }
            else {
                token.type = Token::Type::Word;
            }
        }
        else {
            throw FilterError{ QString( "\"%1\" is not part of a display filter." ).arg( c ), i };
        }
        tokens.push_back( token );
    }
    Token end;
    end.position = static_cast<int>( filter.size() );
    tokens.push_back( end );
    return tokens;
}

// ── Parser ───────────────────────────────────────────────────────────────

class Parser {
public:
    explicit Parser( const QString& filter )
        : tokens_( tokenize( filter ) )
    {
    }

    FilterExpression parse()
    {
        if ( peek().type == Token::Type::End ) {
            throw FilterError{ "Type a display filter, such as tcp.port == 443.", 0 };
        }
        auto expression = parseOr();
        if ( peek().type == Token::Type::Close ) {
            throw FilterError{ "This ) closes no (.", peek().position };
        }
        if ( peek().type != Token::Type::End ) {
            throw FilterError{ "Expected && or || here.", peek().position };
        }
        return expression;
    }

private:
    const Token& peek() const
    {
        return tokens_[ next_ ];
    }

    const Token& take()
    {
        return tokens_[ next_++ ];
    }

    /// @p operands combined with @p kind, those of the same kind merged.
    static FilterExpression combine( FilterExpression::Kind kind,
                                     std::vector<FilterExpression> operands )
    {
        if ( operands.size() == 1 ) {
            return std::move( operands.front() );
        }
        FilterExpression combined;
        combined.kind = kind;
        for ( auto& operand : operands ) {
            if ( operand.kind == kind ) {
                for ( auto& inner : operand.operands ) {
                    combined.operands.push_back( std::move( inner ) );
                }
            }
            else {
                combined.operands.push_back( std::move( operand ) );
            }
        }
        return combined;
    }

    FilterExpression parseOr()
    {
        std::vector<FilterExpression> operands{ parseAnd() };
        while ( peek().type == Token::Type::Or ) {
            take();
            operands.push_back( parseAnd() );
        }
        return combine( FilterExpression::Kind::Or, std::move( operands ) );
    }

    FilterExpression parseAnd()
    {
        std::vector<FilterExpression> operands{ parseUnary() };
        while ( peek().type == Token::Type::And ) {
            take();
            operands.push_back( parseUnary() );
        }
        return combine( FilterExpression::Kind::And, std::move( operands ) );
    }

    /// Parentheses and negations nested at most: each is a call deeper, and
    /// a filter of many thousand would overflow the stack.
    static constexpr int kMaxDepth = 64;

    /// One level deeper for the ( or ! at @p token, while it is parsed.
    class Deeper {
    public:
        Deeper( int& depth, const Token& token )
            : depth_( depth )
        {
            if ( ++depth_ > kMaxDepth ) {
                --depth_;
                throw FilterError{ QString( "Parentheses and negations are nested more than "
                                            "%1 deep here." )
                                       .arg( kMaxDepth ),
                                   token.position };
            }
        }
        ~Deeper()
        {
            --depth_;
        }
        Deeper( const Deeper& ) = delete;
        Deeper& operator=( const Deeper& ) = delete;

    private:
        int& depth_;
    };

    FilterExpression parseUnary()
    {
        if ( peek().type == Token::Type::Not ) {
            const Deeper deeper( depth_, take() );
            FilterExpression negation;
            negation.kind = FilterExpression::Kind::Not;
            negation.operands.push_back( parseUnary() );
            return negation;
        }
        return parsePrimary();
    }

    FilterExpression parsePrimary()
    {
        const auto& token = take();
        switch ( token.type ) {
        case Token::Type::Open: {
            const Deeper deeper( depth_, token );
            auto inner = parseOr();
            if ( peek().type != Token::Type::Close ) {
                throw FilterError{
                    QString( "Expected ) to close the ( at column %1." ).arg( token.position + 1 ),
                    peek().position
                };
            }
            take();
            return inner;
        }
        case Token::Type::Word:
            return parseTest( token );
        case Token::Type::End:
            throw FilterError{ "The filter ends where a field, a protocol or ( is expected.",
                               token.position };
        default:
            throw FilterError{ "Expected a field, a protocol or ( here.", token.position };
        }
    }

    /// A field alone or compared, or a protocol name.
    FilterExpression parseTest( const Token& word )
    {
        if ( !word.text.front().isLetter() ) {
            throw FilterError{
                QString( "Expected a field or a protocol, not the value %1." ).arg( word.text ),
                word.position
            };
        }
        FilterExpression test;
        const auto lower = word.text.toLower();
        if ( lower.contains( '.' ) ) {
            const auto* info = fieldNamed( lower );
            if ( !info ) {
                throw FilterError{ QString( "The field %1 is not supported; the supported fields "
                                            "are %2." )
                                       .arg( word.text, supportedFields() ),
                                   word.position };
            }
            test.field = info->field;
            if ( peek().type == Token::Type::Compare ) {
                parseComparison( test, *info );
            }
            return test;
        }

        // tcp, udp, ip and ipv6 are those packets, not a Protocol column.
        static const QStringList shorthands{ "tcp", "udp", "ip", "ipv6" };
        static const FilterField shorthandFields[] = { FilterField::TcpPort, FilterField::UdpPort,
                                                       FilterField::IpAddr, FilterField::Ipv6Addr };
        if ( shorthands.contains( lower ) ) {
            test.field = shorthandFields[ shorthands.indexOf( lower ) ];
        }
        else {
            test.kind = FilterExpression::Kind::Protocol;
            test.protocol = word.text;
        }
        if ( peek().type == Token::Type::Compare ) {
            throw FilterError{ QString( "%1 is a protocol, which is not compared; compare a field "
                                        "such as tcp.port or ip.addr." )
                                   .arg( word.text ),
                               peek().position };
        }
        return test;
    }

    void parseComparison( FilterExpression& test, const FieldInfo& info )
    {
        const auto& op = take();
        test.op = op.op;
        const auto& value = take();
        if ( value.type != Token::Type::Word ) {
            throw FilterError{ QString( "Expected a value after %1." ).arg( op.text ),
                               value.position };
        }
        if ( fieldNamed( value.text.toLower() ) ) {
            throw FilterError{ "Comparing two fields is not supported: compare a field with a "
                               "value.",
                               value.position };
        }
        if ( info.kind == ValueKind::Ipv4 || info.kind == ValueKind::Ipv6 ) {
            if ( test.op != FilterOperator::Equal && test.op != FilterOperator::NotEqual ) {
                throw FilterError{ QString( "%1 is compared with == or != only." )
                                       .arg( QString::fromLatin1( info.name ) ),
                                   op.position };
            }
            parseAddress( test, info, value );
        }
        else {
            parseNumber( test, info, value );
        }
    }

    static void parseAddress( FilterExpression& test, const FieldInfo& info, const Token& value )
    {
        auto text = value.text;
        int prefix = -1;
        if ( const auto slash = text.indexOf( '/' ); slash >= 0 ) {
            if ( info.kind == ValueKind::Ipv6 ) {
                throw FilterError{ "Address prefixes are supported for IPv4 only.",
                                   value.position + static_cast<int>( slash ) };
            }
            bool ok = false;
            prefix = text.mid( slash + 1 ).toInt( &ok );
            if ( !ok || prefix < 0 || prefix > 32 || !text.at( slash + 1 ).isDigit() ) {
                throw FilterError{ "Expected a prefix length from 0 to 32 after /.",
                                   value.position + static_cast<int>( slash ) + 1 };
            }
            text = text.left( slash );
        }

        uint32_t ipv4 = 0;
        uint8_t ipv6[ 16 ];
        const bool isIpv4 = parseIpv4( text, ipv4 );
        const bool isIpv6 = !isIpv4 && parseIpv6( text, ipv6 );
        if ( info.kind == ValueKind::Ipv4 ) {
            if ( !isIpv4 ) {
                throw FilterError{
                    isIpv6 ? QString( "%1 is an IPv6 address: compare it with ipv6.%2." )
                                 .arg( text, QString::fromLatin1( info.name ).mid( 3 ) )
                           : QString( "%1 is not an IPv4 address." ).arg( text ),
                    value.position
                };
            }
            if ( prefix >= 0 && prefix < 32 ) {
                const auto mask = prefix == 0 ? 0u : ~0u << ( 32 - prefix );
                ipv4 &= mask;
                test.prefixLength = prefix;
            }
            test.address = ipv4Text( ipv4 );
            return;
        }
        if ( !isIpv6 ) {
            throw FilterError{ isIpv4 ? QString( "%1 is an IPv4 address: compare it with ip.%2." )
                                            .arg( text, QString::fromLatin1( info.name ).mid( 5 ) )
                                      : QString( "%1 is not an IPv6 address." ).arg( text ),
                               value.position };
        }
        test.address = QString::fromStdString( formatIpv6( ipv6 ) );
    }

    static void parseNumber( FilterExpression& test, const FieldInfo& info, const Token& value )
    {
        bool ok = false;
        const auto& text = value.text;
        const bool hex = text.startsWith( "0x", Qt::CaseInsensitive );
        bool digits = text.size() > ( hex ? 2 : 0 );
        for ( int i = hex ? 2 : 0; i < text.size(); ++i ) {
            const auto c = text[ i ];
            digits = digits && ( hex ? isHexDigit( c ) : ( c >= '0' && c <= '9' ) );
        }
        const auto number = digits ? text.mid( hex ? 2 : 0 ).toULongLong( &ok, hex ? 16 : 10 ) : 0;
        if ( !ok ) {
            throw FilterError{ QString( "%1 is not a number." ).arg( text ), value.position };
        }
        if ( number > maximumOf( info.kind ) ) {
            throw FilterError{
                QString( "%1 is too big for a port: ports go up to 65535." ).arg( text ),
                value.position
            };
        }
        test.number = number;
    }

    std::vector<Token> tokens_;
    size_t next_ = 0;
    int depth_ = 0; ///< Parentheses and negations open now.
};

// ── Numbers ──────────────────────────────────────────────────────────────

/// The pattern of @p count digits.
QString anyDigits( size_t count )
{
    return count == 0   ? QString()
           : count == 1 ? QStringLiteral( R"(\d)" )
                        : QString( R"(\d{%1})" ).arg( count );
}

/// The pattern of a digit from @p low to @p high.
QString digitClass( char low, char high )
{
    if ( low == high ) {
        return QString( QChar( low ) );
    }
    if ( low == '0' && high == '9' ) {
        return QStringLiteral( R"(\d)" );
    }
    return QString( "[%1-%2]" ).arg( QChar( low ), QChar( high ) );
}

/// The pattern of the digit strings from @p low to @p high, both as long,
/// leading zeros included.
QString digitsRange( const std::string& low, const std::string& high )
{
    if ( low == high ) {
        return QString::fromStdString( low );
    }
    if ( low[ 0 ] == high[ 0 ] ) {
        return QChar( low[ 0 ] ) + digitsRange( low.substr( 1 ), high.substr( 1 ) );
    }
    const auto rest = low.size() - 1;
    const bool lowFrom0 = low.find_first_not_of( '0', 1 ) == std::string::npos;
    const bool highTo9 = high.find_first_not_of( '9', 1 ) == std::string::npos;
    QStringList parts;
    if ( !lowFrom0 ) {
        parts << QChar( low[ 0 ] ) + digitsRange( low.substr( 1 ), std::string( rest, '9' ) );
    }
    const char middleLow = lowFrom0 ? low[ 0 ] : static_cast<char>( low[ 0 ] + 1 );
    const char middleHigh = highTo9 ? high[ 0 ] : static_cast<char>( high[ 0 ] - 1 );
    if ( middleLow <= middleHigh ) {
        parts << digitClass( middleLow, middleHigh ) + anyDigits( rest );
    }
    if ( !highTo9 ) {
        parts << QChar( high[ 0 ] ) + digitsRange( std::string( rest, '0' ), high.substr( 1 ) );
    }
    return parts.size() == 1 ? parts.front() : "(?:" + parts.join( '|' ) + ")";
}

// ── Patterns ─────────────────────────────────────────────────────────────

/// The arrow between the ports in Info.
const QString kArrow = QString::fromUtf8( " \xe2\x86\x92 " );

/// A Source or Destination column with an IPv4 or an IPv6 address; the
/// latter tells itself from a MAC address, the column's value without an
/// IP address, by its "::" or its eight groups.
const QString kAnyIpv4 = QStringLiteral( R"(\d+\.\d+\.\d+\.\d+)" );
const QString kAnyIpv6
    = QStringLiteral( R"((?:[0-9a-f:]*::[0-9a-f:]*|[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}))" );

/// The Protocol column of an IPv4 packet: an ARP packet shows its sender
/// and target IPv4 addresses in Source and Destination too.
const QString kNotArp = QStringLiteral( R"((?!ARP )\S+)" );

/// The pattern of a packet line's columns up to Length, from its start:
/// Stream as @p stream, Source and Destination as @p addresses, Protocol
/// as @p protocol and Length as @p length.
QString columns( const QString& stream, const QString& addresses, const QString& protocol,
                 const QString& length )
{
    // upToSourcePattern() starts with ^, which the whole pattern has once.
    return QString( "%1%2 +%3 +%4 " )
        .arg( upToSourcePattern( stream ).mid( 1 ), addresses, protocol, length );
}

/// Any packet line.
QString packetLine()
{
    return columns( R"(\S+)", R"(\S+ +\S+)", R"(\S+)", R"(\d+)" );
}

/// The start of a TCP or UDP packet's Info, after columns(), with its ports
/// as @p ports: after the MAC columns a Line Layout may add, the tunnels
/// the packet came through and the TCP analysis markers, the source and
/// destination ports, then the TCP flags or the UDP payload length.
QString transportInfo( bool tcp, const QString& ports )
{
    static const QString mac = QStringLiteral( R"((?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|-))" );
    return QString( R"( *(?:%1 +%1 +)?(?:(?:IPv[46]-in-\S+|GRE(?: key=0x[0-9A-F]+)?|)"
                    R"(VXLAN(?: VNI \d+)?) \| )*(?:\[TCP [^\]]*\] )*%2 %3)" )
        .arg( mac, ports, tcp ? QStringLiteral( R"(\[)" ) : QStringLiteral( "Len=" ) );
}

/// The pattern of IPv4 address @p address, or of the network it starts
/// when @p prefixLength is from 0 to 31.
QString ipv4Pattern( const QString& address, int prefixLength )
{
    if ( prefixLength < 0 ) {
        return literalPattern( address );
    }
    const auto octets = address.split( '.' );
    QStringList patterns;
    for ( int i = 0; i < 4; ++i ) {
        const int bits = std::clamp( prefixLength - 8 * i, 0, 8 );
        const auto low = octets[ i ].toUInt();
        const auto high = low | ( 0xFFu >> bits );
        patterns << numberRangePattern( low, high );
    }
    return patterns.join( R"(\.)" );
}

bool isTcp( FilterField field )
{
    return field == FilterField::TcpPort || field == FilterField::TcpSrcPort
           || field == FilterField::TcpDstPort || field == FilterField::TcpStream;
}

/// The pattern of the values of @p comparison's field it selects, empty
/// for none; for Present, and for NotEqual, which is Present and not
/// Equal, those of any value.
QString valuesPattern( const FilterExpression& comparison )
{
    const auto& info = infoOf( comparison.field );
    if ( info.kind == ValueKind::Ipv4 || info.kind == ValueKind::Ipv6 ) {
        // The address, and the name a DNS answer gave it, if its column
        // shows one (LineLayout::hostNames).
        QString address;
        if ( comparison.op != FilterOperator::Equal ) {
            address = info.kind == ValueKind::Ipv4 ? kAnyIpv4 : kAnyIpv6;
        }
        else {
            address = info.kind == ValueKind::Ipv4
                          ? ipv4Pattern( comparison.address, comparison.prefixLength )
                          : literalPattern( comparison.address );
        }
        return "(?:" + address + ")" + nameSuffixPattern();
    }

    const auto n = comparison.number;
    const auto maximum = maximumOf( info.kind );
    switch ( comparison.op ) {
    case FilterOperator::Equal:
        return QString::number( n );
    case FilterOperator::Less:
        return n == 0 ? QString() : numberRangePattern( 0, n - 1 );
    case FilterOperator::LessEqual:
        return numberRangePattern( 0, n );
    case FilterOperator::Greater:
        return n >= maximum ? QString() : numberRangePattern( n + 1, maximum );
    case FilterOperator::GreaterEqual:
        return numberRangePattern( n, maximum );
    default:
        return QStringLiteral( R"(\d+)" );
    }
}

/// The pattern, from the start of a packet line, of the lines in which
/// @p comparison's field has one of @p values.
QString fieldPattern( FilterField field, const QString& values )
{
    const QString any = R"(\S+)";
    switch ( field ) {
    case FilterField::IpAddr:
        return columns( any, QString( R"((?:%1 +\S+|\S+ +%1))" ).arg( values ), kNotArp, R"(\d+)" );
    case FilterField::IpSrc:
        return columns( any, values + R"( +\S+)", kNotArp, R"(\d+)" );
    case FilterField::IpDst:
        return columns( any, R"(\S+ +)" + values, kNotArp, R"(\d+)" );
    case FilterField::Ipv6Addr:
        return columns( any, QString( R"((?:%1 +\S+|\S+ +%1))" ).arg( values ), any, R"(\d+)" );
    case FilterField::Ipv6Src:
        return columns( any, values + R"( +\S+)", any, R"(\d+)" );
    case FilterField::Ipv6Dst:
        return columns( any, R"(\S+ +)" + values, any, R"(\d+)" );
    case FilterField::TcpPort:
    case FilterField::UdpPort:
        return packetLine()
               + transportInfo( isTcp( field ),
                                QString( "(?:%1%2\\d+|\\d+%2%1)" ).arg( values, kArrow ) );
    case FilterField::TcpSrcPort:
    case FilterField::UdpSrcPort:
        return packetLine() + transportInfo( isTcp( field ), values + kArrow + R"(\d+)" );
    case FilterField::TcpDstPort:
    case FilterField::UdpDstPort:
        return packetLine() + transportInfo( isTcp( field ), R"(\d+)" + kArrow + values );
    case FilterField::TcpStream:
    case FilterField::UdpStream:
        return columns( values, R"(\S+ +\S+)", any, R"(\d+)" )
               + transportInfo( isTcp( field ), R"(\d+)" + kArrow + R"(\d+)" );
    case FilterField::FrameLen:
        return columns( any, R"(\S+ +\S+)", any, values );
    }
    return {};
}

/// The pattern that never matches.
const QString kNever = QStringLiteral( "(?!)" );

/// The pattern, from the start of a packet line, of the lines @p test
/// selects: a comparison other than NotEqual, or a protocol.
QString testPattern( const FilterExpression& test )
{
    if ( test.kind == FilterExpression::Kind::Protocol ) {
        return columns( R"(\S+)", R"(\S+ +\S+)", "(?i:" + literalPattern( test.protocol ) + ")",
                        R"(\d+)" );
    }
    const auto values = valuesPattern( test );
    return values.isEmpty() ? kNever : fieldPattern( test.field, values );
}

bool isNotEqual( const FilterExpression& expression )
{
    return expression.kind == FilterExpression::Kind::Comparison
           && expression.op == FilterOperator::NotEqual;
}

bool isTest( const FilterExpression& expression )
{
    return ( expression.kind == FilterExpression::Kind::Comparison
             || expression.kind == FilterExpression::Kind::Protocol )
           && !isNotEqual( expression );
}

/// @p expression as assertions at the start of the line.
QString assertion( const FilterExpression& expression )
{
    using Kind = FilterExpression::Kind;
    switch ( expression.kind ) {
    case Kind::And: {
        QString all;
        for ( const auto& operand : expression.operands ) {
            all += assertion( operand );
        }
        return all;
    }
    case Kind::Or: {
        QStringList any;
        for ( const auto& operand : expression.operands ) {
            any << assertion( operand );
        }
        return "(?:" + any.join( '|' ) + ")";
    }
    case Kind::Not: {
        const auto& operand = expression.operands.front();
        return "(?!" + ( isTest( operand ) ? testPattern( operand ) : assertion( operand ) ) + ")";
    }
    case Kind::Comparison:
    case Kind::Protocol:
        if ( isNotEqual( expression ) ) {
            // Like Wireshark's !=: the field is there, and no value of it is
            // the one compared with.
            auto present = expression;
            present.op = FilterOperator::Present;
            auto equal = expression;
            equal.op = FilterOperator::Equal;
            return "(?=" + testPattern( present ) + ")(?!" + testPattern( equal ) + ")";
        }
        return "(?=" + testPattern( expression ) + ")";
    }
    return {};
}

/// Whether a line @p expression selects is a packet line anyway.
bool selectsPacketLinesOnly( const FilterExpression& expression )
{
    using Kind = FilterExpression::Kind;
    switch ( expression.kind ) {
    case Kind::And:
        return std::any_of( expression.operands.begin(), expression.operands.end(),
                            selectsPacketLinesOnly );
    case Kind::Or:
        return std::all_of( expression.operands.begin(), expression.operands.end(),
                            selectsPacketLinesOnly );
    case Kind::Not:
        return false;
    default:
        return true;
    }
}

} // namespace

ParsedDisplayFilter parseDisplayFilter( const QString& filter )
{
    try {
        return { Parser( filter ).parse(), {}, -1 };
    } catch ( const FilterError& error ) {
        return { {}, error.message, error.position };
    }
}

QString filterPattern( const FilterExpression& expression )
{
    // A single test reads the line itself; anything else is assertions at
    // its start, which a negation alone would make match any other line.
    if ( isTest( expression ) ) {
        return "^" + testPattern( expression );
    }
    const auto guard
        = selectsPacketLinesOnly( expression ) ? QString() : "(?=" + packetLine() + ")";
    return "^" + guard + assertion( expression );
}

DisplayFilterPattern displayFilterPattern( const QString& filter )
{
    const auto parsed = parseDisplayFilter( filter );
    if ( !parsed.error.isEmpty() ) {
        return { {}, parsed.error, parsed.errorPosition };
    }
    return { filterPattern( parsed.expression ), {}, -1 };
}

QString numberRangePattern( uint64_t low, uint64_t high )
{
    if ( low > high ) {
        return {};
    }
    const bool unbounded = high == std::numeric_limits<uint64_t>::max();
    const auto lowText = std::to_string( low );
    const auto highText = std::to_string( high );
    const auto lowDigits = lowText.size();
    const auto highDigits = unbounded ? lowDigits : highText.size();

    QStringList parts;
    for ( auto digits = lowDigits; digits <= highDigits; ++digits ) {
        // The numbers of this many digits in the range
        const auto from = digits == lowDigits ? lowText : "1" + std::string( digits - 1, '0' );
        const auto to
            = digits == highText.size() && !unbounded ? highText : std::string( digits, '9' );
        parts << digitsRange( from, to );
    }
    if ( unbounded ) {
        parts << QString( R"([1-9]\d{%1,})" ).arg( lowDigits );
    }
    return parts.size() == 1 ? parts.front() : "(?:" + parts.join( '|' ) + ")";
}

} // namespace tcpdump
