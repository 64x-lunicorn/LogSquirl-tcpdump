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
 * @file payload_describer.cpp
 * @brief The application-protocol detectors, and the order they are tried in.
 *
 * Every detector has the same shape: the payload and its ports in, a
 * description out if it recognises the payload.  Each transport has a table
 * of detectors; the first match wins, and the last entry of each table, the
 * port hint with the payload preview, always answers.
 */

#include "payload_describer.h"

#include "protocol_names.h"
#include "wire_bytes.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <optional>
#include <utility>
#include <vector>

namespace tcpdump {

namespace {

// ── Payload text ─────────────────────────────────────────────────────────

/// Format a protocol code as "0xNN".
std::string hexCode( uint8_t code )
{
    char buf[ 8 ];
    std::snprintf( buf, sizeof( buf ), "0x%02X", code );
    return buf;
}

/// Payload bytes as text: printable ASCII as is, anything else as \xNN, so
/// that a field can neither break the line nor hide what it contains.
/// Within quotes, '"' is escaped too.
std::string escapeBytes( const uint8_t* p, size_t len, bool quoted )
{
    std::string out;
    out.reserve( len );
    for ( size_t i = 0; i < len; ++i ) {
        const auto c = p[ i ];
        if ( c == '\\' || ( quoted && c == '"' ) ) {
            out += '\\';
            out += static_cast<char>( c );
        }
        else if ( c >= 0x20 && c < 0x7F ) {
            out += static_cast<char>( c );
        }
        else {
            out += "\\x" + hexCode( c ).substr( 2 );
        }
    }
    return out;
}

std::string quotedBytes( const uint8_t* p, size_t len )
{
    return '"' + escapeBytes( p, len, true ) + '"';
}

/// Longest first line, in bytes, before it is cut.
constexpr size_t kMaxFirstLineBytes = 120;

/// The first line of a payload, up to CR/LF and at most kMaxFirstLineBytes
/// bytes, escaped.
std::string firstLine( const uint8_t* payload, size_t len )
{
    size_t end = 0;
    while ( end < len && end < kMaxFirstLineBytes && payload[ end ] != '\r'
            && payload[ end ] != '\n' ) {
        ++end;
    }
    return escapeBytes( payload, end, false );
}

/// Most bytes of a field (a server name, a domain name) shown, the same cap
/// as a first line's.
constexpr size_t kMaxFieldBytes = kMaxFirstLineBytes;

/// @p len bytes of a field as text, at most kMaxFieldBytes of them, then an
/// ellipsis.
std::string fieldText( const uint8_t* p, size_t len )
{
    if ( len <= kMaxFieldBytes ) {
        return escapeBytes( p, len, false );
    }
    return escapeBytes( p, kMaxFieldBytes, false ) + "\xe2\x80\xa6";
}

/// ASCII letter, independent of the C locale (unlike std::isalpha).
bool isAsciiAlpha( uint8_t c )
{
    return ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
}

// ── HTTP ─────────────────────────────────────────────────────────────────

/// The bytes of a header's value.
struct HeaderValue {
    const uint8_t* data = nullptr;
    size_t len = 0;
};

/// @p a and the lower case ASCII @p name are the same, case aside,
/// independent of the C locale (unlike std::tolower).
bool equalsIgnoringCase( const uint8_t* a, const char* name, size_t len )
{
    for ( size_t i = 0; i < len; ++i ) {
        auto c = a[ i ];
        if ( c >= 'A' && c <= 'Z' ) {
            c = static_cast<uint8_t>( c - 'A' + 'a' );
        }
        if ( c != static_cast<uint8_t>( name[ i ] ) ) {
            return false;
        }
    }
    return true;
}

/// The value of the header @p name (lower case) in the header section of
/// the HTTP message at @p payload, without the blanks around it: the first
/// one, of the header lines after the start line up to the empty line that
/// ends the section.  Only a whole line counts, one the segment holds up to
/// its line feed; an empty value is none.
std::optional<HeaderValue> headerValue( const uint8_t* payload, size_t len, const char* name )
{
    const size_t nameLen = std::strlen( name );
    auto lineFeed = []( const uint8_t* from, const uint8_t* end ) {
        return static_cast<const uint8_t*>(
            std::memchr( from, '\n', static_cast<size_t>( end - from ) ) );
    };
    const uint8_t* const end = payload + len;
    const uint8_t* line = lineFeed( payload, end ); // the end of the start line
    while ( line != nullptr ) {
        ++line;
        const uint8_t* const eol = lineFeed( line, end );
        if ( eol == nullptr ) {
            return std::nullopt; // cut by the segment
        }
        const uint8_t* lineEnd = eol;
        if ( lineEnd > line && lineEnd[ -1 ] == '\r' ) {
            --lineEnd;
        }
        if ( lineEnd == line ) {
            return std::nullopt; // the end of the header section
        }
        if ( static_cast<size_t>( lineEnd - line ) > nameLen && line[ nameLen ] == ':'
             && equalsIgnoringCase( line, name, nameLen ) ) {
            auto isBlank = []( uint8_t c ) { return c == ' ' || c == '\t'; };
            const uint8_t* value = line + nameLen + 1;
            while ( value < lineEnd && isBlank( *value ) ) {
                ++value;
            }
            while ( lineEnd > value && isBlank( lineEnd[ -1 ] ) ) {
                --lineEnd;
            }
            if ( value == lineEnd ) {
                return std::nullopt;
            }
            return HeaderValue{ value, static_cast<size_t>( lineEnd - value ) };
        }
        line = eol;
    }
    return std::nullopt;
}

/// The request line, the host of the Host header put before a path,
/// "GET example.com/index.html HTTP/1.1".  A target that is no path (a URL
/// that names its host, CONNECT's host and port, "*") stays as it is.
std::string httpRequest( const uint8_t* payload, size_t len )
{
    auto line = firstLine( payload, len );
    const auto host = headerValue( payload, len, "host" );
    const auto space = line.find( ' ' ); // after the method, which is plain ASCII
    if ( host && space != std::string::npos && space + 1 < line.size()
         && line[ space + 1 ] == '/' ) {
        line.insert( space + 1, fieldText( host->data, host->len ) );
    }
    return line;
}

/// The status line, then the Content-Type and Content-Length headers the
/// response has, "HTTP/1.1 200 OK, Content-Type: text/html, Content-Length: 1234".
std::string httpResponse( const uint8_t* payload, size_t len )
{
    auto line = firstLine( payload, len );
    static const std::pair<const char*, const char*> kShown[] = {
        { "content-type", "Content-Type" },
        { "content-length", "Content-Length" },
    };
    for ( const auto& [ key, name ] : kShown ) {
        if ( const auto value = headerValue( payload, len, key ) ) {
            line += std::string( ", " ) + name + ": " + fieldText( value->data, value->len );
        }
    }
    return line;
}

/// Detect HTTP request or response from payload start.
std::string detectHttp( const uint8_t* payload, size_t len )
{
    if ( len < 4 )
        return {};

    // HTTP methods
    auto startsWith = [ & ]( const char* prefix ) {
        auto pLen = std::strlen( prefix );
        return len >= pLen && std::memcmp( payload, prefix, pLen ) == 0;
    };

    if ( startsWith( "GET " ) || startsWith( "POST " ) || startsWith( "PUT " )
         || startsWith( "DELETE " ) || startsWith( "HEAD " ) || startsWith( "PATCH " )
         || startsWith( "OPTIONS " ) || startsWith( "CONNECT " ) ) {
        return httpRequest( payload, len );
    }

    if ( startsWith( "HTTP/" ) ) {
        return httpResponse( payload, len );
    }

    return {};
}

// ── NMEA ─────────────────────────────────────────────────────────────────

/// Detect NMEA 0183 sentences in payload (GPS: $GPGGA, $GNGSA, $GPGSV, etc.)
/// Requires the mandatory comma after the 5-char sentence ID to avoid false
/// positives on ADB protocol frames like $WRTE which also match $ + 5 alpha.
std::string detectNmea( const uint8_t* payload, size_t len )
{
    // Scan for '$' + 5 alpha chars + ',' (NMEA 0183 mandatory format)
    for ( size_t i = 0; i + 7 < len; ++i ) {
        if ( payload[ i ] == '$' && isAsciiAlpha( payload[ i + 1 ] )
             && isAsciiAlpha( payload[ i + 2 ] ) && isAsciiAlpha( payload[ i + 3 ] )
             && isAsciiAlpha( payload[ i + 4 ] ) && isAsciiAlpha( payload[ i + 5 ] )
             && payload[ i + 6 ] == ',' ) {
            // Found an NMEA sentence — extract until CR/LF
            return firstLine( payload + i, len - i );
        }
    }
    return {};
}

// ── Payload preview ──────────────────────────────────────────────────────

/// Build an ASCII preview of a payload: printable bytes as themselves,
/// every other byte as a dot, at most kMaxPreviewChars characters followed
/// by an ellipsis.  Returns empty if the payload is predominantly binary
/// (less than 40% printable), where a preview would only be dots.
std::string payloadPreview( const uint8_t* payload, size_t len )
{
    auto isPrintable = []( uint8_t c ) { return c >= 0x20 && c < 0x7F; };

    const auto printable
        = static_cast<size_t>( std::count_if( payload, payload + len, isPrintable ) );
    if ( printable == 0 || printable * 10 < len * 4 ) {
        return {};
    }

    const size_t shown = std::min( len, kMaxPreviewChars );
    std::string preview;
    preview.reserve( shown + 3 );
    for ( size_t i = 0; i < shown; ++i ) {
        preview += isPrintable( payload[ i ] ) ? static_cast<char>( payload[ i ] ) : '.';
    }
    if ( len > shown ) {
        preview += "\xe2\x80\xa6"; // …
    }
    return preview;
}

// ── Binary fields ────────────────────────────────────────────────────────

/// Reads the fields of a binary message (TLS, QUIC) from its bytes, never
/// beyond them.  A read that does not fit fails and leaves the reader as it
/// was.
class FieldReader {
public:
    FieldReader( const uint8_t* data, size_t len, bool complete = true )
        : data_( data )
        , len_( len )
        , complete_( complete )
    {
    }

    bool u8( uint8_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        value = data_[ pos_++ ];
        return true;
    }

    bool u16( uint16_t& value )
    {
        if ( len_ - pos_ < 2 ) {
            return false;
        }
        value = readBE16( data_ + pos_ );
        pos_ += 2;
        return true;
    }

    bool u24( uint32_t& value )
    {
        if ( len_ - pos_ < 3 ) {
            return false;
        }
        value = ( static_cast<uint32_t>( data_[ pos_ ] ) << 16 ) | readBE16( data_ + pos_ + 1 );
        pos_ += 3;
        return true;
    }

    bool u32( uint32_t& value )
    {
        if ( len_ - pos_ < 4 ) {
            return false;
        }
        value = readBE32( data_ + pos_ );
        pos_ += 4;
        return true;
    }

    /// A QUIC variable-length integer (RFC 9000, 16): its first two bits
    /// say whether it takes 1, 2, 4 or 8 bytes.
    bool varint( uint64_t& value )
    {
        if ( len_ - pos_ < 1 ) {
            return false;
        }
        const size_t n = size_t{ 1 } << ( data_[ pos_ ] >> 6 );
        if ( len_ - pos_ < n ) {
            return false;
        }
        value = data_[ pos_ ] & 0x3F;
        for ( size_t i = 1; i < n; ++i ) {
            value = ( value << 8 ) | data_[ pos_ + i ];
        }
        pos_ += n;
        return true;
    }

    bool skip( size_t n )
    {
        if ( len_ - pos_ < n ) {
            return false;
        }
        pos_ += n;
        return true;
    }

    /// Skip a field behind its 8-bit length.
    bool skipVector8()
    {
        uint8_t n = 0;
        return u8( n ) && skip( n );
    }

    /// The next @p n bytes as a reader of their own: as many of them as
    /// there are, so a cut message is read as far as it goes.
    FieldReader take( size_t n )
    {
        const size_t available = std::min( n, len_ - pos_ );
        FieldReader part( data_ + pos_, available, available == n );
        pos_ += available;
        return part;
    }

    /// The next 8- or 16-bit length and the bytes it counts.
    bool takeVector8( FieldReader& part )
    {
        uint8_t n = 0;
        if ( !u8( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    bool takeVector16( FieldReader& part )
    {
        uint16_t n = 0;
        if ( !u16( n ) ) {
            return false;
        }
        part = take( n );
        return true;
    }

    /// All the bytes this reader was taken for are there.
    bool complete() const
    {
        return complete_;
    }

    /// All its bytes are there and read.
    bool readToEnd() const
    {
        return complete_ && pos_ == len_;
    }

    size_t remaining() const
    {
        return len_ - pos_;
    }
    const uint8_t* here() const
    {
        return data_ + pos_;
    }

private:
    const uint8_t* data_;
    size_t len_;
    size_t pos_ = 0;
    bool complete_;
};

// ── DNS ──────────────────────────────────────────────────────────────────

/// Longest name on the wire, its length bytes and the root label included
/// (RFC 1035, 3.1).
constexpr size_t kMaxDnsNameBytes = 255;

/// Most compression pointers followed in one name.  Each must point before
/// itself, so a chain of them ends anyway; this bounds its length.
constexpr size_t kMaxDnsPointers = 64;

/// Most answers listed in one message, and messages in one TCP segment.
constexpr size_t kMaxDnsAnswers = 4;
constexpr size_t kMaxDnsMessages = 4;

/// A DNS message: the bytes compression pointers count from.
struct DnsMessage {
    const uint8_t* data;
    size_t len;
};

/// The name of a record type, as Wireshark writes it, or "TYPEnnn" (RFC 3597).
std::string dnsTypeName( uint16_t type )
{
    switch ( type ) {
    case 1:
        return "A";
    case 2:
        return "NS";
    case 5:
        return "CNAME";
    case 6:
        return "SOA";
    case 12:
        return "PTR";
    case 13:
        return "HINFO";
    case 15:
        return "MX";
    case 16:
        return "TXT";
    case 28:
        return "AAAA";
    case 33:
        return "SRV";
    case 35:
        return "NAPTR";
    case 39:
        return "DNAME";
    case 41:
        return "OPT";
    case 43:
        return "DS";
    case 46:
        return "RRSIG";
    case 47:
        return "NSEC";
    case 48:
        return "DNSKEY";
    case 50:
        return "NSEC3";
    case 52:
        return "TLSA";
    case 64:
        return "SVCB";
    case 65:
        return "HTTPS";
    case 251:
        return "IXFR";
    case 252:
        return "AXFR";
    case 255:
        return "ANY";
    case 257:
        return "CAA";
    default:
        return "TYPE" + std::to_string( type );
    }
}

/// The operation of a message (its opcode), as Wireshark names it.
std::string dnsOperation( unsigned opcode )
{
    switch ( opcode ) {
    case 0:
        return "Standard query";
    case 1:
        return "Inverse query";
    case 2:
        return "Server status request";
    case 4:
        return "Zone change notification";
    case 5:
        return "Dynamic update";
    case 6:
        return "DNS stateful operation";
    default:
        return "Unknown operation (" + std::to_string( opcode ) + ")";
    }
}

/// A response code other than "no error", as "[NXDOMAIN]".
std::string dnsResponseCode( unsigned rcode )
{
    static const char* const kNames[]
        = { nullptr, "FORMERR", "SERVFAIL", "NXDOMAIN", "NOTIMP", "REFUSED" };
    if ( rcode < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return std::string( "[" ) + kNames[ rcode ] + "]";
    }
    return "[RCODE=" + std::to_string( rcode ) + "]";
}

/// Read the name at @p reader's position, a part of @p message, as text
/// into @p name, and move the reader past it.  Compression pointers
/// (RFC 1035, 4.1.4) are followed within the message, and only backwards:
/// a pointer to itself, to a later byte or beyond the message, a label of a
/// reserved type and a name longer than 255 bytes fail the read.  The text
/// is cut at kMaxFieldBytes; the root is "<Root>", as in Wireshark.
bool readDnsName( const DnsMessage& message, FieldReader& reader, std::string& name )
{
    std::string raw;
    size_t pos = static_cast<size_t>( reader.here() - message.data );
    size_t end = 0; // where the name ends in place: behind its first pointer, or its root label
    size_t wireBytes = 1; // the root label
    size_t pointers = 0;
    for ( ;; ) {
        if ( pos >= message.len ) {
            return false;
        }
        const uint8_t length = message.data[ pos ];
        if ( ( length & 0xC0 ) == 0xC0 ) {
            if ( message.len - pos < 2 ) {
                return false;
            }
            const size_t target
                = ( static_cast<size_t>( length & 0x3F ) << 8 ) | message.data[ pos + 1 ];
            if ( target >= pos || ++pointers > kMaxDnsPointers ) {
                return false;
            }
            if ( end == 0 ) {
                end = pos + 2;
            }
            pos = target;
            continue;
        }
        if ( ( length & 0xC0 ) != 0 ) {
            return false;
        }
        if ( length == 0 ) {
            if ( end == 0 ) {
                end = pos + 1;
            }
            break;
        }
        wireBytes += 1 + length;
        if ( wireBytes > kMaxDnsNameBytes || message.len - pos - 1 < length ) {
            return false;
        }
        if ( !raw.empty() ) {
            raw += '.';
        }
        raw.append( reinterpret_cast<const char*>( message.data + pos + 1 ), length );
        pos += 1 + length;
    }

    if ( !reader.skip( end - static_cast<size_t>( reader.here() - message.data ) ) ) {
        return false;
    }
    name = raw.empty() ? "<Root>"
                       : fieldText( reinterpret_cast<const uint8_t*>( raw.data() ), raw.size() );
    return true;
}

/// A question as "A example.com".
bool readDnsQuestion( const DnsMessage& message, FieldReader& reader, std::string& text )
{
    std::string name;
    uint16_t type = 0;
    if ( !readDnsName( message, reader, name ) || !reader.u16( type ) || !reader.skip( 2 ) ) {
        return false;
    }
    text = dnsTypeName( type ) + " " + name;
    return true;
}

/// The character-strings of a TXT record, quoted, at most kMaxFieldBytes of
/// them, then an ellipsis.
bool dnsTextStrings( FieldReader data, std::string& text )
{
    size_t shown = 0;
    FieldReader string( nullptr, 0 );
    while ( data.remaining() > 0 ) {
        if ( !data.takeVector8( string ) || !string.complete() ) {
            return false;
        }
        if ( shown + string.remaining() > kMaxFieldBytes ) {
            text += " \xe2\x80\xa6";
            return true;
        }
        shown += string.remaining();
        text += " " + quotedBytes( string.here(), string.remaining() );
    }
    return true;
}

/// An answer as its type and data, "A 93.184.216.34", "MX 10 mail.example.com";
/// the data of a type not listed here is left out.  A record cut short or
/// with malformed data fails the read.
bool readDnsAnswer( const DnsMessage& message, FieldReader& reader, std::string& text )
{
    std::string owner;
    uint16_t type = 0;
    uint16_t length = 0;
    if ( !readDnsName( message, reader, owner ) || !reader.u16( type ) || !reader.skip( 2 + 4 )
         || !reader.u16( length ) ) {
        return false;
    }
    auto data = reader.take( length );
    if ( !data.complete() ) {
        return false;
    }

    text = dnsTypeName( type );
    std::string name;
    uint16_t preference = 0;
    uint16_t weight = 0;
    uint16_t port = 0;
    switch ( type ) {
    case 1: // A
        if ( length != 4 ) {
            return false;
        }
        text += " " + formatIpv4( data.here() );
        return true;
    case 28: // AAAA
        if ( length != 16 ) {
            return false;
        }
        text += " " + formatIpv6( data.here() );
        return true;
    case 2:  // NS
    case 5:  // CNAME
    case 6:  // SOA: its primary name server
    case 12: // PTR
    case 39: // DNAME
        if ( !readDnsName( message, data, name ) ) {
            return false;
        }
        text += " " + name;
        return true;
    case 15: // MX
        if ( !data.u16( preference ) || !readDnsName( message, data, name ) ) {
            return false;
        }
        text += " " + std::to_string( preference ) + " " + name;
        return true;
    case 16: // TXT
        return dnsTextStrings( data, text );
    case 33: // SRV
        if ( !data.u16( preference ) || !data.u16( weight ) || !data.u16( port )
             || !readDnsName( message, data, name ) ) {
            return false;
        }
        text += " " + std::to_string( preference ) + " " + std::to_string( weight ) + " "
                + std::to_string( port ) + " " + name;
        return true;
    default:
        return true;
    }
}

/// Describe a DNS message like Wireshark: "Standard query 0x1a2b A
/// example.com", "Standard query response 0x1a2b A example.com A
/// 93.184.216.34".  The first question is shown, then a response code
/// other than "no error", then the answers, up to kMaxDnsAnswers.  Answers
/// not listed, beyond the cap or cut short, are counted: "… (6 answers)".
/// Empty if the message is shorter than its header.
std::string describeDnsMessage( const DnsMessage& message )
{
    FieldReader reader( message.data, message.len );
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t questions = 0;
    uint16_t answers = 0;
    if ( !reader.u16( id ) || !reader.u16( flags ) || !reader.u16( questions )
         || !reader.u16( answers ) || !reader.skip( 4 ) ) {
        return {};
    }

    const bool isResponse = ( flags & 0x8000 ) != 0;
    char idText[ 8 ];
    std::snprintf( idText, sizeof( idText ), "0x%04x", id );
    std::string description
        = dnsOperation( ( flags >> 11 ) & 0x0F ) + ( isResponse ? " response " : " " ) + idText;

    // The questions: the first one shown, every one read to find the answers.
    bool readable = true;
    for ( unsigned i = 0; i < questions && readable; ++i ) {
        std::string question;
        readable = readDnsQuestion( message, reader, question );
        if ( readable && i == 0 ) {
            description += " " + question;
        }
    }

    const auto rcode = flags & 0x000F;
    if ( isResponse && rcode != 0 ) {
        description += " " + dnsResponseCode( rcode );
    }

    size_t listed = 0;
    for ( ; readable && listed < answers && listed < kMaxDnsAnswers; ++listed ) {
        std::string answer;
        readable = readDnsAnswer( message, reader, answer );
        if ( !readable ) {
            break;
        }
        description += " " + answer;
    }
    if ( listed < answers ) {
        if ( listed > 0 ) {
            description += " \xe2\x80\xa6";
        }
        description
            += " (" + std::to_string( answers ) + ( answers == 1 ? " answer)" : " answers)" );
    }
    return description;
}

/// Describe a DNS message sent over UDP: the whole datagram.
std::string detectDns( const uint8_t* payload, size_t len )
{
    return describeDnsMessage( { payload, len } );
}

/// A DNS-over-TCP message header that is plausible: a header's length, a
/// known operation, the Z bit clear and at most one question, as every
/// message over TCP has.  Tells the start of a message from the middle of
/// one, which a segment may begin with.
bool isPlausibleDnsHeader( FieldReader message, uint16_t length )
{
    uint16_t id = 0;
    uint16_t flags = 0;
    uint16_t questions = 0;
    if ( length < 12 || !message.u16( id ) || !message.u16( flags ) || !message.u16( questions ) ) {
        return false;
    }
    const unsigned opcode = ( flags >> 11 ) & 0x0F;
    return opcode <= 6 && opcode != 3 && ( flags & 0x0040 ) == 0 && questions <= 1;
}

/// Describe the DNS messages of a TCP segment (RFC 1035, 4.2.2), each
/// behind its 2-byte length: "Standard query 0x0001 A example.com, Standard
/// query 0x0002 AAAA example.com", up to kMaxDnsMessages, then an ellipsis.
/// A message cut by the segment is described as far as it goes and ends
/// the list.  Empty if the segment does not begin with a message: the rest
/// of one that began in an earlier segment is not described.
std::string detectDnsOverTcp( const uint8_t* payload, size_t len )
{
    std::string description;
    size_t described = 0;
    FieldReader segment( payload, len );
    uint16_t length = 0;
    while ( segment.u16( length ) ) {
        auto message = segment.take( length );
        if ( !isPlausibleDnsHeader( message, length ) ) {
            break;
        }
        if ( !description.empty() ) {
            description += ", ";
        }
        if ( described == kMaxDnsMessages ) {
            description += "\xe2\x80\xa6";
            break;
        }
        description += describeDnsMessage( { message.here(), message.remaining() } );
        ++described;
        if ( !message.complete() ) {
            break;
        }
    }
    return description;
}

// ── DHCP ─────────────────────────────────────────────────────────────────

/// Where the BOOTP header (RFC 2131, 2) has the fields described: the
/// client's own address, the one the server assigns ("your" address), the
/// client hardware address, the server name and file fields, which an
/// overload option fills with options, and the options behind the magic
/// cookie.
constexpr size_t kDhcpCiaddrAt = 12;
constexpr size_t kDhcpYiaddrAt = 16;
constexpr size_t kDhcpChaddrAt = 28;
constexpr size_t kDhcpSnameAt = 44;
constexpr size_t kDhcpSnameBytes = 64;
constexpr size_t kDhcpFileAt = 108;
constexpr size_t kDhcpFileBytes = 128;
constexpr size_t kDhcpCookieAt = 236;
constexpr size_t kDhcpOptionsAt = 240;
constexpr uint32_t kDhcpMagicCookie = 0x63825363;

/// What the options of a DHCP message say that its description shows.
struct DhcpOptions {
    int messageType = -1;                      ///< Option 53; -1: none.
    const uint8_t* requestedAddress = nullptr; ///< Option 50.
    std::string hostName;                      ///< Option 12, as text.
    uint8_t overload = 0; ///< Option 52: 1 the file field, 2 sname, 3 both hold options.
};

/// Walk the options in @p field (RFC 2132, 2): pads skipped, up to the end
/// option or the end of the field.  An option whose length runs past the
/// field ends the walk; one of the wrong length is ignored.  Only the
/// options field itself may overload others (@p mayOverload).
void readDhcpOptions( FieldReader field, DhcpOptions& options, bool mayOverload )
{
    uint8_t code = 0;
    FieldReader value( nullptr, 0 );
    while ( field.u8( code ) && code != 255 ) {
        if ( code == 0 ) {
            continue;
        }
        if ( !field.takeVector8( value ) || !value.complete() ) {
            return;
        }
        const auto length = value.remaining();
        switch ( code ) {
        case 53:
            if ( length == 1 ) {
                options.messageType = value.here()[ 0 ];
            }
            break;
        case 50:
            if ( length == 4 ) {
                options.requestedAddress = value.here();
            }
            break;
        case 12:
            if ( length > 0 ) {
                options.hostName = fieldText( value.here(), length );
            }
            break;
        case 52:
            if ( mayOverload && length == 1 ) {
                options.overload = value.here()[ 0 ];
            }
            break;
        default:
            break;
        }
    }
}

/// A DHCP message type (option 53) as Wireshark names it, "DHCP Discover".
std::string dhcpMessageName( int type )
{
    static const char* const kNames[] = {
        nullptr,
        "Discover",
        "Offer",
        "Request",
        "Decline",
        "ACK",
        "NAK",
        "Release",
        "Inform",
        "Force Renew",
        "Lease query",
        "Lease Unassigned",
        "Lease Unknown",
        "Lease Active",
        "Bulk Lease Query",
        "Lease Query Done",
        "Active LeaseQuery",
        "Lease Query Status",
        "TLS",
    };
    if ( type > 0 && static_cast<size_t>( type ) < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return std::string( "DHCP " ) + kNames[ type ];
    }
    char buf[ 48 ];
    std::snprintf( buf, sizeof( buf ), "DHCP Unknown Message Type (0x%02x)", type );
    return buf;
}

/// A non-zero IPv4 address at @p at of the message, if it holds one there.
const uint8_t* dhcpAddress( const uint8_t* payload, size_t len, size_t at )
{
    if ( len < at + 4 || readBE32( payload + at ) == 0 ) {
        return nullptr;
    }
    return payload + at;
}

/// Describe a DHCP message like Wireshark, with the client and its address:
/// "DHCP Offer - Transaction ID 0x3903f326, 192.168.1.50 for
/// 00:11:22:33:44:55", "DHCP Discover - Transaction ID 0x3903f326 from
/// 00:11:22:33:44:55, Host Name: laptop".  The address is the one the
/// server assigns, else the one the client requests (option 50), else the
/// one it holds.  A message without a message type option (BOOTP) is a
/// "Boot Request" or "Boot Reply".  Options are read in the options field,
/// then in the file and sname fields if an overload option says they hold
/// options.  Empty if the payload is no BOOTP message, or shorter than its
/// transaction id.
std::string detectDhcp( const uint8_t* payload, size_t len )
{
    FieldReader header( payload, len );
    uint8_t op = 0;
    uint8_t htype = 0;
    uint8_t hlen = 0;
    uint32_t xid = 0;
    if ( !header.u8( op ) || ( op != 1 && op != 2 ) || !header.u8( htype ) || !header.u8( hlen )
         || !header.skip( 1 ) || !header.u32( xid ) ) {
        return {};
    }

    DhcpOptions options;
    if ( len >= kDhcpOptionsAt && readBE32( payload + kDhcpCookieAt ) == kDhcpMagicCookie ) {
        readDhcpOptions( { payload + kDhcpOptionsAt, len - kDhcpOptionsAt }, options, true );
        if ( options.overload & 1 ) {
            readDhcpOptions( { payload + kDhcpFileAt, kDhcpFileBytes }, options, false );
        }
        if ( options.overload & 2 ) {
            readDhcpOptions( { payload + kDhcpSnameAt, kDhcpSnameBytes }, options, false );
        }
    }

    char xidText[ 16 ];
    std::snprintf( xidText, sizeof( xidText ), "0x%08x", xid );
    std::string description = options.messageType >= 0
                                  ? dhcpMessageName( options.messageType )
                                  : ( op == 1 ? "Boot Request" : "Boot Reply" );
    description += std::string( " - Transaction ID " ) + xidText;

    const uint8_t* address = dhcpAddress( payload, len, kDhcpYiaddrAt );
    if ( !address ) {
        address = options.requestedAddress;
    }
    if ( !address ) {
        address = dhcpAddress( payload, len, kDhcpCiaddrAt );
    }
    const bool ethernet = htype == 1 && hlen == 6 && len >= kDhcpChaddrAt + 6;
    if ( address ) {
        description += ", " + formatIpv4( address );
    }
    if ( ethernet ) {
        description
            += ( address || op == 2 ? " for " : " from " ) + formatMac( payload + kDhcpChaddrAt );
    }
    if ( !options.hostName.empty() ) {
        description += ", Host Name: " + options.hostName;
    }
    return description;
}

// ── DHCPv6 ───────────────────────────────────────────────────────────────

/// Most relays one message is looked into: RFC 8415, 7.6, lets a message
/// pass at most 8 of them.
constexpr int kMaxDhcpv6Relays = 8;

/// Most bytes of a DUID shown, as hexadecimal.
constexpr size_t kMaxDuidBytes = 32;

constexpr uint8_t kDhcpv6RelayForward = 12;
constexpr uint8_t kDhcpv6RelayReply = 13;

/// A DHCPv6 message type as Wireshark names it, "Solicit", or "Unknown (99)".
std::string dhcpv6MessageName( uint8_t type )
{
    static const char* const kNames[] = {
        nullptr,
        "Solicit",
        "Advertise",
        "Request",
        "Confirm",
        "Renew",
        "Rebind",
        "Reply",
        "Release",
        "Decline",
        "Reconfigure",
        "Information-request",
        "Relay-forw",
        "Relay-reply",
        "Leasequery",
        "Leasequery-reply",
        "Leasequery-done",
        "Leasequery-data",
        "Reconfigure-request",
        "Reconfigure-reply",
        "DHCPv4-query",
        "DHCPv4-response",
    };
    if ( type > 0 && type < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return kNames[ type ];
    }
    return "Unknown (" + std::to_string( type ) + ")";
}

/// @p len bytes as lowercase hexadecimal, at most kMaxDuidBytes of them,
/// then an ellipsis.
std::string hexBytes( const uint8_t* p, size_t len )
{
    std::string out;
    char buf[ 3 ];
    for ( size_t i = 0; i < len && i < kMaxDuidBytes; ++i ) {
        std::snprintf( buf, sizeof( buf ), "%02x", p[ i ] );
        out += buf;
    }
    return len > kMaxDuidBytes ? out + "\xe2\x80\xa6" : out;
}

/// Describe a DHCPv6 message like Wireshark: "Solicit XID: 0x1a2b3c CID:
/// 000100011c39cf88001122334455", the client's DUID (option 1) if it has
/// one; a relay message names its link address and the message it relays
/// (option 9), "Relay-forw L: 2001:db8::1, Solicit XID: …", up to
/// kMaxDhcpv6Relays deep.  Options are walked within the message; one whose
/// length runs past it ends the walk.  Empty if the message is shorter than
/// its header.
std::string describeDhcpv6( FieldReader message, int relays = 0 )
{
    uint8_t type = 0;
    if ( !message.u8( type ) ) {
        return {};
    }
    const bool relay = type == kDhcpv6RelayForward || type == kDhcpv6RelayReply;
    std::string description = dhcpv6MessageName( type );
    if ( relay ) {
        if ( message.remaining() < 1 + 16 + 16 ) {
            return {};
        }
        description += " L: " + formatIpv6( message.here() + 1 );
        message.skip( 1 + 16 + 16 );
    }
    else {
        uint32_t xid = 0;
        if ( !message.u24( xid ) ) {
            return {};
        }
        char xidText[ 16 ];
        std::snprintf( xidText, sizeof( xidText ), " XID: 0x%06x", xid );
        description += xidText;
    }

    uint16_t code = 0;
    FieldReader value( nullptr, 0 );
    while ( message.u16( code ) && message.takeVector16( value ) && value.complete() ) {
        if ( !relay && code == 1 && value.remaining() > 0 ) {
            description += " CID: " + hexBytes( value.here(), value.remaining() );
            break;
        }
        if ( relay && code == 9 ) {
            const auto relayed
                = relays < kMaxDhcpv6Relays ? describeDhcpv6( value, relays + 1 ) : std::string();
            if ( !relayed.empty() ) {
                description += ", " + relayed;
            }
            break;
        }
    }
    return description;
}

std::string detectDhcpv6( const uint8_t* payload, size_t len )
{
    return describeDhcpv6( { payload, len } );
}

// ── NTP ──────────────────────────────────────────────────────────────────

/// The NTP header of modes 0 to 5 (RFC 5905, 7.3), without extensions.
constexpr size_t kNtpHeaderBytes = 48;
constexpr uint8_t kNtpModeClient = 3;
constexpr uint8_t kNtpModeControl = 6;

/// An NTP mode as Wireshark's Info names it.
const char* ntpModeName( uint8_t mode )
{
    static const char* const kNames[] = {
        "reserved", "symmetric active", "symmetric passive", "client",
        "server",   "broadcast",        "control",           "private",
    };
    return kNames[ mode & 7 ];
}

/// The reference identifier of a stratum 0 or 1 packet as text: a
/// kiss-o'-death code ("RATE") or the primary source ("GPS"), padded with
/// NULs; empty unless it is printable ASCII.
std::string ntpReferenceText( const uint8_t* id )
{
    size_t length = 4;
    while ( length > 0 && id[ length - 1 ] == 0 ) {
        --length;
    }
    for ( size_t i = 0; i < length; ++i ) {
        if ( id[ i ] < 0x20 || id[ i ] >= 0x7F ) {
            return {};
        }
    }
    return std::string( reinterpret_cast<const char*>( id ), length );
}

/// Describe an NTP packet like Wireshark, "NTP Version 4, server", then its
/// stratum, "stratum 2", with the reference identifier of a primary server
/// or a kiss-o'-death, "stratum 1 (GPS)".  The stratum of a client request,
/// 0 as a rule, is left out unless it is set.  Control (mode 6) and private
/// (mode 7) messages have another header: only their version and mode are
/// shown.  Empty if the version is not 1 to 4, or the packet of mode 0 to 5
/// shorter than its header.
std::string detectNtp( const uint8_t* payload, size_t len )
{
    if ( len < 1 ) {
        return {};
    }
    const uint8_t version = ( payload[ 0 ] >> 3 ) & 7;
    const uint8_t mode = payload[ 0 ] & 7;
    if ( version < 1 || version > 4 || ( mode < kNtpModeControl && len < kNtpHeaderBytes ) ) {
        return {};
    }
    std::string description
        = "NTP Version " + std::to_string( version ) + ", " + ntpModeName( mode );
    if ( mode >= kNtpModeControl ) {
        return description;
    }
    const uint8_t stratum = payload[ 1 ];
    if ( mode == kNtpModeClient && stratum == 0 ) {
        return description;
    }
    description += ", stratum " + std::to_string( stratum );
    if ( stratum <= 1 ) {
        const auto reference = ntpReferenceText( payload + 12 );
        if ( !reference.empty() ) {
            description += " (" + reference + ")";
        }
    }
    return description;
}

// ── TLS ──────────────────────────────────────────────────────────────────

/// Most bytes of a hello field (a server name, the protocol list) shown.
constexpr size_t kMaxTlsFieldBytes = kMaxFieldBytes;

/// Most records and handshake messages named in one segment.
constexpr size_t kMaxTlsMessages = 4;

/// A protocol version as "TLS 1.3".
std::string tlsVersionName( uint16_t version )
{
    switch ( version ) {
    case 0x0300:
        return "SSL 3.0";
    case 0x0301:
        return "TLS 1.0";
    case 0x0302:
        return "TLS 1.1";
    case 0x0303:
        return "TLS 1.2";
    case 0x0304:
        return "TLS 1.3";
    default: {
        char buf[ 16 ];
        std::snprintf( buf, sizeof( buf ), "TLS 0x%04X", version );
        return buf;
    }
    }
}

/// A GREASE value (RFC 8701), sent to keep servers tolerant, not meant.
bool isGrease( uint16_t value )
{
    return ( value & 0x0F0F ) == 0x0A0A && ( value >> 8 ) == ( value & 0xFF );
}

/// The host name of a server_name extension (RFC 6066), or empty.
std::string tlsServerName( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector16( list ) ) {
        return {};
    }
    uint8_t type = 0;
    FieldReader name( nullptr, 0 );
    while ( list.u8( type ) && list.takeVector16( name ) && name.complete() ) {
        if ( type == 0 ) { // host_name
            return fieldText( name.here(), name.remaining() );
        }
    }
    return {};
}

/// The protocols of an ALPN extension (RFC 7301), as "h2,http/1.1".
std::string tlsAlpn( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector16( list ) ) {
        return {};
    }
    std::string protocols;
    size_t shown = 0;
    FieldReader protocol( nullptr, 0 );
    while ( list.takeVector8( protocol ) && protocol.complete() ) {
        if ( shown + protocol.remaining() > kMaxTlsFieldBytes ) {
            return protocols + ( protocols.empty() ? "" : "," ) + "\xe2\x80\xa6";
        }
        if ( !protocols.empty() ) {
            protocols += ',';
        }
        protocols += escapeBytes( protocol.here(), protocol.remaining(), false );
        shown += protocol.remaining();
    }
    return protocols;
}

/// The highest version of a ClientHello's supported_versions extension
/// (RFC 8446), GREASE aside; 0 if it names none.
uint16_t tlsHighestVersion( FieldReader data )
{
    FieldReader list( nullptr, 0 );
    if ( !data.takeVector8( list ) ) {
        return 0;
    }
    uint16_t highest = 0;
    uint16_t version = 0;
    while ( list.u16( version ) ) {
        if ( !isGrease( version ) ) {
            highest = std::max( highest, version );
        }
    }
    return highest;
}

/// The extensions of a hello, read as far as they are there, each one
/// whole; @p onExtension(type, data) is called for each.  True if all of
/// them were read, so that a field one of them would have named is known
/// to be absent.
template <typename OnExtension>
bool readTlsExtensions( FieldReader& hello, OnExtension onExtension )
{
    if ( hello.readToEnd() ) {
        return true; // a hello without extensions
    }
    FieldReader extensions( nullptr, 0 );
    if ( !hello.takeVector16( extensions ) ) {
        return false;
    }
    uint16_t type = 0;
    FieldReader data( nullptr, 0 );
    while ( extensions.u16( type ) && extensions.takeVector16( data ) && data.complete() ) {
        onExtension( type, data );
    }
    return extensions.readToEnd();
}

/// "Client Hello, SNI=example.com, TLS 1.3, ALPN=h2,http/1.1": the fields
/// a ClientHello holds, each left out if absent or cut off.  The version is
/// the highest the client offers.
std::string tlsClientHello( FieldReader hello )
{
    std::string description = "Client Hello";
    uint16_t legacyVersion = 0;
    if ( !hello.u16( legacyVersion ) || !hello.skip( 32 ) || !hello.skipVector8() ) {
        return description;
    }
    uint16_t cipherSuitesLength = 0;
    if ( !hello.u16( cipherSuitesLength ) || !hello.skip( cipherSuitesLength )
         || !hello.skipVector8() ) {
        return description;
    }

    std::string serverName;
    std::string protocols;
    uint16_t version = 0;
    const bool allRead = readTlsExtensions( hello, [ & ]( uint16_t type, FieldReader data ) {
        if ( type == 0x0000 && serverName.empty() ) {
            serverName = tlsServerName( data );
        }
        else if ( type == 0x002B && version == 0 ) {
            version = tlsHighestVersion( data );
        }
        else if ( type == 0x0010 && protocols.empty() ) {
            protocols = tlsAlpn( data );
        }
    } );
    if ( version == 0 && allRead ) {
        version = legacyVersion;
    }

    if ( !serverName.empty() ) {
        description += ", SNI=" + serverName;
    }
    if ( version != 0 ) {
        description += ", " + tlsVersionName( version );
    }
    if ( !protocols.empty() ) {
        description += ", ALPN=" + protocols;
    }
    return description;
}

/// "Server Hello, TLS 1.3": the version the server chose, if it is there.
std::string tlsServerHello( FieldReader hello )
{
    std::string description = "Server Hello";
    uint16_t legacyVersion = 0;
    if ( !hello.u16( legacyVersion ) || !hello.skip( 32 ) || !hello.skipVector8()
         || !hello.skip( 2 + 1 ) ) { // cipher suite, compression method
        return description;
    }
    uint16_t version = 0;
    const bool allRead = readTlsExtensions( hello, [ & ]( uint16_t type, FieldReader data ) {
        uint16_t selected = 0;
        if ( type == 0x002B && data.u16( selected ) ) {
            version = selected;
        }
    } );
    if ( version == 0 && allRead ) {
        version = legacyVersion;
    }
    if ( version != 0 ) {
        description += ", " + tlsVersionName( version );
    }
    return description;
}

/// The name of a handshake message, with the fields of the hellos.
std::string tlsHandshakeMessage( uint8_t type, FieldReader body )
{
    switch ( type ) {
    case 0:
        return "Hello Request";
    case 1:
        return tlsClientHello( body );
    case 2:
        return tlsServerHello( body );
    case 4:
        return "New Session Ticket";
    case 8:
        return "Encrypted Extensions";
    case 11:
        return "Certificate";
    case 12:
        return "Server Key Exchange";
    case 13:
        return "Certificate Request";
    case 14:
        return "Server Hello Done";
    case 15:
        return "Certificate Verify";
    case 16:
        return "Client Key Exchange";
    case 20:
        return "Finished";
    default:
        return "Handshake";
    }
}

/// A TLS record header: a content type TLS knows and protocol version 3.x.
bool isTlsRecordHeader( const uint8_t* p )
{
    return p[ 0 ] >= 0x14 && p[ 0 ] <= 0x17 && p[ 1 ] == 0x03;
}

/// Describe the TLS records of a segment, in order: "Server Hello, TLS 1.3,
/// Change Cipher Spec, Application Data".  The payload must begin with a
/// record; the records are named up to kMaxTlsMessages, then an ellipsis.
/// A record cut short is named as far as it goes, and ends the list.
std::string detectTls( const uint8_t* payload, size_t len )
{
    // A record header, and a handshake record's message type.
    if ( len < 6 || !isTlsRecordHeader( payload ) ) {
        return {};
    }

    std::vector<std::string> names;
    bool afterChangeCipherSpec = false;
    FieldReader segment( payload, len );
    while ( names.size() <= kMaxTlsMessages && segment.remaining() >= 5
            && isTlsRecordHeader( segment.here() ) ) {
        uint8_t contentType = 0;
        uint16_t length = 0;
        segment.u8( contentType );
        segment.skip( 2 );
        segment.u16( length );
        auto fragment = segment.take( length );

        switch ( contentType ) {
        case 0x14:
            names.emplace_back( "Change Cipher Spec" );
            afterChangeCipherSpec = true;
            break;
        case 0x15:
            names.emplace_back( "Alert" );
            break;
        case 0x16: {
            if ( afterChangeCipherSpec ) {
                // The Finished message, encrypted with the new keys.
                names.emplace_back( "Encrypted Handshake Message" );
                break;
            }
            uint8_t type = 0;
            uint32_t messageLength = 0;
            if ( !fragment.u8( type ) ) {
                names.emplace_back( "Handshake" );
                break;
            }
            if ( !fragment.u24( messageLength ) ) {
                names.push_back( tlsHandshakeMessage( type, FieldReader( nullptr, 0, false ) ) );
                break;
            }
            for ( ;; ) {
                auto message = fragment.take( messageLength );
                names.push_back( tlsHandshakeMessage( type, message ) );
                if ( !message.complete() || names.size() > kMaxTlsMessages || !fragment.u8( type )
                     || !fragment.u24( messageLength ) ) {
                    break;
                }
            }
            break;
        }
        default:
            names.emplace_back( "Application Data" );
            break;
        }

        if ( !fragment.complete() ) {
            break;
        }
    }

    if ( names.size() > kMaxTlsMessages ) {
        names.resize( kMaxTlsMessages );
        names.emplace_back( "\xe2\x80\xa6" );
    }
    std::string description;
    for ( const auto& name : names ) {
        if ( !description.empty() ) {
            description += ", ";
        }
        description += name;
    }
    return description;
}

// ── QUIC ─────────────────────────────────────────────────────────────────

constexpr uint8_t kQuicLongHeader = 0x80; ///< The header form bit: a long header.
constexpr uint8_t kQuicFixedBit = 0x40;   ///< Set in every QUIC v1 and v2 packet.

constexpr uint32_t kQuicV1 = 0x00000001;
constexpr uint32_t kQuicV2 = 0x6B3343CF;

/// Longest connection ID of QUIC v1 and v2; the version-independent
/// header (RFC 8999) allows 255 bytes, in a Version Negotiation packet.
constexpr size_t kMaxQuicCidBytes = 20;

/// Most packets of one datagram named, the same cap as TLS records'.
constexpr size_t kMaxQuicPackets = kMaxTlsMessages;

/// Most versions of a Version Negotiation packet named.
constexpr size_t kMaxQuicVersions = 8;

/// A draft version of the IETF drafts that already have the long header of
/// QUIC v1 (separate connection ID lengths): draft-22 to draft-34.
bool isQuicDraft( uint32_t version )
{
    return ( version >> 8 ) == 0xFF0000 && ( version & 0xFF ) >= 22 && ( version & 0xFF ) <= 34;
}

/// A version whose packets the describer can read: v1, v2 and the drafts.
bool isKnownQuicVersion( uint32_t version )
{
    return version == kQuicV1 || version == kQuicV2 || isQuicDraft( version );
}

/// A version as "1", "2", "draft-29", or "0x1A2A3A4A".
std::string quicVersionName( uint32_t version )
{
    if ( version == kQuicV1 ) {
        return "1";
    }
    if ( version == kQuicV2 ) {
        return "2";
    }
    if ( isQuicDraft( version ) ) {
        return "draft-" + std::to_string( version & 0xFF );
    }
    char buf[ 16 ];
    std::snprintf( buf, sizeof( buf ), "0x%08X", version );
    return buf;
}

/// The name of a long header packet type; QUIC v2 (RFC 9369) numbers them
/// differently from v1 and the drafts.
const char* quicLongPacketName( uint32_t version, uint8_t firstByte )
{
    static const char* const kV1[] = { "Initial", "0-RTT", "Handshake", "Retry" };
    static const char* const kV2[] = { "Retry", "Initial", "0-RTT", "Handshake" };
    const auto type = static_cast<size_t>( ( firstByte >> 4 ) & 0x03 );
    return version == kQuicV2 ? kV2[ type ] : kV1[ type ];
}

/// Connection ID bytes in hex, as Wireshark shows them.
std::string quicCid( const uint8_t* p, size_t len )
{
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve( 2 * len );
    for ( size_t i = 0; i < len; ++i ) {
        out += kDigits[ p[ i ] >> 4 ];
        out += kDigits[ p[ i ] & 0x0F ];
    }
    return out;
}

/// The fields every long header starts with (RFC 8999, 5.1).
struct QuicLongHeader {
    uint8_t firstByte = 0;
    uint32_t version = 0;
    FieldReader dcid{ nullptr, 0 };
    FieldReader scid{ nullptr, 0 };
};

/// Read a long header's version-independent fields: true if the packet
/// begins with a long header of a known version, or with a Version
/// Negotiation packet's, whose connection IDs are whole.
bool readQuicLongHeader( FieldReader& packet, QuicLongHeader& header )
{
    if ( !packet.u8( header.firstByte ) || !( header.firstByte & kQuicLongHeader )
         || !packet.u32( header.version ) ) {
        return false;
    }
    const bool negotiation = header.version == 0;
    if ( !negotiation
         && ( !( header.firstByte & kQuicFixedBit ) || !isKnownQuicVersion( header.version ) ) ) {
        return false;
    }
    if ( !packet.takeVector8( header.dcid ) || !header.dcid.complete()
         || !packet.takeVector8( header.scid ) || !header.scid.complete() ) {
        return false;
    }
    return negotiation
           || ( header.dcid.remaining() <= kMaxQuicCidBytes
                && header.scid.remaining() <= kMaxQuicCidBytes );
}

/// ", DCID=…, SCID=…", each left out if empty.
std::string quicCids( const QuicLongHeader& header )
{
    std::string out;
    if ( header.dcid.remaining() > 0 ) {
        out += ", DCID=" + quicCid( header.dcid.here(), header.dcid.remaining() );
    }
    if ( header.scid.remaining() > 0 ) {
        out += ", SCID=" + quicCid( header.scid.here(), header.scid.remaining() );
    }
    return out;
}

/// "Version Negotiation, DCID=…, SCID=…, Versions=1,draft-29": the versions
/// the server supports, if they are a whole list holding one this describer
/// knows; a client never sends such a packet, so anything less is no QUIC.
std::string quicVersionNegotiation( const QuicLongHeader& header, FieldReader versions )
{
    if ( versions.remaining() == 0 || versions.remaining() % 4 != 0 ) {
        return {};
    }
    std::string names;
    bool known = false;
    size_t named = 0;
    uint32_t version = 0;
    while ( versions.u32( version ) ) {
        known = known || isKnownQuicVersion( version );
        if ( named == kMaxQuicVersions ) {
            names += ",\xe2\x80\xa6";
        }
        if ( named++ < kMaxQuicVersions ) {
            names += ( names.empty() ? "" : "," ) + quicVersionName( version );
        }
    }
    if ( !known ) {
        return {};
    }
    return "Version Negotiation" + quicCids( header ) + ", Versions=" + names;
}

/// Skip the rest of a long header packet after its connection IDs: true if
/// another packet may follow it in the datagram (RFC 9000, 12.2).
bool skipQuicLongPacket( FieldReader& packet, uint32_t version, uint8_t firstByte )
{
    const std::string name = quicLongPacketName( version, firstByte );
    if ( name == "Retry" ) {
        return false; // A Retry has no length: it fills the datagram.
    }
    uint64_t length = 0;
    if ( name == "Initial" ) {
        if ( !packet.varint( length ) || length > packet.remaining()
             || !packet.skip( static_cast<size_t>( length ) ) ) {
            return false;
        }
    }
    return packet.varint( length ) && length <= packet.remaining()
           && packet.skip( static_cast<size_t>( length ) );
}

/// Describe a QUIC datagram from the public header of its packets:
/// "Initial, Handshake, Version 1, DCID=…, SCID=…".  Only a datagram that
/// begins with a long header of a known version, or with a Version
/// Negotiation packet, is QUIC by its bytes alone; a short header's is told
/// by its stream (describeInStream).  The packets are encrypted: their
/// type is all there is to name.  Packets coalesced behind the first are
/// named up to kMaxQuicPackets, a short header one as Protected Payload.
std::string detectQuic( const uint8_t* payload, size_t len )
{
    FieldReader datagram( payload, len );
    QuicLongHeader first;
    if ( !readQuicLongHeader( datagram, first ) ) {
        return {};
    }
    if ( first.version == 0 ) {
        return quicVersionNegotiation( first, datagram.take( datagram.remaining() ) );
    }

    std::vector<std::string> names{ quicLongPacketName( first.version, first.firstByte ) };
    bool more = skipQuicLongPacket( datagram, first.version, first.firstByte );
    while ( more && datagram.remaining() > 0 && names.size() <= kMaxQuicPackets ) {
        const uint8_t firstByte = *datagram.here();
        if ( ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) == kQuicFixedBit ) {
            names.emplace_back( "Protected Payload" ); // fills the datagram
            break;
        }
        QuicLongHeader next;
        if ( !readQuicLongHeader( datagram, next ) || next.version != first.version ) {
            break; // Padding, or bytes that are no packet
        }
        names.emplace_back( quicLongPacketName( next.version, next.firstByte ) );
        more = skipQuicLongPacket( datagram, next.version, next.firstByte );
    }

    if ( names.size() > kMaxQuicPackets ) {
        names.resize( kMaxQuicPackets );
        names.emplace_back( "\xe2\x80\xa6" );
    }
    std::string description;
    for ( const auto& name : names ) {
        description += ( description.empty() ? "" : ", " ) + name;
    }
    return description + ", Version " + quicVersionName( first.version ) + quicCids( first );
}

// ── HTTP/2 ───────────────────────────────────────────────────────────────

/// The connection preface a client begins an HTTP/2 connection with
/// (RFC 9113, 3.4), whichever way it learnt the server speaks HTTP/2.
constexpr char kHttp2Preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr size_t kHttp2PrefaceBytes = sizeof( kHttp2Preface ) - 1;

constexpr size_t kHttp2FrameHeaderBytes = 9;

/// The largest frame payload either side may send unless the other raised
/// it with SETTINGS_MAX_FRAME_SIZE (RFC 9113, 4.2).  A larger length is
/// taken for bytes that are no frame header.
constexpr uint32_t kHttp2DefaultMaxFrameSize = 16384;

/// Most frames of a segment named before the rest are summed up as "…".
constexpr size_t kMaxHttp2Frames = 4;

/// The name of an HTTP/2 frame header's type, or null if the header breaks
/// a rule of its type (RFC 9113, 6; RFC 7838, 8336, 9218) or the type is
/// unknown: those of a stream must name a stream, those of the connection
/// stream 0, and some have a fixed length.
const char* http2FrameName( uint8_t type, uint32_t length, uint32_t stream )
{
    enum class On { Stream, Connection, Either };
    struct Rule {
        const char* name;
        On on;
        uint32_t minLength;
        uint32_t maxLength;
    };
    constexpr uint32_t kAny = kHttp2DefaultMaxFrameSize;
    Rule rule{};
    switch ( type ) {
    case 0x0:
        rule = { "DATA", On::Stream, 0, kAny };
        break;
    case 0x1:
        rule = { "HEADERS", On::Stream, 0, kAny };
        break;
    case 0x2:
        rule = { "PRIORITY", On::Stream, 5, 5 };
        break;
    case 0x3:
        rule = { "RST_STREAM", On::Stream, 4, 4 };
        break;
    case 0x4:
        rule = { "SETTINGS", On::Connection, 0, kAny };
        break;
    case 0x5:
        rule = { "PUSH_PROMISE", On::Stream, 4, kAny };
        break;
    case 0x6:
        rule = { "PING", On::Connection, 8, 8 };
        break;
    case 0x7:
        rule = { "GOAWAY", On::Connection, 8, kAny };
        break;
    case 0x8:
        rule = { "WINDOW_UPDATE", On::Either, 4, 4 };
        break;
    case 0x9:
        rule = { "CONTINUATION", On::Stream, 0, kAny };
        break;
    case 0xA:
        rule = { "ALTSVC", On::Either, 2, kAny };
        break;
    case 0xC:
        rule = { "ORIGIN", On::Connection, 0, kAny };
        break;
    case 0x10:
        rule = { "PRIORITY_UPDATE", On::Connection, 4, kAny };
        break;
    default:
        return nullptr;
    }
    if ( length < rule.minLength || length > rule.maxLength ) {
        return nullptr;
    }
    if ( ( rule.on == On::Stream && stream == 0 )
         || ( rule.on == On::Connection && stream != 0 ) ) {
        return nullptr;
    }
    if ( type == 0x4 && length % 6 != 0 ) {
        return nullptr; // SETTINGS: 6 bytes a setting
    }
    return rule.name;
}

/// The HTTP/2 frames at @p p, the @p len captured bytes of a @p wireLen-byte
/// TCP payload, named with their streams, "HEADERS[1], DATA[1]": up to
/// kMaxHttp2Frames, then "…", as for a header beyond the captured bytes.
/// Empty if a header there breaks a rule of its type (the bytes are no
/// frames, or the segment begins inside one) or there is none.
std::string http2Frames( const uint8_t* p, size_t len, size_t wireLen )
{
    std::vector<std::string> names;
    size_t offset = 0;
    while ( offset < wireLen ) {
        if ( names.size() == kMaxHttp2Frames || offset >= len
             || len - offset < kHttp2FrameHeaderBytes ) {
            if ( names.empty() ) {
                return {};
            }
            names.emplace_back( "\xe2\x80\xa6" );
            break;
        }
        FieldReader header( p + offset, kHttp2FrameHeaderBytes );
        uint32_t length = 0;
        uint8_t type = 0;
        uint8_t flags = 0;
        uint32_t stream = 0;
        header.u24( length );
        header.u8( type );
        header.u8( flags );
        header.u32( stream );
        if ( stream & 0x80000000u ) {
            return {}; // the reserved bit, which a sender leaves unset
        }
        const char* name = http2FrameName( type, length, stream );
        if ( name == nullptr ) {
            return {};
        }
        names.push_back( std::string( name ) + "[" + std::to_string( stream ) + "]" );
        offset += kHttp2FrameHeaderBytes + length;
    }
    std::string description;
    for ( const auto& name : names ) {
        description += ( description.empty() ? "" : ", " ) + name;
    }
    return description;
}

/// The HTTP/2 connection preface, "Magic", and the frames behind it.
std::string detectHttp2Preface( const uint8_t* payload, size_t len )
{
    if ( len < kHttp2PrefaceBytes
         || std::memcmp( payload, kHttp2Preface, kHttp2PrefaceBytes ) != 0 ) {
        return {};
    }
    const auto frames = http2Frames( payload + kHttp2PrefaceBytes, len - kHttp2PrefaceBytes,
                                     len - kHttp2PrefaceBytes );
    return frames.empty() ? "Magic" : "Magic, " + frames;
}

// ── SOCKS ────────────────────────────────────────────────────────────────

bool isSocksPort( uint16_t port )
{
    return port == 1080 || port == 1081 || port == 3128 || port == 9050 || port == 9051;
}

const char* socks5MethodName( uint8_t method )
{
    switch ( method ) {
    case 0x00:
        return "No Authentication";
    case 0x01:
        return "GSSAPI";
    case 0x02:
        return "Username/Password";
    case 0xFF:
        return "No Acceptable Methods";
    default:
        return "Unknown";
    }
}

std::string socks5Method( uint8_t method )
{
    return std::string( socks5MethodName( method ) ) + " (" + hexCode( method ) + ")";
}

/// The address of a SOCKS5 request or reply at @p p (address type first),
/// if the message ends exactly behind it: "<type>", "<host>:<port>".
bool socks5Address( const uint8_t* p, size_t len, std::string& type, std::string& address )
{
    if ( len < 1 ) {
        return false;
    }
    switch ( p[ 0 ] ) {
    case 0x01:
        if ( len != 1 + 4 + 2 ) {
            return false;
        }
        type = "IPv4";
        address = formatIpv4( p + 1 ) + ":" + std::to_string( readBE16( p + 5 ) );
        return true;
    case 0x03: {
        if ( len < 2 ) {
            return false;
        }
        const size_t nameLen = p[ 1 ];
        if ( nameLen == 0 || len != 2 + nameLen + 2 ) {
            return false;
        }
        type = "Domain";
        address = escapeBytes( p + 2, nameLen, false ) + ":"
                  + std::to_string( readBE16( p + 2 + nameLen ) );
        return true;
    }
    case 0x04:
        if ( len != 1 + 16 + 2 ) {
            return false;
        }
        type = "IPv6";
        address = "[" + formatIpv6( p + 1 ) + "]:" + std::to_string( readBE16( p + 17 ) );
        return true;
    default:
        return false;
    }
}

/// A SOCKS message sent by the client to the proxy, or empty if the payload
/// does not have the exact shape of one.
std::string socksClientMessage( const uint8_t* p, size_t len )
{
    if ( len < 2 ) {
        return {};
    }

    // SOCKS5 greeting (RFC 1928): 05 <nmethods> <methods...>
    if ( p[ 0 ] == 0x05 && p[ 1 ] > 0 && len == 2 + static_cast<size_t>( p[ 1 ] ) ) {
        std::string methods;
        for ( size_t i = 2; i < len; ++i ) {
            if ( !methods.empty() ) {
                methods += ", ";
            }
            methods += socks5Method( p[ i ] );
        }
        return "SOCKS5 Client Greeting, Version: 5, Methods: " + std::to_string( p[ 1 ] ) + " ["
               + methods + "]";
    }

    // SOCKS5 request: 05 <cmd> 00 <atyp> <address> <port>
    if ( p[ 0 ] == 0x05 && len >= 4 && p[ 2 ] == 0x00 && p[ 1 ] >= 0x01 && p[ 1 ] <= 0x03 ) {
        std::string type;
        std::string address;
        if ( socks5Address( p + 3, len - 3, type, address ) ) {
            static const char* const kCommands[] = { "Connect", "Bind", "UDP Associate" };
            return "SOCKS5 Connect, Version: 5, Command: " + std::string( kCommands[ p[ 1 ] - 1 ] )
                   + " (" + hexCode( p[ 1 ] ) + "), Address Type: " + type
                   + ", Destination: " + address;
        }
        return {};
    }

    // Username/password request (RFC 1929): 01 <ulen> <user> <plen> <password>
    if ( p[ 0 ] == 0x01 ) {
        const size_t userLen = p[ 1 ];
        if ( len < 2 + userLen + 1 ) {
            return {};
        }
        const size_t passLen = p[ 2 + userLen ];
        if ( len != 2 + userLen + 1 + passLen ) {
            return {};
        }
        return "SOCKS5 Auth Request, User: " + quotedBytes( p + 2, userLen )
               + ", Pass: " + quotedBytes( p + 3 + userLen, passLen );
    }

    // SOCKS4 / SOCKS4a request: 04 <cmd> <port> <ip> <userid> 00 [<domain> 00]
    if ( p[ 0 ] == 0x04 && len >= 9 && ( p[ 1 ] == 0x01 || p[ 1 ] == 0x02 ) && p[ len - 1 ] == 0 ) {
        const auto* userEnd = static_cast<const uint8_t*>( std::memchr( p + 8, 0, len - 8 ) );
        const auto userLen = static_cast<size_t>( userEnd - ( p + 8 ) );
        const size_t domainStart = 8 + userLen + 1;
        // SOCKS4a: the address 0.0.0.x (x != 0) says a domain follows.
        const bool socks4a = p[ 4 ] == 0 && p[ 5 ] == 0 && p[ 6 ] == 0 && p[ 7 ] != 0;
        size_t domainLen = 0;
        if ( socks4a ) {
            if ( domainStart >= len ) {
                return {};
            }
            domainLen = len - 1 - domainStart;
            if ( domainLen == 0 || std::memchr( p + domainStart, 0, domainLen ) != nullptr ) {
                return {};
            }
        }
        else if ( domainStart != len ) {
            return {};
        }

        std::string result
            = "SOCKS4, Version: 4, Command: " + std::string( p[ 1 ] == 0x01 ? "Connect" : "Bind" )
              + " (" + hexCode( p[ 1 ] ) + "), Destination: " + formatIpv4( p + 4 ) + ":"
              + std::to_string( readBE16( p + 2 ) );
        if ( userLen > 0 ) {
            result += ", User: " + quotedBytes( p + 8, userLen );
        }
        if ( socks4a ) {
            result += ", Domain: " + escapeBytes( p + domainStart, domainLen, false );
        }
        return result;
    }

    return {};
}

/// A SOCKS message sent by the proxy to the client, or empty if the payload
/// does not have the exact shape of one.
std::string socksServerMessage( const uint8_t* p, size_t len )
{
    if ( len < 2 ) {
        return {};
    }

    // SOCKS5 method choice: 05 <method>
    if ( p[ 0 ] == 0x05 && len == 2 ) {
        return "SOCKS5 Server Choice, Version: 5, Method: " + socks5Method( p[ 1 ] );
    }

    // SOCKS5 reply: 05 <status> 00 <atyp> <address> <port>
    if ( p[ 0 ] == 0x05 && len >= 4 && p[ 2 ] == 0x00 ) {
        std::string type;
        std::string address;
        if ( !socks5Address( p + 3, len - 3, type, address ) ) {
            return {};
        }
        static const char* const kStatus[] = {
            "Succeeded",           "General Failure",       "Not Allowed by Ruleset",
            "Network Unreachable", "Host Unreachable",      "Connection Refused",
            "TTL Expired",         "Command Not Supported", "Address Type Not Supported",
        };
        const auto code = p[ 1 ];
        const char* status
            = code < sizeof( kStatus ) / sizeof( kStatus[ 0 ] ) ? kStatus[ code ] : "Unknown";
        return "SOCKS5 Reply, Version: 5, Status: " + std::string( status ) + " (" + hexCode( code )
               + "), Bound: " + address;
    }

    // Username/password response (RFC 1929): 01 <status>
    if ( p[ 0 ] == 0x01 && len == 2 ) {
        return "SOCKS5 Auth Response, Status: "
               + std::string( p[ 1 ] == 0x00 ? "Success" : "Failure" ) + " (" + hexCode( p[ 1 ] )
               + ")";
    }

    // SOCKS4 reply: 00 <status> <port> <ip>
    if ( p[ 0 ] == 0x00 && len == 8 && p[ 1 ] >= 0x5A && p[ 1 ] <= 0x5D ) {
        static const char* const kStatus[] = {
            "Request Granted",
            "Request Rejected",
            "Failed, Cannot Connect to identd",
            "Failed, identd Mismatch",
        };
        std::string result = "SOCKS4 Reply, Status: " + std::string( kStatus[ p[ 1 ] - 0x5A ] )
                             + " (" + hexCode( p[ 1 ] ) + ")";
        const auto port = readBE16( p + 2 );
        const auto ip = formatIpv4( p + 4 );
        if ( port != 0 || ip != "0.0.0.0" ) {
            result += ", Bound: " + ip + ":" + std::to_string( port );
        }
        return result;
    }

    return {};
}

/// Detect SOCKS4/SOCKS5 handshake messages (RFC 1928, RFC 1929, SOCKS4/4a).
/// Only on a known proxy port, and only a payload with the exact shape of a
/// message the client sends to that port, or the proxy sends from it.
/// User names and passwords are shown: they cross the wire in clear text.
std::string detectSocks( const uint8_t* payload, size_t len, uint16_t srcPort, uint16_t dstPort )
{
    std::string message;
    if ( isSocksPort( dstPort ) ) {
        message = socksClientMessage( payload, len );
    }
    if ( message.empty() && isSocksPort( srcPort ) ) {
        message = socksServerMessage( payload, len );
    }
    return message;
}

// ── The detectors of a transport ─────────────────────────────────────────

/// What a detector looks at.
struct Payload {
    const uint8_t* data;
    size_t len;
    uint16_t srcPort;
    uint16_t dstPort;
    Transport transport;
};

/// A detector: the description of the payload if it recognises it.
using Detector = std::optional<PayloadDescription> ( * )( const Payload& );

/// A description with the given label and text.
std::optional<PayloadDescription> described( const char* label, std::string description )
{
    PayloadDescription result;
    result.label = label;
    result.description = std::move( description );
    return result;
}

/// A description with the given label, if the detector found anything.
std::optional<PayloadDescription> describedIfAny( const char* label, std::string description )
{
    if ( description.empty() ) {
        return std::nullopt;
    }
    return described( label, std::move( description ) );
}

/// A description with the label a port names: recognised if the payload
/// parsed (@p description is not empty), else only the port's guess, which
/// does not stick to the stream.
std::optional<PayloadDescription> describedOnPort( const char* label, std::string description )
{
    auto result = described( label, std::move( description ) );
    result->guessed = result->description.empty();
    return result;
}

bool onPort( const Payload& p, uint16_t port )
{
    return p.srcPort == port || p.dstPort == port;
}

/// DNS over TCP on port 53: described if the segment begins with a message.
std::optional<PayloadDescription> dnsOverTcpMessage( const Payload& p )
{
    if ( !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return describedIfAny( "DNS", detectDnsOverTcp( p.data, p.len ) );
}

std::optional<PayloadDescription> tlsRecord( const Payload& p )
{
    return describedIfAny( "TLS", detectTls( p.data, p.len ) );
}

std::optional<PayloadDescription> httpMessage( const Payload& p )
{
    return describedIfAny( "HTTP", detectHttp( p.data, p.len ) );
}

std::optional<PayloadDescription> http2Preface( const Payload& p )
{
    return describedIfAny( "HTTP2", detectHttp2Preface( p.data, p.len ) );
}

std::optional<PayloadDescription> quicPacket( const Payload& p )
{
    return describedIfAny( "QUIC", detectQuic( p.data, p.len ) );
}

std::optional<PayloadDescription> nmeaSentence( const Payload& p )
{
    return describedIfAny( "NMEA", detectNmea( p.data, p.len ) );
}

std::optional<PayloadDescription> socksMessage( const Payload& p )
{
    return describedIfAny( "SOCKS", detectSocks( p.data, p.len, p.srcPort, p.dstPort ) );
}

/// The last resort: the protocol the ports suggest, and a preview of the
/// payload's text.  Always answers, possibly with nothing.
std::optional<PayloadDescription> portHintAndPreview( const Payload& p )
{
    PayloadDescription result;
    auto proto = servicePortName( p.transport, p.srcPort );
    if ( !proto ) {
        proto = servicePortName( p.transport, p.dstPort );
    }
    if ( proto ) {
        result.label = proto;
        result.guessed = true;
    }
    result.description = payloadPreview( p.data, p.len );
    result.preview = !result.description.empty();
    return result;
}

/// The TCP detectors, in the order they are tried.
constexpr Detector kTcpDetectors[]
    = { dnsOverTcpMessage, tlsRecord,    httpMessage,       http2Preface,
        nmeaSentence,      socksMessage, portHintAndPreview };

/// DNS on port 53, mDNS on port 5353: named by the port, described if the
/// payload parses as a DNS message.
std::optional<PayloadDescription> dnsMessage( const Payload& p )
{
    const bool mdns = onPort( p, 5353 );
    if ( !mdns && !onPort( p, 53 ) ) {
        return std::nullopt;
    }
    return describedOnPort( mdns ? "mDNS" : "DNS", detectDns( p.data, p.len ) );
}

/// SSDP on port 1900: HTTP-shaped messages.
std::optional<PayloadDescription> ssdpMessage( const Payload& p )
{
    if ( !onPort( p, 1900 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "SSDP", detectHttp( p.data, p.len ) );
}

/// NTP on port 123: named by the port, described if it is an NTP packet.
std::optional<PayloadDescription> ntpPacket( const Payload& p )
{
    if ( !onPort( p, 123 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "NTP", detectNtp( p.data, p.len ) );
}

/// DHCP on ports 67 and 68: named by the port, described if it is a BOOTP
/// message.
std::optional<PayloadDescription> dhcpPacket( const Payload& p )
{
    if ( !onPort( p, 67 ) && !onPort( p, 68 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "DHCP", detectDhcp( p.data, p.len ) );
}

/// DHCPv6 on ports 546 and 547: named by the port, described if the
/// message has its header.
std::optional<PayloadDescription> dhcpv6Packet( const Payload& p )
{
    if ( !onPort( p, 546 ) && !onPort( p, 547 ) ) {
        return std::nullopt;
    }
    return describedOnPort( "DHCPv6", detectDhcpv6( p.data, p.len ) );
}

/// The UDP detectors, in the order they are tried: ports first, then content.
constexpr Detector kUdpDetectors[]
    = { dnsMessage,   ssdpMessage, ntpPacket,    dhcpPacket,
        dhcpv6Packet, quicPacket,  nmeaSentence, portHintAndPreview };

/// The detectors of a transport, as a range.
template <size_t N>
std::pair<const Detector*, const Detector*> detectorsOf( const Detector ( &table )[ N ] )
{
    return { table, table + N };
}

/// The description as one line: a control character a detector let
/// through, a newline above all, is escaped as \xNN.  The detectors escape
/// the payload text they quote, so this normally changes nothing; the
/// guarantee that one packet is one line rests here, not on each of them.
std::string oneLine( std::string description )
{
    auto isControl = []( char c ) {
        const auto byte = static_cast<uint8_t>( c );
        return byte < 0x20 || byte == 0x7F;
    };
    if ( std::none_of( description.begin(), description.end(), isControl ) ) {
        return description;
    }
    std::string escaped;
    escaped.reserve( description.size() + 8 );
    for ( const char c : description ) {
        if ( isControl( c ) ) {
            escaped += "\\x" + hexCode( static_cast<uint8_t>( c ) ).substr( 2 );
        }
        else {
            escaped += c;
        }
    }
    return escaped;
}

} // namespace

// ── The describer ────────────────────────────────────────────────────────

PayloadDescription describePayload( Transport transport, const uint8_t* payload, size_t len,
                                    uint16_t srcPort, uint16_t dstPort )
{
    const Payload p{ payload, len, srcPort, dstPort, transport };
    const auto [ first, last ]
        = transport == Transport::Tcp ? detectorsOf( kTcpDetectors ) : detectorsOf( kUdpDetectors );
    for ( auto detect = first; detect != last; ++detect ) {
        if ( auto result = ( *detect )( p ) ) {
            result->description = oneLine( std::move( result->description ) );
            return *result;
        }
    }
    return {};
}

namespace {

/// Put @p description in place of the one in @p pkt's Info, and @p label
/// in place of its protocol: recognised from its content, so the label
/// sticks to the stream (StreamLabels).
void redescribe( PacketRecord& pkt, const char* label, const std::string& description )
{
    pkt.previewBytes = 0;
    pkt.protocol = label;
    pkt.protocolRecognised = true;
    pkt.info = pkt.info.substr( 0, pkt.info.find( kDescriptionSeparator ) ) + kDescriptionSeparator
               + description;
}

/// A UDP packet in its stream: QUIC short headers after a long header.
void describeQuicInStream( PacketRecord& pkt, const Stream& stream )
{
    auto& quic = stream.state->quic;
    FieldReader head( pkt.payloadHead.data(), pkt.payloadHeadLen );

    if ( pkt.protocol == "QUIC" ) {
        // A long header the describer named: the connection ID its sender
        // chose is the one the other side sends short headers to.
        QuicLongHeader header;
        if ( readQuicLongHeader( head, header ) ) {
            quic.seen = true;
            if ( header.version != 0 ) {
                quic.dcidLength[ 1 - stream.direction ]
                    = static_cast<int8_t>( header.scid.remaining() );
            }
        }
        return;
    }

    // A short header: the fixed bit without the long header bit, and room
    // for a packet number and the 16 bytes header protection samples.
    const auto dcidLength = quic.dcidLength[ stream.direction ];
    const size_t minimumLength = 1 + std::max<int>( dcidLength, 0 ) + 4 + 16;
    uint8_t firstByte = 0;
    if ( !quic.seen || !head.u8( firstByte )
         || ( firstByte & ( kQuicLongHeader | kQuicFixedBit ) ) != kQuicFixedBit
         || pkt.payloadLen < minimumLength ) {
        return;
    }
    std::string description = "Protected Payload";
    if ( dcidLength > 0 && head.remaining() >= static_cast<size_t>( dcidLength ) ) {
        description += ", DCID=" + quicCid( head.here(), static_cast<size_t>( dcidLength ) );
    }
    redescribe( pkt, "QUIC", description );
}

/// A TCP segment in its stream: HTTP/2 frames after the preface, those
/// whose header lies in the payload's first kPayloadHeadBytes.
void describeHttp2InStream( PacketRecord& pkt, StreamState& state )
{
    if ( pkt.protocol == "HTTP2" ) {
        state.http2 = true; // the preface
        return;
    }
    if ( !state.http2 ) {
        return;
    }
    const auto frames = http2Frames( pkt.payloadHead.data(), pkt.payloadHeadLen,
                                     std::max<size_t>( pkt.payloadLen, pkt.payloadHeadLen ) );
    if ( !frames.empty() ) {
        redescribe( pkt, "HTTP2", frames );
    }
}

} // namespace

void describeInStream( PacketRecord& pkt, const Stream& stream )
{
    if ( !stream.state || !pkt.transport ) {
        return;
    }
    if ( *pkt.transport == Transport::Udp ) {
        describeQuicInStream( pkt, stream );
    }
    else {
        describeHttp2InStream( pkt, *stream.state );
    }
}

void limitPreview( PacketRecord& pkt, size_t maxChars )
{
    static const std::string kEllipsis = "\xe2\x80\xa6";
    const std::string separator = kDescriptionSeparator;
    auto& info = pkt.info;
    // The preview and the separator before it end the Info, or there is none.
    if ( pkt.previewBytes == 0 || info.size() < pkt.previewBytes + separator.size()
         || info.compare( info.size() - pkt.previewBytes - separator.size(), separator.size(),
                          separator )
                != 0 ) {
        return;
    }
    const auto start = info.size() - pkt.previewBytes;
    if ( maxChars == 0 ) {
        info.erase( start - separator.size() );
        pkt.previewBytes = 0;
        return;
    }
    // One character per byte, but for the describer's ellipsis.
    const bool cut
        = info.size() - start >= kEllipsis.size()
          && info.compare( info.size() - kEllipsis.size(), kEllipsis.size(), kEllipsis ) == 0;
    const auto chars = pkt.previewBytes - ( cut ? kEllipsis.size() : 0 );
    if ( chars <= maxChars ) {
        return;
    }
    info.erase( start + maxChars );
    info += kEllipsis;
    pkt.previewBytes = maxChars + kEllipsis.size();
}

} // namespace tcpdump
