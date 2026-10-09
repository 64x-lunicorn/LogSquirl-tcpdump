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
 * @file describe_sip.cpp
 * @brief The SIP detector of the Payload Describer: SIP requests and
 *        responses, every one in a TCP segment, the SDP body summarised,
 *        and the media streams it announces handed on for RTP and RTCP.
 */

#include "describe_common.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── SIP ──────────────────────────────────────────────────────────────────

namespace {

/// Header lines of one message, and lines of one SDP body, read at most;
/// a message with more header lines is malformed, an SDP body's further
/// lines are not looked at.
constexpr size_t kMaxSipHeaderLines = 128;
constexpr size_t kMaxSdpLines = 256;

/// Most media streams of an SDP body named in Info.
constexpr size_t kShownSdpMedia = 4;

/// Bytes of a Call-ID shown before it is cut.
constexpr size_t kShownCallIdBytes = 12;

/// Longest method name taken for one: RFC 3261 sets none, the longest
/// registered is SUBSCRIBE's 9 bytes.
constexpr size_t kMaxMethodBytes = 32;

/// A Content-Length larger than this is malformed: a SIP message is no
/// gigabyte.
constexpr size_t kMaxContentLength = 100000000;

/// Bytes of a message, never beyond the payload.
struct Text {
    const uint8_t* data = nullptr;
    size_t len = 0;

    bool empty() const
    {
        return len == 0;
    }
    std::string str() const
    {
        return std::string( reinterpret_cast<const char*>( data ), len );
    }
};

bool isBlank( uint8_t c )
{
    return c == ' ' || c == '\t';
}

bool isDigit( uint8_t c )
{
    return c >= '0' && c <= '9';
}

/// @p t without the blanks around it.
Text trimmed( Text t )
{
    while ( t.len > 0 && isBlank( t.data[ 0 ] ) ) {
        ++t.data;
        --t.len;
    }
    while ( t.len > 0 && isBlank( t.data[ t.len - 1 ] ) ) {
        --t.len;
    }
    return t;
}

/// @p t is the lower case ASCII @p name, case aside.
bool equalsNoCase( Text t, const char* name )
{
    const size_t n = std::strlen( name );
    if ( t.len != n ) {
        return false;
    }
    for ( size_t i = 0; i < n; ++i ) {
        auto c = t.data[ i ];
        if ( c >= 'A' && c <= 'Z' ) {
            c = static_cast<uint8_t>( c - 'A' + 'a' );
        }
        if ( c != static_cast<uint8_t>( name[ i ] ) ) {
            return false;
        }
    }
    return true;
}

bool startsWith( Text t, const char* prefix )
{
    const size_t n = std::strlen( prefix );
    return t.len >= n && std::memcmp( t.data, prefix, n ) == 0;
}

/// @p t from byte @p n on.
Text after( Text t, size_t n )
{
    n = std::min( n, t.len );
    return { t.data + n, t.len - n };
}

/// The first word of @p t, up to a blank, and in @p rest what follows it,
/// blanks skipped.
Text word( Text t, Text& rest )
{
    size_t n = 0;
    while ( n < t.len && !isBlank( t.data[ n ] ) ) {
        ++n;
    }
    rest = trimmed( after( t, n ) );
    return { t.data, n };
}

/// A decimal number of at most @p maxDigits digits, all of @p t.
std::optional<size_t> number( Text t, size_t maxDigits )
{
    if ( t.empty() || t.len > maxDigits ) {
        return std::nullopt;
    }
    size_t value = 0;
    for ( size_t i = 0; i < t.len; ++i ) {
        if ( !isDigit( t.data[ i ] ) ) {
            return std::nullopt;
        }
        value = value * 10 + ( t.data[ i ] - '0' );
    }
    return value;
}

/**
 * Lines of a message: each up to its line feed, a carriage return before it
 * dropped.  A line the bytes end in before its line feed is the last, and
 * whole only if @p complete says the bytes are all there are.
 */
class Lines {
public:
    Lines( Text bytes, bool complete )
        : at_( bytes.data )
        , end_( bytes.data + bytes.len )
        , complete_( complete )
    {
    }

    /// The next line; false if none is left, or the next is cut.
    bool next( Text& line )
    {
        if ( at_ == end_ ) {
            return false;
        }
        const auto* lf = static_cast<const uint8_t*>(
            std::memchr( at_, '\n', static_cast<size_t>( end_ - at_ ) ) );
        if ( lf == nullptr && !complete_ ) {
            cut_ = true;
            return false;
        }
        const uint8_t* lineEnd = lf ? lf : end_;
        line = { at_, static_cast<size_t>( lineEnd - at_ ) };
        if ( line.len > 0 && line.data[ line.len - 1 ] == '\r' ) {
            --line.len;
        }
        at_ = lf ? lf + 1 : end_;
        return true;
    }

    /// The bytes ended inside a line.
    bool cut() const
    {
        return cut_;
    }
    const uint8_t* here() const
    {
        return at_;
    }

private:
    const uint8_t* at_;
    const uint8_t* end_;
    bool complete_;
    bool cut_ = false;
};

// ── Addresses ────────────────────────────────────────────────────────────

/// An IPv4 address in dotted decimal, as an SDP c= line writes it.
std::optional<std::array<uint8_t, 4>> ipv4Address( Text t )
{
    std::array<uint8_t, 4> bytes{};
    size_t part = 0;
    size_t i = 0;
    while ( part < 4 ) {
        size_t start = i;
        while ( i < t.len && isDigit( t.data[ i ] ) && i - start < 3 ) {
            ++i;
        }
        const auto value = number( { t.data + start, i - start }, 3 );
        if ( !value || *value > 255 ) {
            return std::nullopt;
        }
        bytes[ part++ ] = static_cast<uint8_t>( *value );
        if ( part < 4 ) {
            if ( i >= t.len || t.data[ i ] != '.' ) {
                return std::nullopt;
            }
            ++i;
        }
    }
    return i == t.len ? std::optional( bytes ) : std::nullopt;
}

/// An IPv6 address in any of RFC 4291's text forms, `::` and a dotted
/// IPv4 tail among them.
std::optional<std::array<uint8_t, 16>> ipv6Address( Text t )
{
    std::array<uint16_t, 8> groups{};
    size_t count = 0;
    std::optional<size_t> gap; // where "::" stands, in groups
    size_t i = 0;
    if ( startsWith( t, "::" ) ) {
        gap = 0;
        i = 2;
    }
    while ( i < t.len ) {
        if ( count == 8 ) {
            return std::nullopt;
        }
        size_t start = i;
        int value = 0;
        while ( i < t.len && hexDigit( t.data[ i ] ) >= 0 && i - start < 4 ) {
            value = value * 16 + hexDigit( t.data[ i ] );
            ++i;
        }
        if ( i < t.len && t.data[ i ] == '.' && count <= 6 ) {
            const auto v4 = ipv4Address( after( t, start ) );
            if ( !v4 ) {
                return std::nullopt;
            }
            groups[ count++ ] = static_cast<uint16_t>( ( *v4 )[ 0 ] << 8 | ( *v4 )[ 1 ] );
            groups[ count++ ] = static_cast<uint16_t>( ( *v4 )[ 2 ] << 8 | ( *v4 )[ 3 ] );
            i = t.len;
            break;
        }
        if ( i == start ) {
            return std::nullopt;
        }
        groups[ count++ ] = static_cast<uint16_t>( value );
        if ( i == t.len ) {
            break;
        }
        if ( t.data[ i ] != ':' ) {
            return std::nullopt;
        }
        ++i;
        if ( i < t.len && t.data[ i ] == ':' ) {
            if ( gap ) {
                return std::nullopt;
            }
            gap = count;
            ++i;
        }
        else if ( i == t.len ) {
            return std::nullopt; // a single trailing colon
        }
    }
    if ( gap ? count > 7 : count != 8 ) {
        return std::nullopt;
    }
    std::array<uint8_t, 16> bytes{};
    const size_t zeros = 8 - count;
    for ( size_t g = 0, out = 0; g < count; ++g, ++out ) {
        if ( gap && g == *gap ) {
            out += zeros;
        }
        bytes[ 2 * out ] = static_cast<uint8_t>( groups[ g ] >> 8 );
        bytes[ 2 * out + 1 ] = static_cast<uint8_t>( groups[ g ] );
    }
    return bytes;
}

/// The address of an SDP c= line's value, "IN IP4 192.0.2.1" (a multicast
/// address's "/ttl" dropped), in the form the address columns write it;
/// empty if it is a host name or no address.
std::string connectionAddress( Text value )
{
    Text rest;
    const auto net = word( value, rest );
    const auto type = word( rest, rest );
    const auto address = word( rest, rest );
    if ( !equalsNoCase( net, "in" ) || !rest.empty() ) {
        return {};
    }
    Text bare = address;
    for ( size_t i = 0; i < bare.len; ++i ) {
        if ( bare.data[ i ] == '/' ) {
            bare.len = i;
        }
    }
    if ( equalsNoCase( type, "ip4" ) ) {
        if ( const auto v4 = ipv4Address( bare ) ) {
            return formatIpv4( v4->data() );
        }
    }
    else if ( equalsNoCase( type, "ip6" ) ) {
        if ( const auto v6 = ipv6Address( bare ) ) {
            return formatIpv6( v6->data() );
        }
    }
    return {};
}

// ── SDP ──────────────────────────────────────────────────────────────────

/// What an SDP body says: its media lines, and the RTP media streams they
/// announce.
struct Sdp {
    std::vector<std::string> media; ///< m= values, as shown
    size_t mediaCount = 0;
    std::vector<MediaEndpoint> endpoints;
    std::string origin; ///< SipCall::origin
    bool malformed = false;
    bool cut = false;
};

/// A media stream while its lines are read.
struct Medium {
    std::string ip; ///< The session's c= address, or its own
    uint16_t port = 0;
    std::optional<uint16_t> rtcpPort;
    bool rtp = false; ///< A transport over RTP: RTP/AVP, RTP/SAVPF, …
};

/// The port of an m= line's value, "audio 49170/2 RTP/AVP 0", and whether
/// its transport is RTP.
std::optional<Medium> mediaLine( Text value, const std::string& sessionIp )
{
    Text rest;
    word( value, rest ); // the media type
    auto portText = word( rest, rest );
    const auto proto = word( rest, rest );
    for ( size_t i = 0; i < portText.len; ++i ) {
        if ( portText.data[ i ] == '/' ) {
            portText.len = i; // the number of ports
        }
    }
    const auto port = number( portText, 5 );
    if ( !port || *port > 0xFFFF || proto.empty() ) {
        return std::nullopt;
    }
    Medium medium;
    medium.ip = sessionIp;
    medium.port = static_cast<uint16_t>( *port );
    const auto p = proto.str();
    medium.rtp = p.find( "RTP/" ) != std::string::npos;
    return medium;
}

/// The side an o= line's value names, "alice 2890844526 2890844526 IN IP4
/// 192.0.2.10": all but the session's version, "alice 2890844526 IN IP4
/// 192.0.2.10", at most kMaxSipCallIdBytes.
std::string originOf( Text value )
{
    Text rest;
    auto origin = word( value, rest ).str();  // the username
    origin += ' ' + word( rest, rest ).str(); // the session's id
    word( rest, rest );                       // its version
    origin += ' ' + rest.str();
    origin.resize( std::min( origin.size(), kMaxSipCallIdBytes ) );
    return origin;
}

/// An SDP body (RFC 4566), @p complete if all of it was captured.
Sdp describeSdp( Text body, bool complete )
{
    Sdp sdp;
    Lines lines( body, complete );
    Text line;
    if ( !lines.next( line ) ) {
        sdp.cut = true; // within its first line
        return sdp;
    }
    if ( !startsWith( line, "v=" ) ) {
        sdp.malformed = true;
        return sdp;
    }
    std::string sessionIp;
    std::vector<Medium> media;
    for ( size_t n = 1; n < kMaxSdpLines && lines.next( line ); ++n ) {
        if ( line.len < 2 || line.data[ 1 ] != '=' ) {
            continue;
        }
        const Text value = after( line, 2 );
        if ( sdp.mediaCount > media.size() && line.data[ 0 ] != 'm' ) {
            continue; // a line of a medium past kMaxSdpMedia
        }
        switch ( line.data[ 0 ] ) {
        case 'o':
            sdp.origin = originOf( value );
            break;
        case 'c':
            ( media.empty() ? sessionIp : media.back().ip ) = connectionAddress( value );
            break;
        case 'm': {
            ++sdp.mediaCount;
            if ( sdp.media.size() < kShownSdpMedia ) {
                sdp.media.push_back( fieldText( value.data, value.len ) );
            }
            if ( media.size() < kMaxSdpMedia ) {
                if ( auto medium = mediaLine( value, sessionIp ) ) {
                    media.push_back( std::move( *medium ) );
                }
                else {
                    media.push_back( Medium{} ); // its attributes are its own
                }
            }
            break;
        }
        case 'a':
            if ( media.empty() ) {
                break;
            }
            if ( equalsNoCase( value, "rtcp-mux" ) ) {
                media.back().rtcpPort = media.back().port;
            }
            else if ( startsWith( value, "rtcp:" ) ) {
                Text rest;
                const auto port = number( word( after( value, 5 ), rest ), 5 );
                if ( port && *port > 0 && *port <= 0xFFFF ) {
                    media.back().rtcpPort = static_cast<uint16_t>( *port );
                }
            }
            break;
        default:
            break;
        }
    }
    sdp.cut = lines.cut();
    for ( const auto& m : media ) {
        if ( m.rtp && m.port != 0 && !m.ip.empty() ) {
            const uint16_t rtcp
                = m.rtcpPort.value_or( m.port < 0xFFFF ? static_cast<uint16_t>( m.port + 1 ) : 0 );
            sdp.endpoints.push_back( { m.ip, m.port, rtcp } );
        }
    }
    return sdp;
}

std::string sdpText( const Sdp& sdp )
{
    std::string text = "SDP";
    if ( sdp.malformed ) {
        return text + " [Malformed Packet]";
    }
    if ( !sdp.media.empty() ) {
        text += " (" + joinNames( sdp.media, kShownSdpMedia, sdp.mediaCount > sdp.media.size() )
                + ")";
    }
    return sdp.cut ? text + " " + kEllipsis : text;
}

// ── A SIP message ────────────────────────────────────────────────────────

/// The start line of a request or a response.
struct StartLine {
    bool request = false;
    Text method; ///< A request's
    Text uri;    ///< A request's
    Text code;   ///< A response's
    Text reason; ///< A response's
};

bool isTokenChar( uint8_t c )
{
    return isAsciiAlpha( c ) || isDigit( c ) || std::strchr( "-.!%*_+`'~", c ) != nullptr;
}

/// A start line, "INVITE sip:bob@example.com SIP/2.0" or "SIP/2.0 200 OK".
std::optional<StartLine> startLine( Text line )
{
    StartLine start;
    if ( startsWith( line, "SIP/2.0 " ) ) {
        const Text rest = after( line, 8 );
        if ( rest.len < 3 || rest.data[ 0 ] < '1' || rest.data[ 0 ] > '6'
             || !isDigit( rest.data[ 1 ] ) || !isDigit( rest.data[ 2 ] )
             || ( rest.len > 3 && rest.data[ 3 ] != ' ' ) ) {
            return std::nullopt;
        }
        start.code = { rest.data, 3 };
        start.reason = trimmed( after( rest, 4 ) );
        return start;
    }
    start.request = true;
    size_t n = 0;
    while ( n < line.len && isTokenChar( line.data[ n ] ) ) {
        ++n;
    }
    if ( n == 0 || n > kMaxMethodBytes || n >= line.len || line.data[ n ] != ' ' ) {
        return std::nullopt;
    }
    start.method = { line.data, n };
    const Text rest = after( line, n + 1 );
    size_t u = 0;
    bool scheme = false;
    while ( u < rest.len && rest.data[ u ] > 0x20 && rest.data[ u ] < 0x7F ) {
        scheme = scheme || rest.data[ u ] == ':';
        ++u;
    }
    if ( u == 0 || !scheme || !isAsciiAlpha( rest.data[ 0 ] ) ) {
        return std::nullopt;
    }
    start.uri = { rest.data, u };
    const Text version = after( rest, u );
    if ( version.len != 8 || std::memcmp( version.data, " SIP/2.0", 8 ) != 0 ) {
        return std::nullopt;
    }
    return start;
}

/// One SIP message as far as it was read.
struct Message {
    StartLine start;
    std::optional<Text> callId;
    std::optional<Text> cseq;
    std::optional<Text> contentType;
    std::optional<size_t> contentLength;
    bool headersCut = false; ///< The bytes end in the header section.
    bool malformed = false;
    Text body;                    ///< As much of it as was captured
    bool bodyCut = false;         ///< The body goes on beyond the bytes
    const uint8_t* end = nullptr; ///< Where the next message would begin
};

/// The message at the start of @p bytes, whose start line has been checked.
/// Over TCP, a body without Content-Length is none; over UDP, it is the
/// rest of the datagram.
Message readMessage( Text bytes, const StartLine& start, bool overTcp )
{
    Message m;
    m.start = start;
    Lines lines( bytes, false );
    Text line;
    lines.next( line ); // the start line
    size_t count = 0;
    bool ended = false;
    while ( lines.next( line ) ) {
        if ( line.empty() ) {
            ended = true;
            break;
        }
        if ( ++count > kMaxSipHeaderLines ) {
            m.malformed = true;
            break;
        }
        if ( isBlank( line.data[ 0 ] ) ) {
            continue; // a folded line goes on with the header before it
        }
        const auto* colon = static_cast<const uint8_t*>( std::memchr( line.data, ':', line.len ) );
        if ( colon == nullptr ) {
            m.malformed = true;
            break;
        }
        const Text name = trimmed( { line.data, static_cast<size_t>( colon - line.data ) } );
        const Text value = trimmed( after( line, static_cast<size_t>( colon - line.data ) + 1 ) );
        if ( ( equalsNoCase( name, "call-id" ) || equalsNoCase( name, "i" ) ) && !m.callId ) {
            m.callId = value;
        }
        else if ( equalsNoCase( name, "cseq" ) && !m.cseq ) {
            m.cseq = value;
        }
        else if ( ( equalsNoCase( name, "content-type" ) || equalsNoCase( name, "c" ) )
                  && !m.contentType ) {
            m.contentType = value;
        }
        else if ( ( equalsNoCase( name, "content-length" ) || equalsNoCase( name, "l" ) )
                  && !m.contentLength ) {
            const auto length = number( value, 9 );
            if ( !length || *length > kMaxContentLength ) {
                m.malformed = true;
                break;
            }
            m.contentLength = *length;
        }
    }
    const uint8_t* const bytesEnd = bytes.data + bytes.len;
    if ( m.malformed ) {
        m.end = bytesEnd;
        return m;
    }
    if ( !ended ) {
        m.headersCut = true;
        m.end = bytesEnd;
        return m;
    }
    const uint8_t* bodyStart = lines.here();
    const auto available = static_cast<size_t>( bytesEnd - bodyStart );
    const size_t length = m.contentLength.value_or( overTcp ? 0 : available );
    m.body = { bodyStart, std::min( length, available ) };
    m.bodyCut = length > available;
    m.end = bodyStart + m.body.len;
    return m;
}

/// The value of a CSeq header, "314159 INVITE": its number and method.
bool cseqParts( Text value, Text& sequence, Text& method )
{
    Text rest;
    sequence = word( value, rest );
    method = word( rest, rest );
    return number( sequence, 10 ) && !method.empty() && rest.empty();
}

/// The body's media type, without parameters, "application/sdp".
bool isSdp( const Message& m )
{
    if ( !m.contentType ) {
        return startsWith( m.body, "v=0" );
    }
    Text type = *m.contentType;
    for ( size_t i = 0; i < type.len; ++i ) {
        if ( type.data[ i ] == ';' ) {
            type.len = i;
        }
    }
    return equalsNoCase( trimmed( type ), "application/sdp" );
}

/// A message as Info shows it, "Request: INVITE sip:bob@example.com, CSeq
/// 1, Call-ID a84b4c76e667…, SDP (audio 49170 RTP/AVP 0 8)"; its call's
/// media in @p call.
std::string messageText( const Message& m, SipCall& call )
{
    std::string text;
    Text sequence;
    Text method;
    const bool cseqOk = m.cseq && cseqParts( *m.cseq, sequence, method );
    if ( m.start.request ) {
        text = "Request: " + escapeBytes( m.start.method.data, m.start.method.len, false ) + " "
               + fieldText( m.start.uri.data, m.start.uri.len );
    }
    else {
        text = "Status: " + m.start.code.str();
        if ( !m.start.reason.empty() ) {
            text += " " + fieldText( m.start.reason.data, m.start.reason.len );
        }
        if ( cseqOk ) {
            text += " (" + fieldText( method.data, method.len ) + ")";
        }
    }
    if ( cseqOk ) {
        text += ", CSeq " + sequence.str();
    }
    if ( m.callId ) {
        const auto& id = *m.callId;
        text += ", Call-ID " + escapeBytes( id.data, std::min( id.len, kShownCallIdBytes ), false );
        if ( id.len > kShownCallIdBytes ) {
            text += kEllipsis;
        }
        call.callId = std::string( reinterpret_cast<const char*>( id.data ),
                                   std::min( id.len, kMaxSipCallIdBytes ) );
    }
    if ( m.malformed ) {
        return text + " [Malformed Packet]";
    }
    if ( m.headersCut ) {
        return text + " " + kEllipsis;
    }
    if ( !cseqOk || !m.callId ) {
        return text + " [Malformed Packet]";
    }
    if ( m.start.request && equalsNoCase( m.start.method, "bye" ) ) {
        call.ends = true;
    }
    if ( !m.body.empty() || m.bodyCut ) {
        if ( isSdp( m ) ) {
            const auto sdp = describeSdp( m.body, !m.bodyCut );
            text += ", " + sdpText( sdp );
            call.media = sdp.endpoints;
            call.origin = sdp.origin;
            if ( m.bodyCut && !sdp.cut ) {
                text += " " + kEllipsis;
            }
        }
        else if ( m.bodyCut ) {
            text += " " + kEllipsis;
        }
    }
    return text;
}

/// Skip the line ends a message may be preceded by (RFC 3261, 7.5), and
/// the keep-alives of a connection (RFC 5626, 4.4.1).
const uint8_t* skipLineEnds( const uint8_t* at, const uint8_t* end )
{
    while ( at < end && ( *at == '\r' || *at == '\n' ) ) {
        ++at;
    }
    return at;
}

/// The start line the bytes begin with, if they hold all of it.
std::optional<StartLine> startLineOf( Text bytes )
{
    Lines lines( bytes, false );
    Text line;
    if ( !lines.next( line ) ) {
        return std::nullopt;
    }
    return startLine( line );
}

} // namespace

std::string detectSip( const uint8_t* payload, size_t len, bool overTcp,
                       std::vector<SipCall>& calls )
{
    const uint8_t* const end = payload + len;
    // Line ends before the first message are skipped as between messages.
    const uint8_t* at = skipLineEnds( payload, end );
    auto start = startLineOf( { at, static_cast<size_t>( end - at ) } );
    if ( !start ) {
        return {};
    }
    std::vector<std::string> messages;
    bool more = false;
    while ( start ) {
        if ( messages.size() == kMaxSipMessages ) {
            more = true;
            break;
        }
        const auto message
            = readMessage( { at, static_cast<size_t>( end - at ) }, *start, overTcp );
        SipCall call;
        messages.push_back( messageText( message, call ) );
        if ( call.ends || !call.media.empty() ) {
            calls.push_back( std::move( call ) );
        }
        if ( !overTcp || message.end == end || message.malformed || message.headersCut
             || message.bodyCut ) {
            break;
        }
        at = skipLineEnds( message.end, end );
        if ( at == end ) {
            break;
        }
        start = startLineOf( { at, static_cast<size_t>( end - at ) } );
        more = !start;
    }
    std::string text;
    for ( const auto& m : messages ) {
        text += ( text.empty() ? "" : "; " ) + m;
    }
    return more ? text + "; " + kEllipsis : text;
}

std::string detectSipKeepAlive( const uint8_t* payload, size_t len )
{
    if ( len == 4 && std::memcmp( payload, "\r\n\r\n", 4 ) == 0 ) {
        return "Keep-alive (ping)";
    }
    if ( len == 2 && std::memcmp( payload, "\r\n", 2 ) == 0 ) {
        return "Keep-alive (pong)";
    }
    return {};
}

std::optional<size_t> frameSipMessage( const uint8_t* payload, size_t len )
{
    // The keep-alives before a message go with it.
    const auto* at = skipLineEnds( payload, payload + len );
    const Text bytes{ at, static_cast<size_t>( payload + len - at ) };
    const auto start = startLineOf( bytes );
    if ( !start ) {
        return std::nullopt;
    }
    const auto message = readMessage( bytes, *start, true );
    if ( message.malformed ) {
        return std::nullopt;
    }
    if ( message.headersCut ) {
        return len + 1;
    }
    // Over TCP, Content-Length is mandatory (RFC 3261, 18.3): without it,
    // the body is none.
    return static_cast<size_t>( message.body.data - payload ) + message.contentLength.value_or( 0 );
}

} // namespace tcpdump::describer
