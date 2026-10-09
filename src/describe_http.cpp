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
 * @file describe_http.cpp
 * @brief The HTTP and HTTP/2 detectors of the Payload Describer, and HTTP/2
 *        frames in a stream that began with the preface.
 */

#include "describe_common.h"

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── HTTP ─────────────────────────────────────────────────────────────────

namespace {

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

} // namespace

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

/// The HTTP/1.x header section a segment begins with, the start line up to
/// the empty line that ends it, or nothing if no request or status line
/// starts there.  Its body, if any, is not part of it: the description
/// reads the header section only.  While the empty line has not come, one
/// byte more than there is.
std::optional<size_t> frameHttpHeader( const uint8_t* payload, size_t len )
{
    if ( detectHttp( payload, std::min<size_t>( len, 8 ) ).empty() ) {
        return std::nullopt;
    }
    for ( size_t i = 0; i + 1 < len; ++i ) {
        if ( payload[ i ] != '\n' ) {
            continue;
        }
        if ( payload[ i + 1 ] == '\n' ) {
            return i + 2;
        }
        if ( payload[ i + 1 ] == '\r' && i + 2 < len && payload[ i + 2 ] == '\n' ) {
            return i + 3;
        }
    }
    return len + 1;
}

// ── HTTP/2 ───────────────────────────────────────────────────────────────

namespace {

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
    bool more = false;
    while ( offset < wireLen ) {
        if ( names.size() == kMaxHttp2Frames || offset >= len
             || len - offset < kHttp2FrameHeaderBytes ) {
            if ( names.empty() ) {
                return {};
            }
            more = true;
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
    return joinNames( std::move( names ), kMaxHttp2Frames, more );
}

} // namespace

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

// ── HTTP/2 in its stream ─────────────────────────────────────────────────

/// A TCP segment in its stream: HTTP/2 frames after the preface, those
/// whose header lies in the payload's first kPayloadHeadBytes.
void describeHttp2InStream( PacketRecord& pkt, StreamState& state )
{
    if ( pkt.streamCue == StreamCue::Http2Preface ) {
        state.http2 = true;
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

} // namespace tcpdump::describer

// ── HTTP/2 with its header blocks, for the TLS Decryption ───────────────

namespace tcpdump {

using namespace describer;

namespace {

constexpr uint8_t kHttp2Headers = 0x1;
constexpr uint8_t kHttp2PushPromise = 0x5;
constexpr uint8_t kHttp2Continuation = 0x9;
constexpr uint8_t kHttp2FlagEndHeaders = 0x4;
constexpr uint8_t kHttp2FlagPadded = 0x8;
constexpr uint8_t kHttp2FlagPriority = 0x20;

bool carriesHeaderBlock( uint8_t type )
{
    return type == kHttp2Headers || type == kHttp2PushPromise || type == kHttp2Continuation;
}

/// The value of the field @p name of @p fields, the first one; null if none.
const std::string* fieldValue( const std::vector<HeaderField>& fields, const char* name )
{
    for ( const auto& field : fields ) {
        if ( field.name == name ) {
            return &field.value;
        }
    }
    return nullptr;
}

std::string text( const std::string& value )
{
    return fieldText( reinterpret_cast<const uint8_t*>( value.data() ), value.size() );
}

/// What a decoded header block says: "GET example.com/index.html" for a
/// request, "200, Content-Type: text/html, Content-Length: 1234" for a
/// response; empty for trailers.
std::string headerBlockSummary( const std::vector<HeaderField>& fields )
{
    if ( const auto* method = fieldValue( fields, ":method" ) ) {
        auto summary = text( *method );
        const auto* authority = fieldValue( fields, ":authority" );
        const auto* path = fieldValue( fields, ":path" );
        if ( authority || path ) {
            summary += ' ';
        }
        if ( authority && ( !path || ( !path->empty() && ( *path )[ 0 ] == '/' ) ) ) {
            summary += text( *authority );
        }
        if ( path ) {
            summary += text( *path );
        }
        return summary;
    }
    if ( const auto* status = fieldValue( fields, ":status" ) ) {
        auto summary = text( *status );
        static const std::pair<const char*, const char*> kShown[] = {
            { "content-type", "Content-Type" },
            { "content-length", "Content-Length" },
        };
        for ( const auto& [ key, name ] : kShown ) {
            if ( const auto* value = fieldValue( fields, key ) ) {
                summary += std::string( ", " ) + name + ": " + text( *value );
            }
        }
        return summary;
    }
    return {};
}

} // namespace

std::string Http2Direction::describe( const uint8_t* data, size_t len )
{
    std::vector<std::string> names;
    frameName_ = SIZE_MAX;
    blockName_ = SIZE_MAX;
    size_t at = 0;
    if ( !started_ ) {
        started_ = true;
        if ( len >= kHttp2PrefaceBytes
             && std::memcmp( data, kHttp2Preface, kHttp2PrefaceBytes ) == 0 ) {
            names.emplace_back( "Magic" );
            at = kHttp2PrefaceBytes;
        }
    }
    while ( at < len ) {
        if ( skip_ > 0 ) {
            const auto n = std::min( skip_, len - at );
            skip_ -= n;
            at += n;
            continue;
        }
        if ( frame_.size() < kHttp2FrameHeaderBytes ) {
            const auto n = std::min( kHttp2FrameHeaderBytes - frame_.size(), len - at );
            frame_.insert( frame_.end(), data + at, data + at + n );
            at += n;
            if ( frame_.size() < kHttp2FrameHeaderBytes ) {
                break;
            }
            FieldReader header( frame_.data(), kHttp2FrameHeaderBytes );
            uint32_t length = 0;
            uint8_t type = 0;
            uint8_t flags = 0;
            uint32_t stream = 0;
            header.u24( length );
            header.u8( type );
            header.u8( flags );
            header.u32( stream );
            stream &= 0x7FFFFFFFu; // the reserved bit
            const char* name
                = http2FrameName( type, std::min( length, kHttp2DefaultMaxFrameSize ), stream );
            names.push_back( ( name ? std::string( name ) : hexCode( type ) ) + "["
                             + std::to_string( stream ) + "]" );
            frameName_ = names.size() - 1;
            frameLength_ = length;
            if ( !carriesHeaderBlock( type ) || headersAbandoned_
                 || length > kMaxHeaderBlockBytes ) {
                if ( carriesHeaderBlock( type ) && !headersAbandoned_ ) {
                    abandonHeaders(); // a block too long to hold
                }
                skip_ = length;
                frame_.clear();
                continue;
            }
            frame_.reserve( kHttp2FrameHeaderBytes + length );
        }
        const auto want = kHttp2FrameHeaderBytes + frameLength_ - frame_.size();
        const auto n = std::min( want, len - at );
        frame_.insert( frame_.end(), data + at, data + at + n );
        at += n;
        if ( n == want ) {
            frameDone( names, frameName_ );
            frame_.clear();
            frameName_ = SIZE_MAX;
        }
    }
    return joinNames( std::move( names ), kMaxHttp2Frames );
}

void Http2Direction::frameDone( std::vector<std::string>& names, size_t nameIndex )
{
    const uint8_t type = frame_[ 3 ];
    const uint8_t flags = frame_[ 4 ];
    FieldReader payload( frame_.data() + kHttp2FrameHeaderBytes, frameLength_ );
    uint8_t padding = 0;
    if ( type != kHttp2Continuation && ( flags & kHttp2FlagPadded ) && !payload.u8( padding ) ) {
        abandonHeaders();
        return;
    }
    if ( ( type == kHttp2Headers && ( flags & kHttp2FlagPriority ) && !payload.skip( 5 ) )
         || ( type == kHttp2PushPromise && !payload.skip( 4 ) ) || payload.remaining() < padding ) {
        abandonHeaders();
        return;
    }
    const auto fragment = payload.remaining() - padding;
    if ( type == kHttp2Continuation ) {
        if ( !inBlock_ || block_.size() + fragment > kMaxHeaderBlockBytes ) {
            abandonHeaders();
            return;
        }
    }
    else {
        if ( inBlock_ ) {
            abandonHeaders(); // a new block before the last one ended
            return;
        }
        inBlock_ = true;
        block_.clear();
        blockName_ = nameIndex;
    }
    block_.insert( block_.end(), payload.here(), payload.here() + fragment );
    if ( !( flags & kHttp2FlagEndHeaders ) ) {
        return;
    }
    std::vector<HeaderField> fields;
    const bool decoded = hpack_.decode( block_.data(), block_.size(), fields );
    inBlock_ = false;
    std::vector<uint8_t>().swap( block_ );
    if ( !decoded ) {
        abandonHeaders();
        return;
    }
    const auto summary = headerBlockSummary( fields );
    if ( blockName_ < names.size() && !summary.empty() ) {
        names[ blockName_ ] += ": " + summary;
    }
    blockName_ = SIZE_MAX;
}

size_t Http2Direction::memory() const
{
    return frame_.capacity() + block_.capacity() + hpack_.tableSize();
}

void Http2Direction::abandonHeaders()
{
    headersAbandoned_ = true;
    hpack_.abandon();
    inBlock_ = false;
    blockName_ = SIZE_MAX;
    std::vector<uint8_t>().swap( block_ );
    if ( frame_.size() >= kHttp2FrameHeaderBytes ) {
        // The header block frame being read: the rest of it is passed over.
        skip_ = kHttp2FrameHeaderBytes + frameLength_ - frame_.size();
        std::vector<uint8_t>().swap( frame_ );
    }
}

} // namespace tcpdump
