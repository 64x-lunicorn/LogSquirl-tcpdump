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
 * @file describe_smb.cpp
 * @brief The SMB detector of the Payload Describer: the NetBIOS Session
 *        Service messages (RFC 1002; direct TCP on port 445 has the same
 *        4-byte header) a segment holds, the SMB2/3 commands in them
 *        (MS-SMB2) as Wireshark names them, compounded ones too, the SMB 3
 *        transform headers, SMB1 by its command, and their framing for the
 *        TCP Reassembly.
 */

#include "describe_common.h"

#include <cstdio>
#include <iterator>

namespace tcpdump::describer {

namespace {

const std::string kEllipsis = "\xe2\x80\xa6";
const std::string kMalformed = " [Malformed Packet]";

/// The NetBIOS Session Service header: type, flags, 16-bit length; on port
/// 445 a zero byte and a 24-bit length, the same for a session message.
constexpr size_t kNbssHeaderBytes = 4;
constexpr uint8_t kSessionMessage = 0x00;

/// The SMB2 header, sync and async alike.
constexpr size_t kSmb2HeaderBytes = 64;
/// The SMB 3 transform header of an encrypted message.
constexpr size_t kTransformHeaderBytes = 52;
/// The SMB 3.1.1 compression transform header.
constexpr size_t kCompressionHeaderBytes = 16;
/// The SMB1 header, up to its flags.
constexpr size_t kSmb1FlagsEnd = 10;

constexpr uint32_t kFlagResponse = 0x00000001;
constexpr uint8_t kSmb1FlagReply = 0x80;

/// Most commands named in a segment, compounded or not, then "…".
constexpr size_t kMaxCommands = 8;
/// Most dialects named in a Negotiate Protocol Request, then "…".
constexpr size_t kMaxDialects = 8;

uint16_t readLE16( const uint8_t* p )
{
    return static_cast<uint16_t>( p[ 0 ] | ( p[ 1 ] << 8 ) );
}

uint32_t readLE32( const uint8_t* p )
{
    return static_cast<uint32_t>( readLE16( p ) )
           | ( static_cast<uint32_t>( readLE16( p + 2 ) ) << 16 );
}

uint64_t readLE64( const uint8_t* p )
{
    return static_cast<uint64_t>( readLE32( p ) )
           | ( static_cast<uint64_t>( readLE32( p + 4 ) ) << 32 );
}

/// @p value as "0x" and @p digits uppercase hexadecimal digits.
std::string hexValue( uint32_t value, int digits )
{
    char buffer[ 16 ];
    std::snprintf( buffer, sizeof buffer, "0x%0*X", digits, value );
    return buffer;
}

/// The four bytes of a protocol ID: @p first, then "SMB".
bool magicIs( const uint8_t* p, uint8_t first )
{
    return p[ 0 ] == first && p[ 1 ] == 'S' && p[ 2 ] == 'M' && p[ 3 ] == 'B';
}

bool knownMagic( const uint8_t* p )
{
    return magicIs( p, 0xFE ) || magicIs( p, 0xFD ) || magicIs( p, 0xFC ) || magicIs( p, 0xFF );
}

// ── Names ────────────────────────────────────────────────────────────────

/// The SMB2 commands, as Wireshark names them.
const char* commandName( uint16_t command )
{
    static const char* const kNames[] = { "Negotiate Protocol",
                                          "Session Setup",
                                          "Session Logoff",
                                          "Tree Connect",
                                          "Tree Disconnect",
                                          "Create",
                                          "Close",
                                          "Flush",
                                          "Read",
                                          "Write",
                                          "Lock",
                                          "Ioctl",
                                          "Cancel",
                                          "KeepAlive",
                                          "Find",
                                          "Notify",
                                          "GetInfo",
                                          "SetInfo",
                                          "Break" };
    return command < std::size( kNames ) ? kNames[ command ] : nullptr;
}

std::string commandText( uint16_t command )
{
    const char* name = commandName( command );
    return name ? std::string( name ) : "Unknown command " + hexValue( command, 4 );
}

enum Command : uint16_t {
    kNegotiate = 0x00,
    kTreeConnect = 0x03,
    kCreate = 0x05,
    kRead = 0x08,
    kWrite = 0x09,
    kIoctl = 0x0B,
    kFind = 0x0E,
    kGetInfo = 0x10,
    kSetInfo = 0x11,
};

/// The NT status codes an SMB2 response commonly carries, as Wireshark
/// (MS-ERREF) names them.
const char* ntStatusName( uint32_t status )
{
    struct Name {
        uint32_t status;
        const char* name;
    };
    static const Name kNames[] = {
        { 0x00000103, "STATUS_PENDING" },
        { 0x0000010B, "STATUS_NOTIFY_CLEANUP" },
        { 0x0000010C, "STATUS_NOTIFY_ENUM_DIR" },
        { 0x80000005, "STATUS_BUFFER_OVERFLOW" },
        { 0x80000006, "STATUS_NO_MORE_FILES" },
        { 0xC0000001, "STATUS_UNSUCCESSFUL" },
        { 0xC0000002, "STATUS_NOT_IMPLEMENTED" },
        { 0xC0000003, "STATUS_INVALID_INFO_CLASS" },
        { 0xC0000008, "STATUS_INVALID_HANDLE" },
        { 0xC000000D, "STATUS_INVALID_PARAMETER" },
        { 0xC000000E, "STATUS_NO_SUCH_DEVICE" },
        { 0xC000000F, "STATUS_NO_SUCH_FILE" },
        { 0xC0000010, "STATUS_INVALID_DEVICE_REQUEST" },
        { 0xC0000011, "STATUS_END_OF_FILE" },
        { 0xC0000016, "STATUS_MORE_PROCESSING_REQUIRED" },
        { 0xC0000022, "STATUS_ACCESS_DENIED" },
        { 0xC0000023, "STATUS_BUFFER_TOO_SMALL" },
        { 0xC0000033, "STATUS_OBJECT_NAME_INVALID" },
        { 0xC0000034, "STATUS_OBJECT_NAME_NOT_FOUND" },
        { 0xC0000035, "STATUS_OBJECT_NAME_COLLISION" },
        { 0xC000003A, "STATUS_OBJECT_PATH_NOT_FOUND" },
        { 0xC0000043, "STATUS_SHARING_VIOLATION" },
        { 0xC0000054, "STATUS_FILE_LOCK_CONFLICT" },
        { 0xC0000055, "STATUS_LOCK_NOT_GRANTED" },
        { 0xC0000056, "STATUS_DELETE_PENDING" },
        { 0xC0000061, "STATUS_PRIVILEGE_NOT_HELD" },
        { 0xC000006A, "STATUS_WRONG_PASSWORD" },
        { 0xC000006D, "STATUS_LOGON_FAILURE" },
        { 0xC000006E, "STATUS_ACCOUNT_RESTRICTION" },
        { 0xC0000071, "STATUS_PASSWORD_EXPIRED" },
        { 0xC0000072, "STATUS_ACCOUNT_DISABLED" },
        { 0xC000009A, "STATUS_INSUFFICIENT_RESOURCES" },
        { 0xC00000B5, "STATUS_IO_TIMEOUT" },
        { 0xC00000BA, "STATUS_FILE_IS_A_DIRECTORY" },
        { 0xC00000BB, "STATUS_NOT_SUPPORTED" },
        { 0xC00000C9, "STATUS_NETWORK_NAME_DELETED" },
        { 0xC00000CC, "STATUS_BAD_NETWORK_NAME" },
        { 0xC0000101, "STATUS_DIRECTORY_NOT_EMPTY" },
        { 0xC0000103, "STATUS_NOT_A_DIRECTORY" },
        { 0xC0000120, "STATUS_CANCELLED" },
        { 0xC0000128, "STATUS_FILE_CLOSED" },
        { 0xC000015B, "STATUS_LOGON_TYPE_NOT_GRANTED" },
        { 0xC0000184, "STATUS_INVALID_DEVICE_STATE" },
        { 0xC0000193, "STATUS_ACCOUNT_EXPIRED" },
        { 0xC0000203, "STATUS_USER_SESSION_DELETED" },
        { 0xC0000224, "STATUS_PASSWORD_MUST_CHANGE" },
        { 0xC0000225, "STATUS_NOT_FOUND" },
        { 0xC0000234, "STATUS_ACCOUNT_LOCKED_OUT" },
        { 0xC0000257, "STATUS_PATH_NOT_COVERED" },
        { 0xC000035C, "STATUS_NETWORK_SESSION_EXPIRED" },
    };
    for ( const auto& entry : kNames ) {
        if ( entry.status == status ) {
            return entry.name;
        }
    }
    return nullptr;
}

std::string ntStatusText( uint32_t status )
{
    const char* name = ntStatusName( status );
    return name ? std::string( name ) : "Unknown (" + hexValue( status, 8 ) + ")";
}

/// A dialect, as MS-SMB2 numbers it: "3.1.1".
std::string dialectText( uint16_t dialect )
{
    switch ( dialect ) {
    case 0x0202:
        return "2.0.2";
    case 0x0210:
        return "2.1";
    case 0x02FF:
        return "2.x";
    case 0x0300:
        return "3.0";
    case 0x0302:
        return "3.0.2";
    case 0x0311:
        return "3.1.1";
    default:
        return hexValue( dialect, 4 );
    }
}

/// The FSCTL and IOCTL codes clients commonly send, as Wireshark names them.
const char* ioctlName( uint32_t code )
{
    switch ( code ) {
    case 0x00060194:
        return "FSCTL_DFS_GET_REFERRALS";
    case 0x000601B0:
        return "FSCTL_DFS_GET_REFERRALS_EX";
    case 0x0009003C:
        return "FSCTL_GET_COMPRESSION";
    case 0x000900A4:
        return "FSCTL_SET_REPARSE_POINT";
    case 0x000900A8:
        return "FSCTL_GET_REPARSE_POINT";
    case 0x000900C0:
        return "FSCTL_CREATE_OR_GET_OBJECT_ID";
    case 0x000980C8:
        return "FSCTL_SET_ZERO_DATA";
    case 0x00098208:
        return "FSCTL_FILE_LEVEL_TRIM";
    case 0x00110018:
        return "FSCTL_PIPE_WAIT";
    case 0x0011400C:
        return "FSCTL_PIPE_PEEK";
    case 0x0011C017:
        return "FSCTL_PIPE_TRANSCEIVE";
    case 0x00140078:
        return "FSCTL_SRV_REQUEST_RESUME_KEY";
    case 0x001401D4:
        return "FSCTL_LMR_REQUEST_RESILIENCY";
    case 0x001401FC:
        return "FSCTL_QUERY_NETWORK_INTERFACE_INFO";
    case 0x00140204:
        return "FSCTL_VALIDATE_NEGOTIATE_INFO";
    case 0x00144064:
        return "FSCTL_SRV_ENUMERATE_SNAPSHOTS";
    case 0x001440F2:
        return "FSCTL_SRV_COPYCHUNK";
    case 0x001480F2:
        return "FSCTL_SRV_COPYCHUNK_WRITE";
    default:
        return nullptr;
    }
}

std::string ioctlText( uint32_t code )
{
    const char* name = ioctlName( code );
    return name ? std::string( name ) : hexValue( code, 8 );
}

/// The information classes of a Find request.
std::string findClassText( uint8_t infoClass )
{
    switch ( infoClass ) {
    case 0x01:
        return "SMB2_FIND_DIRECTORY_INFO";
    case 0x02:
        return "SMB2_FIND_FULL_DIRECTORY_INFO";
    case 0x03:
        return "SMB2_FIND_BOTH_DIRECTORY_INFO";
    case 0x0C:
        return "SMB2_FIND_NAME_INFO";
    case 0x25:
        return "SMB2_FIND_ID_BOTH_DIRECTORY_INFO";
    case 0x26:
        return "SMB2_FIND_ID_FULL_DIRECTORY_INFO";
    default:
        return "Class " + hexCode( infoClass );
    }
}

/// The information type and class of a GetInfo or SetInfo request,
/// "FILE_INFO/SMB2_FILE_ALL_INFO".
std::string infoText( uint8_t type, uint8_t infoClass )
{
    const char* className = nullptr;
    std::string text;
    switch ( type ) {
    case 0x01:
        text = "FILE_INFO";
        switch ( infoClass ) {
        case 0x04:
            className = "SMB2_FILE_BASIC_INFO";
            break;
        case 0x05:
            className = "SMB2_FILE_STANDARD_INFO";
            break;
        case 0x06:
            className = "SMB2_FILE_INTERNAL_INFO";
            break;
        case 0x0A:
            className = "SMB2_FILE_RENAME_INFO";
            break;
        case 0x0D:
            className = "SMB2_FILE_DISPOSITION_INFO";
            break;
        case 0x12:
            className = "SMB2_FILE_ALL_INFO";
            break;
        case 0x14:
            className = "SMB2_FILE_ENDOFFILE_INFO";
            break;
        case 0x16:
            className = "SMB2_FILE_STREAM_INFO";
            break;
        case 0x22:
            className = "SMB2_FILE_NETWORK_OPEN_INFO";
            break;
        case 0x23:
            className = "SMB2_FILE_ATTRIBUTE_TAG_INFO";
            break;
        default:
            break;
        }
        break;
    case 0x02:
        text = "FS_INFO";
        switch ( infoClass ) {
        case 0x01:
            className = "SMB2_FS_VOLUME_INFO";
            break;
        case 0x03:
            className = "SMB2_FS_SIZE_INFO";
            break;
        case 0x04:
            className = "SMB2_FS_DEVICE_INFO";
            break;
        case 0x05:
            className = "SMB2_FS_ATTRIBUTE_INFO";
            break;
        case 0x07:
            className = "SMB2_FS_FULL_SIZE_INFO";
            break;
        case 0x08:
            className = "SMB2_FS_OBJECTID_INFO";
            break;
        default:
            break;
        }
        break;
    case 0x03:
        text = "SEC_INFO";
        break;
    case 0x04:
        text = "QUOTA_INFO";
        break;
    default:
        return "Info type " + hexCode( type );
    }
    return text + "/" + ( className ? std::string( className ) : hexCode( infoClass ) );
}

/// The SMB1 commands a client still sends before it negotiates SMB2, and
/// the common others, as Wireshark names them.
std::string smb1CommandText( uint8_t command )
{
    switch ( command ) {
    case 0x04:
        return "Close";
    case 0x25:
        return "Trans";
    case 0x2B:
        return "Echo";
    case 0x2E:
        return "Read AndX";
    case 0x2F:
        return "Write AndX";
    case 0x32:
        return "Trans2";
    case 0x71:
        return "Tree Disconnect";
    case 0x72:
        return "Negotiate Protocol";
    case 0x73:
        return "Session Setup AndX";
    case 0x74:
        return "Logoff AndX";
    case 0x75:
        return "Tree Connect AndX";
    case 0xA0:
        return "NT Trans";
    case 0xA2:
        return "NT Create AndX";
    default:
        return "Unknown command " + hexCode( command );
    }
}

/// The NBSS message types other than a session message (RFC 1002, 4.3.1).
const char* nbssTypeName( uint8_t type )
{
    switch ( type ) {
    case 0x81:
        return "Session request";
    case 0x82:
        return "Positive session response";
    case 0x83:
        return "Negative session response";
    case 0x84:
        return "Retarget session response";
    case 0x85:
        return "Session keep-alive";
    default:
        return nullptr;
    }
}

// ── UTF-16 names ─────────────────────────────────────────────────────────

/// Append the code point @p c as UTF-8, a control character as \xNN or
/// \uNNNN, so that a name can neither break the line nor hide what it
/// contains.
void appendCodePoint( std::string& out, uint32_t c )
{
    if ( c < 0x20 || c == 0x7F ) {
        out += "\\x" + hexCode( static_cast<uint8_t>( c ) ).substr( 2 );
    }
    else if ( c < 0x80 ) {
        out += static_cast<char>( c );
    }
    else if ( c < 0xA0 || ( c >= 0xD800 && c < 0xE000 ) ) {
        char buffer[ 8 ];
        std::snprintf( buffer, sizeof buffer, "\\u%04X", static_cast<unsigned>( c ) );
        out += buffer;
    }
    else if ( c < 0x800 ) {
        out += static_cast<char>( 0xC0 | ( c >> 6 ) );
        out += static_cast<char>( 0x80 | ( c & 0x3F ) );
    }
    else if ( c < 0x10000 ) {
        out += static_cast<char>( 0xE0 | ( c >> 12 ) );
        out += static_cast<char>( 0x80 | ( ( c >> 6 ) & 0x3F ) );
        out += static_cast<char>( 0x80 | ( c & 0x3F ) );
    }
    else {
        out += static_cast<char>( 0xF0 | ( c >> 18 ) );
        out += static_cast<char>( 0x80 | ( ( c >> 12 ) & 0x3F ) );
        out += static_cast<char>( 0x80 | ( ( c >> 6 ) & 0x3F ) );
        out += static_cast<char>( 0x80 | ( c & 0x3F ) );
    }
}

/// A UTF-16LE name of @p len bytes as UTF-8: at most kMaxFieldBytes
/// characters, then an ellipsis.  Unlike fieldText(), a backslash stays
/// one, as it separates the parts of a path; an unpaired surrogate is
/// shown as \uNNNN, an odd last byte is dropped.
std::string utf16Text( const uint8_t* p, size_t len )
{
    std::string out;
    size_t chars = 0;
    for ( size_t i = 0; i + 1 < len; i += 2 ) {
        if ( chars++ == kMaxFieldBytes ) {
            out += kEllipsis;
            break;
        }
        uint32_t c = readLE16( p + i );
        if ( c >= 0xD800 && c < 0xDC00 && i + 3 < len ) {
            const uint32_t low = readLE16( p + i + 2 );
            if ( low >= 0xDC00 && low < 0xE000 ) {
                c = 0x10000 + ( ( c - 0xD800 ) << 10 ) + ( low - 0xDC00 );
                i += 2;
            }
        }
        appendCodePoint( out, c );
    }
    return out;
}

// ── An SMB2 command ──────────────────────────────────────────────────────

/// The bytes of one SMB2 command, header and all: @p captured of them were
/// captured, @p length it takes (up to the next compounded command).
struct Command2 {
    const uint8_t* p;
    size_t captured;
    size_t length;

    bool u8( size_t at, uint8_t& value ) const
    {
        if ( at >= captured ) {
            return false;
        }
        value = p[ at ];
        return true;
    }
    bool u16( size_t at, uint16_t& value ) const
    {
        if ( at > captured || captured - at < 2 ) {
            return false;
        }
        value = readLE16( p + at );
        return true;
    }
    bool u32( size_t at, uint32_t& value ) const
    {
        if ( at > captured || captured - at < 4 ) {
            return false;
        }
        value = readLE32( p + at );
        return true;
    }
    bool u64( size_t at, uint64_t& value ) const
    {
        if ( at > captured || captured - at < 8 ) {
            return false;
        }
        value = readLE64( p + at );
        return true;
    }

    /// The name at the offset (from the header) and length the fields at
    /// @p at give: appended to @p text after @p prefix, unless it is empty.
    /// One beyond the command is malformed; one beyond the captured bytes
    /// is left out.  False if malformed.
    bool name( size_t at, const char* prefix, std::string& text ) const
    {
        uint16_t offset = 0;
        uint16_t bytes = 0;
        if ( !u16( at, offset ) || !u16( at + 2, bytes ) || bytes == 0 ) {
            return true;
        }
        if ( size_t{ offset } + bytes > length || offset < kSmb2HeaderBytes ) {
            text += kMalformed;
            return false;
        }
        if ( size_t{ offset } + bytes <= captured ) {
            text += prefix + utf16Text( p + offset, bytes );
        }
        return true;
    }
};

/// The body offsets of the fields a command's text shows.
constexpr size_t kBody = kSmb2HeaderBytes;

/// The fields of a request after its name, " Len:65536 Off:0"; false if
/// they are malformed, and nothing after them is read.
bool requestFields( uint16_t command, const Command2& c, std::string& text )
{
    uint8_t infoType = 0;
    uint8_t infoClass = 0;
    uint16_t count = 0;
    uint32_t length = 0;
    uint64_t offset = 0;
    switch ( command ) {
    case kNegotiate: {
        if ( !c.u16( kBody + 2, count ) ) {
            return true;
        }
        if ( kBody + 36 + size_t{ count } * 2 > c.length ) {
            text += kMalformed;
            return false;
        }
        std::vector<std::string> dialects;
        for ( size_t i = 0; i < count && i <= kMaxDialects; ++i ) {
            uint16_t dialect = 0;
            if ( !c.u16( kBody + 36 + i * 2, dialect ) ) {
                break;
            }
            dialects.push_back( dialectText( dialect ) );
        }
        if ( !dialects.empty() ) {
            text += " Dialects: " + joinNames( std::move( dialects ), kMaxDialects );
        }
        return true;
    }
    case kTreeConnect:
        return c.name( kBody + 4, " Tree: ", text );
    case kCreate:
        return c.name( kBody + 44, " File: ", text );
    case kRead:
    case kWrite:
        if ( c.u32( kBody + 4, length ) && c.u64( kBody + 8, offset ) ) {
            text += " Len:" + std::to_string( length ) + " Off:" + std::to_string( offset );
        }
        return true;
    case kIoctl:
        if ( c.u32( kBody + 4, length ) ) {
            text += " " + ioctlText( length );
        }
        return true;
    case kFind:
        if ( !c.u8( kBody + 2, infoClass ) ) {
            return true;
        }
        text += " " + findClassText( infoClass );
        return c.name( kBody + 24, " Pattern: ", text );
    case kGetInfo:
    case kSetInfo:
        if ( c.u8( kBody + 2, infoType ) && c.u8( kBody + 3, infoClass ) ) {
            text += " " + infoText( infoType, infoClass );
        }
        return true;
    default:
        return true;
    }
}

/// The fields of a successful response after its name.
void responseFields( uint16_t command, const Command2& c, std::string& text )
{
    uint16_t dialect = 0;
    uint32_t code = 0;
    switch ( command ) {
    case kNegotiate:
        if ( c.u16( kBody + 4, dialect ) ) {
            text += " Dialect: " + dialectText( dialect );
        }
        break;
    case kIoctl:
        if ( c.u32( kBody + 4, code ) ) {
            text += " " + ioctlText( code );
        }
        break;
    default:
        break;
    }
}

/// The SMB2 commands of a message that begins at @p p, @p length bytes
/// long, of which @p captured were captured: every compounded one, as long
/// as @p budget lasts.  @p more is set if it ran out before the last.
std::string smb2Text( const uint8_t* p, size_t captured, size_t length, size_t& budget, bool& more )
{
    std::string text;
    size_t at = 0;
    while ( true ) {
        if ( budget == 0 ) {
            more = true;
            break;
        }
        --budget;
        if ( !text.empty() ) {
            text += "; ";
        }
        const uint8_t* h = p + at;
        const size_t avail = captured - at;
        const size_t left = length - at;
        if ( avail >= 6 && readLE16( h + 4 ) != kSmb2HeaderBytes ) {
            text += "Invalid header size " + std::to_string( readLE16( h + 4 ) ) + kMalformed;
            break;
        }
        if ( left < kSmb2HeaderBytes && avail == left ) {
            text += "Header" + kMalformed;
            break;
        }
        if ( avail < 14 ) {
            text += "Header " + kEllipsis;
            break;
        }
        const uint16_t command = readLE16( h + 12 );
        text += commandText( command );
        if ( avail < 24 ) {
            text += " " + kEllipsis;
            break;
        }
        const bool response = ( readLE32( h + 16 ) & kFlagResponse ) != 0;
        text += response ? " Response" : " Request";
        const uint32_t status = readLE32( h + 8 );
        const uint32_t next = readLE32( h + 20 );
        const bool chained = next != 0;
        if ( chained && ( next < kSmb2HeaderBytes || next > left ) ) {
            text += ", Invalid NextCommand " + std::to_string( next ) + kMalformed;
            break;
        }
        const size_t span = chained ? next : left;
        const Command2 c{ h, std::min( span, avail ), span };
        if ( response && status != 0 ) {
            text += ", Error: " + ntStatusText( status );
        }
        else if ( response ) {
            responseFields( command, c, text );
        }
        else if ( !requestFields( command, c, text ) ) {
            break;
        }
        if ( avail < span ) {
            text += " " + kEllipsis;
            break;
        }
        if ( !chained ) {
            break;
        }
        at += next; // within length, and captured as avail >= span
    }
    return text;
}

// ── A message ────────────────────────────────────────────────────────────

/// One NBSS message, as far as it was read.
struct Message {
    std::string text;
    const char* label = nullptr; ///< Null if it is none the describer knows
    bool last = true;            ///< No message can follow it in these bytes
    bool more = false;           ///< Commands of it were left unnamed
    uint64_t length = 0;         ///< The bytes it takes, header and all
};

/// The SMB 3 transform header, "Encrypted SMB3", or the compression
/// transform header, "Compressed SMB3, LZ77, Original size 4096".
std::string transformText( const uint8_t* p, size_t captured, size_t length )
{
    if ( magicIs( p, 0xFD ) ) {
        return length < kTransformHeaderBytes ? "Encrypted SMB3" + kMalformed : "Encrypted SMB3";
    }
    std::string text = "Compressed SMB3";
    if ( length < kCompressionHeaderBytes ) {
        return text + kMalformed;
    }
    if ( captured < kCompressionHeaderBytes ) {
        return text;
    }
    static const char* const kAlgorithms[]
        = { "None", "LZNT1", "LZ77", "LZ77+Huffman", "Pattern_V1", "LZ4" };
    const uint16_t algorithm = readLE16( p + 8 );
    text += ", ";
    text += algorithm < std::size( kAlgorithms ) ? std::string( kAlgorithms[ algorithm ] )
                                                 : "Algorithm " + hexValue( algorithm, 4 );
    text += ", Original size " + std::to_string( readLE32( p + 4 ) );
    if ( readLE16( p + 10 ) & 0x0001 ) {
        text += ", chained";
    }
    return text;
}

/// An SMB1 message: its command only.
std::string smb1Text( const uint8_t* p, size_t captured )
{
    if ( captured < 5 ) {
        return "Header " + kEllipsis;
    }
    std::string text = smb1CommandText( p[ 4 ] );
    if ( captured < kSmb1FlagsEnd ) {
        return text + " " + kEllipsis;
    }
    return text + ( ( p[ 9 ] & kSmb1FlagReply ) ? " Response" : " Request" );
}

/// The NBSS message at @p p, of which @p len bytes were captured.
Message readMessage( const uint8_t* p, size_t len, size_t& budget )
{
    Message m;
    if ( len < kNbssHeaderBytes ) {
        m.text = "Header " + kEllipsis;
        m.label = "NBSS";
        return m;
    }
    const uint8_t type = p[ 0 ];
    if ( type != kSessionMessage ) {
        const char* name = nbssTypeName( type );
        if ( !name ) {
            m.text = "Unknown message type " + hexCode( type ) + kMalformed;
            return m;
        }
        m.label = "NBSS";
        m.text = name;
        m.length = kNbssHeaderBytes + ( ( size_t{ p[ 1 ] } & 0x01 ) << 16 ) + readBE16( p + 2 );
        m.last = len < m.length;
        if ( m.last ) {
            m.text += " " + kEllipsis;
        }
        return m;
    }
    const size_t length = ( size_t{ p[ 1 ] } << 16 ) | readBE16( p + 2 );
    m.length = kNbssHeaderBytes + length;
    const bool whole = len >= m.length;
    m.last = !whole;
    const uint8_t* body = p + kNbssHeaderBytes;
    const size_t captured = whole ? length : len - kNbssHeaderBytes;
    if ( captured < 4 ) {
        m.label = "NBSS";
        m.text = whole ? "Session message, " + std::to_string( length ) + " bytes"
                       : "Session message " + kEllipsis;
        return m;
    }
    if ( magicIs( body, 0xFE ) ) {
        m.label = "SMB2";
        m.text = smb2Text( body, captured, length, budget, m.more );
        return m;
    }
    if ( magicIs( body, 0xFF ) ) {
        m.label = "SMB";
        m.text = smb1Text( body, captured );
    }
    else if ( magicIs( body, 0xFD ) || magicIs( body, 0xFC ) ) {
        m.label = "SMB2";
        m.text = transformText( body, captured, length );
    }
    else {
        m.text = "Session message, " + std::to_string( length ) + " bytes";
        m.last = true;
        return m;
    }
    if ( budget > 0 ) {
        --budget;
    }
    if ( !whole ) {
        m.text += " " + kEllipsis;
    }
    return m;
}

} // namespace

bool beginsWithSmb( const uint8_t* payload, size_t len )
{
    return len >= kNbssHeaderBytes + 4 && payload[ 0 ] == kSessionMessage
           && knownMagic( payload + kNbssHeaderBytes );
}

SmbDescription detectSmb( const uint8_t* payload, size_t len )
{
    SmbDescription result;
    size_t budget = kMaxCommands;
    size_t at = 0;
    while ( at < len ) {
        if ( budget == 0 ) {
            result.text += "; " + kEllipsis;
            break;
        }
        auto message = readMessage( payload + at, len - at, budget );
        if ( at == 0 ) {
            if ( !message.label ) {
                return {}; // the segment begins with none of NBSS's messages
            }
            result.label = message.label;
        }
        result.text += ( result.text.empty() ? "" : "; " ) + message.text;
        if ( message.more ) {
            result.text += "; " + kEllipsis;
            break;
        }
        if ( message.last ) {
            break;
        }
        at += static_cast<size_t>( message.length ); // whole, so within len
    }
    return result;
}

std::optional<size_t> frameSmbMessage( const uint8_t* payload, size_t len, bool onSmbPort )
{
    if ( len == 0 ) {
        return onSmbPort ? std::optional<size_t>( 1 ) : std::nullopt;
    }
    const uint8_t type = payload[ 0 ];
    if ( type == kSessionMessage ) {
        if ( len >= kNbssHeaderBytes + 4 ? !knownMagic( payload + kNbssHeaderBytes )
                                         : !onSmbPort ) {
            return std::nullopt; // no message: described as it is
        }
        if ( len < kNbssHeaderBytes ) {
            return len + 1;
        }
        return kNbssHeaderBytes + ( ( size_t{ payload[ 1 ] } << 16 ) | readBE16( payload + 2 ) );
    }
    if ( !onSmbPort || !nbssTypeName( type ) ) {
        return std::nullopt;
    }
    if ( len < kNbssHeaderBytes ) {
        return len + 1;
    }
    return kNbssHeaderBytes + ( ( size_t{ payload[ 1 ] } & 0x01 ) << 16 ) + readBE16( payload + 2 );
}

} // namespace tcpdump::describer
