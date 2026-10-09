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
 * @file describe_someip.cpp
 * @brief The SOME/IP detector of the Payload Describer: SOME/IP messages
 *        (AUTOSAR PRS_SOMEIPProtocol), every one in a datagram or segment,
 *        the entries and options of SOME/IP-SD (PRS_SOMEIPServiceDiscovery
 *        Protocol), their framing over TCP, and the name table.
 */

#include "describe_common.h"
#include "someip.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>

namespace tcpdump {

namespace {

/// The configuration SomeIpScope put in place on this thread, if any.
thread_local const SomeIpConfig* tSomeIpConfig = nullptr;

} // namespace

SomeIpScope::SomeIpScope( const SomeIpConfig& config )
    : previous_( tSomeIpConfig )
{
    tSomeIpConfig = &config;
}

SomeIpScope::~SomeIpScope()
{
    tSomeIpConfig = previous_;
}

// ── The name table and the ports ─────────────────────────────────────────

namespace {

/// A number in hexadecimal with 0x, or decimal, up to @p max.
std::optional<uint32_t> idNumber( const std::string& word, uint32_t max )
{
    if ( word.empty() || word.size() > 12 ) {
        return std::nullopt;
    }
    const bool hex
        = word.size() > 2 && word[ 0 ] == '0' && ( word[ 1 ] == 'x' || word[ 1 ] == 'X' );
    uint64_t value = 0;
    for ( size_t i = hex ? 2 : 0; i < word.size(); ++i ) {
        const char c = word[ i ];
        int digit = -1;
        if ( c >= '0' && c <= '9' ) {
            digit = c - '0';
        }
        else if ( hex && c >= 'a' && c <= 'f' ) {
            digit = c - 'a' + 10;
        }
        else if ( hex && c >= 'A' && c <= 'F' ) {
            digit = c - 'A' + 10;
        }
        if ( digit < 0 ) {
            return std::nullopt;
        }
        value = value * ( hex ? 16 : 10 ) + static_cast<uint64_t>( digit );
        if ( value > max ) {
            return std::nullopt;
        }
    }
    return static_cast<uint32_t>( value );
}

/// The rest of a line as a name: blanks around it trimmed, cut at a
/// control character and at kMaxSomeIpNameBytes.
std::string nameOf( std::string rest )
{
    const auto control = std::find_if( rest.begin(), rest.end(), []( char c ) {
        const auto byte = static_cast<uint8_t>( c );
        return ( byte < 0x20 && c != '\t' ) || byte == 0x7F;
    } );
    rest.erase( control, rest.end() );
    const auto first = rest.find_first_not_of( " \t" );
    if ( first == std::string::npos ) {
        return {};
    }
    rest = rest.substr( first, rest.find_last_not_of( " \t" ) - first + 1 );
    if ( rest.size() > kMaxSomeIpNameBytes ) {
        rest.resize( kMaxSomeIpNameBytes );
    }
    return rest;
}

size_t nameCount( const SomeIpNames& names )
{
    return names.services.size() + names.methods.size() + names.eventgroups.size();
}

} // namespace

SomeIpNames parseSomeIpNames( const std::string& text, std::vector<std::string>* problems )
{
    SomeIpNames names;
    std::istringstream lines( text );
    std::string line;
    size_t number = 0;
    auto problem = [ & ]( const char* what ) {
        if ( problems && problems->size() < 16 ) {
            problems->push_back( "line " + std::to_string( number ) + ": " + what );
        }
    };
    while ( std::getline( lines, line ) && nameCount( names ) < kMaxSomeIpNames ) {
        ++number;
        if ( !line.empty() && line.back() == '\r' ) {
            line.pop_back();
        }
        std::istringstream words( line );
        std::string kind;
        if ( !( words >> kind ) || kind[ 0 ] == '#' ) {
            continue;
        }
        std::string serviceWord;
        words >> serviceWord;
        const auto service = idNumber( serviceWord, 0xFFFF );
        if ( !service ) {
            problem( "no service ID" );
            continue;
        }
        std::optional<uint32_t> id;
        if ( kind != "service" ) {
            std::string idWord;
            words >> idWord;
            id = idNumber( idWord, 0xFFFF );
            if ( !id ) {
                problem( "no method, event or eventgroup ID" );
                continue;
            }
        }
        std::string rest;
        std::getline( words, rest );
        auto name = nameOf( rest );
        if ( name.empty() ) {
            problem( "no name" );
            continue;
        }
        const uint32_t key = ( *service << 16 ) | id.value_or( 0 );
        if ( kind == "service" ) {
            names.services[ static_cast<uint16_t>( *service ) ] = std::move( name );
        }
        else if ( kind == "method" || kind == "event" ) {
            names.methods[ key ] = std::move( name );
        }
        else if ( kind == "eventgroup" ) {
            names.eventgroups[ key ] = std::move( name );
        }
        else {
            problem( "neither service, method, event nor eventgroup" );
        }
    }
    return names;
}

std::optional<SomeIpNames> loadSomeIpNames( const std::string& path,
                                            std::vector<std::string>* problems )
{
    std::ifstream file( path, std::ios::binary );
    if ( !file ) {
        return std::nullopt;
    }
    std::string text( kMaxSomeIpNamesFileBytes, '\0' );
    file.read( text.data(), static_cast<std::streamsize>( text.size() ) );
    if ( file.bad() ) {
        return std::nullopt;
    }
    text.resize( static_cast<size_t>( file.gcount() ) );
    return parseSomeIpNames( text, problems );
}

std::vector<uint16_t> parseSomeIpPorts( const std::string& text )
{
    std::vector<uint16_t> ports;
    std::string word;
    auto take = [ & ] {
        const auto port = idNumber( word, 0xFFFF );
        word.clear();
        if ( port && *port != 0 && ports.size() < kMaxSomeIpPorts
             && std::find( ports.begin(), ports.end(), *port ) == ports.end() ) {
            ports.push_back( static_cast<uint16_t>( *port ) );
        }
    };
    for ( const char c : text ) {
        if ( c == ',' || c == ' ' || c == '\t' || c == ';' ) {
            take();
        }
        else {
            word += c;
            if ( word.size() > 16 ) {
                word.resize( 16 ); // no number: skipped whole
            }
        }
    }
    take();
    return ports;
}

std::string someIpPortsText( const std::vector<uint16_t>& ports )
{
    std::string text;
    for ( const auto port : ports ) {
        text += ( text.empty() ? "" : ", " ) + std::to_string( port );
    }
    return text;
}

} // namespace tcpdump

namespace tcpdump::describer {

// ── SOME/IP ──────────────────────────────────────────────────────────────

namespace {

/// The header: Message ID, Length, Request ID, Protocol and Interface
/// Version, Message Type, Return Code.
constexpr size_t kHeaderBytes = 16;
/// The bytes the Length field does not count: Message ID and Length.
constexpr size_t kUncountedBytes = 8;
/// The SOME/IP-TP header behind a segmented message's header.
constexpr size_t kTpHeaderBytes = 4;
constexpr uint8_t kProtocolVersion = 0x01;
constexpr uint8_t kTpFlag = 0x20;

constexpr uint16_t kSdService = 0xFFFF;
constexpr uint16_t kSdMethod = 0x8100;

/// Most messages named in a datagram or segment, then "…".
constexpr size_t kMaxMessages = 8;
/// Most SD entries named in a message, then "…", and read at all.
constexpr size_t kMaxSdEntriesNamed = 8;
constexpr size_t kMaxSdEntries = 64;
/// Most SD options read, and named for one entry.
constexpr size_t kMaxSdOptions = 64;
constexpr size_t kMaxSdOptionsNamed = 4;
/// Bytes of an SD entry; those of an option's Length and Type.
constexpr size_t kSdEntryBytes = 16;
constexpr size_t kSdOptionHeaderBytes = 3;

/// By the header alone (the heuristic, and the framer off SOME/IP's
/// ports), a message of more than this many bytes is taken for none: no SOME/IP message on a port
/// not SOME/IP's is so long, and random bytes seldom pass for one.
constexpr uint32_t kMaxHeuristicLength = 1024 * 1024;

/// The message types (PRS_SOMEIP_00055), as AUTOSAR names them; null for
/// one that is none.  The TP flag (0x20) makes a type a segment's.
const char* messageTypeName( uint8_t type )
{
    switch ( type ) {
    case 0x00:
        return "REQUEST";
    case 0x01:
        return "REQUEST_NO_RETURN";
    case 0x02:
        return "NOTIFICATION";
    case 0x40:
        return "REQUEST_ACK";
    case 0x41:
        return "REQUEST_NO_RETURN_ACK";
    case 0x42:
        return "NOTIFICATION_ACK";
    case 0x80:
        return "RESPONSE";
    case 0x81:
        return "ERROR";
    case 0xC0:
        return "RESPONSE_ACK";
    case 0xC1:
        return "ERROR_ACK";
    case 0x20:
        return "TP_REQUEST";
    case 0x21:
        return "TP_REQUEST_NO_RETURN";
    case 0x22:
        return "TP_NOTIFICATION";
    case 0xA0:
        return "TP_RESPONSE";
    case 0xA1:
        return "TP_ERROR";
    default:
        return nullptr;
    }
}

/// The type carries a return code of its own: a response or an error.
bool answers( uint8_t type )
{
    return ( type & 0x80 ) != 0;
}

/// The return codes (PRS_SOMEIP_00191), as Wireshark names them.
std::string returnCodeName( uint8_t code )
{
    static const char* const kNames[] = {
        "E_OK",
        "E_NOT_OK",
        "E_UNKNOWN_SERVICE",
        "E_UNKNOWN_METHOD",
        "E_NOT_READY",
        "E_NOT_REACHABLE",
        "E_TIMEOUT",
        "E_WRONG_PROTOCOL_VERSION",
        "E_WRONG_INTERFACE_VERSION",
        "E_MALFORMED_MESSAGE",
        "E_WRONG_MESSAGE_TYPE",
        "E_E2E_REPEATED",
        "E_E2E_WRONG_SEQUENCE",
        "E_E2E",
        "E_E2E_NOT_AVAILABLE",
        "E_E2E_NO_NEW_DATA",
    };
    if ( code < std::size( kNames ) ) {
        return kNames[ code ];
    }
    if ( code < 0x20 ) {
        return "Reserved " + hexCode( code );
    }
    if ( code <= 0x5E ) {
        return "Service Error " + hexCode( code );
    }
    return "Return Code " + hexCode( code );
}

/// @p id, and the name the table gives it in parentheses.
template <typename Key>
std::string named( uint16_t id, const std::map<Key, std::string>* names, Key key )
{
    auto text = id16( id );
    if ( names ) {
        const auto it = names->find( key );
        if ( it != names->end() ) {
            const auto& name = it->second;
            text += " ("
                    + escapeBytes( reinterpret_cast<const uint8_t*>( name.data() ), name.size(),
                                   false )
                    + ")";
        }
    }
    return text;
}

const SomeIpNames* configuredNames()
{
    return tSomeIpConfig ? &tSomeIpConfig->names : nullptr;
}

std::string serviceText( uint16_t service )
{
    const auto* names = configuredNames();
    return named<uint16_t>( service, names ? &names->services : nullptr, service );
}

/// "Method 0x0001", or "Event 0x8001" for an ID with its high bit set.
std::string methodText( uint16_t service, uint16_t method )
{
    const auto* names = configuredNames();
    return std::string( ( method & 0x8000 ) ? "Event " : "Method " )
           + named<uint32_t>( method, names ? &names->methods : nullptr,
                              ( uint32_t{ service } << 16 ) | method );
}

std::string eventgroupText( uint16_t service, uint16_t eventgroup )
{
    const auto* names = configuredNames();
    return "Eventgroup "
           + named<uint32_t>( eventgroup, names ? &names->eventgroups : nullptr,
                              ( uint32_t{ service } << 16 ) | eventgroup );
}

/// The fixed part of a message's header.
struct Header {
    uint16_t service = 0;
    uint16_t method = 0;
    uint32_t length = 0; ///< Bytes from the Request ID to the end
    uint16_t client = 0;
    uint16_t session = 0;
    uint8_t protocolVersion = 0;
    uint8_t interfaceVersion = 0;
    uint8_t type = 0;
    uint8_t returnCode = 0;
};

Header readHeader( const uint8_t* p )
{
    Header h;
    h.service = readBE16( p );
    h.method = readBE16( p + 2 );
    h.length = readBE32( p + 4 );
    h.client = readBE16( p + 8 );
    h.session = readBE16( p + 10 );
    h.protocolVersion = p[ 12 ];
    h.interfaceVersion = p[ 13 ];
    h.type = p[ 14 ];
    h.returnCode = p[ 15 ];
    return h;
}

/// The header follows the rules a message on any port must keep to be
/// taken for SOME/IP: protocol version 1, a known message type, a return
/// code of a known range (E_OK in a request or notification), and a
/// length that covers the rest of the header (and the TP header).
bool plausible( const Header& h )
{
    if ( h.protocolVersion != kProtocolVersion || !messageTypeName( h.type ) || h.returnCode > 0x5E
         || ( !answers( h.type ) && h.returnCode != 0 ) ) {
        return false;
    }
    const size_t least
        = kHeaderBytes - kUncountedBytes + ( ( h.type & kTpFlag ) ? kTpHeaderBytes : 0 );
    return h.length >= least;
}

/// The magic cookies that let a receiver find the next message in a TCP
/// stream (PRS_SOMEIP_00154): client to server, server to client.
bool isMagicCookie( const Header& h )
{
    return h.service == 0xFFFF && ( h.method == 0x0000 || h.method == 0x8000 ) && h.length == 8
           && h.client == 0xDEAD && h.session == 0xBEEF;
}

// ── SOME/IP-SD ───────────────────────────────────────────────────────────

/// An endpoint option's address, port and transport, "192.0.2.10:30501
/// UDP"; empty if its length is not the type's.
std::string endpointText( uint8_t type, FieldReader option )
{
    const bool v6 = ( type & 0x02 ) != 0;
    const size_t addressBytes = v6 ? 16 : 4;
    if ( option.remaining() != 1 + addressBytes + 4 || !option.complete() ) {
        return {};
    }
    option.skip( 1 ); // reserved / discardable flag
    const auto* address = option.here();
    option.skip( addressBytes + 1 );
    uint8_t l4 = 0;
    uint16_t port = 0;
    option.u8( l4 );
    option.u16( port );
    std::string text = v6 ? "[" + formatIpv6( address ) + "]" : formatIpv4( address );
    text += ":" + std::to_string( port ) + " ";
    text += l4 == 0x06 ? "TCP" : l4 == 0x11 ? "UDP" : "L4 " + hexCode( l4 );
    if ( type == 0x14 || type == 0x16 ) {
        text += " multicast";
    }
    else if ( type == 0x24 || type == 0x26 ) {
        text += " SD";
    }
    return text;
}

/// An option as an entry lists it: its endpoint, or the name of its type.
/// @p option holds its bytes after Length and Type.
std::string optionText( uint8_t type, FieldReader option )
{
    switch ( type ) {
    case 0x01:
        return "Configuration";
    case 0x02:
        return "Load Balancing";
    case 0x04:
    case 0x06:
    case 0x14:
    case 0x16:
    case 0x24:
    case 0x26: {
        auto text = endpointText( type, option );
        return text.empty() ? "[Malformed option]" : text;
    }
    default:
        return "Option " + hexCode( type );
    }
}

/// "v1.0", the major version and, unless it is any, the minor; empty if
/// the major version is any (0xFF).
std::string versionText( uint8_t major, std::optional<uint32_t> minor )
{
    if ( major == 0xFF ) {
        return {};
    }
    auto text = " v" + std::to_string( major );
    if ( minor && *minor != 0xFFFFFFFF ) {
        text += "." + std::to_string( *minor );
    }
    return text;
}

/// An SD entry, "Offer Service 0x1234 Instance 0x0001 v1.0 TTL=3
/// (192.0.2.10:30501 UDP)", its options looked up in @p options.
std::string entryText( FieldReader entry, const std::vector<std::string>& options,
                       bool optionsRead )
{
    uint8_t type = 0;
    uint8_t index1 = 0;
    uint8_t index2 = 0;
    uint8_t counts = 0;
    uint16_t service = 0;
    uint16_t instance = 0;
    uint8_t major = 0;
    uint32_t ttl = 0;
    uint32_t last = 0;
    entry.u8( type );
    entry.u8( index1 );
    entry.u8( index2 );
    entry.u8( counts );
    entry.u16( service );
    entry.u16( instance );
    entry.u8( major );
    entry.u24( ttl );
    entry.u32( last );

    std::string text;
    const bool eventgroupEntry = type == 0x06 || type == 0x07;
    switch ( type ) {
    case 0x00:
        text = "Find Service";
        break;
    case 0x01:
        text = ttl == 0 ? "Stop Offer Service" : "Offer Service";
        break;
    case 0x06:
        text = ttl == 0 ? "Stop Subscribe Eventgroup" : "Subscribe Eventgroup";
        break;
    case 0x07:
        text = ttl == 0 ? "Subscribe Eventgroup Nack" : "Subscribe Eventgroup Ack";
        break;
    default:
        return "Entry " + hexCode( type );
    }
    text += " " + serviceText( service );
    if ( instance != 0xFFFF ) {
        text += " Instance " + id16( instance );
    }
    if ( eventgroupEntry ) {
        text += " " + eventgroupText( service, static_cast<uint16_t>( last & 0xFFFF ) );
        text += versionText( major, std::nullopt );
    }
    else {
        text += versionText( major, last );
    }
    if ( type != 0x00 && ttl != 0 ) {
        text += " TTL=" + std::to_string( ttl );
    }

    // The two runs of options the entry refers to.
    std::vector<std::string> referred;
    bool outOfRange = false;
    for ( const auto& [ index, count ] : { std::pair<size_t, size_t>{ index1, counts >> 4 },
                                           std::pair<size_t, size_t>{ index2, counts & 0x0F } } ) {
        for ( size_t i = index; i < index + count; ++i ) {
            if ( i < options.size() ) {
                referred.push_back( options[ i ] );
            }
            else {
                outOfRange = optionsRead;
            }
        }
    }
    if ( !referred.empty() ) {
        text += " (" + joinNames( std::move( referred ), kMaxSdOptionsNamed ) + ")";
    }
    if ( outOfRange ) {
        text += " [Malformed Packet]";
    }
    return text;
}

/// The entries of an SD message's payload, @p sd, with their options:
/// "Find Service 0x1234, Offer Service 0x5678 …".
std::string sdText( FieldReader sd )
{
    uint8_t flags = 0;
    uint32_t entriesLength = 0;
    if ( !sd.u8( flags ) || !sd.skip( 3 ) || !sd.u32( entriesLength ) ) {
        return sd.complete() ? "[Malformed Packet]" : kEllipsis;
    }
    if ( entriesLength % kSdEntryBytes != 0
         || ( sd.complete() && entriesLength > sd.remaining() ) ) {
        return "[Malformed Packet]";
    }
    auto entries = sd.take( entriesLength );
    const bool entriesWhole = entries.complete();

    // The options, read before the entries refer to them.
    std::vector<std::string> options;
    bool optionsRead = false;
    bool malformed = false;
    uint32_t optionsLength = 0;
    if ( entriesWhole && sd.u32( optionsLength ) ) {
        if ( optionsLength > sd.remaining() && sd.complete() ) {
            malformed = true;
        }
        auto array = sd.take( optionsLength );
        while ( array.remaining() > 0 && options.size() < kMaxSdOptions ) {
            uint16_t length = 0;
            uint8_t type = 0;
            if ( !array.u16( length ) || !array.u8( type ) || length == 0 ) {
                malformed = malformed || array.complete();
                break;
            }
            auto option = array.take( length );
            if ( !option.complete() ) {
                malformed = malformed || array.complete();
                break;
            }
            options.push_back( optionText( type, option ) );
        }
        optionsRead = array.readToEnd() && !malformed;
        malformed = malformed || ( sd.complete() && sd.remaining() > 0 );
    }

    std::vector<std::string> names;
    bool more = false;
    size_t count = 0;
    while ( entries.remaining() >= kSdEntryBytes ) {
        if ( ++count > kMaxSdEntries ) {
            more = true;
            break;
        }
        names.push_back( entryText( entries.take( kSdEntryBytes ), options, optionsRead ) );
    }
    auto text = names.empty() ? std::string( "No entries" )
                              : joinNames( std::move( names ), kMaxSdEntriesNamed, more );
    if ( !entriesWhole || ( !sd.complete() && !optionsRead ) ) {
        markCut( text );
    }
    else if ( malformed ) {
        text += " [Malformed Packet]";
    }
    return text;
}

// ── The messages of a datagram or segment ────────────────────────────────

/// One message, as far as it was read.
struct Message {
    std::string text;
    bool sd = false;
    bool valid = false; ///< Whole and plausible: what a heuristic accepts
    bool last = false;  ///< No message can follow it in these bytes
    size_t length = 0;  ///< The bytes it takes, header and all
};

/// The message at @p p, of which @p len bytes were captured.
Message readMessage( const uint8_t* p, size_t len )
{
    Message m;
    if ( len < kUncountedBytes ) {
        m.text = "[Malformed Packet]";
        m.last = true;
        return m;
    }
    const auto length = readBE32( p + 4 );
    const uint16_t service = readBE16( p );
    const uint16_t method = readBE16( p + 2 );
    m.length = kUncountedBytes + static_cast<size_t>( length );
    m.sd = service == kSdService && method == kSdMethod;
    if ( len < kHeaderBytes ) {
        // The header itself is cut: what it begins with.
        m.text = "Service " + serviceText( service ) + " " + methodText( service, method );
        m.text += length < kHeaderBytes - kUncountedBytes ? " [Malformed Packet]" : " " + kEllipsis;
        m.last = true;
        return m;
    }
    const auto h = readHeader( p );
    if ( isMagicCookie( h ) ) {
        m.text = "Magic Cookie";
        m.valid = len >= m.length;
        m.last = !m.valid;
        return m;
    }
    m.text = "Service " + serviceText( h.service ) + " " + methodText( h.service, h.method )
             + " Client " + id16( h.client ) + " Session " + id16( h.session );
    const char* typeName = messageTypeName( h.type );
    m.text += typeName ? std::string( " " ) + typeName : " Message Type " + hexCode( h.type );
    if ( ( h.type & 0x81 ) == 0x81 || h.returnCode != 0 ) { // an error says its code
        m.text += " (" + returnCodeName( h.returnCode ) + ")";
    }
    if ( h.protocolVersion != kProtocolVersion || !typeName
         || h.length < kHeaderBytes - kUncountedBytes ) {
        if ( h.protocolVersion != kProtocolVersion ) {
            m.text += " Protocol Version " + std::to_string( h.protocolVersion );
        }
        m.text += " [Malformed Packet]";
        m.last = true;
        return m;
    }

    const bool whole = len >= m.length;
    FieldReader body( p + kHeaderBytes, std::min( len, m.length ) - kHeaderBytes, whole );
    size_t payloadBytes = m.length - kHeaderBytes;
    if ( h.type & kTpFlag ) {
        uint32_t tp = 0;
        if ( body.u32( tp ) ) {
            payloadBytes -= kTpHeaderBytes;
            m.text += " Offset=" + std::to_string( static_cast<uint64_t>( tp & 0xFFFFFFF0u ) );
            if ( tp & 0x01 ) {
                m.text += " More";
            }
        }
    }
    if ( m.sd && !( h.type & kTpFlag ) ) {
        m.text = sdText( body );
    }
    else {
        m.text
            += ", " + std::to_string( payloadBytes ) + " byte" + ( payloadBytes == 1 ? "" : "s" );
        if ( !whole ) {
            m.text += " " + kEllipsis;
        }
    }
    m.valid = whole && plausible( h ) && h.length <= kMaxHeuristicLength
              && m.text.find( "[Malformed" ) == std::string::npos;
    m.last = !whole;
    return m;
}

} // namespace

SomeIpDescription detectSomeIp( const uint8_t* payload, size_t len, bool heuristic )
{
    SomeIpDescription result;
    if ( len == 0 ) {
        return result;
    }
    if ( heuristic ) {
        // Every message, named or not, whole and by the rules.
        for ( size_t at = 0; at < len; ) {
            const auto message = readMessage( payload + at, len - at );
            if ( !message.valid ) {
                return {};
            }
            if ( message.last ) {
                break;
            }
            at += message.length;
        }
    }
    result.text = nameMessages( len, kMaxMessages, "; ", [ & ]( size_t at ) {
        auto message = readMessage( payload + at, len - at );
        if ( at == 0 ) {
            result.sd = message.sd;
        }
        return NamedMessage{ std::move( message.text ), message.length, message.last };
    } );
    return result;
}

bool onSomeIpPort( uint16_t srcPort, uint16_t dstPort )
{
    auto is = [ & ]( uint16_t port ) { return srcPort == port || dstPort == port; };
    if ( is( kSomeIpSdPort ) ) {
        return true;
    }
    if ( tSomeIpConfig ) {
        for ( const auto port : tSomeIpConfig->ports ) {
            if ( is( port ) ) {
                return true;
            }
        }
    }
    return false;
}

std::optional<size_t> frameSomeIpMessage( const uint8_t* payload, size_t len, bool onPort )
{
    if ( onPort && len < kUncountedBytes ) {
        return len + 1;
    }
    if ( len < ( onPort ? kUncountedBytes : kHeaderBytes ) ) {
        return std::nullopt;
    }
    const auto length = readBE32( payload + 4 );
    if ( length < kHeaderBytes - kUncountedBytes ) {
        return std::nullopt; // no message: described as it is
    }
    if ( len >= kHeaderBytes ) {
        const auto h = readHeader( payload );
        if ( !isMagicCookie( h )
             && ( h.protocolVersion != kProtocolVersion
                  || ( !onPort && ( !plausible( h ) || length > kMaxHeuristicLength ) ) ) ) {
            return std::nullopt;
        }
    }
    return kUncountedBytes + static_cast<size_t>( length );
}

} // namespace tcpdump::describer
