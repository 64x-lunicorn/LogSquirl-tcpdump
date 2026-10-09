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
 * @file describe_mqtt.cpp
 * @brief The MQTT detector of the Payload Describer: MQTT 3.1, 3.1.1 and
 *        5.0 control packets, every one in a segment, and the packets of a
 *        connection that began with a CONNECT on another port.
 */

#include "describe_common.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace tcpdump::describer {

// ── MQTT ─────────────────────────────────────────────────────────────────

namespace {

/// Most packets named in one segment, and topic filters in one SUBSCRIBE
/// or UNSUBSCRIBE.
constexpr size_t kMaxMqttPackets = 4;
constexpr size_t kMaxMqttTopicFilters = 4;

/// Most bytes of a PUBLISH payload shown.
constexpr size_t kMaxMqttPayloadBytes = 32;

/// Most bytes of a Remaining Length or another variable byte integer.
constexpr size_t kMaxMqttVarintBytes = 4;

/// How a read went: the field is there, it lies beyond the captured bytes
/// (the packet goes on in a later segment, or was cut at the snaplen), or
/// it does not fit in the length its packet declares.
enum class Read { Ok, Cut, Malformed };

/**
 * The fields of an MQTT packet, or of a part of one: the length it
 * declares, and as many of its bytes as were captured.  A read beyond the
 * declared length is malformed; one within it but beyond the captured
 * bytes is cut.  The bytes are read by a FieldReader, never beyond them.
 */
class Fields {
public:
    Fields( FieldReader bytes, size_t declared )
        : bytes_( bytes )
        , declared_( declared )
    {
    }

    Read u8( uint8_t& value )
    {
        const auto status = need( 1 );
        if ( status == Read::Ok ) {
            bytes_.u8( value );
        }
        return status;
    }

    Read u16( uint16_t& value )
    {
        const auto status = need( 2 );
        if ( status == Read::Ok ) {
            bytes_.u16( value );
        }
        return status;
    }

    Read skip( size_t n )
    {
        const auto status = need( n );
        if ( status == Read::Ok ) {
            bytes_.skip( n );
        }
        return status;
    }

    /// The next @p n declared bytes as fields of their own, as many of them
    /// as were captured.
    Read take( size_t n, Fields& part )
    {
        if ( declared_ < n ) {
            return Read::Malformed;
        }
        part = Fields( bytes_.take( n ), n );
        declared_ -= n;
        return Read::Ok;
    }

    /// A variable byte integer (MQTT 5.0, 1.5.5): 7 bits a byte, least
    /// significant first, at most 4 bytes, in as few as hold its value.
    Read varint( uint32_t& value )
    {
        value = 0;
        for ( size_t i = 0; i < kMaxMqttVarintBytes; ++i ) {
            uint8_t byte = 0;
            if ( const auto status = u8( byte ); status != Read::Ok ) {
                return status;
            }
            value |= static_cast<uint32_t>( byte & 0x7F ) << ( 7 * i );
            if ( ( byte & 0x80 ) == 0 ) {
                return i > 0 && byte == 0 ? Read::Malformed : Read::Ok;
            }
        }
        return Read::Malformed;
    }

    /// A UTF-8 string or binary data behind its 16-bit length (1.5.4,
    /// 1.5.6): cut unless all of it was captured.
    Read string( Fields& value )
    {
        uint16_t n = 0;
        auto status = u16( n );
        if ( status == Read::Ok ) {
            status = take( n, value );
        }
        if ( status == Read::Ok && value.cut() ) {
            status = Read::Cut;
        }
        return status;
    }

    /// All declared bytes are read: those left over make the packet malformed.
    Read atEnd() const
    {
        return declared_ == 0 ? Read::Ok : Read::Malformed;
    }

    /// Fewer bytes were captured than declared.
    bool cut() const
    {
        return bytes_.remaining() < declared_;
    }

    /// The declared bytes not read yet, and the captured ones.
    size_t declared() const
    {
        return declared_;
    }
    size_t captured() const
    {
        return bytes_.remaining();
    }
    const uint8_t* here() const
    {
        return bytes_.here();
    }

private:
    Read need( size_t n )
    {
        if ( declared_ < n ) {
            return Read::Malformed;
        }
        if ( bytes_.remaining() < n ) {
            return Read::Cut;
        }
        declared_ -= n;
        return Read::Ok;
    }

    FieldReader bytes_;
    size_t declared_;
};

/// What the packets of one segment tell about the ones behind them: the
/// protocol level a CONNECT named, 0 while none has.  MQTT 5.0 adds
/// properties to most packets; without a CONNECT before them, a packet
/// whose shape allows both is read with them if they parse.
struct Session {
    uint8_t level = 0;
};

/// The control packet types (MQTT 5.0, 2.1.2), as Wireshark names them.
const char* const kMqttPacketNames[ 16 ] = {
    nullptr,
    "Connect Command",
    "Connect Ack",
    "Publish Message",
    "Publish Ack",
    "Publish Received",
    "Publish Release",
    "Publish Complete",
    "Subscribe Request",
    "Subscribe Ack",
    "Unsubscribe Request",
    "Unsubscribe Ack",
    "Ping Request",
    "Ping Response",
    "Disconnect Req",
    "Authentication Exchange",
};

/// The flags a packet of @p type may have in its fixed header (2.1.3).
bool validFlags( unsigned type, unsigned flags )
{
    switch ( type ) {
    case 3: // PUBLISH: DUP, QoS and RETAIN, QoS 3 aside
        return ( flags & 0x06 ) != 0x06;
    case 6:  // PUBREL
    case 8:  // SUBSCRIBE
    case 10: // UNSUBSCRIBE
        return flags == 0x2;
    default:
        return flags == 0;
    }
}

/// An MQTT 5.0 reason code, as the specification names it (2.4); 0x00 is
/// named by the caller, as it means something else to each packet.
std::string mqttReason( uint8_t code )
{
    switch ( code ) {
    case 0x04:
        return "Disconnect with Will Message";
    case 0x10:
        return "No matching subscribers";
    case 0x11:
        return "No subscription existed";
    case 0x18:
        return "Continue authentication";
    case 0x19:
        return "Re-authenticate";
    case 0x80:
        return "Unspecified error";
    case 0x81:
        return "Malformed Packet";
    case 0x82:
        return "Protocol Error";
    case 0x83:
        return "Implementation specific error";
    case 0x84:
        return "Unsupported Protocol Version";
    case 0x85:
        return "Client Identifier not valid";
    case 0x86:
        return "Bad User Name or Password";
    case 0x87:
        return "Not authorized";
    case 0x88:
        return "Server unavailable";
    case 0x89:
        return "Server busy";
    case 0x8A:
        return "Banned";
    case 0x8B:
        return "Server shutting down";
    case 0x8C:
        return "Bad authentication method";
    case 0x8D:
        return "Keep Alive timeout";
    case 0x8E:
        return "Session taken over";
    case 0x8F:
        return "Topic Filter invalid";
    case 0x90:
        return "Topic Name invalid";
    case 0x91:
        return "Packet Identifier in use";
    case 0x92:
        return "Packet Identifier not found";
    case 0x93:
        return "Receive Maximum exceeded";
    case 0x94:
        return "Topic Alias invalid";
    case 0x95:
        return "Packet too large";
    case 0x96:
        return "Message rate too high";
    case 0x97:
        return "Quota exceeded";
    case 0x98:
        return "Administrative action";
    case 0x99:
        return "Payload format invalid";
    case 0x9A:
        return "Retain not supported";
    case 0x9B:
        return "QoS not supported";
    case 0x9C:
        return "Use another server";
    case 0x9D:
        return "Server moved";
    case 0x9E:
        return "Shared Subscriptions not supported";
    case 0x9F:
        return "Connection rate exceeded";
    case 0xA0:
        return "Maximum connect time";
    case 0xA1:
        return "Subscription Identifiers not supported";
    case 0xA2:
        return "Wildcard Subscriptions not supported";
    default:
        return "Unknown (" + hexCode( code ) + ")";
    }
}

/// An MQTT 3.1 / 3.1.1 CONNACK return code (3.1.1, 3.2.2.3).
std::string mqtt3ReturnCode( uint8_t code )
{
    static const char* const kNames[] = {
        "Connection Accepted", "Unacceptable Protocol Version", "Identifier Rejected",
        "Server Unavailable",  "Bad User Name or Password",     "Not Authorized",
    };
    if ( code < sizeof( kNames ) / sizeof( kNames[ 0 ] ) ) {
        return kNames[ code ];
    }
    return "Unknown (" + hexCode( code ) + ")";
}

/// @p value's bytes as quoted text, at most kMaxFieldBytes of them, then
/// an ellipsis, as for a value cut by the capture.
std::string quotedField( const Fields& value )
{
    const size_t shown = std::min( value.captured(), kMaxFieldBytes );
    return quotedBytes( value.here(), shown ) + ( shown < value.declared() ? "\xe2\x80\xa6" : "" );
}

/// A topic name or filter: no control characters, as a topic should hold
/// none (MQTT 5.0, 4.7.3), and no wildcard in a name.
bool validTopic( const Fields& topic, bool filter )
{
    const auto* p = topic.here();
    for ( size_t i = 0; i < topic.captured(); ++i ) {
        if ( p[ i ] < 0x20 || p[ i ] == 0x7F
             || ( !filter && ( p[ i ] == '+' || p[ i ] == '#' ) ) ) {
            return false;
        }
    }
    return true;
}

/**
 * Skip MQTT 5.0 properties behind their length (2.2.2), each by the size
 * its identifier gives it; keep the Reason String in @p reason, if asked
 * for.  An unknown identifier makes them malformed.
 */
Read skipProperties( Fields& fields, std::string* reason )
{
    uint32_t length = 0;
    Fields props( FieldReader( nullptr, 0 ), 0 );
    auto status = fields.varint( length );
    if ( status == Read::Ok ) {
        status = fields.take( length, props );
    }
    while ( status == Read::Ok && props.declared() > 0 ) {
        uint32_t id = 0;
        Fields value( FieldReader( nullptr, 0 ), 0 );
        status = props.varint( id );
        if ( status != Read::Ok ) {
            break;
        }
        switch ( id ) {
        case 0x01: // Payload Format Indicator
        case 0x17: // Request Problem Information
        case 0x19: // Request Response Information
        case 0x24: // Maximum QoS
        case 0x25: // Retain Available
        case 0x28: // Wildcard Subscription Available
        case 0x29: // Subscription Identifier Available
        case 0x2A: // Shared Subscription Available
            status = props.skip( 1 );
            break;
        case 0x13: // Server Keep Alive
        case 0x21: // Receive Maximum
        case 0x22: // Topic Alias Maximum
        case 0x23: // Topic Alias
            status = props.skip( 2 );
            break;
        case 0x02: // Message Expiry Interval
        case 0x11: // Session Expiry Interval
        case 0x18: // Will Delay Interval
        case 0x27: // Maximum Packet Size
            status = props.skip( 4 );
            break;
        case 0x0B: // Subscription Identifier
            status = props.varint( id );
            break;
        case 0x26: // User Property: a pair of strings
            status = props.string( value );
            if ( status == Read::Ok ) {
                status = props.string( value );
            }
            break;
        case 0x03: // Content Type
        case 0x08: // Response Topic
        case 0x09: // Correlation Data
        case 0x12: // Assigned Client Identifier
        case 0x15: // Authentication Method
        case 0x16: // Authentication Data
        case 0x1A: // Response Information
        case 0x1C: // Server Reference
            status = props.string( value );
            break;
        case 0x1F: // Reason String
            status = props.string( value );
            if ( status == Read::Ok && reason != nullptr ) {
                *reason = quotedField( value );
            }
            break;
        default:
            return Read::Malformed;
        }
    }
    return status;
}

/// What a packet says, besides its name: details in parentheses behind
/// it, "(id=3, QoS 1)", and a tail behind them, " [topic] \"payload\"".
struct Packet {
    std::vector<std::string> details;
    std::string tail;
};

/// The protocol version a CONNECT's protocol name and level give, or null.
const char* mqttVersion( const Fields& name, uint8_t level )
{
    auto is = [ &name ]( const char* text ) {
        const auto n = std::strlen( text );
        return name.captured() == n && std::memcmp( name.here(), text, n ) == 0;
    };
    if ( level == 3 && is( "MQIsdp" ) ) {
        return "3.1";
    }
    if ( level == 4 && is( "MQTT" ) ) {
        return "3.1.1";
    }
    if ( level == 5 && is( "MQTT" ) ) {
        return "5.0";
    }
    return nullptr;
}

/// CONNECT (3.1): "(MQTT 3.1.1, Keep Alive 60, Clean Session, Client ID
/// \"sensor-1\", User \"bob\")".  The will and the password are skipped.
Read connect( Fields& body, Session& session, Packet& packet )
{
    Fields field( FieldReader( nullptr, 0 ), 0 );
    uint8_t level = 0;
    uint8_t flags = 0;
    uint16_t keepAlive = 0;
    auto status = body.string( field );
    if ( status == Read::Ok ) {
        status = body.u8( level );
    }
    if ( status != Read::Ok ) {
        return status;
    }
    const char* version = mqttVersion( field, level );
    if ( version == nullptr ) {
        return Read::Malformed;
    }
    session.level = level;
    packet.details.push_back( std::string( "MQTT " ) + version );

    if ( ( status = body.u8( flags ) ) != Read::Ok ) {
        return status;
    }
    const bool will = ( flags & 0x04 ) != 0;
    const unsigned willQos = ( flags >> 3 ) & 0x03;
    if ( ( flags & 0x01 ) != 0 || willQos == 3 || ( !will && ( flags & 0x38 ) != 0 )
         || ( level < 5 && ( flags & 0xC0 ) == 0x40 ) ) {
        return Read::Malformed; // reserved bit, will QoS, password without user (3.1.1)
    }
    if ( ( status = body.u16( keepAlive ) ) != Read::Ok ) {
        return status;
    }
    packet.details.push_back( "Keep Alive " + std::to_string( keepAlive ) );
    if ( flags & 0x02 ) {
        packet.details.emplace_back( level == 5 ? "Clean Start" : "Clean Session" );
    }
    if ( level == 5 && ( status = skipProperties( body, nullptr ) ) != Read::Ok ) {
        return status;
    }
    if ( ( status = body.string( field ) ) != Read::Ok ) {
        return status;
    }
    packet.details.push_back( "Client ID " + quotedField( field ) );
    if ( will ) {
        if ( level == 5 && ( status = skipProperties( body, nullptr ) ) != Read::Ok ) {
            return status;
        }
        if ( ( status = body.string( field ) ) != Read::Ok
             || ( status = body.string( field ) ) != Read::Ok ) {
            return status;
        }
    }
    if ( flags & 0x80 ) {
        if ( ( status = body.string( field ) ) != Read::Ok ) {
            return status;
        }
        packet.details.push_back( "User " + quotedField( field ) );
    }
    if ( flags & 0x40 && ( status = body.string( field ) ) != Read::Ok ) {
        return status;
    }
    return body.atEnd();
}

/// The packet is an MQTT 5.0 one: its CONNECT said so, or, without one,
/// it is longer than an MQTT 3.1.1 packet of its type can be.
bool isMqtt5( const Session& session, size_t length, size_t mqtt3Length )
{
    return session.level == 5 || ( session.level == 0 && length > mqtt3Length );
}

/// A reason code other than success, and the reason string behind it.
void addReason( Packet& packet, uint8_t code, const std::string& reason )
{
    if ( code != 0x00 ) {
        packet.details.push_back( mqttReason( code ) );
    }
    if ( !reason.empty() ) {
        packet.details.push_back( reason );
    }
}

/// CONNACK (3.2): "(Connection Accepted)", "(Not authorized, \"…\")".
Read connectAck( Fields& body, const Session& session, Packet& packet )
{
    const bool v5 = isMqtt5( session, body.declared(), 2 );
    uint8_t ackFlags = 0;
    uint8_t code = 0;
    auto status = body.u8( ackFlags );
    if ( status == Read::Ok && ( ackFlags & 0xFE ) != 0 ) {
        return Read::Malformed;
    }
    if ( status == Read::Ok ) {
        status = body.u8( code );
    }
    if ( status != Read::Ok ) {
        return status;
    }
    if ( !v5 ) {
        packet.details.push_back( mqtt3ReturnCode( code ) );
    }
    else {
        packet.details.push_back( code == 0 ? "Success" : mqttReason( code ) );
        std::string reason;
        if ( ( status = skipProperties( body, &reason ) ) != Read::Ok ) {
            return status;
        }
        if ( !reason.empty() ) {
            packet.details.push_back( reason );
        }
    }
    if ( ackFlags & 0x01 ) {
        packet.details.emplace_back( "Session Present" );
    }
    return body.atEnd();
}

/// PUBLISH (3.3): "(QoS 1, id=3, Retain) [sensors/temp] \"21.5\"", the
/// payload cut at kMaxMqttPayloadBytes.  MQTT 5.0 properties are skipped:
/// without a CONNECT to tell, the bytes behind the topic and id are taken
/// for properties if they parse as those a PUBLISH may carry.
Read publish( Fields& body, unsigned flags, Session& session, Packet& packet )
{
    const unsigned qos = ( flags >> 1 ) & 0x03;
    if ( qos > 0 ) {
        packet.details.push_back( "QoS " + std::to_string( qos ) );
    }
    if ( flags & 0x08 ) {
        packet.details.emplace_back( "DUP" );
    }
    if ( flags & 0x01 ) {
        packet.details.emplace_back( "Retain" );
    }

    Fields topic( FieldReader( nullptr, 0 ), 0 );
    auto status = body.string( topic );
    if ( status != Read::Ok ) {
        return status == Read::Cut && !validTopic( topic, false ) ? Read::Malformed : status;
    }
    if ( !validTopic( topic, false ) ) {
        return Read::Malformed;
    }
    packet.tail = " [" + fieldText( topic.here(), topic.captured() ) + "]";
    if ( qos > 0 ) {
        uint16_t id = 0;
        if ( ( status = body.u16( id ) ) != Read::Ok ) {
            return status;
        }
        if ( id == 0 ) {
            return Read::Malformed;
        }
        packet.details.insert( packet.details.begin() + 1, "id=" + std::to_string( id ) );
    }

    if ( session.level == 5 ) {
        if ( ( status = skipProperties( body, nullptr ) ) != Read::Ok ) {
            return status;
        }
    }
    else if ( session.level == 0 ) {
        auto withProperties = body;
        if ( skipProperties( withProperties, nullptr ) == Read::Ok ) {
            body = withProperties;
        }
    }

    const size_t shown = std::min( body.captured(), kMaxMqttPayloadBytes );
    if ( shown > 0 ) {
        packet.tail += " " + quotedBytes( body.here(), shown );
    }
    if ( shown < body.declared() ) {
        packet.tail += shown > 0 ? "\xe2\x80\xa6" : " \xe2\x80\xa6";
    }
    return Read::Ok;
}

/// PUBACK, PUBREC, PUBREL, PUBCOMP (3.4 to 3.7) and UNSUBACK (3.11):
/// "(id=3)", with an MQTT 5.0 reason code other than success and its
/// reason string, "(id=3, No matching subscribers)".  An UNSUBACK's reason
/// codes, one per topic filter, are not listed.
Read acknowledgement( Fields& body, unsigned type, const Session& session, Packet& packet )
{
    const bool v5 = isMqtt5( session, body.declared(), 2 );
    uint16_t id = 0;
    auto status = body.u16( id );
    if ( status != Read::Ok ) {
        return status;
    }
    packet.details.push_back( "id=" + std::to_string( id ) );
    if ( !v5 ) {
        return body.atEnd();
    }
    if ( type == 11 ) {
        std::string reason;
        if ( ( status = skipProperties( body, &reason ) ) != Read::Ok ) {
            return status;
        }
        addReason( packet, 0, reason );
        return body.declared() > 0 ? Read::Ok : Read::Malformed; // a reason code per filter
    }
    uint8_t code = 0;
    std::string reason;
    if ( body.declared() > 0 && ( status = body.u8( code ) ) != Read::Ok ) {
        return status;
    }
    if ( body.declared() > 0 && ( status = skipProperties( body, &reason ) ) != Read::Ok ) {
        return status;
    }
    addReason( packet, code, reason );
    return body.atEnd();
}

/**
 * The topic filters of a SUBSCRIBE (with an options byte each) or an
 * UNSUBSCRIBE, MQTT 5.0 properties first if @p v5: at least one, none
 * empty, up to kMaxMqttTopicFilters of them in @p names.
 */
Read topicFilters( Fields body, bool options, bool v5, std::vector<std::string>& names, bool& more )
{
    names.clear();
    more = false;
    Read status = v5 ? skipProperties( body, nullptr ) : Read::Ok;
    size_t count = 0;
    while ( status == Read::Ok && body.declared() > 0 ) {
        Fields filter( FieldReader( nullptr, 0 ), 0 );
        status = body.string( filter );
        if ( status == Read::Malformed || ( filter.declared() == 0 && status == Read::Ok )
             || !validTopic( filter, true ) ) {
            return Read::Malformed;
        }
        if ( status == Read::Cut ) {
            break;
        }
        uint8_t option = 0;
        if ( options && ( status = body.u8( option ) ) == Read::Ok ) {
            // QoS 3 and reserved bits; MQTT 5.0 adds No Local, Retain As
            // Published and Retain Handling below the reserved two.
            const bool valid = ( option & 0x03 ) != 3
                               && ( v5 ? ( option & 0xC0 ) == 0 && ( option & 0x30 ) != 0x30
                                       : ( option & 0xFC ) == 0 );
            if ( !valid ) {
                return Read::Malformed;
            }
        }
        if ( count++ < kMaxMqttTopicFilters ) {
            names.push_back( fieldText( filter.here(), filter.captured() ) );
        }
        else {
            more = true;
        }
    }
    if ( status == Read::Ok && count == 0 ) {
        return Read::Malformed;
    }
    return status;
}

/// SUBSCRIBE (3.8) and UNSUBSCRIBE (3.10): "(id=1) [sensors/+/temp,
/// alerts/#]".  Without a CONNECT to tell, the filters are read as MQTT
/// 3.1.1's, then, if they do not parse so, behind MQTT 5.0 properties.
Read subscription( Fields& body, unsigned type, const Session& session, Packet& packet )
{
    uint16_t id = 0;
    auto status = body.u16( id );
    if ( status != Read::Ok ) {
        return status;
    }
    if ( id == 0 ) {
        return Read::Malformed;
    }
    packet.details.push_back( "id=" + std::to_string( id ) );

    const bool options = type == 8;
    std::vector<std::string> names;
    bool more = false;
    status = topicFilters( body, options, session.level == 5, names, more );
    if ( status == Read::Malformed && session.level == 0 ) {
        status = topicFilters( body, options, true, names, more );
    }
    if ( status != Read::Malformed && ( !names.empty() || more ) ) {
        packet.tail = " [" + joinNames( names, kMaxMqttTopicFilters, more ) + "]";
    }
    return status;
}

/// SUBACK (3.9): "(id=1)".  Its return codes are not listed: without a
/// CONNECT before it, an MQTT 5.0 one cannot be told from an MQTT 3.1.1
/// one.
Read subscribeAck( Fields& body, Packet& packet )
{
    uint16_t id = 0;
    auto status = body.u16( id );
    if ( status != Read::Ok ) {
        return status;
    }
    packet.details.push_back( "id=" + std::to_string( id ) );
    return body.declared() > 0 ? Read::Ok : Read::Malformed; // a return code per filter
}

/// DISCONNECT (3.14) and AUTH (3.15): without a body, success; MQTT 5.0
/// adds a reason code and properties, "(Server shutting down)".
Read reasonOnly( Fields& body, unsigned type, Packet& packet )
{
    if ( body.declared() == 0 ) {
        return Read::Ok;
    }
    uint8_t code = 0;
    std::string reason;
    auto status = body.u8( code );
    if ( status == Read::Ok && body.declared() > 0 ) {
        status = skipProperties( body, &reason );
    }
    if ( status != Read::Ok ) {
        return status;
    }
    if ( type == 15 ) {
        packet.details.push_back( code == 0 ? "Success" : mqttReason( code ) );
        addReason( packet, 0, reason );
    }
    else {
        addReason( packet, code, reason );
    }
    return body.atEnd();
}

/// The body of a packet of @p type, described into @p packet.
Read describeBody( unsigned type, unsigned flags, Fields& body, Session& session, Packet& packet )
{
    switch ( type ) {
    case 1:
        return connect( body, session, packet );
    case 2:
        return connectAck( body, session, packet );
    case 3:
        return publish( body, flags, session, packet );
    case 4:
    case 5:
    case 6:
    case 7:
    case 11:
        return acknowledgement( body, type, session, packet );
    case 8:
    case 10:
        return subscription( body, type, session, packet );
    case 9:
        return subscribeAck( body, packet );
    case 12:
    case 13:
        return body.atEnd();
    default: // 14, 15
        if ( session.level != 0 && session.level < 5 ) {
            return type == 14 ? body.atEnd() : Read::Malformed; // AUTH is MQTT 5.0's
        }
        return reasonOnly( body, type, packet );
    }
}

/// A packet as text: its name, its details in parentheses, its tail, and
/// " …" if it goes on beyond the captured bytes.
std::string packetText( const char* name, const Packet& packet, bool cut )
{
    std::string text = name;
    if ( !packet.details.empty() ) {
        text += " (" + joinNames( packet.details, packet.details.size() ) + ")";
    }
    text += packet.tail;
    static const std::string kEllipsis = "\xe2\x80\xa6";
    if ( cut
         && ( text.size() < kEllipsis.size()
              || text.compare( text.size() - kEllipsis.size(), kEllipsis.size(), kEllipsis )
                     != 0 ) ) {
        text += " " + kEllipsis;
    }
    return text;
}

/// The MQTT packets at @p p, the @p len captured bytes of a @p wireLen-byte
/// TCP payload: "Publish Message [a], Publish Message [b]", up to
/// kMaxMqttPackets, then "…".  A packet that goes on beyond the captured
/// bytes, in the next segment, is described as far as it goes and ends
/// in " …"; one whose fields break the rules of its type, or do not fit
/// in its length, is "<name> [Malformed Packet]".  Empty if the first
/// packet is not one: the segment begins inside a packet, or holds none.
/// The first packet counts as malformed only if it ends exactly where the
/// payload does, which the middle of a packet hardly does.
std::string describeMqttPackets( const uint8_t* p, size_t len, size_t wireLen )
{
    // A packet may go on in the next segment: the segment declares no
    // length of its own.
    Fields segment( FieldReader( p, len ), SIZE_MAX );
    Session session;
    std::vector<std::string> names;
    bool more = len < wireLen;
    while ( segment.captured() > 0 ) {
        uint8_t first = 0;
        uint32_t length = 0;
        if ( names.size() == kMaxMqttPackets ) {
            more = true;
            break;
        }
        segment.u8( first );
        const unsigned type = first >> 4;
        const unsigned flags = first & 0x0F;
        if ( type == 0 || !validFlags( type, flags ) ) {
            if ( names.empty() ) {
                return {};
            }
            names.emplace_back( "[Malformed Packet]" );
            more = false;
            break;
        }
        const char* name = kMqttPacketNames[ type ];
        Fields body( FieldReader( nullptr, 0 ), 0 );
        auto status = segment.varint( length );
        if ( status == Read::Ok ) {
            status = segment.take( length, body );
        }
        if ( status != Read::Ok ) {
            // The fixed header is cut, or its length does not fit.
            if ( names.empty() ) {
                return {};
            }
            names.push_back( status == Read::Cut ? std::string( name ) + " \xe2\x80\xa6"
                                                 : std::string( "[Malformed Packet]" ) );
            more = false;
            break;
        }
        Packet packet;
        status = describeBody( type, flags, body, session, packet );
        if ( status == Read::Malformed ) {
            if ( names.empty() && ( body.cut() || segment.captured() > 0 || len < wireLen ) ) {
                return {};
            }
            names.push_back( std::string( name ) + " [Malformed Packet]" );
            continue;
        }
        names.push_back( packetText( name, packet, status == Read::Cut || body.cut() ) );
        if ( status == Read::Cut || body.cut() ) {
            more = false; // said by the packet's own ellipsis
            break;
        }
    }
    return joinNames( std::move( names ), kMaxMqttPackets, more );
}

} // namespace

/// The payload begins with a CONNECT: its fixed header, the protocol name
/// and level of one of the MQTT versions.
bool isMqttConnect( const uint8_t* payload, size_t len )
{
    Fields packet( FieldReader( payload, len ), len );
    Fields body( FieldReader( nullptr, 0 ), 0 );
    Fields name( FieldReader( nullptr, 0 ), 0 );
    uint8_t first = 0;
    uint32_t length = 0;
    uint8_t level = 0;
    return packet.u8( first ) == Read::Ok && first == 0x10 && packet.varint( length ) == Read::Ok
           && packet.take( std::min<size_t>( length, packet.declared() ), body ) == Read::Ok
           && body.string( name ) == Read::Ok && body.u8( level ) == Read::Ok
           && mqttVersion( name, level ) != nullptr;
}

std::optional<size_t> frameMqttPacket( const uint8_t* payload, size_t len )
{
    if ( len == 0 || ( payload[ 0 ] >> 4 ) == 0
         || !validFlags( payload[ 0 ] >> 4, payload[ 0 ] & 0x0F ) ) {
        return std::nullopt;
    }
    // The Remaining Length, a variable byte integer (MQTT 5.0, 1.5.5).
    size_t remaining = 0;
    for ( size_t i = 0; i < kMaxMqttVarintBytes; ++i ) {
        if ( 1 + i >= len ) {
            return len + 1;
        }
        const uint8_t digit = payload[ 1 + i ];
        remaining |= static_cast<size_t>( digit & 0x7F ) << ( 7 * i );
        if ( ( digit & 0x80 ) == 0 ) {
            return 2 + i + remaining;
        }
    }
    return std::nullopt;
}

std::string detectMqtt( const uint8_t* payload, size_t len, bool onMqttPort )
{
    if ( !onMqttPort && !isMqttConnect( payload, len ) ) {
        return {};
    }
    return describeMqttPackets( payload, len, len );
}

// ── MQTT in its stream ───────────────────────────────────────────────────

/// A TCP segment in its stream: MQTT packets after a CONNECT on a port
/// other than MQTT's, those in the payload's first kPayloadHeadBytes.
void describeMqttInStream( PacketRecord& pkt, StreamState& state )
{
    if ( pkt.streamCue == StreamCue::MqttConnect ) {
        state.protocols |= StreamState::kMqtt;
        return;
    }
    if ( !( state.protocols & StreamState::kMqtt ) || pkt.protocolRecognised
         || pkt.payloadHeadLen == 0 ) {
        return;
    }
    const auto packets
        = describeMqttPackets( pkt.payloadHead.data(), pkt.payloadHeadLen,
                               std::max<size_t>( pkt.payloadLen, pkt.payloadHeadLen ) );
    if ( !packets.empty() ) {
        redescribe( pkt, "MQTT", packets );
    }
}

} // namespace tcpdump::describer
