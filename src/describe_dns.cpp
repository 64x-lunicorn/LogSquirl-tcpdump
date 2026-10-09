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
 * @file describe_dns.cpp
 * @brief The DNS and mDNS detector of the Payload Describer, over UDP and TCP.
 */

#include "describe_common.h"

#include <cstdio>
#include <optional>
#include <string>

namespace tcpdump::describer {

// ── DNS ──────────────────────────────────────────────────────────────────

namespace {

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

} // namespace

/// Describe a DNS message sent over UDP: the whole datagram.
std::string detectDns( const uint8_t* payload, size_t len )
{
    return describeDnsMessage( { payload, len } );
}

namespace {

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

} // namespace

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

/// The DNS-over-TCP message a segment begins with, behind its 2-byte length:
/// 2 bytes more than that length, or nothing if the bytes there are no
/// plausible message header.  Fewer bytes than a header's are taken for one.
std::optional<size_t> frameDnsOverTcp( const uint8_t* payload, size_t len )
{
    if ( len < 2 ) {
        return size_t{ 2 };
    }
    const uint16_t length = readBE16( payload );
    constexpr size_t kHeaderFieldsRead = 2 + 6; // length, ID, flags, questions
    if ( length < 12
         || ( len >= kHeaderFieldsRead
              && !isPlausibleDnsHeader( FieldReader( payload + 2, len - 2 ), length ) ) ) {
        return std::nullopt;
    }
    return size_t{ 2 } + length;
}

} // namespace tcpdump::describer
