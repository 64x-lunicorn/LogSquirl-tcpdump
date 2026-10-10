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
 * @file packet_formatter.cpp
 * @brief Formats parsed PacketRecord structs into Wireshark-style text lines.
 *
 * Output example:
 *   1   0      2026-10-09 08:41:12.123456Z 0.000000 192.168.1.1 10.0.0.1    TCP      60     443 → …
 *
 * Length is the packet's length on the wire; a packet cut at the snaplen
 * ends its Info with "[cut to N bytes]", N the bytes captured.
 */

#include "packet_formatter.h"

#include "capture_reader.h"

#include <algorithm>
#include <cstdio>
#include <optional>

namespace tcpdump {

namespace {

/// Width of the relative time column, with three more digits for nanoseconds.
size_t timeWidth( TimePrecision precision )
{
    return precision == TimePrecision::Nanoseconds ? 18 : 15;
}

/// Width of the UTC time column: the time and two spaces.
size_t utcTimeWidth( TimePrecision precision )
{
    return precision == TimePrecision::Nanoseconds ? 32 : 29;
}

/// Width of a MAC address column: the address and two spaces.
constexpr size_t kMacWidth = 19;

/// Whether @p layout shows the UTC Time column.
bool showsUtcTime( const LineLayout& layout )
{
    return layout.timeColumns != TimeColumns::RelativeOnly;
}

/// Whether @p layout shows the relative Time column.
bool showsTime( const LineLayout& layout )
{
    return layout.timeColumns != TimeColumns::AbsoluteOnly;
}

/// The proleptic Gregorian date @p days after 1970-01-01, for any day of the
/// int64_t range; Howard Hinnant's civil_from_days.
struct CivilDate {
    int64_t year;
    unsigned month;
    unsigned day;
};

CivilDate civilFromDays( int64_t days )
{
    days += 719468; // Days from 0000-03-01 to 1970-01-01
    const int64_t era = ( days >= 0 ? days : days - 146096 ) / 146097;
    const auto dayOfEra = static_cast<unsigned>( days - era * 146097 );
    const unsigned yearOfEra
        = ( dayOfEra - dayOfEra / 1460 + dayOfEra / 36524 - dayOfEra / 146096 ) / 365;
    const unsigned dayOfYear = dayOfEra - ( 365 * yearOfEra + yearOfEra / 4 - yearOfEra / 100 );
    const unsigned shiftedMonth = ( 5 * dayOfYear + 2 ) / 153; // March is 0
    const unsigned day = dayOfYear - ( 153 * shiftedMonth + 2 ) / 5 + 1;
    const unsigned month = shiftedMonth < 10 ? shiftedMonth + 3 : shiftedMonth - 9;
    const int64_t year = static_cast<int64_t>( yearOfEra ) + era * 400 + ( month <= 2 ? 1 : 0 );
    return { year, month, day };
}

/// @p deltaSec seconds and @p deltaNsec nanoseconds (each of either sign,
/// |deltaNsec| below a second) as seconds with 9 or 6 decimals, computed in
/// integers so that neither precision nor range is lost: two times centuries
/// apart differ by more nanoseconds than an int64_t holds.
std::string formatRelativeTime( int64_t deltaSec, int64_t deltaNsec, TimePrecision precision )
{
    // Give both parts the same sign
    if ( deltaSec > 0 && deltaNsec < 0 ) {
        --deltaSec;
        deltaNsec += 1000000000;
    }
    else if ( deltaSec < 0 && deltaNsec > 0 ) {
        ++deltaSec;
        deltaNsec -= 1000000000;
    }
    const bool negative = deltaSec < 0 || deltaNsec < 0;
    const auto magnitude = []( int64_t value ) {
        return value < 0 ? 0 - static_cast<uint64_t>( value ) : static_cast<uint64_t>( value );
    };
    const auto seconds = static_cast<unsigned long long>( magnitude( deltaSec ) );
    const auto fraction = magnitude( deltaNsec );
    char buf[ 40 ];
    if ( precision == TimePrecision::Nanoseconds ) {
        std::snprintf( buf, sizeof( buf ), "%s%llu.%09llu", negative ? "-" : "", seconds,
                       static_cast<unsigned long long>( fraction ) );
    }
    else {
        std::snprintf( buf, sizeof( buf ), "%s%llu.%06llu", negative ? "-" : "", seconds,
                       static_cast<unsigned long long>( fraction / 1000 ) );
    }
    return buf;
}

/// Writes @p value left-aligned in a column @p width wide, and at least one
/// space after it, so that a value as wide as its column, or wider, does not
/// run into the next one; an empty value as "-", so that the column is not
/// lost between its neighbours.
void writeColumn( std::string& out, const std::string& value, size_t width )
{
    if ( value.empty() ) {
        out += '-';
    }
    else {
        out += value;
    }
    const auto size = std::max<size_t>( value.size(), 1 );
    out.append( size < width ? width - size : 1, ' ' );
}

/// Writes the Source or Destination column of @p address, or of @p mac
/// without one: the address and its name, if @p names has one for it.
void writeAddressColumn( std::string& out, const std::string& address, const std::string& mac,
                         const HostNames* names )
{
    constexpr size_t kWidth = 40;
    const auto* name = names && !address.empty() ? names->find( address ) : nullptr;
    if ( name ) {
        writeColumn( out, address + "(" + *name + ")", kWidth );
    }
    else {
        writeColumn( out, address.empty() ? mac : address, kWidth );
    }
}

} // namespace

std::string formatUtcTime( int64_t seconds, uint32_t nanoseconds, TimePrecision precision )
{
    // Floor division, so that a time before 1970 falls on the day before
    int64_t days = seconds / 86400;
    int64_t secondOfDay = seconds % 86400;
    if ( secondOfDay < 0 ) {
        secondOfDay += 86400;
        --days;
    }
    const auto date = civilFromDays( days );

    const auto hour = static_cast<unsigned>( secondOfDay / 3600 );
    const auto minute = static_cast<unsigned>( secondOfDay / 60 % 60 );
    const auto second = static_cast<unsigned>( secondOfDay % 60 );
    const bool nano = precision == TimePrecision::Nanoseconds;
    auto fraction = static_cast<unsigned long>( nano ? nanoseconds : nanoseconds / 1000 );

    // Four digits as usual; ISO 8601's expanded year, with its sign, beyond.
    std::string text;
    if ( date.year >= 0 && date.year <= 9999 ) {
        text.resize( 4 );
        auto year = static_cast<unsigned>( date.year );
        for ( size_t i = 4; i-- > 0; year /= 10 ) {
            text[ i ] = static_cast<char>( '0' + year % 10 );
        }
    }
    else {
        char year[ 24 ];
        std::snprintf( year, sizeof( year ), "%+05lld", static_cast<long long>( date.year ) );
        text = year;
    }
    // The rest by hand, as every packet line has one: "-MM-DD hh:mm:ss.fZ".
    auto two = [ &text ]( char before, unsigned value ) {
        text += before;
        text += static_cast<char>( '0' + value / 10 % 10 );
        text += static_cast<char>( '0' + value % 10 );
    };
    text.reserve( text.size() + 21 );
    two( '-', date.month );
    two( '-', date.day );
    two( ' ', hour );
    two( ':', minute );
    two( ':', second );
    text += '.';
    const size_t digits = nano ? 9 : 6;
    if ( fraction >= ( nano ? 1000000000ul : 1000000ul ) ) {
        // More digits than the precision has, which %0*lu would print too.
        return text + std::to_string( fraction ) + 'Z';
    }
    const auto at = text.size();
    text.resize( at + digits );
    for ( size_t i = digits; i-- > 0; fraction /= 10 ) {
        text[ at + i ] = static_cast<char>( '0' + fraction % 10 );
    }
    text += 'Z';
    return text;
}

std::string formatPacketLine( const PacketRecord& pkt, int64_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, TimePrecision precision, const LineLayout& layout,
                              const HostNames* names )
{
    // Time relative to the first packet; negative for an earlier packet.
    // Packet times are never before 1970, so the seconds' difference fits.
    const int64_t deltaSec = pkt.timestampSec - baseTimeSec;
    const int64_t deltaNsec
        = static_cast<int64_t>( pkt.timestampNsec ) - static_cast<int64_t>( baseTimeNsec );

    const std::string streamStr = streamId >= 0             ? std::to_string( streamId )
                                  : streamId == kUnnumbered ? "?"
                                                            : "-";

    // Use fixed-width columns like Wireshark's packet list; built in one
    // string, as every packet has a line
    std::string oss;
    oss.reserve( 160 + pkt.info.size() );
    writeColumn( oss, std::to_string( pkt.number ), 7 );
    writeColumn( oss, streamStr, 8 );
    // Each packet's own wall-clock time, also for one recorded before the
    // first packet, whose relative time is negative
    if ( showsUtcTime( layout ) ) {
        writeColumn( oss, formatUtcTime( pkt.timestampSec, pkt.timestampNsec, precision ),
                     utcTimeWidth( precision ) );
    }
    if ( showsTime( layout ) ) {
        writeColumn( oss, formatRelativeTime( deltaSec, deltaNsec, precision ),
                     timeWidth( precision ) );
    }
    if ( !layout.hostNames ) {
        names = nullptr;
    }
    writeAddressColumn( oss, pkt.srcIp, pkt.srcMac, names );
    writeAddressColumn( oss, pkt.dstIp, pkt.dstMac, names );
    writeColumn( oss, pkt.protocol, 10 );
    // The length on the wire, as Wireshark's Length column; a packet cut at
    // the snaplen says in Info how much of it was captured, so that a reader
    // knows why its description stops short.
    writeColumn( oss, std::to_string( pkt.originalLen ), 7 );
    // Before Info, which a Log Format reads as the rest of the line: the
    // MAC addresses are read as its start, the other columns as ever.
    if ( layout.macColumns ) {
        writeColumn( oss, pkt.srcMac, kMacWidth );
        writeColumn( oss, pkt.dstMac, kMacWidth );
    }
    // The tunnels a packet came through, outermost first, before the
    // description of the packet inside them: kept apart from info, whose
    // start the TCP analysis markers and the Stream Labels look at.
    for ( const auto& tunnel : pkt.tunnels ) {
        oss += tunnel.name;
        oss += kDescriptionSeparator;
    }
    oss += pkt.info;
    if ( pkt.capturedLen < pkt.originalLen ) {
        oss += pkt.info.empty() ? "[cut to " : " [cut to ";
        oss += std::to_string( pkt.capturedLen );
        oss += " bytes]";
    }

    return oss;
}

std::string PacketFormatter::header() const
{
    std::string hdr;
    writeColumn( hdr, "No.", 7 );
    writeColumn( hdr, "Stream", 8 );
    if ( showsUtcTime( layout_ ) ) {
        writeColumn( hdr, "UTC Time", utcTimeWidth( precision_ ) );
    }
    if ( showsTime( layout_ ) ) {
        writeColumn( hdr, "Time", timeWidth( precision_ ) );
    }
    writeColumn( hdr, "Source", 40 );
    writeColumn( hdr, "Destination", 40 );
    writeColumn( hdr, "Protocol", 10 );
    writeColumn( hdr, "Length", 7 );
    if ( layout_.macColumns ) {
        writeColumn( hdr, "Source MAC", kMacWidth );
        writeColumn( hdr, "Destination MAC", kMacWidth );
    }
    hdr += "Info";
    return hdr;
}

std::string PacketFormatter::format( const PacketRecord& pkt, int streamId, const HostNames* names )
{
    if ( !haveBase_ ) {
        haveBase_ = true;
        baseTimeSec_ = pkt.timestampSec;
        baseTimeNsec_ = pkt.timestampNsec;
    }
    return formatPacketLine( pkt, baseTimeSec_, baseTimeNsec_, streamId, precision_, layout_,
                             names );
}

std::vector<std::string> formatAllPackets( const std::vector<uint8_t>& capture,
                                           const PipelineOptions& options,
                                           const LineLayout& layout )
{
    MemorySource memory( capture.data(), capture.size() );
    HeadSource source( memory );
    const auto reader = makeCaptureReader( source );
    if ( !reader->open() ) {
        return {};
    }
    PacketFormatter formatter( reader->precision(), layout );
    PacketPipeline pipeline( options );
    std::optional<HostNames> names;
    if ( layout.hostNames ) {
        names.emplace();
    }
    std::vector<std::string> lines{ formatter.header() };

    PacketRecord pkt;
    while ( reader->next( pkt ) ) {
        const auto payload = reader->payloadOf( pkt );
        const auto outcome = pipeline.run( pkt, payload );
        lines.push_back( formatter.format( pkt, outcome.stream.id, names ? &*names : nullptr ) );
        // Behind its own line, as in a conversion: a name labels the packets after its answer.
        if ( names ) {
            names->learn( pkt, payload, outcome.messages.bytes );
        }
    }
    return lines;
}

} // namespace tcpdump
