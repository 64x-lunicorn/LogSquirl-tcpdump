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

#include "stream_labels.h"
#include "tcp_analysis.h"

#include <algorithm>
#include <cstdio>
#include <sstream>

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
void writeColumn( std::ostream& out, const std::string& value, size_t width )
{
    const std::string shown = value.empty() ? "-" : value;
    const auto padding = shown.size() < width ? width - shown.size() : 1;
    out << shown << std::string( padding, ' ' );
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

    // Four digits as usual; ISO 8601's expanded year, with its sign, beyond
    char year[ 24 ];
    if ( date.year >= 0 && date.year <= 9999 ) {
        std::snprintf( year, sizeof( year ), "%04lld", static_cast<long long>( date.year ) );
    }
    else {
        std::snprintf( year, sizeof( year ), "%+05lld", static_cast<long long>( date.year ) );
    }

    const auto hour = static_cast<int>( secondOfDay / 3600 );
    const auto minute = static_cast<int>( secondOfDay / 60 % 60 );
    const auto second = static_cast<int>( secondOfDay % 60 );
    const bool nano = precision == TimePrecision::Nanoseconds;
    const auto fraction = static_cast<unsigned long>( nano ? nanoseconds : nanoseconds / 1000 );
    char buf[ 64 ];
    std::snprintf( buf, sizeof( buf ),
                   nano ? "%s-%02u-%02u %02d:%02d:%02d.%09luZ"
                        : "%s-%02u-%02u %02d:%02d:%02d.%06luZ",
                   year, date.month, date.day, hour, minute, second, fraction );
    return buf;
}

std::string formatPacketLine( const PacketRecord& pkt, int64_t baseTimeSec, uint32_t baseTimeNsec,
                              int streamId, TimePrecision precision )
{
    // Time relative to the first packet; negative for an earlier packet.
    // Packet times are never before 1970, so the seconds' difference fits.
    const int64_t deltaSec = pkt.timestampSec - baseTimeSec;
    const int64_t deltaNsec
        = static_cast<int64_t>( pkt.timestampNsec ) - static_cast<int64_t>( baseTimeNsec );

    const std::string streamStr = streamId >= 0             ? std::to_string( streamId )
                                  : streamId == kUnnumbered ? "?"
                                                            : "-";

    // Use fixed-width columns like Wireshark's packet list
    std::ostringstream oss;
    writeColumn( oss, std::to_string( pkt.number ), 7 );
    writeColumn( oss, streamStr, 8 );
    // Each packet's own wall-clock time, also for one recorded before the
    // first packet, whose relative time is negative
    writeColumn( oss, formatUtcTime( pkt.timestampSec, pkt.timestampNsec, precision ),
                 utcTimeWidth( precision ) );
    writeColumn( oss, formatRelativeTime( deltaSec, deltaNsec, precision ),
                 timeWidth( precision ) );
    writeColumn( oss, pkt.srcIp.empty() ? pkt.srcMac : pkt.srcIp, 40 );
    writeColumn( oss, pkt.dstIp.empty() ? pkt.dstMac : pkt.dstIp, 40 );
    writeColumn( oss, pkt.protocol, 10 );
    // The length on the wire, as Wireshark's Length column; a packet cut at
    // the snaplen says in Info how much of it was captured, so that a reader
    // knows why its description stops short.
    writeColumn( oss, std::to_string( pkt.originalLen ), 7 );
    oss << pkt.info;
    if ( pkt.capturedLen < pkt.originalLen ) {
        oss << ( pkt.info.empty() ? "" : " " ) << "[cut to " << pkt.capturedLen << " bytes]";
    }

    return oss.str();
}

std::string PacketFormatter::header() const
{
    std::ostringstream hdr;
    writeColumn( hdr, "No.", 7 );
    writeColumn( hdr, "Stream", 8 );
    writeColumn( hdr, "UTC Time", utcTimeWidth( precision_ ) );
    writeColumn( hdr, "Time", timeWidth( precision_ ) );
    writeColumn( hdr, "Source", 40 );
    writeColumn( hdr, "Destination", 40 );
    writeColumn( hdr, "Protocol", 10 );
    writeColumn( hdr, "Length", 7 );
    hdr << "Info";
    return hdr.str();
}

std::string PacketFormatter::format( const PacketRecord& pkt, int streamId )
{
    if ( !haveBase_ ) {
        haveBase_ = true;
        baseTimeSec_ = pkt.timestampSec;
        baseTimeNsec_ = pkt.timestampNsec;
    }
    return formatPacketLine( pkt, baseTimeSec_, baseTimeNsec_, streamId, precision_ );
}

std::vector<std::string> formatAllPackets( const std::vector<PacketRecord>& packets )
{
    auto finest = TimePrecision::Microseconds;
    for ( const auto& pkt : packets ) {
        finest = std::max( finest, pkt.precision );
    }
    PacketFormatter formatter( finest );
    StreamTracker tracker;
    StreamLabels labels;
    std::vector<std::string> lines;
    lines.reserve( packets.size() + 1 );
    lines.push_back( formatter.header() );

    for ( auto pkt : packets ) {
        const auto stream = tracker.track( pkt );
        analyseTcp( pkt, stream );
        labels.apply( pkt, stream );
        lines.push_back( formatter.format( pkt, stream.id ) );
    }
    return lines;
}

} // namespace tcpdump
