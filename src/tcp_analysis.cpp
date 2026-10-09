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
 * @file tcp_analysis.cpp
 * @brief Implementation of the TCP Analysis.
 */

#include "tcp_analysis.h"

#include <algorithm>
#include <string>

namespace tcpdump {

static_assert( sizeof( TcpDirection ) == 32, "TcpDirection is paid twice per numbered stream" );

namespace {

constexpr uint8_t kTcpFin = 0x01;
constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpRst = 0x04;
constexpr uint8_t kTcpAck = 0x10;

/// Wireshark's limits for telling the kinds of retransmission apart when it
/// knows no round-trip time: a fast retransmission comes within 20 ms of
/// the other direction's last segment, an out-of-order one within 3 ms.
constexpr uint64_t kFastRetransmissionNs = 20000000;
constexpr uint64_t kOutOfOrderNs = 3000000;

/// Sequence number comparisons modulo 2^32, as Wireshark's LT_SEQ and GT_SEQ.
bool seqBefore( uint32_t a, uint32_t b )
{
    return static_cast<int32_t>( a - b ) < 0;
}
bool seqAfter( uint32_t a, uint32_t b )
{
    return static_cast<int32_t>( a - b ) > 0;
}

/// @p pkt's time in nanoseconds since the epoch, modulo 2^64.
uint64_t timeNs( const PacketRecord& pkt )
{
    return static_cast<uint64_t>( pkt.timestampSec ) * 1000000000u + pkt.timestampNsec;
}

/// Nanoseconds from @p then to @p now; 0 if @p now is not later, as in a
/// capture that needs reordering.
uint64_t elapsedNs( uint64_t then, uint64_t now )
{
    const auto delta = static_cast<int64_t>( now - then );
    return delta > 0 ? static_cast<uint64_t>( delta ) : 0;
}

/// RFC 7323's largest shift count of the window scale option; a larger one
/// counts as 14, in Wireshark too.
constexpr uint8_t kMaxWindowShift = 14;

/// A window of @p raw sent in direction @p dir, shifted by its scale if
/// @p scaled.
uint32_t windowOf( const TcpDirection& dir, uint16_t raw, bool scaled )
{
    return scaled ? static_cast<uint32_t>( raw ) << ( dir.windowScale - 1 ) : raw;
}

/// The window of the last segment of @p dir, as it was shown.
uint32_t lastWindow( const TcpDirection& dir )
{
    return windowOf( dir, dir.window, ( dir.flags & TcpDirection::kWindowScaled ) != 0 );
}

/// One segment as the classification sees it: relative numbers.
struct Segment {
    uint32_t number; ///< The packet number.
    uint64_t time;   ///< timeNs()
    uint32_t seq;
    uint32_t ack;
    uint32_t len; ///< Payload bytes on the wire.
    uint8_t flags;
    uint16_t rawWindow; ///< The window as sent.
    bool windowScaled;  ///< Whether it is shifted by its direction's scale.
    uint32_t window;    ///< The window as shown: windowOf() the two.
};

/**
 * Check @p seg's ACK and window, up to Wireshark's finished_fwd: whether it
 * probes or closes a window, keeps the connection alive or repeats an ACK.
 * @p dupAckFrame is set for a duplicate ACK.
 */
void checkAck( TcpDirection& fwd, TcpDirection& rev, const Segment& seg, TcpMarkers& markers,
               uint32_t& dupAckFrame )
{
    const bool synFinRst = ( seg.flags & ( kTcpSyn | kTcpFin | kTcpRst ) ) != 0;
    const bool fwdWindowKnown = ( fwd.flags & TcpDirection::kWindowKnown ) != 0;
    const bool revWindowKnown = ( rev.flags & TcpDirection::kWindowKnown ) != 0;
    // Windows are compared as shown, scaled, as Wireshark does.
    const auto fwdWindow = lastWindow( fwd );

    if ( seg.len == 1 && seg.seq == fwd.nextSeq && revWindowKnown && rev.window == 0 ) {
        markers.set( TcpMarker::ZeroWindowProbe );
        return;
    }
    if ( seg.window == 0 && !synFinRst ) {
        markers.set( TcpMarker::ZeroWindow );
    }
    if ( fwd.nextSeq != 0 && seqAfter( seg.seq, fwd.nextSeq ) && !( seg.flags & kTcpRst ) ) {
        markers.set( TcpMarker::PreviousSegmentNotCaptured );
    }
    if ( seg.len <= 1 && fwd.nextSeq != 0 && seg.seq == fwd.nextSeq - 1 && !synFinRst ) {
        markers.set( TcpMarker::KeepAlive );
    }
    if ( seg.len == 0 && seg.window != 0 && ( !fwdWindowKnown || seg.window != fwdWindow )
         && seg.seq == fwd.nextSeq && seg.ack == fwd.lastAck && !synFinRst ) {
        markers.set( TcpMarker::WindowUpdate );
    }

    // The rest repeat the last segment's position and window, without data.
    if ( seg.len != 0 || !fwdWindowKnown || seg.window != fwdWindow || seg.seq != fwd.nextSeq
         || synFinRst ) {
        return;
    }
    if ( seg.window != 0 && seg.ack == fwd.lastAck && ( rev.flags & TcpDirection::kKeepAlive ) ) {
        markers.set( TcpMarker::KeepAliveAck );
        return;
    }
    if ( seg.window == 0 && ( seg.ack == fwd.lastAck || seg.ack == fwd.lastAck + 1 )
         && ( rev.flags & TcpDirection::kZeroWindowProbe ) ) {
        markers.set( TcpMarker::ZeroWindowProbeAck );
        // The receiver took the probe's byte after all.
        if ( seg.ack == fwd.lastAck + 1 ) {
            rev.nextSeq = seg.ack;
        }
        return;
    }
    if ( seg.window != 0 && seg.ack == fwd.lastAck ) {
        ++fwd.dupAcks;
        markers.set( TcpMarker::DupAck );
        dupAckFrame = fwd.lastNonDupAck;
    }
}

/**
 * Classify @p seg, sent in direction @p fwd with @p rev the other one, and
 * remember what it tells in @p fwd: Wireshark's tcp_analyze_sequence_number()
 * with its default preferences, less what needs a list of the segments
 * sent, SACK or the round-trip time (see the Developer Guide).
 */
TcpMarkers classify( TcpDirection& fwd, TcpDirection& rev, const Segment& seg,
                     uint32_t& dupAckFrame )
{
    const bool synFin = ( seg.flags & ( kTcpSyn | kTcpFin ) ) != 0;
    TcpMarkers markers;
    checkAck( fwd, rev, seg, markers, dupAckFrame );
    if ( seg.ack != fwd.lastAck ) {
        fwd.lastNonDupAck = seg.number;
        fwd.dupAcks = 0;
    }

    // A segment that takes up sequence numbers but does not advance them is
    // sent again, or late; a keep-alive is neither.
    if ( ( seg.len > 0 || synFin ) && !markers.test( TcpMarker::KeepAlive ) ) {
        bool notAdvanced = fwd.nextSeq != 0 && seqBefore( seg.seq, fwd.nextSeq );
        // New data that starts one byte behind may follow a probe.
        if ( seg.len > 1 && fwd.nextSeq - 1 == seg.seq ) {
            notAdvanced = false;
        }
        const auto end = seg.seq + seg.len;
        if ( seg.len > 0 && rev.lastAck != 0 && !seqAfter( end, rev.lastAck ) ) {
            markers.set( TcpMarker::SpuriousRetransmission );
        }
        else if ( notAdvanced ) {
            const auto t = elapsedNs( rev.lastTime, seg.time );
            if ( t < kFastRetransmissionNs && rev.dupAcks >= 2 && rev.lastAck == seg.seq ) {
                markers.set( TcpMarker::FastRetransmission );
            }
            else if ( t < kOutOfOrderNs
                      && ( fwd.nextSeq != end + ( synFin ? 1 : 0 )
                           || !( fwd.flags & TcpDirection::kAdvancedWithData ) ) ) {
                markers.set( TcpMarker::OutOfOrder );
            }
            else {
                markers.set( TcpMarker::Retransmission );
            }
        }
    }

    // Remember what the segment tells; a probe does not advance nextSeq.
    const auto nextSeq = seg.seq + seg.len + ( synFin ? 1 : 0 );
    uint8_t flags
        = TcpDirection::kWindowKnown | ( seg.windowScaled ? TcpDirection::kWindowScaled : 0 );
    if ( fwd.nextSeq == 0 || seqAfter( nextSeq, fwd.nextSeq + ( synFin ? 1 : 0 ) ) ) {
        flags |= seg.len > 0 ? TcpDirection::kAdvancedWithData : 0;
    }
    else {
        flags |= fwd.flags & TcpDirection::kAdvancedWithData;
    }
    if ( ( fwd.nextSeq == 0 || seqAfter( nextSeq, fwd.nextSeq ) )
         && !markers.test( TcpMarker::ZeroWindowProbe ) ) {
        fwd.nextSeq = nextSeq;
    }
    if ( markers.test( TcpMarker::KeepAlive ) ) {
        flags |= TcpDirection::kKeepAlive;
    }
    if ( markers.test( TcpMarker::ZeroWindowProbe ) ) {
        flags |= TcpDirection::kZeroWindowProbe;
    }
    fwd.flags = static_cast<uint8_t>( ( fwd.flags & ~TcpDirection::kSegmentFlags ) | flags );
    fwd.window = seg.rawWindow;
    fwd.lastAck = seg.ack;
    fwd.lastTime = seg.time;
    return markers;
}

/// The markers of @p markers as Wireshark writes them at the start of Info:
/// each kind in front of those it adds before it, followed by a space.
std::string markerText( const TcpMarkers& markers, uint32_t dupAckFrame, uint32_t dupAcks )
{
    std::string text;
    for ( size_t i = 0; i < kTcpMarkerKinds; ++i ) {
        const auto marker = static_cast<TcpMarker>( i );
        if ( !markers.test( marker ) ) {
            continue;
        }
        std::string one = std::string( "[" ) + tcpMarkerName( marker );
        if ( marker == TcpMarker::DupAck ) {
            one += " " + std::to_string( dupAckFrame ) + "#" + std::to_string( dupAcks );
        }
        text = one + "] " + text;
    }
    return text;
}

/// Whether a segment with @p flags and sequence number @p seq, sent in the
/// direction @p fwd, starts a new connection on the same addresses and
/// ports: a SYN without ACK whose sequence number is not its direction's
/// base.  A retransmitted SYN is not one.
bool startsNewConnection( const TcpDirection& fwd, uint8_t flags, uint32_t seq )
{
    return ( flags & kTcpSyn ) && !( flags & kTcpAck ) && ( fwd.flags & TcpDirection::kBaseSeqSet )
           && fwd.baseSeq != seq;
}

/// Learn the bases of @p fwd, the packet's direction, and @p rev, the other
/// one, from a segment with sequence number @p seq and acknowledgement
/// number @p ack, if not known yet.  Unsigned arithmetic wraps at 2^32.
void learnBases( TcpDirection& fwd, TcpDirection& rev, uint8_t flags, uint32_t seq, uint32_t ack )
{
    const bool syn = ( flags & kTcpSyn ) != 0;
    if ( !( fwd.flags & TcpDirection::kBaseSeqSet ) ) {
        fwd.baseSeq = syn ? seq : seq - 1;
        fwd.flags |= TcpDirection::kBaseSeqSet;
    }
    // A SYN's acknowledgement field is not the other side's yet.
    if ( !( rev.flags & TcpDirection::kBaseSeqSet ) && ( flags & kTcpAck ) ) {
        rev.baseSeq = ack - 1;
        rev.flags |= TcpDirection::kBaseSeqSet;
    }
}

} // namespace

const char* tcpMarkerName( TcpMarker marker )
{
    switch ( marker ) {
    case TcpMarker::Retransmission:
        return "TCP Retransmission";
    case TcpMarker::FastRetransmission:
        return "TCP Fast Retransmission";
    case TcpMarker::SpuriousRetransmission:
        return "TCP Spurious Retransmission";
    case TcpMarker::OutOfOrder:
        return "TCP Out-Of-Order";
    case TcpMarker::PreviousSegmentNotCaptured:
        return "TCP Previous segment not captured";
    case TcpMarker::WindowUpdate:
        return "TCP Window Update";
    case TcpMarker::KeepAlive:
        return "TCP Keep-Alive";
    case TcpMarker::KeepAliveAck:
        return "TCP Keep-Alive ACK";
    case TcpMarker::DupAck:
        return "TCP Dup ACK";
    case TcpMarker::ZeroWindowProbe:
        return "TCP ZeroWindowProbe";
    case TcpMarker::ZeroWindow:
        return "TCP ZeroWindow";
    case TcpMarker::ZeroWindowProbeAck:
        return "TCP ZeroWindowProbeAck";
    }
    return "TCP";
}

TcpMarkers analyseTcp( PacketRecord& pkt, const Stream& stream )
{
    if ( pkt.transport != Transport::Tcp || !stream.state ) {
        return {};
    }
    auto& fwd = stream.state->tcp[ stream.direction ];
    auto& rev = stream.state->tcp[ 1 - stream.direction ];
    if ( startsNewConnection( fwd, pkt.tcpFlags, pkt.tcpSeq ) ) {
        // Everything known of the old connection is forgotten, both
        // directions and what other modules keep of the stream.
        *stream.state = StreamState();
    }
    learnBases( fwd, rev, pkt.tcpFlags, pkt.tcpSeq, pkt.tcpAck );
    const bool syn = ( pkt.tcpFlags & kTcpSyn ) != 0;
    if ( syn && pkt.tcpHeaderLen >= 20 ) {
        fwd.windowScale
            = pkt.tcpWindowShift
                  ? static_cast<uint8_t>( std::min( *pkt.tcpWindowShift, kMaxWindowShift ) + 1 )
                  : 0;
    }

    const auto seq = pkt.tcpSeq - fwd.baseSeq;
    const auto ack = ( pkt.tcpFlags & kTcpAck ) ? pkt.tcpAck - rev.baseSeq : 0;
    // Scaling applies once both SYNs carried the option, never to a SYN.
    const bool windowScaled = !syn && fwd.windowScale != 0 && rev.windowScale != 0;
    const auto window = windowOf( fwd, pkt.tcpWindow, windowScaled );

    // The parser wrote the numbers as they are, right after the flags: the
    // first "Seq=" of Info, before any payload description.
    const auto raw = formatTcpNumbers( pkt.tcpSeq, pkt.tcpAck, pkt.tcpWindow );
    const auto at = pkt.info.find( "Seq=" );
    if ( at != std::string::npos && pkt.info.compare( at, raw.size(), raw ) == 0 ) {
        pkt.info.replace( at, raw.size(), formatTcpNumbers( seq, ack, window ) );
    }

    if ( pkt.tcpHeaderLen < 20 ) {
        return {};
    }
    uint32_t dupAckFrame = 0;
    const auto markers = classify( fwd, rev,
                                   { pkt.number, timeNs( pkt ), seq, ack, pkt.payloadLen,
                                     pkt.tcpFlags, pkt.tcpWindow, windowScaled, window },
                                   dupAckFrame );
    pkt.info.insert( 0, markerText( markers, dupAckFrame, fwd.dupAcks ) );
    return markers;
}

} // namespace tcpdump
