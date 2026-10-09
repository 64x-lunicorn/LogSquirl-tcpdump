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
 * @file media_expectations.h
 * @brief Describes RTP and RTCP on the addresses and ports SIP's SDP bodies
 *        announced.
 *
 * RTP has no port of its own and no header a detector could tell from any
 * other UDP payload with confidence: Wireshark describes it where the SDP
 * of a call said it would be sent.  So do the MediaExpectations, owned by
 * the Converter next to the Stream Tracker: the capture-wide side table of
 * the media endpoints announced so far, which no single stream's state
 * could hold, since the SIP signalling and its media are different
 * conversations.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace tcpdump {

/**
 * The media endpoints the SIP calls of one capture announced, and the
 * description of the UDP packets sent to or from them.
 *
 * An SDP body (PacketRecord::sipCalls) announces, for each RTP media
 * stream, the address and port its RTP is to be sent to, and its RTCP's
 * port, the next one unless `a=rtcp:` names another.  Each is expected,
 * as an RTP or an RTCP endpoint, for the call its Call-ID names.  A UDP
 * packet from or to an expected endpoint is described as RTP or RTCP if
 * it has their header (an RTP endpoint may carry RTCP too, RFC 5761),
 * from the first kPayloadHeadBytes of its payload.  The memory is bounded:
 *
 * - at most maxExpectations endpoints are expected; a new one past that
 *   replaces the one whose last packet (or announcement) is the oldest;
 * - an endpoint without a packet for kIdleSeconds of capture time is no
 *   longer expected;
 * - a BYE ends its call's expectations, and an SDP body replaces those its
 *   call's side announced before (a re-INVITE), the side by the body's o=
 *   line (SipCall::origin): an answer keeps the offer's, also when both
 *   ends' media are on one address.
 */
class MediaExpectations {
public:
    /// Endpoints expected at most by default, some 250 KB of memory.
    static constexpr size_t kMaxExpectations = 1024;
    /// Capture time after which an endpoint without a packet expires.
    static constexpr int64_t kIdleSeconds = 300;

    explicit MediaExpectations( size_t maxExpectations = kMaxExpectations )
        : max_( maxExpectations )
    {
    }

    /**
     * Learn what @p pkt's SIP messages announce or end, then describe it as
     * RTP or RTCP if it is a UDP packet from or to an expected endpoint.
     * Run on every packet, in capture order, after describeInStream() and
     * before the Stream Labels, so that the RTP label sticks to its stream.
     */
    void apply( PacketRecord& pkt );

    /// Endpoints expected now, the expired among them until looked up.
    size_t size() const
    {
        return expected_.size();
    }

private:
    struct Expectation {
        std::string ip;
        std::string callId;
        std::string origin;   ///< The side of the call that announced it
        bool rtcp = false;    ///< An RTCP endpoint, not an RTP one
        int64_t lastSeen = 0; ///< Capture time of its last packet or announcement
    };

    void announce( const SipCall& call, int64_t now );
    void expect( const std::string& ip, uint16_t port, bool rtcp, const SipCall& call,
                 int64_t now );
    /// The fresh expectation of @p ip and @p port, or null; an expired one is forgotten.
    Expectation* find( const std::string& ip, uint16_t port, int64_t now );

    /// By "address port".
    std::unordered_map<std::string, Expectation> expected_;
    size_t max_;
};

} // namespace tcpdump
