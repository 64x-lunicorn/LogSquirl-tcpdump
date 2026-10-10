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
 * @file tls_decryption.h
 * @brief Decrypts the TLS records of a capture with the secrets of a key
 *        log, and describes what they carry.
 *
 * Pure C++ — no Qt dependency.
 */

#pragma once

#include "pcap_parser.h"
#include "stream_tracker.h"
#include "tcp_reassembly.h"
#include "tls_key_log.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace tcpdump {

/// Begins the description of a segment whose TLS records were decrypted,
/// before kDescriptionSeparator and what they carry.
constexpr const char* kDecryptedMarker = "TLS (decrypted)";

/**
 * The TLS Decryption: follows the TLS sessions of a capture's TCP streams,
 * finds their secrets in the key log by the ClientHello's random, and
 * decrypts their records, so that what they carry is described: the
 * requests and responses of HTTP/1.1 and HTTP/2 (HPACK decoded), the
 * encrypted handshake messages and alerts.  A segment with a record it
 * decrypted is described as "TLS (decrypted) | GET example.com/ HTTP/1.1",
 * labelled HTTP or HTTP2 when it carries that; one with none it could
 * decrypt keeps its description.
 *
 * TLS 1.2 with AES-GCM, ChaCha20-Poly1305 and AES-CBC with HMAC
 * (MAC-then-encrypt, or encrypt-then-MAC, RFC 7366), and TLS 1.3 with
 * AES-GCM and ChaCha20-Poly1305, its key updates followed.  Not decrypted:
 * TLS 1.3 early data (0-RTT), TLS 1.0 and 1.1, a renegotiated TLS 1.2
 * session's later keys, and sessions the key log has no secrets for.
 *
 * The records come from the TCP Reassembly, whole and in order (the
 * messages TcpReassembly::apply() returns).  A record the capture lost is
 * passed over: the next one is tried with the next kSequenceLookahead
 * sequence numbers too.  After kMaxFailures records in a row that would not
 * decrypt, a direction is given up.  HTTP/2 after application data that
 * went missing so is read from the next record's start, a frame's, its
 * header blocks no longer decoded (Http2Direction::resync()).
 *
 * Memory is bounded: a session keeps its randoms, its keys and sequence
 * numbers, no records, and of TLS 1.3 per direction an encrypted handshake
 * message over more than one record until it is whole, up to 16 KiB:
 * some 3.3 KB a session with keys.  kMaxSessions are followed at most
 * (about 55 MB); a new one beyond takes the place of the session with the
 * least recent record, whose connection's end was not captured or is far.  An HTTP/2
 * session keeps per direction what Http2Direction holds, all of them
 * together at most kHttp2MemoryLimit; one that would pass it names its
 * frames only.  The plaintext of a segment's records lives while the
 * segment is described.
 */
class TlsDecryption {
public:
    /// The secrets of the session whose ClientHello has the random at
    /// the pointer, tls::kRandomBytes of it; null if there are none.
    using Lookup = std::function<const tls::SessionSecrets*( const uint8_t* clientRandom )>;
    /// How much of the key log has been read (tls::KeyLogFile::bytesRead()):
    /// a session it had no secrets for is looked for again once it grew.
    using KeyLogBytes = std::function<int64_t()>;

    /// TLS sessions followed at most; a later one takes the place of the
    /// one with the least recent record.
    static constexpr size_t kMaxSessions = 16384;
    /// Records a direction may have lost, and still be decrypted after.
    static constexpr uint32_t kSequenceLookahead = 8;
    /// Records in a row that would not decrypt before a direction is given up.
    static constexpr uint8_t kMaxFailures = 8;
    /// Bytes the HTTP/2 sessions hold at most, all together.
    static constexpr size_t kHttp2MemoryLimit = 32 * 1024 * 1024;

    /// Without @p keyLogBytes a session without secrets is looked for on
    /// each of its records.  @p maxSessions are followed at most.
    explicit TlsDecryption( Lookup lookup, KeyLogBytes keyLogBytes = {},
                            size_t maxSessions = kMaxSessions );
    ~TlsDecryption();
    TlsDecryption( const TlsDecryption& ) = delete;
    TlsDecryption& operator=( const TlsDecryption& ) = delete;

    /**
     * Run on every packet, in capture order, after the TCP Reassembly, with
     * the messages it returned for the packet.  Follows the handshakes in
     * them, decrypts their records and describes the packet anew if it
     * decrypted one.  Packets of other transports, and of no stream or one
     * past the stream cap, are left as they are.
     */
    void apply( PacketRecord& pkt, const Stream& stream, const ReassembledMessages& messages );

    /// Sessions with at least one record decrypted so far.
    size_t sessionsDecrypted() const
    {
        return sessionsDecrypted_;
    }

    /// Sessions followed now.
    size_t sessions() const
    {
        return sessions_.size();
    }

    /// Bytes the HTTP/2 sessions hold now.
    size_t http2Memory() const
    {
        return http2Memory_;
    }

private:
    struct Direction;
    struct Session;

    /// Decrypt and describe the records a segment completed.
    void records( PacketRecord& pkt, const Stream& stream, const ReassembledMessages& messages );
    /// Follow the hellos among the handshake messages of a plaintext record.
    void handshake( const Stream& stream, ByteView fragment );
    /// Set up a session's keys from the key log, unless they are.
    bool ensureKeys( Session& session );
    /// TLS 1.3: protect @p direction with the keys of traffic @p secret.
    bool setTrafficSecret( Session& session, Direction& direction, tls::SecretBytes secret );
    /// Decrypt a protected record into @p plain and its content type.
    bool decrypt( Session& session, Direction& direction, uint8_t type, uint16_t version,
                  ByteView fragment, tls::PlainBytes& plain, uint8_t& inner );
    /// TLS 1.3: what the decrypted handshake @p messages of direction @p d
    /// change: the keys after a Finished or a KeyUpdate, ALPN.  A message
    /// over more than one record is read once it is whole.
    void afterHandshake( Session& session, unsigned d, ByteView messages );
    /// The label and description of the application data a segment of
    /// direction @p d carried, decrypted.
    /// The application data went missing where @p resyncs say.
    std::pair<const char*, std::string> application( Session& session, unsigned d,
                                                     const tls::PlainBytes& data,
                                                     const std::vector<size_t>& resyncs,
                                                     const PacketRecord& pkt );
    /// A record of direction @p direction, of @p type as the record
    /// header says, was lost or would not decrypt.
    void lost( Session& session, Direction& direction, uint8_t type );
    void erase( int streamId );

    Lookup lookup_;
    KeyLogBytes keyLogBytes_;
    size_t maxSessions_;
    std::unordered_map<int, std::unique_ptr<Session>> sessions_;
    /// The streams of the sessions, the one with the least recent record
    /// first.
    std::list<int> recent_;
    size_t sessionsDecrypted_ = 0;
    size_t http2Memory_ = 0;
};

} // namespace tcpdump
