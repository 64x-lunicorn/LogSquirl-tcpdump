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
 * @file tls_key_log.h
 * @brief The Key Log: the TLS secrets of an SSLKEYLOGFILE, by the sessions'
 *        client random.
 *
 * The NSS key log format browsers, curl and OpenSSL applications write
 * when SSLKEYLOGFILE names a file: one secret per line, "<label>
 * <client random> <secret>", both in hexadecimal.  The secrets are kept in
 * memory only, for one conversion, and wiped when it ends; nothing here
 * logs, shows or copies them.
 */

#pragma once

#include "tls_crypto.h"

#include <QString>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>

namespace tcpdump::tls {

/// Bytes of a ClientHello's random, by which the key log names a session.
constexpr size_t kRandomBytes = 32;
using ClientRandom = std::array<uint8_t, kRandomBytes>;

/// The secrets a key log holds for one TLS session; empty if it has none.
struct SessionSecrets {
    SecretBytes masterSecret;           ///< TLS 1.2: CLIENT_RANDOM.
    SecretBytes clientHandshakeTraffic; ///< TLS 1.3: CLIENT_HANDSHAKE_TRAFFIC_SECRET.
    SecretBytes serverHandshakeTraffic; ///< TLS 1.3: SERVER_HANDSHAKE_TRAFFIC_SECRET.
    SecretBytes clientTraffic;          ///< TLS 1.3: CLIENT_TRAFFIC_SECRET_0.
    SecretBytes serverTraffic;          ///< TLS 1.3: SERVER_TRAFFIC_SECRET_0.
};

/**
 * The secrets of a key log, by client random.  Lines of other labels (the
 * early and exporter secrets, RSA pre-master secrets), comments and lines
 * that break the format are passed over.
 */
class KeyLog {
public:
    /// Take the secrets of the lines in the @p len bytes at @p text; a
    /// line may end in CR LF, the last one without a line feed.  A TLS 1.3
    /// secret is 32 or 48 bytes, as long as its hash; a TLS 1.2 master
    /// secret 48.  Returns the number of secrets taken.
    size_t addLines( const char* text, size_t len );

    /// The secrets of the session whose ClientHello has @p clientRandom,
    /// kRandomBytes of it; null if there are none.
    const SessionSecrets* find( const uint8_t* clientRandom ) const;

    /// Sessions the log holds secrets for.
    size_t sessions() const
    {
        return secrets_.size();
    }

private:
    std::map<ClientRandom, SessionSecrets> secrets_;
};

/**
 * A key log file, read when the conversion starts and again as it grows,
 * as the file of a live capture does while the browser writes it: a
 * session whose secrets are not there yet, or not all of a TLS 1.3
 * session's, reads what was added, at most every kRereadInterval and only
 * when the file grew.  A last line without its line feed is not read until
 * it has one: it may be half written.  Read only: the file is never
 * written, copied or kept open.
 */
class KeyLogFile {
public:
    /// Bytes of a key log read at most, some 350,000 sessions.
    static constexpr int64_t kMaxBytes = 64 * 1024 * 1024;
    /// How often at most the file is read again for a session's secrets.
    static constexpr std::chrono::milliseconds kRereadInterval{ 500 };

    /// The key log at @p path, read now.
    explicit KeyLogFile( const QString& path );

    /// Whether the file could be read; error() says why not.
    bool readable() const
    {
        return error_.isEmpty();
    }
    /// Why the file could not be read: never any of its contents.
    const QString& error() const
    {
        return error_;
    }

    /// The secrets of a session, reading what the file has gained when
    /// there are none, or not all, and kRereadInterval has passed.
    const SessionSecrets* find( const uint8_t* clientRandom );

    /// Bytes of the file read so far, whole lines, reading what it has
    /// gained when kRereadInterval has passed.  A session not found is
    /// looked for again once this grew.
    int64_t bytesRead();

    /// Times the file was read, for the tests.
    int reads() const
    {
        return reads_;
    }

    const KeyLog& keys() const
    {
        return keys_;
    }

private:
    /// Read what the file has gained since the last read.
    void read();
    /// All the secrets a session of its kind needs are there.
    static bool complete( const SessionSecrets& secrets );

    QString path_;
    QString error_;
    KeyLog keys_;
    int64_t offset_ = 0;   ///< Bytes of the file read for good: whole lines.
    int64_t fileSize_ = 0; ///< The file's size when it was last read.
    int reads_ = 0;
    std::chrono::steady_clock::time_point lastRead_;
};

} // namespace tcpdump::tls
