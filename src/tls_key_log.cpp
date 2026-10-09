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
 * @file tls_key_log.cpp
 * @brief Implementation of the Key Log.
 */

#include "tls_key_log.h"

#include <QFile>

#include <algorithm>
#include <cstring>
#include <optional>
#include <string_view>

namespace tcpdump::tls {

namespace {

/// The longest secret a line may hold: a SHA-384 traffic secret, or a
/// TLS 1.2 master secret, 48 bytes.
constexpr size_t kMaxSecretBytes = 48;

int hexDigit( char c )
{
    if ( c >= '0' && c <= '9' ) {
        return c - '0';
    }
    if ( c >= 'a' && c <= 'f' ) {
        return c - 'a' + 10;
    }
    if ( c >= 'A' && c <= 'F' ) {
        return c - 'A' + 10;
    }
    return -1;
}

/// The bytes the hexadecimal @p hex spells into @p out, @p bytes of them.
bool fromHex( std::string_view hex, uint8_t* out, size_t bytes )
{
    if ( hex.size() != 2 * bytes ) {
        return false;
    }
    for ( size_t i = 0; i < bytes; ++i ) {
        const int high = hexDigit( hex[ 2 * i ] );
        const int low = hexDigit( hex[ 2 * i + 1 ] );
        if ( high < 0 || low < 0 ) {
            return false;
        }
        out[ i ] = static_cast<uint8_t>( high << 4 | low );
    }
    return true;
}

/// Where a label's secret goes in SessionSecrets.
SecretBytes* slotOf( SessionSecrets& secrets, std::string_view label )
{
    if ( label == "CLIENT_RANDOM" ) {
        return &secrets.masterSecret;
    }
    if ( label == "CLIENT_HANDSHAKE_TRAFFIC_SECRET" ) {
        return &secrets.clientHandshakeTraffic;
    }
    if ( label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" ) {
        return &secrets.serverHandshakeTraffic;
    }
    if ( label == "CLIENT_TRAFFIC_SECRET_0" ) {
        return &secrets.clientTraffic;
    }
    if ( label == "SERVER_TRAFFIC_SECRET_0" ) {
        return &secrets.serverTraffic;
    }
    return nullptr;
}

bool knownLabel( std::string_view label )
{
    SessionSecrets probe;
    return slotOf( probe, label ) != nullptr;
}

} // namespace

size_t KeyLog::addLines( const char* text, size_t len )
{
    size_t taken = 0;
    std::string_view rest( text, len );
    while ( !rest.empty() ) {
        const auto eol = rest.find( '\n' );
        auto line = rest.substr( 0, eol );
        rest = eol == std::string_view::npos ? std::string_view() : rest.substr( eol + 1 );
        if ( !line.empty() && line.back() == '\r' ) {
            line.remove_suffix( 1 );
        }
        // <label> <client random> <secret>
        const auto space1 = line.find( ' ' );
        if ( space1 == std::string_view::npos ) {
            continue;
        }
        const auto space2 = line.find( ' ', space1 + 1 );
        if ( space2 == std::string_view::npos ) {
            continue;
        }
        const auto label = line.substr( 0, space1 );
        const auto randomHex = line.substr( space1 + 1, space2 - space1 - 1 );
        const auto secretHex = line.substr( space2 + 1 );
        ClientRandom random{};
        if ( !knownLabel( label ) || !fromHex( randomHex, random.data(), random.size() )
             || secretHex.size() % 2 != 0 || secretHex.size() / 2 > kMaxSecretBytes ) {
            continue;
        }
        SecretBytes secret( secretHex.size() / 2 );
        if ( secret.empty() || !fromHex( secretHex, secret.data(), secret.size() )
             || ( label == "CLIENT_RANDOM" && secret.size() != kMaxSecretBytes ) ) {
            continue;
        }
        *slotOf( secrets_[ random ], label ) = std::move( secret );
        ++taken;
    }
    return taken;
}

const SessionSecrets* KeyLog::find( const uint8_t* clientRandom ) const
{
    ClientRandom random;
    std::copy( clientRandom, clientRandom + kRandomBytes, random.begin() );
    const auto it = secrets_.find( random );
    return it == secrets_.end() ? nullptr : &it->second;
}

// ── KeyLogFile ───────────────────────────────────────────────────────────

KeyLogFile::KeyLogFile( const QString& path )
    : path_( path )
{
    read();
}

void KeyLogFile::read()
{
    lastRead_ = std::chrono::steady_clock::now();
    QFile file( path_ );
    if ( !file.open( QIODevice::ReadOnly ) ) {
        error_ = QStringLiteral( "Cannot read the TLS key log: %1" ).arg( file.errorString() );
        return;
    }
    error_.clear();
    const auto size = std::min( file.size(), kMaxBytes );
    if ( size <= offset_ || !file.seek( offset_ ) ) {
        return;
    }
    auto bytes = file.read( size - offset_ );
    // The whole lines are read for good.  A last line without its line
    // feed may still be being written: it is taken if it holds a secret,
    // and read again, whole, with what comes after it.
    const auto end = bytes.lastIndexOf( '\n' ) + 1;
    keys_.addLines( bytes.constData(), static_cast<size_t>( bytes.size() ) );
    offset_ += end;
    wipe( bytes.data(), static_cast<size_t>( bytes.size() ) );
}

const SessionSecrets* KeyLogFile::find( const uint8_t* clientRandom )
{
    if ( const auto* secrets = keys_.find( clientRandom ) ) {
        return secrets;
    }
    if ( std::chrono::steady_clock::now() - lastRead_ < kRereadInterval ) {
        return nullptr;
    }
    read();
    return keys_.find( clientRandom );
}

} // namespace tcpdump::tls
