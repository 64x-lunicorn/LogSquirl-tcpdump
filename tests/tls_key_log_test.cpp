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
 * @file tls_key_log_test.cpp
 * @brief BDD tests for the Key Log: the NSS key log format, lines it passes
 *        over, and a file that grows while it is read.
 */

#include <catch2/catch.hpp>

#include "tls_key_log.h"

#include <QFile>
#include <QTemporaryDir>

#include <chrono>
#include <string>

using namespace tcpdump::tls;

namespace {

const std::string kRandom( 64, 'a' );  // 0xaa…
const std::string kRandom2( 64, 'B' ); // 0xbb…, upper case
const std::string kMaster( 96, '1' );  // 48 bytes
const std::string kTraffic( 64, '2' ); // 32 bytes

ClientRandom randomOf( uint8_t byte )
{
    ClientRandom random;
    random.fill( byte );
    return random;
}

size_t add( KeyLog& log, const std::string& text )
{
    return log.addLines( text.data(), text.size() );
}

/// A clock that stands still until the test moves it on, for the
/// interval between two reads of a key log.
struct StillClock {
    std::chrono::steady_clock::time_point at;
    KeyLogFile::Clock clock()
    {
        return [ this ] { return at; };
    }
    /// Moves it on by the interval, so that the next look reads again.
    void passInterval()
    {
        at += KeyLogFile::kRereadInterval;
    }
};

} // namespace

SCENARIO( "The key log takes the secrets of TLS 1.2 and 1.3 sessions", "[tls][keylog]" )
{
    GIVEN( "lines of both, with a comment, CR LF and a last line without its line feed" )
    {
        KeyLog log;
        const auto taken = add( log, "# SSL/TLS secrets log file\n"
                                     "CLIENT_RANDOM "
                                         + kRandom + " " + kMaster
                                         + "\r\n"
                                           "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
                                         + kRandom2 + " " + kTraffic
                                         + "\n"
                                           "SERVER_HANDSHAKE_TRAFFIC_SECRET "
                                         + kRandom2 + " " + kTraffic
                                         + "\n"
                                           "CLIENT_TRAFFIC_SECRET_0 "
                                         + kRandom2 + " " + kTraffic
                                         + "\n"
                                           "EXPORTER_SECRET "
                                         + kRandom2 + " " + kTraffic
                                         + "\n"
                                           "SERVER_TRAFFIC_SECRET_0 "
                                         + kRandom2 + " " + kTraffic );

        THEN( "each session has its secrets, by its client random" )
        {
            REQUIRE( taken == 5 );
            REQUIRE( log.sessions() == 2 );
            const auto* tls12 = log.find( randomOf( 0xAA ).data() );
            REQUIRE( tls12 );
            REQUIRE( tls12->masterSecret.size() == 48 );
            REQUIRE( tls12->masterSecret.data()[ 0 ] == 0x11 );
            const auto* tls13 = log.find( randomOf( 0xBB ).data() );
            REQUIRE( tls13 );
            REQUIRE( tls13->clientHandshakeTraffic.size() == 32 );
            REQUIRE( tls13->serverHandshakeTraffic.size() == 32 );
            REQUIRE( tls13->clientTraffic.size() == 32 );
            REQUIRE( tls13->serverTraffic.size() == 32 );
            REQUIRE( tls13->masterSecret.empty() );
            REQUIRE_FALSE( log.find( randomOf( 0xCC ).data() ) );
        }
    }

    GIVEN( "lines that break the format" )
    {
        KeyLog log;
        const auto taken = add( log, "CLIENT_RANDOM " + kRandom
                                         + "\n" // no secret
                                           "CLIENT_RANDOM "
                                         + kRandom.substr( 2 ) + " " + kMaster
                                         + "\n"
                                           "CLIENT_RANDOM "
                                         + kRandom + " " + kTraffic
                                         + "\n" // 32 bytes
                                           "CLIENT_RANDOM "
                                         + kRandom + " " + kMaster
                                         + "1\n"
                                           "CLIENT_RANDOM "
                                         + kRandom + " " + std::string( 96, 'g' )
                                         + "\n"
                                           "SERVER_TRAFFIC_SECRET_0 "
                                         + kRandom + " " + std::string( 98, '2' )
                                         + "\n" // 49 bytes
                                           "CLIENT_TRAFFIC_SECRET_0 "
                                         + kRandom + " " + std::string( 80, '2' )
                                         + "\n" // 40 bytes: no hash's
                                           "CLIENT_HANDSHAKE_TRAFFIC_SECRET "
                                         + kRandom + " " + std::string( 2, '2' )
                                         + "\n" // 1 byte
                                           "\n \n" );

        THEN( "none of them is taken" )
        {
            REQUIRE( taken == 0 );
            REQUIRE( log.sessions() == 0 );
        }
    }
}

SCENARIO( "A key log file is read again as it grows", "[tls][keylog]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    const auto path = dir.filePath( "keys.log" );

    GIVEN( "a file without the secrets of a session yet" )
    {
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( "# empty so far\n" );
        file.flush();
        StillClock time;
        KeyLogFile keyLog( path, time.clock() );
        REQUIRE( keyLog.readable() );
        REQUIRE_FALSE( keyLog.find( randomOf( 0xAA ).data() ) );

        WHEN( "the browser writes them, half a line first" )
        {
            const auto line = "CLIENT_RANDOM " + kRandom + " " + kMaster + "\n";
            file.write( line.substr( 0, 40 ).c_str() );
            file.flush();

            THEN( "the session is found once the line is whole, and the interval passed" )
            {
                time.passInterval();
                REQUIRE_FALSE( keyLog.find( randomOf( 0xAA ).data() ) );
                file.write( line.substr( 40 ).c_str() );
                file.flush();
                // Not before the interval since the last read has passed.
                time.at += KeyLogFile::kRereadInterval / 2;
                REQUIRE_FALSE( keyLog.find( randomOf( 0xAA ).data() ) );
                time.passInterval();
                const auto* secrets = keyLog.find( randomOf( 0xAA ).data() );
                REQUIRE( secrets );
                REQUIRE( secrets->masterSecret.size() == 48 );
            }
        }
    }

    GIVEN( "a TLS 1.3 session's handshake secrets, its traffic secret half written" )
    {
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        const std::string master( 96, '3' ); // 48 bytes, SHA-384
        file.write( ( "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + kRandom + " " + master + "\n"
                      + "SERVER_HANDSHAKE_TRAFFIC_SECRET " + kRandom + " " + master + "\n"
                      + "CLIENT_TRAFFIC_SECRET_0 " + kRandom + " " + master.substr( 0, 64 ) )
                        .c_str() );
        file.flush();
        StillClock time;
        KeyLogFile keyLog( path, time.clock() );

        THEN( "the half line is not taken, though it would make a SHA-256 secret" )
        {
            const auto* secrets = keyLog.find( randomOf( 0xAA ).data() );
            REQUIRE( secrets );
            REQUIRE( secrets->clientHandshakeTraffic.size() == 48 );
            REQUIRE( secrets->clientTraffic.empty() );
        }

        WHEN( "the rest of the line and the server's traffic secret are written" )
        {
            REQUIRE( keyLog.find( randomOf( 0xAA ).data() ) );
            file.write( ( master.substr( 64 ) + "\nSERVER_TRAFFIC_SECRET_0 " + kRandom + " "
                          + master + "\n" )
                            .c_str() );
            file.flush();
            time.passInterval();

            THEN( "they are read for the session that has some of its secrets already" )
            {
                const auto* secrets = keyLog.find( randomOf( 0xAA ).data() );
                REQUIRE( secrets );
                REQUIRE( secrets->clientTraffic.size() == 48 );
                REQUIRE( secrets->serverTraffic.size() == 48 );
            }
        }
    }

    GIVEN( "a file that does not grow" )
    {
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( "# nothing\n" );
        file.flush();
        StillClock time;
        KeyLogFile keyLog( path, time.clock() );
        const auto read = keyLog.bytesRead();

        THEN( "it is not read again, however often a session is looked for" )
        {
            time.passInterval();
            REQUIRE_FALSE( keyLog.find( randomOf( 0xAA ).data() ) );
            REQUIRE( keyLog.reads() == 1 );
            REQUIRE( keyLog.bytesRead() == read );
        }
    }

    GIVEN( "a path where there is no file" )
    {
        KeyLogFile keyLog( dir.filePath( "missing.log" ) );

        THEN( "it is not readable, and says why without any contents" )
        {
            REQUIRE_FALSE( keyLog.readable() );
            REQUIRE( keyLog.error().startsWith( "Cannot read the TLS key log" ) );
            REQUIRE_FALSE( keyLog.find( randomOf( 0xAA ).data() ) );
        }
    }
}
