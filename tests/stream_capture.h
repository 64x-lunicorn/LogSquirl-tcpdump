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
 * @file stream_capture.h
 * @brief A capture to stream, and the lines it gives as a file, for the
 *        tests of the Capture Sources.
 */

#pragma once

#include "capture_source.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"

#include <catch2/catch.hpp>

#include <QFile>
#include <QString>
#include <QStringList>
#include <QTemporaryDir>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

#ifdef Q_OS_UNIX
#include <unistd.h>
#endif

namespace tcpdump_test {

/// The lines of the text file @p path.
inline QStringList readLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    if ( !lines.isEmpty() && lines.last().isEmpty() ) {
        lines.removeLast();
    }
    return lines;
}

/// Write @p bytes into the file @p path.
inline void writeFile( const QString& path, const Bytes& bytes )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( bytes.data() ),
                static_cast<qint64>( bytes.size() ) );
}

/// The lines convertPcap() writes for @p capture as a file.
inline QStringList linesFromFile( const Bytes& capture )
{
    QTemporaryDir dir;
    const auto path = dir.filePath( QStringLiteral( "capture.pcap" ) );
    writeFile( path, capture );
    const auto result = tcpdump::convertPcap( path, dir.path() );
    REQUIRE( result.status == tcpdump::ConversionResult::Status::Converted );
    return readLines( result.outputPath );
}

/// A conversation over TCP and a DNS-like datagram: enough for streams,
/// analysis and descriptions to show in the lines.
inline std::vector<Bytes> somePackets()
{
    return {
        eth( tcpdump::EthertypeIpv4,
             ipv4( tcpdump::IpProtoTcp, tcp( 40000, 80, {}, 5, 0x02, 100 ) ) ),
        eth( tcpdump::EthertypeIpv4,
             ipv4( tcpdump::IpProtoTcp,
                   tcp( 40000, 80, text( "GET / HTTP/1.1\r\n\r\n" ), 5, 0x18, 101, 1 ) ) ),
        eth( tcpdump::EthertypeIpv4,
             ipv4( tcpdump::IpProtoUdp, udp( 5353, 9999, text( "hello stream" ) ) ) ),
        eth( tcpdump::EthertypeIpv4,
             ipv4( tcpdump::IpProtoTcp, tcp( 40000, 80, {}, 5, 0x11, 119, 1 ) ) ),
    };
}

/// A StreamSource that hands out its bytes, then breaks off with an error.
class BreakingSource : public tcpdump::StreamSource {
public:
    BreakingSource( Bytes bytes, std::string error )
        : bytes_( std::move( bytes ) )
        , failure_( std::move( error ) )
    {
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds ) override
    {
        if ( at_ == bytes_.size() ) {
            error_ = failure_;
            return 0;
        }
        n = std::min( n, bytes_.size() - at_ );
        std::copy_n( bytes_.begin() + static_cast<std::ptrdiff_t>( at_ ), n, dst );
        at_ += n;
        return static_cast<std::ptrdiff_t>( n );
    }
    bool available() override
    {
        return true;
    }

private:
    Bytes bytes_;
    std::string failure_;
    size_t at_ = 0;
};

#ifdef Q_OS_UNIX
/// A pipe; either end is closed at most once, and when it goes.
class Pipe {
public:
    Pipe()
    {
        REQUIRE( ::pipe( fds_ ) == 0 );
    }
    ~Pipe()
    {
        closeRead();
        closeWrite();
    }
    Pipe( const Pipe& ) = delete;
    Pipe& operator=( const Pipe& ) = delete;

    int readEnd() const
    {
        return fds_[ 0 ];
    }

    /// Write all of @p bytes.
    void write( const Bytes& bytes ) const
    {
        size_t done = 0;
        while ( done < bytes.size() ) {
            const auto n = ::write( fds_[ 1 ], bytes.data() + done, bytes.size() - done );
            if ( n <= 0 ) {
                return; // the reader is gone
            }
            done += static_cast<size_t>( n );
        }
    }

    void closeWrite()
    {
        if ( fds_[ 1 ] >= 0 ) {
            ::close( fds_[ 1 ] );
            fds_[ 1 ] = -1;
        }
    }

    void closeRead()
    {
        if ( fds_[ 0 ] >= 0 ) {
            ::close( fds_[ 0 ] );
            fds_[ 0 ] = -1;
        }
    }

private:
    int fds_[ 2 ] = { -1, -1 };
};
#endif

} // namespace tcpdump_test
