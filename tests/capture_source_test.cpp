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
 * @file capture_source_test.cpp
 * @brief BDD tests for reading a capture from a stream as it is written.
 *
 * A synthetic capture is fed through a pipe by a writer thread, in chunks
 * and with pauses, as tcpdump writes one; what is read must be what the
 * same capture gives from a file.
 */

#include <catch2/catch.hpp>

#include <QtGlobal>

#ifdef Q_OS_UNIX

#include "capture_reader.h"
#include "capture_source.h"
#include "pcap_converter.h"
#include "pcapbuilder.h"

#include <QDir>
#include <QFile>
#include <QProcess>
#include <QTemporaryDir>

#include <atomic>
#include <chrono>
#include <thread>

#include <unistd.h>

using namespace tcpdump;
using namespace tcpdump_test;
using Clock = std::chrono::steady_clock;
using std::chrono::milliseconds;

namespace {

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

/// Writes @p capture into @p pipe in chunks of @p chunk bytes (0: the
/// records as they are, @p cuts), pausing now and then, then closes it.
std::thread writeInChunks( Pipe& pipe, Bytes capture, size_t chunk, std::vector<size_t> cuts = {} )
{
    return std::thread( [ &pipe, capture = std::move( capture ), chunk, cuts ] {
        size_t at = 0;
        size_t written = 0;
        while ( at < capture.size() ) {
            size_t end = capture.size();
            if ( chunk > 0 ) {
                end = std::min( at + chunk, capture.size() );
            }
            else {
                for ( const auto cut : cuts ) {
                    if ( cut > at ) {
                        end = std::min( end, cut );
                        break;
                    }
                }
            }
            pipe.write( Bytes( capture.begin() + static_cast<std::ptrdiff_t>( at ),
                               capture.begin() + static_cast<std::ptrdiff_t>( end ) ) );
            at = end;
            if ( ++written % 40 == 0 || chunk == 0 ) {
                std::this_thread::sleep_for( milliseconds( 5 ) );
            }
        }
        pipe.closeWrite();
    } );
}

/// Sets @p stop after @p after unless @p done is set first: a test that
/// would hang ends, and shows that it was stopped.
std::thread watchdog( std::atomic_bool& stop, const std::atomic_bool& done,
                      milliseconds after = milliseconds( 3000 ) )
{
    return std::thread( [ &stop, &done, after ] {
        const auto until = Clock::now() + after;
        while ( !done && Clock::now() < until ) {
            std::this_thread::sleep_for( milliseconds( 5 ) );
        }
        if ( !done ) {
            stop = true;
        }
    } );
}

QStringList readLines( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly | QIODevice::Text ) );
    auto lines = QString::fromUtf8( file.readAll() ).split( '\n' );
    if ( !lines.isEmpty() && lines.last().isEmpty() ) {
        lines.removeLast();
    }
    return lines;
}

/// The lines convertPcap() writes for @p capture as a file.
QStringList linesFromFile( const Bytes& capture )
{
    QTemporaryDir dir;
    const auto path = dir.filePath( QStringLiteral( "capture.pcap" ) );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( capture.data() ),
                static_cast<qint64>( capture.size() ) );
    file.close();
    const auto result = convertPcap( path, dir.path() );
    REQUIRE( result.status == ConversionResult::Status::Converted );
    return readLines( result.outputPath );
}

/// A conversation over TCP and a DNS-like datagram: enough for streams,
/// analysis and descriptions to show in the lines.
std::vector<Bytes> somePackets()
{
    return {
        eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 80, {}, 5, 0x02, 100 ) ) ),
        eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 80, text( "GET / HTTP/1.1\r\n\r\n" ), 5,
                                                   0x18, 101, 1 ) ) ),
        eth( EthertypeIpv4, ipv4( IpProtoUdp, udp( 5353, 9999, text( "hello stream" ) ) ) ),
        eth( EthertypeIpv4, ipv4( IpProtoTcp, tcp( 40000, 80, {}, 5, 0x11, 119, 1 ) ) ),
    };
}

Bytes somePcapng()
{
    Pcapng le;
    Bytes file = le.shb() + le.idb( DltEthernet, 9 );
    uint64_t ts = 1000000000000;
    for ( const auto& p : somePackets() ) {
        file = file + le.epb( 0, ts, p );
        ts += 1500000;
    }
    return file;
}

/// Where each record of a pcap of @p packets starts, and its end.
std::vector<size_t> recordCuts( const std::vector<Bytes>& packets )
{
    std::vector<size_t> cuts{ 24 };
    for ( const auto& p : packets ) {
        cuts.push_back( cuts.back() + 16 + p.size() );
    }
    return cuts;
}

} // namespace

SCENARIO( "A capture read from a pipe gives the lines it gives from a file", "[capture_source]" )
{
    const auto packets = somePackets();
    const std::pair<const char*, Bytes> captures[] = {
        { "pcap", pcapOf( packets ) },
        { "pcapng", somePcapng() },
    };
    for ( const auto& [ format, capture ] : captures ) {
        for ( const size_t chunk : { size_t( 1 ), size_t( 7 ), size_t( 0 ) } ) {
            GIVEN( std::string( "a " ) + format + " written into a pipe in chunks of "
                   + ( chunk ? std::to_string( chunk ) + " bytes" : "whole records" )
                   + ", with pauses" )
            {
                const auto expected = linesFromFile( capture );
                Pipe pipe;
                auto writer
                    = writeInChunks( pipe, capture, chunk,
                                     std::string( format ) == "pcap" ? recordCuts( packets )
                                                                     : std::vector<size_t>{} );
                QTemporaryDir out;
                FdSource source( pipe.readEnd() );
                const auto result = convertStream( source, QStringLiteral( "live" ), out.path() );
                writer.join();

                THEN( "it is converted to the same lines, once the writer closes it" )
                {
                    REQUIRE( result.status == ConversionResult::Status::Converted );
                    REQUIRE( QFileInfo( result.outputPath ).fileName() == "live.log" );
                    REQUIRE( readLines( result.outputPath ) == expected );
                    REQUIRE( result.summary.packets == packets.size() );
                    REQUIRE_FALSE( result.summary.endsInsideRecord );
                }
            }
        }
    }
}

SCENARIO( "A stream's format is decided by its header, without waiting for more",
          "[capture_source]" )
{
    const auto packets = somePackets();
    const auto pcap = pcapOf( packets );
    Pcapng le;
    const auto pcapngHead = le.shb() + le.idb( DltEthernet, 9 );
    const auto preamble = text( "tcpdump: listening on eth0, link-type EN10MB\n" );
    const std::pair<const char*, Bytes> heads[] = {
        { "a pcap's global header", Bytes( pcap.begin(), pcap.begin() + 24 ) },
        { "a pcapng's section header and interface", pcapngHead },
        { "a pcap's global header behind tcpdump's stderr",
          preamble + Bytes( pcap.begin(), pcap.begin() + 24 ) },
    };
    for ( const auto& [ what, head ] : heads ) {
        GIVEN( std::string( "a writer that has sent " ) + what + " and pauses" )
        {
            Pipe pipe;
            pipe.write( head );
            std::atomic_bool stop{ false };
            std::atomic_bool done{ false };
            auto guard = watchdog( stop, done );
            FdSource source( pipe.readEnd(), &stop );
            HeadSource headSource( source );

            WHEN( "the reader is chosen and opened" )
            {
                const auto reader = makeCaptureReader( headSource );
                const bool opened = reader->open();
                done = true;
                guard.join();

                THEN( "it opens on the header alone, and reads the packets once they come" )
                {
                    REQUIRE_FALSE( stop );
                    REQUIRE( opened );
                    REQUIRE( reader->linkTypes() == std::vector<uint32_t>{ DltEthernet } );

                    if ( head == pcapngHead ) {
                        Bytes rest;
                        uint64_t ts = 1000000000000;
                        for ( const auto& p : packets ) {
                            rest = rest + le.epb( 0, ts++, p );
                        }
                        pipe.write( rest );
                        REQUIRE( reader->precision() == TimePrecision::Nanoseconds );
                    }
                    else {
                        pipe.write( Bytes( pcap.begin() + 24, pcap.end() ) );
                    }
                    pipe.closeWrite();
                    PacketRecord pkt;
                    size_t count = 0;
                    while ( reader->next( pkt ) ) {
                        ++count;
                    }
                    REQUIRE( count == packets.size() );
                    REQUIRE_FALSE( reader->truncated() );
                }
            }
            done = true;
            if ( guard.joinable() ) {
                guard.join();
            }
        }
    }

    GIVEN( "a writer that has sent bytes that are no capture, and pauses" )
    {
        Pipe pipe;
        pipe.write( Bytes( 30, 0xFF ) );
        std::atomic_bool stop{ false };
        std::atomic_bool done{ false };
        auto guard = watchdog( stop, done );
        FdSource source( pipe.readEnd(), &stop );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "live" ), out.path(), &stop );
        done = true;
        guard.join();

        THEN( "the conversion fails at once: not a capture" )
        {
            REQUIRE_FALSE( stop );
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "Not a valid pcap or pcapng file" ) );
            REQUIRE( QDir( out.path() ).isEmpty() );
        }
    }
}

SCENARIO( "Stopping a stream that sends nothing ends the wait within 100 ms", "[capture_source]" )
{
    GIVEN( "a pipe that has sent a pcap header and then nothing" )
    {
        Pipe pipe;
        pipe.write( pcapOf( {} ) );
        std::atomic_bool cancel{ false };
        Clock::time_point cancelledAt;
        std::thread canceller( [ &cancel, &cancelledAt ] {
            std::this_thread::sleep_for( milliseconds( 300 ) );
            cancelledAt = Clock::now();
            cancel = true;
        } );

        WHEN( "the conversion waiting for the first packet is cancelled" )
        {
            FdSource source( pipe.readEnd(), &cancel );
            QTemporaryDir out;
            const auto result
                = convertStream( source, QStringLiteral( "live" ), out.path(), &cancel );
            const auto returnedAt = Clock::now();
            canceller.join();

            THEN( "it returns within 100 ms of the request, Cancelled, leaving nothing" )
            {
                REQUIRE( returnedAt - cancelledAt < milliseconds( 100 ) );
                REQUIRE( source.stopped() );
                REQUIRE( result.status == ConversionResult::Status::Cancelled );
                REQUIRE( QDir( out.path() ).isEmpty() );
            }
        }
        if ( canceller.joinable() ) {
            canceller.join();
        }
    }

    GIVEN( "a pipe that has sent nothing at all" )
    {
        Pipe pipe;
        std::atomic_bool stop{ false };
        Clock::time_point stoppedAt;
        std::thread stopper( [ &stop, &stoppedAt ] {
            std::this_thread::sleep_for( milliseconds( 200 ) );
            stoppedAt = Clock::now();
            stop = true;
        } );
        FdSource source( pipe.readEnd(), &stop );
        uint8_t byte = 0;
        const auto got = source.read( &byte, 1 );
        const auto returnedAt = Clock::now();
        stopper.join();

        THEN( "a read returns nothing within 100 ms of the stop, and stays ended" )
        {
            REQUIRE( got == 0 );
            REQUIRE( returnedAt - stoppedAt < milliseconds( 100 ) );
            REQUIRE( source.stopped() );
            REQUIRE( source.error().empty() );
            pipe.write( text( "late" ) );
            REQUIRE( source.read( &byte, 1 ) == 0 );
        }
    }
}

SCENARIO( "The end of a stream ends its capture", "[capture_source]" )
{
    const auto packets = somePackets();
    const auto pcap = pcapOf( packets );

    GIVEN( "a stream closed in the middle of its third record" )
    {
        const auto cuts = recordCuts( packets );
        Pipe pipe;
        auto writer = writeInChunks(
            pipe,
            Bytes( pcap.begin(), pcap.begin() + static_cast<std::ptrdiff_t>( cuts[ 2 ] + 20 ) ),
            7 );
        FdSource source( pipe.readEnd() );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "live" ), out.path() );
        writer.join();

        THEN( "the two whole records are converted, and the capture reported cut off" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == 2 );
            REQUIRE( result.summary.endsInsideRecord );
            REQUIRE( readLines( result.outputPath ).size() == 3 ); // header + 2 packets
        }
    }

    GIVEN( "a stream closed before a whole header" )
    {
        Pipe pipe;
        pipe.write( Bytes( pcap.begin(), pcap.begin() + 10 ) );
        pipe.closeWrite();
        FdSource source( pipe.readEnd() );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "live" ), out.path() );

        THEN( "it fails as too small to be a capture" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "too small" ) );
        }
    }

    GIVEN( "a stream of text that never reaches a header" )
    {
        Pipe pipe;
        pipe.write(
            text( "tcpdump: eth0: You don't have permission to capture on that device\n" ) );
        pipe.closeWrite();
        FdSource source( pipe.readEnd() );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "live" ), out.path() );

        THEN( "it fails: not a capture" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error.contains( "Not a valid pcap or pcapng file" ) );
        }
    }
}

SCENARIO( "A process's stdout is read as a stream", "[capture_source]" )
{
    const auto capture = pcapOf( somePackets() );
    QTemporaryDir dir;
    const auto path = dir.filePath( QStringLiteral( "in.pcap" ) );
    {
        QFile file( path );
        REQUIRE( file.open( QIODevice::WriteOnly ) );
        file.write( reinterpret_cast<const char*>( capture.data() ),
                    static_cast<qint64>( capture.size() ) );
    }

    GIVEN( "a process that writes a capture in two parts with a pause, and exits" )
    {
        QProcess process;
        process.start( QStringLiteral( "/bin/sh" ),
                       { QStringLiteral( "-c" ),
                         QStringLiteral( "head -c 30 \"$1\"; sleep 0.2; tail -c +31 \"$1\"" ),
                         QStringLiteral( "sh" ), path } );
        DeviceSource source( process );
        QTemporaryDir out;
        const auto result = convertStream( source, QStringLiteral( "live" ), out.path() );
        process.waitForFinished();

        THEN( "it gives the lines of the file" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( readLines( result.outputPath ) == linesFromFile( capture ) );
        }
    }

    GIVEN( "a process that writes nothing for seconds" )
    {
        QProcess process;
        process.start( QStringLiteral( "/bin/sleep" ), { QStringLiteral( "5" ) } );
        REQUIRE( process.waitForStarted() );
        std::atomic_bool stop{ false };
        Clock::time_point stoppedAt;
        std::thread stopper( [ &stop, &stoppedAt ] {
            std::this_thread::sleep_for( milliseconds( 200 ) );
            stoppedAt = Clock::now();
            stop = true;
        } );
        DeviceSource source( process, &stop );
        uint8_t byte = 0;
        const auto got = source.read( &byte, 1 );
        const auto returnedAt = Clock::now();
        stopper.join();
        process.kill();
        process.waitForFinished();

        THEN( "a stop ends the wait within 100 ms" )
        {
            REQUIRE( got == 0 );
            REQUIRE( source.stopped() );
            REQUIRE( returnedAt - stoppedAt < milliseconds( 100 ) );
        }
    }
}

#endif // Q_OS_UNIX
