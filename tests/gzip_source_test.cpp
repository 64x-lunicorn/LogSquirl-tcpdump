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
 * @file gzip_source_test.cpp
 * @brief BDD tests for reading gzip-compressed captures: the GzipSource,
 *        its access points, and the Converter, the Packet Panel's cursor and
 *        Export Packets on a `.pcap.gz`.
 */

#include <catch2/catch.hpp>

#include "capture_file.h"
#include "capture_index.h"
#include "capture_reader.h"
#include "gzip_source.h"
#include "gzip_writer.h"
#include "packet_export.h"
#include "pcap_converter.h"

#include <QDir>
#include <QFileInfo>
#include <QTemporaryDir>

#include <algorithm>
#include <random>
#include <vector>

using namespace tcpdump;
using tcpdump_test::fileBytes;
using tcpdump_test::gzipped;
using tcpdump_test::writeFile;

namespace {

/// Bytes that compress somewhat, as a capture's do: words of a small
/// alphabet with random bytes between them.
QByteArray sampleData( int size, unsigned seed = 51 )
{
    std::mt19937 random( seed );
    QByteArray data;
    data.reserve( size );
    while ( data.size() < size ) {
        const auto word = random() % 64;
        for ( unsigned i = 0; i < word % 9 + 2; ++i ) {
            data.append( static_cast<char>( 'a' + ( word + i ) % 26 ) );
        }
        data.append( static_cast<char>( random() & 0xff ) );
    }
    data.truncate( size );
    return data;
}

/// A MemorySource over @p bytes that counts the bytes read from it.
class CountingSource : public ByteSource {
public:
    explicit CountingSource( const QByteArray& bytes )
        : memory_( reinterpret_cast<const uint8_t*>( bytes.constData() ),
                   static_cast<size_t>( bytes.size() ) )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        const auto got = memory_.read( dst, n );
        bytesRead += got;
        return got;
    }

    bool seek( uint64_t offset ) override
    {
        return memory_.seek( offset );
    }

    uint64_t bytesRead = 0;

private:
    MemorySource memory_;
};

/// A CountingSource that hands out at most one byte per read, as a slow
/// pipe may.
class TrickleSource : public CountingSource {
public:
    using CountingSource::CountingSource;

    size_t read( uint8_t* dst, size_t n ) override
    {
        return CountingSource::read( dst, std::min<size_t>( n, 1 ) );
    }
};

/// Everything @p source returns, read @p chunk bytes at a time.
QByteArray readAll( ByteSource& source, size_t chunk )
{
    QByteArray all;
    std::vector<uint8_t> buffer( chunk );
    while ( const auto got = source.read( buffer.data(), buffer.size() ) ) {
        all.append( reinterpret_cast<const char*>( buffer.data() ), static_cast<int>( got ) );
    }
    return all;
}

QString corpus( const char* name )
{
    return QDir( QStringLiteral( TCPDUMP_CORPUS_DIR ) ).filePath( QString::fromLatin1( name ) );
}

ConversionResult convert( const QString& capture, const QString& outputRoot,
                          ConversionOptions options = {},
                          const std::function<void( int )>& progress = {} )
{
    return convertPcap( capture, outputRoot, nullptr, progress, options );
}

} // namespace

SCENARIO( "A gzip stream is told by its magic, also behind a text preamble", "[gzip]" )
{
    const auto stream = gzipped( "capture" );
    size_t offset = 99;

    WHEN( "a file starts with the gzip magic" )
    {
        THEN( "the stream starts at 0" )
        {
            REQUIRE( findGzipStart( reinterpret_cast<const uint8_t*>( stream.constData() ),
                                    static_cast<size_t>( stream.size() ), offset ) );
            REQUIRE( offset == 0 );
        }
    }

    WHEN( "text, such as tcpdump's stderr, comes ahead of it" )
    {
        const auto file = QByteArray( "tcpdump: listening on wlan0\r\n" ) + stream;
        THEN( "the stream starts behind the text" )
        {
            REQUIRE( findGzipStart( reinterpret_cast<const uint8_t*>( file.constData() ),
                                    static_cast<size_t>( file.size() ), offset ) );
            REQUIRE( offset == 29 );
        }
    }

    WHEN( "binary data, or a bare magic in text, comes instead" )
    {
        const auto binary = QByteArray( "\x01\x02", 2 ) + stream;
        const QByteArray bare( "text \x1f\x8b and more" );
        THEN( "there is no gzip stream" )
        {
            REQUIRE_FALSE( findGzipStart( reinterpret_cast<const uint8_t*>( binary.constData() ),
                                          static_cast<size_t>( binary.size() ), offset ) );
            REQUIRE_FALSE( findGzipStart( reinterpret_cast<const uint8_t*>( bare.constData() ),
                                          static_cast<size_t>( bare.size() ), offset ) );
        }
    }

    WHEN( "a pcap or pcapng capture starts the file" )
    {
        const auto pcap = fileBytes( corpus( "mixed.pcap" ) );
        const auto pcapng = fileBytes( corpus( "interfaces.pcapng" ) );
        THEN( "it is no gzip stream" )
        {
            REQUIRE_FALSE( findGzipStart( reinterpret_cast<const uint8_t*>( pcap.constData() ),
                                          static_cast<size_t>( pcap.size() ), offset ) );
            REQUIRE_FALSE( findGzipStart( reinterpret_cast<const uint8_t*>( pcapng.constData() ),
                                          static_cast<size_t>( pcapng.size() ), offset ) );
        }
    }

    WHEN( "gzip data is read where only a stream's capture can be" )
    {
        const auto result = parsePcap( reinterpret_cast<const uint8_t*>( stream.constData() ),
                                       static_cast<size_t>( stream.size() ) );
        THEN( "the error says it is gzip-compressed" )
        {
            REQUIRE_FALSE( result.ok );
            REQUIRE_THAT( result.error, Catch::Contains( "gzip-compressed" ) );
        }
    }
}

SCENARIO( "A gzip stream is decompressed on the fly", "[gzip]" )
{
    const auto data = sampleData( 300 * 1000 );

    for ( const int members : { 1, 3 } ) {
        GIVEN( std::to_string( members ) + " gzip member(s)" )
        {
            const auto compressed = gzipped( data, members );
            CountingSource input( compressed );
            GzipSource gzip( input );

            WHEN( "it is read in pieces of any size" )
            {
                const auto chunk = GENERATE( size_t( 1 ), size_t( 7 ), size_t( 65536 ) );
                const auto all = readAll( gzip, chunk );

                THEN( "it reads as the data, and all of the stream was consumed" )
                {
                    REQUIRE( all == data );
                    REQUIRE_FALSE( gzip.cutOff() );
                    REQUIRE( gzip.error().empty() );
                    REQUIRE( gzip.position() == static_cast<uint64_t>( data.size() ) );
                    REQUIRE( gzip.compressedRead() == static_cast<uint64_t>( compressed.size() ) );
                }
            }
        }
    }

    GIVEN( "a stream followed by bytes that start no member" )
    {
        const auto compressed = gzipped( data ) + QByteArray( 16, '\0' );
        CountingSource input( compressed );
        GzipSource gzip( input );

        THEN( "they are ignored, as gzip ignores trailing garbage" )
        {
            REQUIRE( readAll( gzip, 4096 ) == data );
            REQUIRE_FALSE( gzip.cutOff() );
        }
    }

    GIVEN( "a stream followed by garbage that begins as a member does, but not all of its "
           "magic and method" )
    {
        const auto garbage
            = GENERATE( QByteArray( "\x1f" ), QByteArray( "\x1f\x8b" ), QByteArray( "\x1f junk" ),
                        QByteArray( "\x1f\x8bjunk" ), QByteArray( "\x1f\x8b\x07junk" ) );
        const auto compressed = gzipped( data ) + garbage;
        CountingSource input( compressed );
        GzipSource gzip( input );

        THEN( "it is ignored too, not reported as corrupt" )
        {
            REQUIRE( readAll( gzip, 4096 ) == data );
            REQUIRE_FALSE( gzip.cutOff() );
            REQUIRE( gzip.error().empty() );
        }
    }

    GIVEN( "members and trailing garbage from a source that hands out one byte at a time" )
    {
        const auto compressed = gzipped( data, 3 ) + QByteArray( "\x1f\x8bjunk" );
        TrickleSource input( compressed );
        GzipSource gzip( input );

        THEN( "every member is read, the garbage ignored" )
        {
            REQUIRE( readAll( gzip, 65536 ) == data );
            REQUIRE_FALSE( gzip.cutOff() );
        }
    }
}

SCENARIO( "A gzip stream that is cut off or corrupt ends there", "[gzip]" )
{
    const auto data = sampleData( 200 * 1000 );
    const auto compressed = gzipped( data, 2 );

    GIVEN( "a stream cut off in the middle" )
    {
        const auto cut = compressed.left( compressed.size() / 2 );
        CountingSource input( cut );
        GzipSource gzip( input );
        const auto all = readAll( gzip, 4096 );

        THEN( "what comes before reads as the data, and the stream is cut off" )
        {
            REQUIRE( all.size() > 0 );
            REQUIRE( all.size() < data.size() );
            REQUIRE( data.startsWith( all ) );
            REQUIRE( gzip.cutOff() );
            REQUIRE( gzip.error() == "the gzip stream is cut off" );
        }
    }

    GIVEN( "a stream whose check value does not match" )
    {
        auto corrupt = compressed;
        corrupt[ corrupt.size() - 6 ] = static_cast<char>( corrupt[ corrupt.size() - 6 ] ^ 0x55 );
        CountingSource input( corrupt );
        GzipSource gzip( input );
        const auto all = readAll( gzip, 4096 );

        THEN( "the data is read, and then the stream is reported corrupt" )
        {
            REQUIRE( all == data );
            REQUIRE( gzip.cutOff() );
            REQUIRE_THAT( gzip.error(), Catch::StartsWith( "the gzip data is corrupt (" ) );
        }
    }

    GIVEN( "a stream with an unknown compression method" )
    {
        auto corrupt = compressed;
        corrupt[ 2 ] = 7;
        CountingSource input( corrupt );
        GzipSource gzip( input );

        THEN( "nothing is read and the stream is reported corrupt" )
        {
            REQUIRE( readAll( gzip, 4096 ).isEmpty() );
            REQUIRE( gzip.cutOff() );
            REQUIRE_THAT( gzip.error(), Catch::Contains( "corrupt" ) );
        }
    }
}

SCENARIO( "Mangled gzip never breaks the source", "[gzip][fuzz]" )
{
    const auto data = sampleData( 20 * 1000 );
    const auto compressed = gzipped( data, 2, 4096 );

    GIVEN( "the stream cut at every length" )
    {
        THEN( "what is read is the data's beginning, and the stream is cut off unless it ends "
              "after a whole member, or in the first two bytes of the next, which are not yet "
              "one" )
        {
            const auto firstMember = gzipped( data.left( data.size() / 2 ), 1, 4096 ).size();
            for ( qsizetype n = 0; n < compressed.size(); ++n ) {
                // Kept: the source reads the bytes in place, not a copy.
                const auto cut = compressed.left( n );
                CountingSource input( cut );
                GzipSource gzip( input );
                const auto all = readAll( gzip, 4096 );
                REQUIRE( data.startsWith( all ) );
                INFO( n << " of " << compressed.size() << ", first member " << firstMember );
                REQUIRE( gzip.cutOff() == ( n < firstMember || n > firstMember + 2 ) );
            }
        }
    }

    GIVEN( "the stream with random bytes changed, cut anywhere, read with access points kept" )
    {
        THEN( "it reads as the data's beginning, or is reported cut off" )
        {
            std::mt19937 random( 1952 );
            for ( int round = 0; round < 400; ++round ) {
                auto mutated = compressed;
                const auto changes = 1 + random() % 4;
                for ( unsigned c = 0; c < changes; ++c ) {
                    mutated[ static_cast<qsizetype>( random() % mutated.size() ) ]
                        = static_cast<char>( random() );
                }
                mutated.truncate( static_cast<qsizetype>( random() % ( mutated.size() + 1 ) ) );
                CountingSource input( mutated );
                GzipSource gzip( input );
                gzip.keepAccessPoints( 1024 );
                const auto all = readAll( gzip, 1 + random() % 8192 );
                REQUIRE( all.size() <= 1032 * mutated.size() ); // deflate's ratio at most
                if ( !gzip.cutOff() ) {
                    REQUIRE( data.startsWith( all ) );
                }
                else {
                    REQUIRE_FALSE( gzip.error().empty() );
                }
            }
        }
    }
}

SCENARIO( "Access points let a gzip stream be read from anywhere", "[gzip]" )
{
    const auto data = sampleData( 1024 * 1024 );
    constexpr uint64_t span = 64 * 1024;

    for ( const int members : { 1, 4 } ) {
        GIVEN( std::to_string( members ) + " gzip member(s), read once with access points kept" )
        {
            const auto compressed = gzipped( data, members, 10000 );
            CountingSource first( compressed );
            GzipSource reading( first );
            reading.keepAccessPoints( span );
            REQUIRE( readAll( reading, 65536 ) == data );
            const auto points = reading.accessPoints();
            REQUIRE( points );
            REQUIRE( points->points().size() >= 10 );
            for ( size_t i = 1; i < points->points().size(); ++i ) {
                REQUIRE( points->points()[ i ].out >= points->points()[ i - 1 ].out + span );
            }

            WHEN( "another source of the stream seeks with them, back and forth" )
            {
                CountingSource input( compressed );
                GzipSource gzip( input );
                gzip.useAccessPoints( points );

                std::mt19937 random( 7 );
                std::vector<uint64_t> offsets{ static_cast<uint64_t>( data.size() ) - 1000, 0,
                                               span * 3 + 5, span * 3 + 4 };
                for ( int i = 0; i < 30; ++i ) {
                    offsets.push_back( random() % static_cast<uint64_t>( data.size() - 1000 ) );
                }

                THEN( "each offset reads as the data there" )
                {
                    for ( const auto offset : offsets ) {
                        INFO( "offset " << offset );
                        REQUIRE( gzip.seek( offset ) );
                        REQUIRE( gzip.position() == offset );
                        std::vector<uint8_t> bytes( 1000 );
                        REQUIRE( gzip.read( bytes.data(), bytes.size() ) == bytes.size() );
                        REQUIRE( QByteArray( reinterpret_cast<const char*>( bytes.data() ), 1000 )
                                 == data.mid( static_cast<int>( offset ), 1000 ) );
                    }
                    REQUIRE_FALSE( gzip.cutOff() );
                }
            }

            WHEN( "a fresh source seeks near the end and reads on to it" )
            {
                CountingSource input( compressed );
                GzipSource gzip( input );
                gzip.useAccessPoints( points );
                REQUIRE( gzip.skip( static_cast<uint64_t>( data.size() ) - 100 ) );
                const auto rest = readAll( gzip, 4096 );

                THEN( "only the stream from the last access point on was read" )
                {
                    REQUIRE( rest == data.right( 100 ) );
                    REQUIRE( input.bytesRead < static_cast<uint64_t>( compressed.size() ) / 4 );
                    REQUIRE_FALSE( gzip.cutOff() );
                }
            }
        }
    }

    GIVEN( "a source without access points" )
    {
        const auto compressed = gzipped( data, 2 );
        CountingSource input( compressed );
        GzipSource gzip( input );

        THEN( "a seek back starts again at the beginning, and a seek past the end fails" )
        {
            REQUIRE( gzip.seek( 500000 ) );
            REQUIRE( gzip.seek( 100 ) );
            uint8_t byte = 0;
            REQUIRE( gzip.read( &byte, 1 ) == 1 );
            REQUIRE( byte == static_cast<uint8_t>( data[ 100 ] ) );
            REQUIRE_FALSE( gzip.seek( static_cast<uint64_t>( data.size() ) + 1 ) );
        }
    }
}

SCENARIO( "A gzip-compressed capture converts as the capture in it", "[gzip][converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    for ( const char* name : { "mixed.pcap", "interfaces.pcapng", "sip.pcap" } ) {
        GIVEN( std::string( "the corpus capture " ) + name + ", gzip-compressed" )
        {
            const auto plainPath = corpus( name );
            const auto gzPath = dir.filePath( QString::fromLatin1( name ) + ".gz" );
            writeFile( gzPath, gzipped( fileBytes( plainPath ), 2 ) );

            WHEN( "both are converted" )
            {
                const auto plain = convert( plainPath, dir.path() );
                std::vector<int> permilles;
                const auto gz = convert( gzPath, dir.path(), {}, [ & ]( int permille ) {
                    permilles.push_back( permille );
                } );
                REQUIRE( plain.status == ConversionResult::Status::Converted );
                REQUIRE( gz.status == ConversionResult::Status::Converted );

                THEN( "the text and the summary are the same, and the text is named without .gz" )
                {
                    REQUIRE( fileBytes( gz.outputPath ) == fileBytes( plain.outputPath ) );
                    REQUIRE( gz.summary == plain.summary );
                    REQUIRE( gz.summary.compressionProblem.empty() );
                    REQUIRE( QFileInfo( gz.outputPath ).fileName()
                             == QFileInfo( plain.outputPath ).fileName() );
                }

                THEN( "the progress, in compressed bytes, rises to the end" )
                {
                    REQUIRE_FALSE( permilles.empty() );
                    REQUIRE( std::is_sorted( permilles.begin(), permilles.end() ) );
                    REQUIRE( permilles.back() == 1000 );
                }
            }
        }
    }

    GIVEN( "a gzip-compressed capture behind a text preamble" )
    {
        const auto path = dir.filePath( "adb.pcap.gz" );
        writeFile( path, QByteArray( "tcpdump: listening on wlan0\n" )
                             + gzipped( fileBytes( corpus( "mixed.pcap" ) ) ) );
        const auto plain = convert( corpus( "mixed.pcap" ), dir.path() );
        const auto gz = convert( path, dir.path() );

        THEN( "the capture in it converts" )
        {
            REQUIRE( gz.status == ConversionResult::Status::Converted );
            REQUIRE( fileBytes( gz.outputPath ) == fileBytes( plain.outputPath ) );
        }
    }
}

SCENARIO( "A gzip-compressed capture that is cut off or corrupt ends as cut off",
          "[gzip][converter]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );
    const auto bytes = fileBytes( corpus( "sip.pcap" ) );
    const auto compressed = gzipped( bytes );
    const auto full = convert( corpus( "sip.pcap" ), dir.path() );
    REQUIRE( full.status == ConversionResult::Status::Converted );

    GIVEN( "a gzip stream cut off in the middle" )
    {
        const auto path = dir.filePath( "cut.pcap.gz" );
        writeFile( path, compressed.left( compressed.size() * 2 / 3 ) );
        const auto result = convert( path, dir.path() );

        THEN( "the packets before are shown and the capture is reported cut off" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets > 0 );
            REQUIRE( result.summary.packets < full.summary.packets );
            REQUIRE( result.summary.endsInsideRecord );
            REQUIRE( result.summary.compressionProblem == "the gzip stream is cut off" );
        }
    }

    GIVEN( "a gzip stream whose check value does not match" )
    {
        auto corrupt = compressed;
        corrupt[ corrupt.size() - 6 ] = static_cast<char>( corrupt[ corrupt.size() - 6 ] ^ 0x55 );
        const auto path = dir.filePath( "corrupt.pcap.gz" );
        writeFile( path, corrupt );
        const auto result = convert( path, dir.path() );

        THEN( "every packet is shown and the capture is reported cut off, corrupt" )
        {
            REQUIRE( result.status == ConversionResult::Status::Converted );
            REQUIRE( result.summary.packets == full.summary.packets );
            REQUIRE( result.summary.endsInsideRecord );
            REQUIRE_THAT( result.summary.compressionProblem, Catch::Contains( "corrupt" ) );
        }
    }

    GIVEN( "a gzip stream cut off before the capture's header" )
    {
        const auto path = dir.filePath( "header.pcap.gz" );
        writeFile( path, compressed.left( 12 ) );
        const auto result = convert( path, dir.path() );

        THEN( "the conversion fails, saying why" )
        {
            REQUIRE( result.status == ConversionResult::Status::Failed );
            REQUIRE( result.error
                     == "Cannot read the gzip-compressed capture: the gzip stream is cut off" );
        }
    }
}

SCENARIO( "The packets of a gzip-compressed capture are read back and exported",
          "[gzip][capture_index][packet_export]" )
{
    QTemporaryDir dir;
    REQUIRE( dir.isValid() );

    for ( const char* name : { "sip.pcap", "interfaces.pcapng" } ) {
        GIVEN( std::string( "the corpus capture " ) + name
               + ", gzip-compressed, converted with access points" )
        {
            const auto plainPath = corpus( name );
            const auto gzPath = dir.filePath( QString::fromLatin1( name ) + ".gz" );
            writeFile( gzPath, gzipped( fileBytes( plainPath ), 2, 100 ) );
            ConversionOptions options;
            options.checkpointInterval = 3;
            const auto plain = convert( plainPath, dir.path(), options );
            options.gzipAccessSpan = 200;
            const auto gz = convert( gzPath, dir.path(), options );
            REQUIRE( gz.status == ConversionResult::Status::Converted );
            REQUIRE( gz.index->gzipAccessPoints() );
            REQUIRE( gz.index->gzipAccessPoints()->points().size() >= 2 );
            REQUIRE_FALSE( plain.index->gzipAccessPoints() );

            THEN( "every packet, read in any order, is the uncompressed capture's" )
            {
                std::vector<uint32_t> order( plain.index->packets() );
                for ( size_t i = 0; i < order.size(); ++i ) {
                    order[ i ] = static_cast<uint32_t>( i + 1 );
                }
                std::shuffle( order.begin(), order.end(), std::mt19937( 51 ) );
                CaptureCursor plainCursor( plain.index );
                CaptureCursor gzCursor( gz.index );
                for ( const auto number : order ) {
                    INFO( "packet " << number );
                    CapturedPacket expected;
                    CapturedPacket packet;
                    REQUIRE( plainCursor.read( number, expected ) );
                    REQUIRE( gzCursor.read( number, packet ) );
                    REQUIRE( packet.record.info == expected.record.info );
                    REQUIRE( packet.bytes == expected.bytes );
                    REQUIRE( packet.recordOffset == expected.recordOffset );
                    REQUIRE( packet.recordLength == expected.recordLength );
                }
            }

            THEN( "an export of its packets is that of the uncompressed capture" )
            {
                std::vector<uint32_t> numbers;
                for ( uint32_t n = 1; n <= plain.index->packets(); n += 2 ) {
                    numbers.push_back( n );
                }
                const auto plainOut = dir.filePath( "plain-export" );
                const auto gzOut = dir.filePath( "gz-export" );
                const auto plainExport = exportPackets( plain.index, numbers, plainOut );
                const auto gzExport = exportPackets( gz.index, numbers, gzOut );
                REQUIRE( plainExport.status == ExportResult::Status::Exported );
                REQUIRE( gzExport.status == ExportResult::Status::Exported );
                REQUIRE( gzExport.format == plainExport.format );
                REQUIRE( fileBytes( gzOut ) == fileBytes( plainOut ) );
                // The records are copied as the cursor read them: the
                // capture is decompressed once, not again to copy them.
                REQUIRE( gzExport.recordsReadAgain == 0 );
                REQUIRE( plainExport.recordsReadAgain == 0 );
                REQUIRE( captureFormatOf( gzPath ) == captureFormatOf( plainPath ) );
            }
        }
    }
}

SCENARIO( "A gzip-compressed capture's text is named without its extensions", "[gzip]" )
{
    REQUIRE( captureBaseName( "/x/trace.pcap.gz" ) == "trace" );
    REQUIRE( captureBaseName( "/x/trace.pcapng.GZ" ) == "trace" );
    REQUIRE( captureBaseName( "/x/trace.cap.gz" ) == "trace" );
    REQUIRE( captureBaseName( "/x/trace.pcap" ) == "trace" );
    REQUIRE( captureBaseName( "/x/trace.gz" ) == "trace" );
}
