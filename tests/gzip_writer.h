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
 * @file gzip_writer.h
 * @brief Compressing test captures with gzip, as `gzip` would, in one or
 *        more members.
 */

#pragma once

#include <catch2/catch.hpp>

#include <QByteArray>
#include <QFile>
#include <QString>

#include <zlib.h>

#include <algorithm>

namespace tcpdump_test {

/**
 * @p data compressed into @p members gzip members (its parts, one after
 * the other, as `cat a.gz b.gz` gives them).  With @p flushEvery, each
 * member's deflate data is flushed every that many bytes, ending a block:
 * more places for access points in a small capture.
 */
inline QByteArray gzipped( const QByteArray& data, int members = 1, int flushEvery = 0 )
{
    QByteArray out;
    const auto size = static_cast<int>( data.size() );
    for ( int m = 0; m < members; ++m ) {
        const int from = size * m / members;
        const int to = size * ( m + 1 ) / members;
        z_stream z{};
        REQUIRE(
            deflateInit2( &z, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY )
            == Z_OK );
        QByteArray buffer( 64 * 1024, '\0' );
        int at = from;
        for ( ;; ) {
            const int step = flushEvery > 0 ? std::min( flushEvery, to - at ) : to - at;
            z.next_in = reinterpret_cast<Bytef*>( const_cast<char*>( data.constData() ) + at );
            z.avail_in = static_cast<uInt>( step );
            at += step;
            const int flush = at >= to ? Z_FINISH : Z_SYNC_FLUSH;
            int status = Z_OK;
            do {
                z.next_out = reinterpret_cast<Bytef*>( buffer.data() );
                z.avail_out = static_cast<uInt>( buffer.size() );
                status = deflate( &z, flush );
                REQUIRE( status != Z_STREAM_ERROR );
                out.append( buffer.constData(), buffer.size() - static_cast<int>( z.avail_out ) );
            } while ( z.avail_out == 0 );
            if ( flush == Z_FINISH ) {
                REQUIRE( status == Z_STREAM_END );
                break;
            }
        }
        deflateEnd( &z );
    }
    return out;
}

/// Write @p bytes to a new file at @p path.
inline void writeFile( const QString& path, const QByteArray& bytes )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly | QIODevice::Truncate ) );
    REQUIRE( file.write( bytes ) == bytes.size() );
}

/// The bytes of the file at @p path.
inline QByteArray fileBytes( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return file.readAll();
}

} // namespace tcpdump_test
