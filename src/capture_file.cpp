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
 * @file capture_file.cpp
 * @brief Opening a capture file and reading it as a ByteSource.
 */

#include "capture_file.h"

#include <QFileInfo>

#ifdef Q_OS_UNIX
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace tcpdump {

size_t FileSource::read( uint8_t* dst, size_t n )
{
    const auto got = file_.read( reinterpret_cast<char*>( dst ), static_cast<qint64>( n ) );
    return got > 0 ? static_cast<size_t>( got ) : 0;
}

bool FileSource::skip( uint64_t n )
{
    const auto target = static_cast<uint64_t>( file_.pos() ) + n;
    if ( target > static_cast<uint64_t>( file_.size() ) ) {
        file_.seek( file_.size() );
        return false;
    }
    return file_.seek( static_cast<qint64>( target ) );
}

namespace {

/// The message for a path that is not a regular file.
QString notRegular( const QString& path )
{
    return QStringLiteral( "%1 is not a regular file" ).arg( path );
}

} // namespace

bool openRegularFile( const QString& path, QFile& file, QString& error )
{
    const QFileInfo info( path );
    const auto target = info.canonicalFilePath(); // follows symbolic links
    if ( target.isEmpty() ) {
        error = QStringLiteral( "Cannot open file: %1 does not exist" ).arg( path );
        return false;
    }
    if ( !QFileInfo( target ).isFile() ) {
        error = notRegular( path );
        return false;
    }

#ifdef Q_OS_UNIX
    const int fd
        = ::open( QFile::encodeName( target ).constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC );
    if ( fd < 0 ) {
        error = QStringLiteral( "Cannot open file: %1" )
                    .arg( QString::fromLocal8Bit( std::strerror( errno ) ) );
        return false;
    }
    struct stat st;
    if ( ::fstat( fd, &st ) != 0 || !S_ISREG( st.st_mode ) ) {
        ::close( fd );
        error = notRegular( path );
        return false;
    }
    const int flags = ::fcntl( fd, F_GETFL );
    if ( flags != -1 ) {
        ::fcntl( fd, F_SETFL, flags & ~O_NONBLOCK );
    }
    if ( !file.open( fd, QIODevice::ReadOnly, QFileDevice::AutoCloseHandle ) ) {
        ::close( fd );
        error = QStringLiteral( "Cannot open file: %1" ).arg( file.errorString() );
        return false;
    }
#else
    file.setFileName( target );
    if ( !file.open( QIODevice::ReadOnly ) ) {
        error = QStringLiteral( "Cannot open file: %1" ).arg( file.errorString() );
        return false;
    }
#endif
    return true;
}

} // namespace tcpdump
