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
 * @file capture_file.h
 * @brief Reading a capture file: opening it safely, and a ByteSource over it.
 *
 * Shared by the Converter, which reads a capture once from front to back,
 * the CaptureCursor (capture_index.h), which reads packets of it again
 * from a checkpoint, and Export Packets, which copies their records.  A
 * gzip-compressed file is read through a GzipSource (gzip_source.h), so
 * that all of them see the capture, decompressed.
 */

#pragma once

#include "pcap_parser.h"

#include <QFile>
#include <QString>

#include <memory>

namespace tcpdump {

class GzipAccessPoints;
class GzipSource;

/// A ByteSource reading a QFile; skipping and seeking seek.
class FileSource : public ByteSource {
public:
    explicit FileSource( QFile& file )
        : file_( file )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;
    bool seek( uint64_t offset ) override;

private:
    QFile& file_;
};

/**
 * A capture file opened for reading, and the ByteSource that reads the
 * capture in it: the file itself, or, if it holds a gzip stream (told by
 * its magic, at its start or behind a text preamble, not by its name), a
 * GzipSource that decompresses it on the fly.  Offsets in source(), such
 * as a record's or a checkpoint's, are offsets in the capture, decompressed.
 */
class CaptureFile {
public:
    CaptureFile();
    ~CaptureFile();
    CaptureFile( const CaptureFile& ) = delete;
    CaptureFile& operator=( const CaptureFile& ) = delete;

    /// Open the regular file at @p path (openRegularFile()); a gzip stream is
    /// read with the access points @p points if given.  On failure, @p error
    /// says why.
    bool open( const QString& path, QString& error,
               std::shared_ptr<const GzipAccessPoints> points = {} );

    /// The capture, decompressed if need be; valid after a successful open().
    ByteSource& source();

    /// The decompression of a gzip-compressed file; null for any other.
    GzipSource* gzip()
    {
        return gzip_.get();
    }

    /// Bytes of the file consumed so far, compressed ones for a gzip
    /// stream: what progress is measured in.
    uint64_t consumed() const;

    /// The file's size in bytes.
    uint64_t size() const;

private:
    QFile file_;
    std::unique_ptr<FileSource> fileSource_;
    std::unique_ptr<GzipSource> gzip_;
};

/// The name a capture file's converted text takes: its name without the
/// extension, and without ".gz" first: "trace.pcap.gz" gives "trace".
QString captureBaseName( const QString& path );

/**
 * Open @p path for reading into @p file if it is, or links to, a regular
 * file; otherwise @p error says why.
 *
 * Reading a FIFO or a device can block for good, and a blocked worker would
 * block the plugin's shutdown, which waits for it.  On Unix the file is
 * opened without blocking and checked with fstat(), so that it cannot be
 * swapped for a FIFO between the check and the opening.  Reading a regular
 * file on a network share that stalls can still block; that is left to the
 * operating system's timeouts.
 */
bool openRegularFile( const QString& path, QFile& file, QString& error );

} // namespace tcpdump
