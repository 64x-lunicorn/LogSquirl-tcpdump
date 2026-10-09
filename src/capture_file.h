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
 * and the CaptureCursor (capture_index.h), which reads packets of it again
 * from a checkpoint.
 */

#pragma once

#include "pcap_parser.h"

#include <QFile>
#include <QString>

namespace tcpdump {

/// A ByteSource reading a QFile; skipping seeks.
class FileSource : public ByteSource {
public:
    explicit FileSource( QFile& file )
        : file_( file )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override;
    bool skip( uint64_t n ) override;

private:
    QFile& file_;
};

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
