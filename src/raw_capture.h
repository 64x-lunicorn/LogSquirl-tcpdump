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
 * @file raw_capture.h
 * @brief A live capture's raw capture on disk: one file, or a ring buffer of
 *        files.
 *
 * The Converter writes every byte it reads from a live stream, unchanged,
 * to the raw capture next to the text file, so that it can be saved,
 * converted again or opened in Wireshark.  Without a ring buffer that is one
 * file, <name>.pcap or <name>.pcapng.
 *
 * With a ring buffer (dumpcap's -b) the Converter starts a new file after
 * the record of a packet that filled the current one, by size or duration:
 * the files are <name>_00001_<time>.pcap, <name>_00002_<time>.pcap, …, the
 * time the local one the file was started at, and only the newest few are
 * kept, the oldest deleted.  Each file is a capture of its own: a pcap's
 * global header, or a pcapng's section header and the interfaces its
 * section declared so far, are copied ahead of its records, so that
 * Wireshark opens any of them.  The CaptureParts (capture_index.h) say where
 * each file's packets and headers lie, for the CaptureCursor to read them
 * back, and for saveCaptureParts() to write the files kept as one capture.
 */

#pragma once

#include "capture_index.h"
#include "pcap_parser.h"

#include <QDir>
#include <QFile>
#include <QString>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace tcpdump {

class RawCapture {
public:
    /// The raw capture of the capture @p baseName in @p dir, in @p format.
    /// With @p ringFiles, a ring buffer that keeps that many files; without
    /// (0), one file.
    RawCapture( const QDir& dir, const QString& baseName, CaptureFormat format,
                uint32_t ringFiles = 0 );

    RawCapture( const RawCapture& ) = delete;
    RawCapture& operator=( const RawCapture& ) = delete;

    /// Create the first file, readable by the user only; never one that
    /// exists.  On failure error() says why.
    bool open();

    /// Append @p n bytes of the capture as it is read.
    bool write( const uint8_t* data, size_t n );

    /// Make what was written readable.
    bool flush();

    /// Flush and close the current file.
    bool close();

    /**
     * Start a new file at @p cut, where the record of the capture's packet
     * @p packetsBefore ends in the capture as it was read; what was written
     * past it moves to the new file, behind a copy of @p headers, the
     * records that file needs ahead of it (CaptureReader::headers()).  The
     * oldest files beyond the ring buffer's are deleted.  A ring buffer's
     * only.
     */
    bool rotate( uint64_t cut, uint32_t packetsBefore, const CaptureHeaders& headers );

    /// Bytes of the current file, the headers copied ahead included.
    uint64_t fileSize() const;

    /// The files kept, oldest first; the last is the one written.
    const std::vector<CapturePart>& parts() const
    {
        return parts_;
    }

    /// The number of the file written, from 1: of all the ring buffer started.
    uint32_t fileNumber() const
    {
        return fileNumber_;
    }

    /// The path of the file written.
    QString path() const
    {
        return file_.fileName();
    }

    /// Why the last call failed.
    const QString& error() const
    {
        return error_;
    }

private:
    /// The path of file number @p number.
    QString pathOf( uint32_t number ) const;
    /// Create file_ at @p path.
    bool create( const QString& path );
    /// Read @p length bytes at @p offset of the current file into @p into.
    bool readBack( uint64_t offset, uint64_t length, QByteArray& into );
    bool fail( const QString& what );

    QDir dir_;
    QString baseName_;
    QString suffix_; ///< "pcap" or "pcapng"
    CaptureFormat format_;
    uint32_t ringFiles_;
    QFile file_;
    std::vector<CapturePart> parts_;
    uint64_t written_ = 0; ///< Bytes of the capture written, as it was read.
    uint32_t fileNumber_ = 0;
    QString error_;
};

/**
 * Write the capture in @p parts, the files of one capture in order, to
 * @p target as one capture file: the first whole, the records of each
 * further one without the headers copied ahead of them.  A capture of one
 * file is copied as it is.  Written aside and renamed when complete; false
 * with @p error if a file cannot be read or the target written.
 */
bool saveCaptureParts( const std::vector<CapturePart>& parts, const QString& target,
                       QString& error );

} // namespace tcpdump
