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
 * @file pcap_converter.cpp
 * @brief Implementation of the streaming pcap-to-text conversion.
 */

#include "pcap_converter.h"

#include "packet_formatter.h"

#include <QFile>

#include <algorithm>

namespace tcpdump {

namespace {

/// A ByteSource reading a QFile.
class FileSource : public ByteSource {
public:
    explicit FileSource( QFile& file )
        : file_( file )
    {
    }

    size_t read( uint8_t* dst, size_t n ) override
    {
        const auto got = file_.read( reinterpret_cast<char*>( dst ), static_cast<qint64>( n ) );
        return got > 0 ? static_cast<size_t>( got ) : 0;
    }

    bool skip( uint64_t n ) override
    {
        const auto target = static_cast<uint64_t>( file_.pos() ) + n;
        if ( target > static_cast<uint64_t>( file_.size() ) ) {
            file_.seek( file_.size() );
            return false;
        }
        return file_.seek( static_cast<qint64>( target ) );
    }

private:
    QFile& file_;
};

} // namespace

ConversionResult convertPcap( const QString& inputPath, const QString& outputPath,
                              const std::atomic_bool* cancel,
                              const std::function<void( int )>& progress )
{
    ConversionResult result;

    QFile input( inputPath );
    if ( !input.open( QIODevice::ReadOnly ) ) {
        result.error = QStringLiteral( "Cannot open file: %1" ).arg( input.errorString() );
        return result;
    }
    FileSource source( input );
    PcapReader reader( source );
    if ( !reader.open() ) {
        result.error = QString::fromStdString( reader.error() );
        return result;
    }
    result.header = reader.header();

    QFile output( outputPath );
    if ( !output.open( QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text ) ) {
        result.error
            = QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() );
        return result;
    }
    auto fail = [ &output, &result ]( const QString& error ) {
        output.remove();
        result.status = ConversionResult::Status::Failed;
        result.error = error;
        return result;
    };

    auto writeLine = [ &output ]( const std::string& line ) {
        return output.write( line.data(), static_cast<qint64>( line.size() ) )
                   == static_cast<qint64>( line.size() )
               && output.write( "\n", 1 ) == 1;
    };

    if ( !writeLine( PacketFormatter::header() ) ) {
        return fail(
            QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
    }

    const auto inputSize = std::max<qint64>( input.size(), 1 );
    int lastPermille = -1;
    PacketFormatter formatter;
    PacketRecord pkt;
    while ( reader.next( pkt ) ) {
        if ( cancel && cancel->load() ) {
            output.remove();
            result.status = ConversionResult::Status::Cancelled;
            return result;
        }
        result.stats.add( pkt );
        if ( !writeLine( formatter.format( pkt ) ) ) {
            return fail(
                QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
        }
        if ( progress ) {
            const auto permille = static_cast<int>( std::min<uint64_t>(
                reader.bytesRead() * 1000 / static_cast<uint64_t>( inputSize ), 1000 ) );
            if ( permille != lastPermille ) {
                lastPermille = permille;
                progress( permille );
            }
        }
    }
    if ( cancel && cancel->load() ) {
        output.remove();
        result.status = ConversionResult::Status::Cancelled;
        return result;
    }
    if ( !output.flush() ) {
        return fail(
            QStringLiteral( "Cannot write the output file: %1" ).arg( output.errorString() ) );
    }
    output.close();

    result.truncated = reader.truncated();
    result.status = ConversionResult::Status::Converted;
    return result;
}

} // namespace tcpdump
