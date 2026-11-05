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
 * @file host_converter.cpp
 * @brief Converting a capture LogSquirl opened, for LogSquirl.
 */

#include "host_converter.h"

#include "pcap_parser.h"
#include "plugin.h"

#include <QFile>

#include <future>
#include <string>
#include <vector>

namespace tcpdump {

namespace {

/// How copyText() ended.
enum class CopyEnd {
    Copied,    ///< The host's file holds the text.
    Failed,    ///< See its error.
    Cancelled, ///< The host cancelled the conversion meanwhile.
};

/// Copy the text file @p from into the host's file @p to, chunk by chunk,
/// stopping when @p control says the conversion was cancelled; why it
/// failed in @p error.
CopyEnd copyText( const QString& from, const QString& to, const HostConvertControl& control,
                  QString& error )
{
    QFile in( from );
    if ( !in.open( QIODevice::ReadOnly ) ) {
        error = QStringLiteral( "Cannot read %1: %2" ).arg( from, in.errorString() );
        return CopyEnd::Failed;
    }
    // The host created the file and keeps it open: it is written in place.
    QFile out( to );
    if ( !out.open( QIODevice::WriteOnly | QIODevice::Truncate ) ) {
        error = QStringLiteral( "Cannot write %1: %2" ).arg( to, out.errorString() );
        return CopyEnd::Failed;
    }
    std::vector<char> chunk( static_cast<std::size_t>( kHostCopyChunk ) );
    for ( ;; ) {
        if ( control.isCancelled() ) {
            return CopyEnd::Cancelled;
        }
        const auto read = in.read( chunk.data(), kHostCopyChunk );
        if ( read < 0 ) {
            error = QStringLiteral( "Cannot read %1: %2" ).arg( from, in.errorString() );
            return CopyEnd::Failed;
        }
        if ( read == 0 ) {
            break;
        }
        if ( out.write( chunk.data(), read ) != read ) {
            error = QStringLiteral( "Cannot write %1: %2" ).arg( to, out.errorString() );
            return CopyEnd::Failed;
        }
    }
    if ( !out.flush() ) {
        error = QStringLiteral( "Cannot write %1: %2" ).arg( to, out.errorString() );
        return CopyEnd::Failed;
    }
    return CopyEnd::Copied;
}

/// Log that the capture @p inputPath could not be converted for the host.
void logFailed( const QString& inputPath, const QString& error )
{
    hostLog( LOGSQUIRL_LOG_ERROR,
             QStringLiteral( "tcpdump plugin: cannot convert %1: %2" ).arg( inputPath, error ) );
}

} // namespace

HostConvertControl HostConvertControl::of( const LogSquirlConvertControl* control )
{
    HostConvertControl result;
    if ( !control ) {
        result.reportProgress = []( uint64_t, uint64_t ) {};
        result.isCancelled = [] { return false; };
        return result;
    }
    // report_progress and is_cancelled are members of every host's control.
    result.reportProgress = [ control ]( uint64_t done, uint64_t total ) {
        control->report_progress( control, done, total );
    };
    result.isCancelled = [ control ] { return control->is_cancelled( control ) != 0; };
    return result;
}

const char* hostConverterExtensions( bool enabled )
{
    return enabled ? kHostConverterExtensions : "";
}

bool isCaptureHead( const unsigned char* head, std::size_t length )
{
    if ( !head || length == 0 ) {
        return false;
    }
    std::size_t offset = 0;
    CaptureFormat format = CaptureFormat::Pcap;
    std::string error;
    return findCaptureStart( head, length, offset, format, error ) == CaptureStart::Found;
}

int convertForHost( const QString& inputPath, const QString& outputPath, const QString& outputRoot,
                    const ConversionOptions& options, const HostConvertControl& control,
                    const ConvertedCaptureSink& sink, const HostConversion& convert )
{
    const HostConversion conversion = convert ? convert : HostConversion( &convertPcap );

    // The conversion runs on a thread of its own; this one, the host's,
    // carries the Cancel over and reports the progress, as the control's
    // functions may be called on it only.  convertPcap() checks the cancel
    // between packets and reads regular files only, so the wait ends soon
    // after a cancel.
    std::atomic_bool cancel{ false };
    std::atomic_int permille{ 0 };
    auto running = std::async( std::launch::async, [ & ] {
        return conversion(
            inputPath, outputRoot, &cancel, [ &permille ]( int done ) { permille.store( done ); },
            options );
    } );
    int reported = -1;
    while ( running.wait_for( kHostConvertPoll ) != std::future_status::ready ) {
        if ( !cancel.load() && control.isCancelled() ) {
            cancel.store( true );
        }
        if ( const int done = permille.load(); done != reported ) {
            reported = done;
            control.reportProgress( static_cast<uint64_t>( done ), kHostProgressTotal );
        }
    }
    auto result = running.get();

    // A cancel wins over a conversion that was done when it came.
    if ( cancel.load() || control.isCancelled()
         || result.status == ConversionResult::Status::Cancelled ) {
        removeOutput( result );
        return kHostConvertCancelled;
    }
    if ( result.status != ConversionResult::Status::Converted ) {
        logFailed( inputPath, result.error );
        removeOutput( result );
        return kHostConvertFailed;
    }

    QString error;
    const auto copied = copyText( result.outputPath, outputPath, control, error );
    removeOutput( result );
    switch ( copied ) {
    case CopyEnd::Cancelled:
        return kHostConvertCancelled;
    case CopyEnd::Failed:
        logFailed( inputPath, error );
        return kHostConvertFailed;
    case CopyEnd::Copied:
        break;
    }

    control.reportProgress( kHostProgressTotal, kHostProgressTotal );
    hostLog( LOGSQUIRL_LOG_INFO, QStringLiteral( "Opened %1 packets from %2" )
                                     .arg( result.summary.packets )
                                     .arg( inputPath ) );
    if ( sink ) {
        sink( outputPath, inputPath, result.summary, std::move( result.index ) );
    }
    return kHostConverted;
}

} // namespace tcpdump
