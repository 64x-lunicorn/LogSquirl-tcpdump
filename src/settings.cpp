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
 * @file settings.cpp
 * @brief Implementation of the settings file.
 */

#include "settings.h"

#include <QDir>
#include <QSettings>
#include <QStringList>

#include <algorithm>

namespace tcpdump {

namespace {

/// The keys of the settings file, all in its [conversion] group.
constexpr const char* kTimeColumnsKey = "conversion/timeColumns";
constexpr const char* kMacColumnsKey = "conversion/macColumns";
constexpr const char* kHostNamesKey = "conversion/hostNames";
constexpr const char* kPreviewKey = "conversion/preview";
constexpr const char* kPreviewCharsKey = "conversion/previewChars";
constexpr const char* kMaxStreamsKey = "conversion/maxStreams";
constexpr const char* kMaxEndpointsKey = "conversion/maxEndpoints";
constexpr const char* kReassemblyMegabytesKey = "conversion/reassemblyMegabytes";
constexpr const char* kTcpTimestampsKey = "conversion/tcpTimestamps";
constexpr const char* kSomeIpPortsKey = "conversion/someIpPorts";
constexpr const char* kSomeIpNamesFileKey = "conversion/someIpNamesFile";
constexpr const char* kKeyLogPathKey = "conversion/tlsKeyLogFile";

/// The keys of the live capture choice, in the [live] group.
constexpr const char* kLiveSourceKey = "live/source";
constexpr const char* kLiveDeviceKey = "live/device";
constexpr const char* kLiveInterfaceKey = "live/interface";
constexpr const char* kLiveFilterKey = "live/filter";
constexpr const char* kLiveSnaplenKey = "live/snaplen";
/// The group of a source's options: live/options/<source>/<name>.
QString liveOptionsGroup( const QString& source )
{
    return QStringLiteral( "live/options/" ) + source;
}

/// The names of the time column choices in the file.
struct TimeColumnsName {
    TimeColumns value;
    const char* name;
};
constexpr TimeColumnsName kTimeColumnsNames[] = {
    { TimeColumns::Both, "both" },
    { TimeColumns::AbsoluteOnly, "absolute" },
    { TimeColumns::RelativeOnly, "relative" },
};

/// The number under @p key, within [@p min, @p max]; @p fallback if there is
/// none.
size_t readCount( const QSettings& file, const char* key, size_t fallback, size_t min, size_t max )
{
    bool ok = false;
    const auto value = file.value( key ).toLongLong( &ok );
    if ( !ok ) {
        return fallback;
    }
    if ( value < static_cast<long long>( min ) ) {
        return min;
    }
    return std::min( static_cast<size_t>( value ), max );
}

/// The flag under @p key; @p fallback if there is none.
bool readFlag( const QSettings& file, const char* key, bool fallback )
{
    const auto value = file.value( key ).toString().toLower();
    if ( value == "true" ) {
        return true;
    }
    if ( value == "false" ) {
        return false;
    }
    return fallback;
}

} // namespace

QString settingsFilePath( const QString& configDir )
{
    return QDir( configDir ).filePath( QStringLiteral( "settings.ini" ) );
}

ConversionOptions loadConversionOptions( const QString& configDir )
{
    ConversionOptions options;
    if ( configDir.isEmpty() ) {
        return options;
    }
    const QSettings file( settingsFilePath( configDir ), QSettings::IniFormat );

    const auto timeColumns = file.value( kTimeColumnsKey ).toString();
    for ( const auto& choice : kTimeColumnsNames ) {
        if ( timeColumns == QLatin1String( choice.name ) ) {
            options.layout.timeColumns = choice.value;
        }
    }
    options.layout.macColumns = readFlag( file, kMacColumnsKey, options.layout.macColumns );
    options.layout.hostNames = readFlag( file, kHostNamesKey, options.layout.hostNames );
    options.preview = readFlag( file, kPreviewKey, options.preview );
    options.tcpTimestamps = readFlag( file, kTcpTimestampsKey, options.tcpTimestamps );
    options.previewChars
        = readCount( file, kPreviewCharsKey, options.previewChars, 1, kMaxPreviewChars );
    options.maxStreams
        = readCount( file, kMaxStreamsKey, options.maxStreams, kMinCap, kMaxStreamCap );
    options.maxEndpoints
        = readCount( file, kMaxEndpointsKey, options.maxEndpoints, kMinCap, kMaxEndpointCap );
    options.reassemblyMegabytes
        = readCount( file, kReassemblyMegabytesKey, options.reassemblyMegabytes, kMinCap,
                     kMaxReassemblyMegabytes );
    // A list in the file ("30501, 30502"), or one port.
    options.someIpPorts = parseSomeIpPorts(
        file.value( kSomeIpPortsKey ).toStringList().join( QLatin1Char( ',' ) ).toStdString() );
    options.someIpNamesFile = file.value( kSomeIpNamesFileKey ).toString();
    options.keyLogPath = file.value( kKeyLogPathKey ).toString();
    return options;
}

bool saveConversionOptions( const QString& configDir, const ConversionOptions& options )
{
    if ( configDir.isEmpty() || !QDir().mkpath( configDir ) ) {
        return false;
    }
    QSettings file( settingsFilePath( configDir ), QSettings::IniFormat );
    for ( const auto& choice : kTimeColumnsNames ) {
        if ( options.layout.timeColumns == choice.value ) {
            file.setValue( kTimeColumnsKey, QLatin1String( choice.name ) );
        }
    }
    file.setValue( kMacColumnsKey, options.layout.macColumns );
    file.setValue( kHostNamesKey, options.layout.hostNames );
    file.setValue( kPreviewKey, options.preview );
    file.setValue( kTcpTimestampsKey, options.tcpTimestamps );
    file.setValue( kPreviewCharsKey, static_cast<qulonglong>( options.previewChars ) );
    file.setValue( kMaxStreamsKey, static_cast<qulonglong>( options.maxStreams ) );
    file.setValue( kMaxEndpointsKey, static_cast<qulonglong>( options.maxEndpoints ) );
    file.setValue( kReassemblyMegabytesKey,
                   static_cast<qulonglong>( options.reassemblyMegabytes ) );
    QStringList ports;
    for ( const auto port : options.someIpPorts ) {
        ports << QString::number( port );
    }
    file.setValue( kSomeIpPortsKey, ports.isEmpty() ? QVariant( QString() ) : QVariant( ports ) );
    file.setValue( kSomeIpNamesFileKey, options.someIpNamesFile );
    file.setValue( kKeyLogPathKey, options.keyLogPath );
    file.sync();
    return file.status() == QSettings::NoError;
}

LiveChoice loadLiveChoice( const QString& configDir )
{
    LiveChoice choice;
    if ( configDir.isEmpty() ) {
        return choice;
    }
    const QSettings file( settingsFilePath( configDir ), QSettings::IniFormat );
    choice.source = file.value( kLiveSourceKey ).toString();
    choice.device = file.value( kLiveDeviceKey ).toString();
    choice.networkInterface = file.value( kLiveInterfaceKey ).toString();
    choice.filter = file.value( kLiveFilterKey ).toString();
    choice.snaplen = static_cast<int>( readCount( file, kLiveSnaplenKey, kDefaultSnaplen, 1,
                                                  static_cast<size_t>( kMaxSnaplen ) ) );
    choice.options = loadLiveOptions( configDir, choice.source );
    return choice;
}

LiveOptions loadLiveOptions( const QString& configDir, const QString& source )
{
    LiveOptions options;
    if ( configDir.isEmpty() || source.isEmpty() ) {
        return options;
    }
    QSettings file( settingsFilePath( configDir ), QSettings::IniFormat );
    file.beginGroup( liveOptionsGroup( source ) );
    for ( const auto& name : file.childKeys() ) {
        options.insert( name, file.value( name ).toString() );
    }
    file.endGroup();
    return options;
}

bool saveLiveChoice( const QString& configDir, const LiveChoice& choice )
{
    if ( configDir.isEmpty() || !QDir().mkpath( configDir ) ) {
        return false;
    }
    QSettings file( settingsFilePath( configDir ), QSettings::IniFormat );
    file.setValue( kLiveSourceKey, choice.source );
    file.setValue( kLiveDeviceKey, choice.device );
    file.setValue( kLiveInterfaceKey, choice.networkInterface );
    file.setValue( kLiveFilterKey, choice.filter );
    file.setValue( kLiveSnaplenKey, choice.snaplen );
    if ( !choice.source.isEmpty() ) {
        file.remove( liveOptionsGroup( choice.source ) );
        file.beginGroup( liveOptionsGroup( choice.source ) );
        for ( auto option = choice.options.cbegin(); option != choice.options.cend(); ++option ) {
            // A secret (a password) is the session's, never the file's.
            if ( !option.key().isEmpty() && !option.key().contains( QLatin1Char( '/' ) )
                 && !isSecretLiveOption( option.key() ) ) {
                file.setValue( option.key(), option.value() );
            }
        }
        file.endGroup();
    }
    file.sync();
    return file.status() == QSettings::NoError;
}

} // namespace tcpdump
