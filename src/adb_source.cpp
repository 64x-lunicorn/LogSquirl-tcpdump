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
 * @file adb_source.cpp
 * @brief The Android source: finding adb, listing devices and interfaces,
 *        asking a device for root and tcpdump, and the capture that ends
 *        tcpdump on the device when it goes.
 */

#include "adb_source.h"

#include <QDir>
#include <QFileInfo>
#include <QRandomGenerator>
#include <QRegularExpression>

#include <stdexcept>

namespace tcpdump {

namespace {

/// How long the commands a capture runs besides (reading tcpdump's stderr,
/// ending it) may take.
constexpr std::chrono::milliseconds kCleanupTimeout{ 5000 };

/// How long a su manager may take to answer (its prompt on the phone).
constexpr int kSuTimeoutSeconds = 5;

/// The probe's markers, at the start of a line of its output.
const QString kUidMark = QStringLiteral( "@uid=" );
const QString kSuMark = QStringLiteral( "@su=" );
const QString kTcpdumpMark = QStringLiteral( "@tcpdump=" );
const QString kLinksMark = QStringLiteral( "@links" );

bool runnable( const QString& path )
{
    const QFileInfo file( path );
    return file.isFile() && file.isExecutable();
}

/// @p script run as root on the device: through su, if that is how root is had.
QString asRoot( const QString& script, bool viaSu )
{
    return viaSu ? QStringLiteral( "su -c " ) + shellQuote( script ) : script;
}

/// The script asking the device's shell how it can capture: its user, su,
/// tcpdump, and, if @p withInterfaces, its interfaces.  @p tempDir is where
/// a pushed tcpdump may be.
QString probeScript( const QString& tempDir, bool withInterfaces )
{
    // su without a terminal, without stdin, and with a timeout where the
    // device has one: a su manager's prompt on the phone is denied in time.
    auto script
        = QStringLiteral( "u=$(id -u); echo \"@uid=$u\"; "
                          "td=$(command -v tcpdump 2>/dev/null); "
                          "for p in /system/bin/tcpdump /system/xbin/tcpdump %1; do "
                          "[ -n \"$td\" ] && break; [ -x \"$p\" ] && td=$p; done; "
                          "s=; if [ \"$u\" != 0 ] && command -v su >/dev/null 2>&1; then "
                          "t=; command -v timeout >/dev/null 2>&1 && t='timeout %2'; "
                          "s=$($t su -c 'id -u' </dev/null 2>/dev/null); "
                          "if [ -z \"$td\" ] && [ \"$s\" = 0 ]; then "
                          "td=$($t su -c 'command -v tcpdump' </dev/null 2>/dev/null); fi; fi; "
                          "echo \"@su=$s\"; echo \"@tcpdump=$td\"" )
              .arg( shellQuote( tempDir + QStringLiteral( "/tcpdump" ) ) )
              .arg( kSuTimeoutSeconds );
    if ( withInterfaces ) {
        script += QStringLiteral( "; echo @links; ip -o link 2>/dev/null || ls /sys/class/net" );
    }
    return script;
}

/// What a capture needs to clean up after itself on the device.
struct DeviceCapture {
    QString adb;
    QString serial;
    bool viaSu = false;
    AdbCaptureFiles files;
};

/// `adb -s <serial> shell <script>`.
ProcessCommand adbShell( const QString& adb, const QString& serial, const QString& script )
{
    return { adb,
             { QStringLiteral( "-s" ), serial, QStringLiteral( "shell" ), script },
             QStringLiteral( "adb" ) };
}

/// Why @p output of an adb command failed, or empty.
QString adbFailure( const ListingOutput& output, const QString& what )
{
    if ( !output.error.isEmpty() ) {
        return output.error;
    }
    if ( output.exitCode != 0 ) {
        auto error = QStringLiteral( "%1 exited with code %2" ).arg( what ).arg( output.exitCode );
        const auto err = output.err.trimmed();
        if ( !err.isEmpty() ) {
            error += QStringLiteral( ":\n" ) + err;
        }
        return error;
    }
    return {};
}

/**
 * The stream of tcpdump on the device, read from the local adb exec-out.
 * As it goes, it ends tcpdump on the device by the pid it left (adb's end
 * alone ends it only once it next writes), and removes its files.  A
 * capture that ends by itself before anything came reads tcpdump's stderr
 * from the device for its error.
 */
class DeviceCaptureSource : public ProcessSource {
public:
    DeviceCaptureSource( const ProcessCommand& command, DeviceCapture device,
                         const std::atomic_bool* stop,
                         std::function<void( const QString& )> onLine )
        : ProcessSource( command, stop, std::move( onLine ) )
        , device_( std::move( device ) )
        , stop_( stop )
    {
    }

    ~DeviceCaptureSource() override
    {
        if ( !started() ) {
            return;
        }
        // Before the local adb is ended (ProcessSource's destructor).  While
        // it runs, the capture's script on the device may not have left its
        // pid yet: the stop mark tells it to end its tcpdump.  Once adb has
        // ended, so has the script, and only its files are left to remove.
        const auto script = waitForEnd( std::chrono::milliseconds( 0 ) )
                                ? adbCleanupScript( device_.files )
                                : adbStopScript( device_.files );
        runListing( adbShell( device_.adb, device_.serial, asRoot( script, device_.viaSu ) ),
                    kCleanupTimeout );
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override
    {
        const auto got = ProcessSource::readFor( dst, n, timeout );
        if ( got > 0 ) {
            captured_ = true;
        }
        else if ( got == 0 && !captured_ && error_.empty() && !( stop_ && *stop_ )
                  && !endedOnPurpose() ) {
            const auto said = deviceStderr();
            error_ = ( said.isEmpty()
                           ? QStringLiteral( "tcpdump on the device ended without a capture" )
                           : said )
                         .toStdString();
        }
        return got;
    }

private:
    /// What tcpdump wrote to stderr on the device.
    QString deviceStderr() const
    {
        const auto script = QStringLiteral( "cat %1" ).arg( shellQuote( device_.files.err ) );
        const auto output
            = runListing( adbShell( device_.adb, device_.serial, asRoot( script, device_.viaSu ) ),
                          kCleanupTimeout );
        return output.error.isEmpty() ? output.out.trimmed() : QString();
    }

    DeviceCapture device_;
    const std::atomic_bool* stop_;
    bool captured_ = false;
};

} // namespace

AdbCaptureFiles AdbCaptureFiles::of( const QString& tempDir, const QString& tag )
{
    const auto base = tempDir + QStringLiteral( "/logsquirl-" ) + tag;
    return { base + QStringLiteral( ".pid" ), base + QStringLiteral( ".err" ),
             base + QStringLiteral( ".stop" ) };
}

QString adbCaptureScript( const QString& tcpdump, const AdbCaptureFiles& files )
{
    // The pid is left after tcpdump has started, and the stop mark looked
    // for after that: a Stop that came before the pid was there (it leaves
    // the mark first, then reads the pid) is seen either way.  Stopped so,
    // its stderr file goes too, which the Stop could not remove yet.
    return QStringLiteral( "%1 2>%2 & p=$!; echo $p >%3; [ -e %4 ] && kill $p; wait $p; "
                           "[ -e %4 ] && rm -f %2; rm -f %3 %4" )
        .arg( tcpdump, shellQuote( files.err ), shellQuote( files.pid ), shellQuote( files.stop ) );
}

QString adbStopScript( const AdbCaptureFiles& files )
{
    // The mark is left for a script that has not left its pid yet, which
    // removes it as it ends; once the pid was read, tcpdump is ended here.
    return QStringLiteral( ": >%1; if p=$(cat %2 2>/dev/null) && [ -n \"$p\" ]; then "
                           "kill $p 2>/dev/null; rm -f %1 %2; fi; rm -f %3" )
        .arg( shellQuote( files.stop ), shellQuote( files.pid ), shellQuote( files.err ) );
}

QString adbCleanupScript( const AdbCaptureFiles& files )
{
    return QStringLiteral( "p=$(cat %1 2>/dev/null) && kill $p 2>/dev/null; rm -f %1 %2 %3" )
        .arg( shellQuote( files.pid ), shellQuote( files.err ), shellQuote( files.stop ) );
}

std::vector<LiveTarget> parseAdbDevices( const QString& out )
{
    static const QRegularExpression entry( QStringLiteral( "^(\\S+)\\s+(.*)$" ) );
    static const QRegularExpression property(
        QStringLiteral( "(?:^|\\s)(model|product|device):(\\S+)" ) );
    std::vector<LiveTarget> devices;
    for ( const auto& raw : out.split( QLatin1Char( '\n' ), Qt::SkipEmptyParts ) ) {
        const auto line = raw.trimmed();
        // The header, and the daemon's "* daemon started successfully".
        if ( line.isEmpty() || line.startsWith( QLatin1Char( '*' ) )
             || line.startsWith( QStringLiteral( "List of devices" ) ) ) {
            continue;
        }
        const auto match = entry.match( line );
        if ( !match.hasMatch() ) {
            continue;
        }
        LiveTarget device;
        device.id = match.captured( 1 );
        const auto rest = match.captured( 2 );
        QMap<QString, QString> properties;
        for ( auto it = property.globalMatch( rest ); it.hasNext(); ) {
            const auto found = it.next();
            properties.insert( found.captured( 1 ), found.captured( 2 ) );
        }
        for ( const auto* key : { "model", "product", "device" } ) {
            if ( properties.contains( QLatin1String( key ) ) ) {
                device.description = properties.value( QLatin1String( key ) );
                device.description.replace( QLatin1Char( '_' ), QLatin1Char( ' ' ) );
                break;
            }
        }
        const auto state = rest.section( QLatin1Char( ' ' ), 0, 0 );
        if ( rest.startsWith( QStringLiteral( "no permissions" ) ) ) {
            device.problem = QStringLiteral(
                "no permissions: on Linux, add a udev rule for the device "
                "(https://developer.android.com/studio/run/device) and reconnect it" );
        }
        else if ( state == QStringLiteral( "unauthorized" ) ) {
            device.problem = QStringLiteral(
                "unauthorized: unlock the device and allow USB debugging in its prompt" );
        }
        else if ( state == QStringLiteral( "offline" ) ) {
            device.problem
                = QStringLiteral( "offline: reconnect it, or restart adb (adb kill-server)" );
        }
        else if ( state != QStringLiteral( "device" ) ) {
            device.problem = QStringLiteral( "%1: not ready for adb" ).arg( state );
        }
        devices.push_back( std::move( device ) );
    }
    return devices;
}

std::vector<LiveTarget> parseDeviceInterfaces( const QString& out )
{
    static const QRegularExpression link(
        QStringLiteral( "^\\d+:\\s+([^:@\\s]+)(?:@[^:\\s]*)?:\\s+<([^>]*)>" ) );
    static const QRegularExpression name( QStringLiteral( "^[A-Za-z0-9._:-]+$" ) );
    std::vector<LiveTarget> interfaces;
    for ( const auto& raw : out.split( QLatin1Char( '\n' ), Qt::SkipEmptyParts ) ) {
        const auto line = raw.trimmed();
        if ( const auto match = link.match( line ); match.hasMatch() ) {
            interfaces.push_back( { match.captured( 1 ), match.captured( 2 ), {} } );
        }
        else if ( name.match( line ).hasMatch() ) {
            interfaces.push_back( { line, {}, {} } );
        }
    }
    return interfaces;
}

QString adbRootGuidance()
{
    return QStringLiteral(
        "Capturing on Android needs root. On an emulator (a system image without Google Play) "
        "or a userdebug or eng build, run adb root once (LogSquirl never runs it itself) and "
        "refresh. On a rooted device, let the su manager (e.g. Magisk) grant root to the Shell "
        "app (com.android.shell) without asking each time. A stock, unrooted device cannot "
        "capture this way." );
}

QString adbTcpdumpGuidance()
{
    return QStringLiteral(
        "Emulator images and userdebug builds have tcpdump in /system/bin (older ones in "
        "/system/xbin). On another device, push a static tcpdump built for its CPU (adb shell "
        "getprop ro.product.cpu.abi): adb push tcpdump /data/local/tmp/, then adb shell chmod "
        "755 /data/local/tmp/tcpdump; the Android source finds it there." );
}

QString adbConnectGuidance()
{
    return QStringLiteral(
        "Connect the device by USB with USB debugging on (Settings > About phone: tap Build "
        "number seven times; then Settings > System > Developer options > USB debugging), or "
        "start an emulator. If it is offline, reconnect it or restart adb: adb kill-server." );
}

QString adbAuthorizeGuidance()
{
    return QStringLiteral(
        "Unlock the device and allow USB debugging in the prompt it shows (\"Always allow from "
        "this computer\"). If no prompt comes, revoke the USB debugging authorizations in "
        "Developer options and reconnect the device." );
}

QString adbInstallHint()
{
    return QStringLiteral(
        "adb not found: install the Android SDK Platform-Tools "
        "(https://developer.android.com/tools/releases/platform-tools) or Android Studio, and "
        "put adb on PATH or set ANDROID_HOME." );
}

AdbPrograms AdbPrograms::forThisComputer()
{
    AdbPrograms where;
    where.os = runningCaptureOs();
    where.searchPath
        = qEnvironmentVariable( "PATH" ).split( QDir::listSeparator(), Qt::SkipEmptyParts );
    const auto add = [ &where ]( const QString& dir ) {
        if ( !dir.isEmpty() && !where.installed.contains( dir ) ) {
            where.installed << dir;
        }
    };
    for ( const auto* variable : { "ANDROID_HOME", "ANDROID_SDK_ROOT" } ) {
        const auto sdk = qEnvironmentVariable( variable );
        if ( !sdk.isEmpty() ) {
            add( QDir( sdk ).filePath( QStringLiteral( "platform-tools" ) ) );
        }
    }
    const auto home = QDir::homePath();
    switch ( where.os ) {
    case CaptureOs::MacOS:
        add( home + QStringLiteral( "/Library/Android/sdk/platform-tools" ) );
        add( QStringLiteral( "/opt/homebrew/bin" ) );
        add( QStringLiteral( "/usr/local/bin" ) );
        break;
    case CaptureOs::Linux:
        add( home + QStringLiteral( "/Android/Sdk/platform-tools" ) );
        add( QStringLiteral( "/usr/lib/android-sdk/platform-tools" ) );
        add( QStringLiteral( "/opt/android-sdk/platform-tools" ) );
        add( QStringLiteral( "/usr/bin" ) );
        add( QStringLiteral( "/usr/local/bin" ) );
        break;
    case CaptureOs::Windows: {
        const auto local = qEnvironmentVariable( "LOCALAPPDATA" );
        if ( !local.isEmpty() ) {
            add( QDir( local ).filePath( QStringLiteral( "Android/Sdk/platform-tools" ) ) );
        }
        const auto programs = qEnvironmentVariable( "ProgramFiles(x86)" );
        if ( !programs.isEmpty() ) {
            add( QDir( programs )
                     .filePath( QStringLiteral( "Android/android-sdk/platform-tools" ) ) );
        }
        break;
    }
    }
    return where;
}

AdbSourceKind::AdbSourceKind( AdbPrograms where )
    : where_( std::move( where ) )
{
}

QString AdbSourceKind::adb() const
{
    const auto name
        = where_.os == CaptureOs::Windows ? QStringLiteral( "adb.exe" ) : QStringLiteral( "adb" );
    for ( const auto& dir : where_.searchPath + where_.installed ) {
        if ( dir.isEmpty() ) {
            continue;
        }
        const auto path = QDir( dir ).filePath( name );
        if ( runnable( path ) ) {
            return path;
        }
    }
    return {};
}

AdbDeviceAccess AdbSourceKind::probe( const QString& serial, bool withInterfaces,
                                      std::chrono::milliseconds timeout ) const
{
    const auto program = adb();
    if ( program.isEmpty() ) {
        throw std::runtime_error( adbInstallHint().toStdString() );
    }
    const auto output = runListing(
        adbShell( program, serial, probeScript( where_.deviceTempDir, withInterfaces ) ), timeout );
    auto failure = adbFailure( output, QStringLiteral( "adb shell" ) );
    if ( failure.isEmpty() && !output.out.contains( kUidMark ) ) {
        failure = QStringLiteral( "The shell of %1 did not answer as expected:\n%2" )
                      .arg( serial, ( output.out + output.err ).trimmed() );
    }
    if ( !failure.isEmpty() ) {
        throw std::runtime_error( failure.toStdString() );
    }
    AdbDeviceAccess access;
    const auto links = output.out.indexOf( QLatin1Char( '\n' ) + kLinksMark );
    const auto head = links < 0 ? output.out : output.out.left( links );
    for ( const auto& raw : head.split( QLatin1Char( '\n' ) ) ) {
        const auto line = raw.trimmed();
        if ( line.startsWith( kUidMark ) ) {
            access.root = line.mid( kUidMark.size() ) == QStringLiteral( "0" );
        }
        else if ( line.startsWith( kSuMark ) ) {
            access.su = line.mid( kSuMark.size() ) == QStringLiteral( "0" );
        }
        else if ( line.startsWith( kTcpdumpMark ) ) {
            access.tcpdump = line.mid( kTcpdumpMark.size() );
        }
    }
    if ( withInterfaces && links >= 0 ) {
        access.interfaces
            = parseDeviceInterfaces( output.out.mid( links + 1 + kLinksMark.size() ) );
    }
    return access;
}

ProcessCommand AdbSourceKind::captureCommand( const LiveChoice& choice,
                                              const AdbDeviceAccess& access,
                                              const QString& tag ) const
{
    const auto files = AdbCaptureFiles::of( where_.deviceTempDir, tag );
    auto tcpdump = QStringLiteral( "%1 -i %2 -s %3 -U -w -" )
                       .arg( shellQuote( access.tcpdump.isEmpty() ? QStringLiteral( "tcpdump" )
                                                                  : access.tcpdump ),
                             shellQuote( choice.networkInterface ) )
                       .arg( choice.snaplen );
    if ( !choice.filter.isEmpty() ) {
        tcpdump += QLatin1Char( ' ' ) + shellQuote( choice.filter );
    }
    // exec-out merges stderr into the capture: the shell's and su's go nowhere.
    const auto line = QStringLiteral( "exec 2>/dev/null; " )
                      + asRoot( adbCaptureScript( tcpdump, files ), access.su && !access.root );
    const auto program = adb();
    return { program.isEmpty() ? QStringLiteral( "adb" ) : program,
             { QStringLiteral( "-s" ), choice.device, QStringLiteral( "exec-out" ), line },
             QStringLiteral( "adb" ) };
}

QString AdbSourceKind::id() const
{
    return QStringLiteral( "adb" );
}

QString AdbSourceKind::displayName() const
{
    return QStringLiteral( "Android" );
}

LiveAvailability AdbSourceKind::availability() const
{
    if ( adb().isEmpty() ) {
        return LiveAvailability::unavailable( adbInstallHint() );
    }
    return {};
}

LiveSourceKind::Devices AdbSourceKind::devices() const
{
    return Devices::Listed;
}

LiveListing AdbSourceKind::listDevices( std::chrono::milliseconds timeout ) const
{
    LiveListing listing;
    const auto program = adb();
    if ( program.isEmpty() ) {
        listing.error = adbInstallHint();
        return listing;
    }
    const auto output = runListing( { program,
                                      { QStringLiteral( "devices" ), QStringLiteral( "-l" ) },
                                      QStringLiteral( "adb" ) },
                                    timeout );
    listing.error = adbFailure( output, QStringLiteral( "adb devices" ) );
    if ( !listing.error.isEmpty() ) {
        return listing;
    }
    listing.targets = parseAdbDevices( output.out );
    if ( listing.targets.empty() ) {
        listing.error = QStringLiteral( "No Android device found.\n\n" ) + adbConnectGuidance();
    }
    return listing;
}

LiveListing AdbSourceKind::listInterfaces( const QString& device,
                                           std::chrono::milliseconds timeout ) const
{
    LiveListing listing;
    if ( device.isEmpty() ) {
        return listing;
    }
    AdbDeviceAccess access;
    try {
        access = probe( device, true, timeout );
    } catch ( const std::exception& e ) {
        listing.error = QString::fromUtf8( e.what() );
        if ( const auto hint = explainFailure( listing.error ); !hint.isEmpty() ) {
            listing.error += QStringLiteral( "\n\n" ) + hint;
        }
        return listing;
    }
    listing.targets.push_back(
        { QStringLiteral( "any" ), QStringLiteral( "all interfaces" ), {} } );
    for ( auto& target : access.interfaces ) {
        if ( target.id != QStringLiteral( "any" ) ) {
            listing.targets.push_back( std::move( target ) );
        }
    }
    if ( !access.root && !access.su ) {
        listing.error
            = QStringLiteral( "%1 gives adb no root, which capturing needs.\n\n" ).arg( device )
              + adbRootGuidance();
    }
    else if ( access.tcpdump.isEmpty() ) {
        listing.error = QStringLiteral( "tcpdump was not found on %1.\n\n" ).arg( device )
                        + adbTcpdumpGuidance();
    }
    return listing;
}

QString AdbSourceKind::validate( const LiveChoice& choice ) const
{
    const auto device = choice.device.trimmed();
    if ( device.isEmpty() ) {
        return QStringLiteral( "Choose a device." );
    }
    static const QRegularExpression serial( QStringLiteral( "^[^\\s-][^\\s]*$" ) );
    if ( !serial.match( choice.device ).hasMatch() ) {
        return QStringLiteral( "A device serial has no spaces and does not start with '-'." );
    }
    if ( auto problem = LiveSourceKind::validate( choice ); !problem.isEmpty() ) {
        return problem;
    }
    static const QRegularExpression name( QStringLiteral( "^[A-Za-z0-9._:-]+$" ) );
    if ( !name.match( choice.networkInterface ).hasMatch() ) {
        return QStringLiteral(
            "An Android interface's name holds letters, digits, '.', '_', ':' and '-'." );
    }
    return {};
}

ProcessCommand AdbSourceKind::command( const LiveChoice& choice ) const
{
    AdbDeviceAccess access;
    access.root = true;
    return captureCommand( choice, access, QStringLiteral( "capture" ) );
}

LiveCapture::SourceFactory AdbSourceKind::makeSource( const LiveChoice& choice ) const
{
    return [ kind = *this, choice ](
               const std::atomic_bool* stop,
               std::function<void( const QString& )> onStderrLine ) -> std::unique_ptr<ByteSource> {
        const auto access = kind.probe( choice.device, false, kListTimeout );
        if ( !access.root && !access.su ) {
            throw std::runtime_error(
                QStringLiteral( "%1 gives adb no root, which capturing needs" )
                    .arg( choice.device )
                    .toStdString() );
        }
        if ( access.tcpdump.isEmpty() ) {
            throw std::runtime_error( QStringLiteral( "tcpdump was not found on %1" )
                                          .arg( choice.device )
                                          .toStdString() );
        }
        // Its own files: captures on one device do not meet.
        const auto tag = QString::number( QRandomGenerator::global()->generate64(), 16 );
        DeviceCapture device{ kind.adb(), choice.device, access.su && !access.root,
                              AdbCaptureFiles::of( kind.where_.deviceTempDir, tag ) };
        return std::make_unique<DeviceCaptureSource>( kind.captureCommand( choice, access, tag ),
                                                      std::move( device ), stop,
                                                      std::move( onStderrLine ) );
    };
}

QString AdbSourceKind::explainFailure( const QString& error ) const
{
    const auto text = error.toLower();
    if ( text.contains( QStringLiteral( "adb not found" ) ) ) {
        return text.contains( QStringLiteral( "platform-tools" ) ) ? QString() : adbInstallHint();
    }
    if ( text.contains( QStringLiteral( "unauthorized" ) ) ) {
        return adbAuthorizeGuidance();
    }
    if ( text.contains( QStringLiteral( "tcpdump" ) )
         && ( text.contains( QStringLiteral( "not found" ) )
              || text.contains( QStringLiteral( "no such file" ) ) ) ) {
        return adbTcpdumpGuidance();
    }
    if ( text.contains( QStringLiteral( "no root" ) ) || isCapturePermissionError( error ) ) {
        return adbRootGuidance();
    }
    if ( text.contains( QStringLiteral( "offline" ) )
         || text.contains( QStringLiteral( "no devices/emulators found" ) )
         || ( text.contains( QStringLiteral( "device" ) )
              && text.contains( QStringLiteral( "not found" ) ) ) ) {
        return adbConnectGuidance();
    }
    return {};
}

} // namespace tcpdump
