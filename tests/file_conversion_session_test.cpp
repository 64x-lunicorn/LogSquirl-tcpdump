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
 * @file file_conversion_session_test.cpp
 * @brief BDD tests for the File Conversion session: what opening a capture
 *        file does to the host, the capture catalog and the output
 *        directory, from its start to its outcome, with a fake host and a
 *        real Capture Catalog, and no widget.
 *
 * The conversion runs on the session's worker, as in the app, and its
 * outcome comes through the event loop, which the waits run until the
 * session told it.  A held converter converts as the app does, then waits
 * until the test lets it go or the session cancels it, so that a cancel or
 * a progress comes while it runs, when the test says.
 */

#include <catch2/catch.hpp>

#include "fake_session_host.h"
#include "fakehost.h"
#include "file_conversion_session.h"
#include "pcapbuilder.h"
#include "settings.h"

#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QFileInfo>
#include <QTemporaryDir>
#include <QTimer>

#include <chrono>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr int kHangGuardMs = 120000;

/// The capture file @p name in @p dir, holding @p content.
QString writeCapture( const QTemporaryDir& dir, const QString& name, const Bytes& content )
{
    const auto path = dir.filePath( name );
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    file.write( reinterpret_cast<const char*>( content.data() ),
                static_cast<qint64>( content.size() ) );
    return path;
}

/// A capture of @p count UDP packets.
Bytes captureOf( int count )
{
    std::vector<Bytes> packets;
    for ( int i = 0; i < count; ++i ) {
        packets.push_back( eth(
            EthertypeIpv4, ipv4( IpProtoUdp, udp( 40000, static_cast<uint16_t>( 1000 + i % 50 ),
                                                  text( "payload" ) ) ) ) );
    }
    return pcapOf( packets );
}

/// The text of the file @p path.
QString readText( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return QString::fromUtf8( file.readAll() );
}

/**
 * A converter that converts as convertPcap() does, reporting @p permille
 * first, then holds its result until let go of (release()) or cancelled,
 * never returning Cancelled itself: a conversion that was done when the
 * cancel came.  It records the options each conversion got.
 */
class HeldConverter {
public:
    explicit HeldConverter( int permille = 0 )
        : permille_( permille )
    {
    }

    FileConversionSession::Converter converter()
    {
        auto state = state_;
        const int permille = permille_;
        return [ state, permille ]( const QString& filePath, const QString& outputRoot,
                                    const std::atomic_bool* cancel,
                                    const std::function<void( int )>& progress,
                                    const ConversionOptions& options ) {
            {
                const std::lock_guard<std::mutex> lock( state->mutex );
                state->options.push_back( options );
            }
            auto result = convertPcap( filePath, outputRoot, nullptr, {}, options );
            if ( permille > 0 && progress ) {
                progress( permille );
            }
            while ( !state->released.load() && !cancel->load() ) {
                std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
            }
            return result;
        };
    }

    /// Let the held conversion return its result.
    void release()
    {
        state_->released.store( true );
    }

    /// The options of each conversion started, in order.
    std::vector<ConversionOptions> options() const
    {
        const std::lock_guard<std::mutex> lock( state_->mutex );
        return state_->options;
    }

private:
    struct State {
        std::atomic_bool released{ false };
        mutable std::mutex mutex;
        std::vector<ConversionOptions> options;
    };
    std::shared_ptr<State> state_ = std::make_shared<State>();
    int permille_;
};

/// A session on a fake host and a real catalog, writing below a temporary
/// directory of its own.
struct Session {
    FakeHost host; // its config directory and log
    FakeSessionHost sessionHost;
    CaptureCatalog catalog{ sessionHost };
    QTemporaryDir outputRoot; ///< Outlives the session, which writes below it.
    FileConversionSession session{ sessionHost, catalog };

    Session()
    {
        REQUIRE( outputRoot.isValid() );
        session.setOutputRoot( outputRoot.path() );
    }

    /// Run the event loop until @p met holds, checked each time the session
    /// tells something; the deadline only guards against a hang.
    bool waitUntil( const std::function<bool()>& met )
    {
        if ( met() ) {
            return true;
        }
        QEventLoop loop;
        const auto check = [ & ] {
            if ( met() ) {
                loop.quit();
            }
        };
        QObject::connect( &session, &FileConversionSession::stateChanged, &loop, check );
        QObject::connect( &session, &FileConversionSession::progressed, &loop, check );
        QObject::connect( &session, &FileConversionSession::finished, &loop, check );
        QTimer::singleShot( kHangGuardMs, &loop, &QEventLoop::quit );
        loop.exec();
        return met();
    }

    /// Run the event loop until the conversion has ended: outcome() is its.
    const FileConversionOutcome& waitForOutcome()
    {
        REQUIRE( waitUntil( [ this ] { return session.outcome().has_value(); } ) );
        return *session.outcome();
    }

    /// Whether the output root holds nothing.
    bool outputRootEmpty() const
    {
        return QDir( outputRoot.path() ).isEmpty();
    }
};

} // namespace

SCENARIO( "A capture file is converted in the background, kept and opened in a tab",
          "[file_session]" )
{
    Session s;
    QTemporaryDir dir;
    const auto capture = writeCapture( dir, "small.pcap", captureOf( 3 ) );

    WHEN( "it is opened" )
    {
        REQUIRE( s.session.start( capture ) );

        THEN( "the session converts it, and says it is reading it" )
        {
            REQUIRE( s.session.state() == FileConversionSession::State::Converting );
            REQUIRE( s.session.isBusy() );
            REQUIRE( s.session.filePath() == capture );
            REQUIRE( s.session.label() == "Reading small.pcap\xe2\x80\xa6" );
            REQUIRE( s.host.logs.contains( "Opening pcap file: " + capture ) );
        }

        AND_WHEN( "the conversion is done" )
        {
            const auto& outcome = s.waitForOutcome();

            THEN( "its text file is kept in the catalog, in front, and its tab opened, not "
                  "followed" )
            {
                REQUIRE_FALSE( s.session.isBusy() );
                REQUIRE( outcome.status == FileConversionOutcome::Status::Opened );
                REQUIRE( outcome.filePath == capture );
                REQUIRE( s.sessionHost.openedTabs == QStringList{ outcome.textPath } );
                REQUIRE( s.sessionHost.openedFollowing == QList<bool>{ false } );
                const auto* entry = s.catalog.find( outcome.textPath );
                REQUIRE( entry );
                REQUIRE( entry->fileName == "small.pcap" );
                REQUIRE( entry->summary.packets == 3 );
                REQUIRE( entry->index );
                REQUIRE( s.catalog.isFront( outcome.textPath ) );
                REQUIRE( readText( outcome.textPath ).count( '\n' ) == 4 ); // header + 3
            }

            THEN( "it is logged, nobody is told, and the summary label is the tab's" )
            {
                const auto opened = "Opened 3 packets from " + capture;
                REQUIRE( outcome.log == opened );
                REQUIRE( s.host.logs.contains( opened ) );
                REQUIRE( outcome.notification.isEmpty() );
                REQUIRE( s.sessionHost.notifications.isEmpty() );
                REQUIRE( outcome.label.isEmpty() );
                REQUIRE( s.session.label().isEmpty() );
            }
        }
    }

    WHEN( "a file whose name holds markup is opened" )
    {
        const auto marked = writeCapture( dir, "<b>.pcap", captureOf( 1 ) );
        REQUIRE( s.session.start( marked ) );

        THEN( "the label shows the name as text" )
        {
            REQUIRE( s.session.label() == "Reading &lt;b&gt;.pcap\xe2\x80\xa6" );
            s.waitForOutcome();
        }
    }
}

SCENARIO( "A capture file that cannot be converted is told, and leaves nothing behind",
          "[file_session]" )
{
    Session s;
    QTemporaryDir dir;

    WHEN( "a file that is not a capture is opened" )
    {
        REQUIRE( s.session.start( writeCapture( dir, "junk.pcap", Bytes( 64, 0xEE ) ) ) );
        const auto& outcome = s.waitForOutcome();

        THEN( "it failed, the error is the label, logged and told, and no tab opened" )
        {
            REQUIRE( outcome.status == FileConversionOutcome::Status::Failed );
            REQUIRE( outcome.error.contains( "magic" ) );
            REQUIRE( outcome.label == "Error: " + outcome.error.toHtmlEscaped() );
            REQUIRE( s.session.label() == outcome.label );
            REQUIRE( outcome.log == "pcap parse error: " + outcome.error );
            REQUIRE( s.host.logs.contains( outcome.log ) );
            REQUIRE( outcome.notification == "Failed to open pcap: " + outcome.error );
            REQUIRE( s.sessionHost.notifications == QStringList{ outcome.notification } );
            REQUIRE( s.sessionHost.openedTabs.isEmpty() );
            REQUIRE( s.catalog.isEmpty() );
        }

        THEN( "its temporary directory is removed" )
        {
            REQUIRE( s.outputRootEmpty() );
        }
    }

    WHEN( "the output root does not exist" )
    {
        s.session.setOutputRoot( dir.filePath( "no-such-root" ) );
        REQUIRE( s.session.start( writeCapture( dir, "small.pcap", captureOf( 1 ) ) ) );
        const auto& outcome = s.waitForOutcome();

        THEN( "the error names the temporary directory, and no tab is opened" )
        {
            REQUIRE( outcome.status == FileConversionOutcome::Status::Failed );
            REQUIRE( outcome.label.startsWith( "Error: Cannot create a temporary directory" ) );
            REQUIRE( s.sessionHost.notifications.size() == 1 );
            REQUIRE( s.sessionHost.notifications.first().contains(
                "Cannot create a temporary directory" ) );
            REQUIRE( s.sessionHost.openedTabs.isEmpty() );
        }
    }
}

SCENARIO( "A running conversion can be cancelled, even once it is done", "[file_session]" )
{
    Session s;
    QTemporaryDir dir;
    const auto capture = writeCapture( dir, "small.pcap", captureOf( 3 ) );
    HeldConverter held;
    s.session.setConverter( held.converter() );
    REQUIRE( s.session.start( capture ) );

    WHEN( "the user cancels it" )
    {
        s.session.cancel();

        THEN( "the session says it is cancelling until the conversion has ended" )
        {
            REQUIRE( s.session.state() == FileConversionSession::State::Cancelling );
            REQUIRE( s.session.isBusy() );
            REQUIRE( s.session.label() == "Cancelling\xe2\x80\xa6" );
            s.waitForOutcome();
        }

        AND_WHEN( "the conversion, done with its file, returns" )
        {
            const auto& outcome = s.waitForOutcome();

            THEN( "the cancel wins: the file is taken back, and no tab opened" )
            {
                REQUIRE( outcome.status == FileConversionOutcome::Status::Cancelled );
                REQUIRE( outcome.textPath.isEmpty() );
                REQUIRE( s.sessionHost.openedTabs.isEmpty() );
                REQUIRE( s.catalog.isEmpty() );
                REQUIRE( s.outputRootEmpty() );
            }

            THEN( "the label says it was cancelled, it is logged, and nobody is told" )
            {
                REQUIRE( outcome.label == "Cancelled." );
                REQUIRE( s.session.label() == "Cancelled." );
                REQUIRE( outcome.log == "Cancelled opening " + capture );
                REQUIRE( s.host.logs.contains( outcome.log ) );
                REQUIRE( outcome.notification.isEmpty() );
                REQUIRE( s.sessionHost.notifications.isEmpty() );
            }

            THEN( "the next file may be opened" )
            {
                REQUIRE_FALSE( s.session.isBusy() );
                REQUIRE( s.session.refusal().isEmpty() );
            }
        }
    }

    WHEN( "nobody cancels it" )
    {
        held.release();
        const auto& outcome = s.waitForOutcome();

        THEN( "it is opened" )
        {
            REQUIRE( outcome.status == FileConversionOutcome::Status::Opened );
            REQUIRE( s.sessionHost.openedTabs == QStringList{ outcome.textPath } );
        }
    }
}

SCENARIO( "A session destroyed while it converts leaves nothing behind", "[file_session]" )
{
    FakeHost host;
    FakeSessionHost sessionHost;
    CaptureCatalog catalog{ sessionHost };
    QTemporaryDir outputRoot;
    QTemporaryDir dir;
    auto session = std::make_unique<FileConversionSession>( sessionHost, catalog );
    session->setOutputRoot( outputRoot.path() );
    HeldConverter held;
    session->setConverter( held.converter() );
    bool told = false;
    QObject::connect( session.get(), &FileConversionSession::finished,
                      [ &told ]( const FileConversionOutcome& ) { told = true; } );
    REQUIRE( session->start( writeCapture( dir, "small.pcap", captureOf( 3 ) ) ) );

    WHEN( "it is destroyed, as when the plugin is unloaded" )
    {
        session.reset();
        QCoreApplication::processEvents();

        THEN( "the conversion was cancelled and waited for: its file is gone, no tab opened, "
              "nothing told" )
        {
            REQUIRE( QDir( outputRoot.path() ).isEmpty() );
            REQUIRE( sessionHost.openedTabs.isEmpty() );
            REQUIRE( sessionHost.notifications.isEmpty() );
            REQUIRE_FALSE( told );
        }
    }
}

SCENARIO( "Each conversion writes a new private file", "[file_session]" )
{
    Session s;
    QTemporaryDir captures;
    QDir( captures.path() ).mkdir( "a" );
    QDir( captures.path() ).mkdir( "b" );

    WHEN( "two captures with the same name are opened one after the other" )
    {
        REQUIRE( s.session.start( writeCapture( captures, "a/capture.pcap", captureOf( 1 ) ) ) );
        const auto first = s.waitForOutcome().textPath;
        REQUIRE( s.session.start( writeCapture( captures, "b/capture.pcap", captureOf( 2 ) ) ) );
        const auto second = s.waitForOutcome().textPath;

        THEN( "each gets its own file, named after the capture, and the first is kept" )
        {
            REQUIRE( s.sessionHost.openedTabs == QStringList{ first, second } );
            REQUIRE( first != second );
            REQUIRE( QFileInfo( first ).fileName() == "capture.log" );
            REQUIRE( QFileInfo( second ).fileName() == "capture.log" );
            REQUIRE( readText( first ).count( '\n' ) == 2 ); // header + 1 packet
            REQUIRE( s.catalog.find( first ) );
        }

        THEN( "each lives in its own directory below the output root" )
        {
            const auto directory = QFileInfo( first ).absoluteDir();
            REQUIRE( QFileInfo( directory.absolutePath() ).absolutePath()
                     == QFileInfo( s.outputRoot.path() ).absoluteFilePath() );
            REQUIRE( directory.dirName().startsWith(
                QString( "logsquirl-tcpdump-%1-" ).arg( QCoreApplication::applicationPid() ) ) );
        }

#ifdef Q_OS_UNIX
        THEN( "only the user can read the file and enter its directory" )
        {
            const QFileDevice::Permissions groupOrOther
                = QFileDevice::ReadGroup | QFileDevice::WriteGroup | QFileDevice::ExeGroup
                  | QFileDevice::ReadOther | QFileDevice::WriteOther | QFileDevice::ExeOther;
            REQUIRE( ( QFile::permissions( first ) & groupOrOther ) == 0 );
            REQUIRE( ( QFile::permissions( QFileInfo( first ).absolutePath() ) & groupOrOther )
                     == 0 );
        }
#endif
    }
}

SCENARIO( "Each conversion reads the options saved when it starts", "[file_session][settings]" )
{
    Session s;
    QTemporaryDir dir;
    const auto capture = writeCapture( dir, "small.pcap", captureOf( 2 ) );
    ConversionOptions options;
    options.layout.timeColumns = TimeColumns::RelativeOnly;
    options.preview = false;
    REQUIRE( saveConversionOptions( s.host.configDir(), options ) );

    WHEN( "the capture is opened" )
    {
        REQUIRE( s.session.start( capture ) );
        const auto first = s.waitForOutcome().textPath;

        THEN( "it is converted with them" )
        {
            const auto text = readText( first );
            REQUIRE_FALSE( text.contains( "UTC Time" ) );
            REQUIRE_FALSE( text.contains( "payload" ) );
        }

        AND_WHEN( "the options change and it is opened again" )
        {
            REQUIRE( saveConversionOptions( s.host.configDir(), {} ) );
            REQUIRE( s.session.start( capture ) );
            const auto second = s.waitForOutcome().textPath;

            THEN( "the new conversion has the new options, the first keeps its own" )
            {
                const auto again = readText( second );
                REQUIRE( again.contains( "UTC Time" ) );
                REQUIRE( again.contains( "payload" ) );
                REQUIRE_FALSE( readText( first ).contains( "UTC Time" ) );
            }
        }
    }

    WHEN( "the options change while the capture is converted" )
    {
        HeldConverter held;
        s.session.setConverter( held.converter() );
        REQUIRE( s.session.start( capture ) );
        REQUIRE( saveConversionOptions( s.host.configDir(), {} ) );
        held.release();
        s.waitForOutcome();

        THEN( "it is converted with the options of its start" )
        {
            REQUIRE( held.options().size() == 1 );
            REQUIRE( held.options().front().layout.timeColumns == TimeColumns::RelativeOnly );
            REQUIRE_FALSE( held.options().front().preview );
        }
    }
}

SCENARIO( "A conversion tells its progress", "[file_session]" )
{
    Session s;
    QTemporaryDir dir;
    HeldConverter held( 500 );
    s.session.setConverter( held.converter() );
    REQUIRE( s.session.start( writeCapture( dir, "small.pcap", captureOf( 1 ) ) ) );
    REQUIRE( s.session.progress() == 0 );

    WHEN( "the conversion reports half of it done" )
    {
        REQUIRE( s.waitUntil( [ &s ] { return s.session.progress() == 500; } ) );

        THEN( "the session has it, still converting" )
        {
            REQUIRE( s.session.state() == FileConversionSession::State::Converting );
            held.release();
            s.waitForOutcome();
        }
    }
}

SCENARIO( "Opening a file is refused while the Activity rule refuses it", "[file_session]" )
{
    Session s;
    QTemporaryDir dir;
    const auto capture = writeCapture( dir, "small.pcap", captureOf( 1 ) );

    WHEN( "a live capture runs" )
    {
        s.sessionHost.running.capturing = true;

        THEN( "no conversion starts, and the user is told why, as the rule says it" )
        {
            const auto why = refusalMessage( ActivityRefusal::Capturing );
            REQUIRE( s.session.refusal() == why );
            REQUIRE_FALSE( s.session.start( capture ) );
            REQUIRE_FALSE( s.session.isBusy() );
            REQUIRE( s.sessionHost.notifications == QStringList{ why } );
            REQUIRE_FALSE( s.session.outcome() );
        }
    }

    WHEN( "packets are exported" )
    {
        s.sessionHost.running.exporting = true;

        THEN( "a file may be opened all the same" )
        {
            REQUIRE( s.session.refusal().isEmpty() );
            REQUIRE( s.session.start( capture ) );
            s.waitForOutcome();
        }
    }

    WHEN( "a conversion runs" )
    {
        HeldConverter held;
        s.session.setConverter( held.converter() );
        REQUIRE( s.session.start( capture ) );

        THEN( "another is refused, with the rule's message, and the first goes on" )
        {
            const auto why = refusalMessage( ActivityRefusal::Converting );
            REQUIRE( s.session.refusal() == why );
            REQUIRE_FALSE( s.session.start( capture ) );
            REQUIRE( s.sessionHost.notifications == QStringList{ why } );
            REQUIRE( s.session.state() == FileConversionSession::State::Converting );
            held.release();
            REQUIRE( s.waitForOutcome().status == FileConversionOutcome::Status::Opened );
            REQUIRE( s.sessionHost.openedTabs.size() == 1 );
        }
    }
}
