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
 * @file export_session_test.cpp
 * @brief BDD tests for the Export session: what exporting the selected
 *        packets does to the host and the file chosen, from its start to its
 *        outcome, with a fake host, a real Capture Catalog and no widget.
 *
 * The export runs on the session's worker, as in the app, and its outcome
 * comes through the event loop, which the waits run until the session told
 * it.  A held exporter holds before it writes, or after, until the test lets
 * it go or the session cancels it, so that a cancel or a progress comes
 * when the test says.
 */

#include <catch2/catch.hpp>

#include "activity.h"
#include "capture_reader.h"
#include "export_session.h"
#include "fake_session_host.h"
#include "fakehost.h"
#include "pcap_converter.h"

#include <QDir>
#include <QEventLoop>
#include <QFile>
#include <QStringList>
#include <QTemporaryDir>
#include <QTimer>

#include <chrono>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

using namespace tcpdump;
using namespace tcpdump_test;

namespace {

constexpr int kHangGuardMs = 120000;

const QString kCapture = QStringLiteral( TCPDUMP_CORPUS_DIR "/mixed.pcap" );

QByteArray readAll( const QString& path )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::ReadOnly ) );
    return file.readAll();
}

/// How many packets the capture file @p path holds.
size_t packetsIn( const QString& path )
{
    const auto bytes = readAll( path );
    const auto parsed = parsePcap( reinterpret_cast<const uint8_t*>( bytes.constData() ),
                                   static_cast<size_t>( bytes.size() ) );
    REQUIRE( parsed.ok );
    return parsed.packets.size();
}

/// Write @p text to the file @p path, as the file an export replaces.
void writeFile( const QString& path, const QByteArray& text )
{
    QFile file( path );
    REQUIRE( file.open( QIODevice::WriteOnly ) );
    REQUIRE( file.write( text ) == text.size() );
}

/// Wait, without the event loop, until @p met holds: the export's result
/// waits for the event loop, which does not run meanwhile.
bool holdsSoon( const std::function<bool()>& met )
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds( 10 );
    while ( !met() && std::chrono::steady_clock::now() < deadline ) {
        std::this_thread::sleep_for( std::chrono::milliseconds( 5 ) );
    }
    return met();
}

/**
 * An exporter that exports as exportPackets() does, reporting @p permille
 * first, and holds before it writes the file (a cancel then stops it) or
 * after (a cancel then comes too late), until let go of (release()) or
 * cancelled.
 */
class HeldExporter {
public:
    enum class Hold { BeforeWriting, AfterWriting };

    explicit HeldExporter( Hold hold, int permille = 0 )
        : hold_( hold )
        , permille_( permille )
    {
    }

    ExportSession::Exporter exporter()
    {
        auto state = state_;
        const auto hold = hold_;
        const int permille = permille_;
        return [ state, hold, permille ]( std::shared_ptr<const CaptureIndex> index,
                                          const PacketNumbers& numbers, const QString& outputPath,
                                          const std::atomic_bool* cancel,
                                          const std::function<void( int )>& progress ) {
            if ( permille > 0 && progress ) {
                progress( permille );
            }
            const auto wait = [ & ] {
                while ( !state->released.load() && !cancel->load() ) {
                    std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
                }
            };
            if ( hold == Hold::BeforeWriting ) {
                wait();
                return exportPackets( std::move( index ), numbers, outputPath, cancel );
            }
            auto result = exportPackets( std::move( index ), numbers, outputPath );
            state->written.store( true );
            wait();
            return result;
        };
    }

    /// Let the held export go on.
    void release()
    {
        state_->released.store( true );
    }

    /// Whether the export, held after writing, has written its file.
    bool written() const
    {
        return state_->written.load();
    }

private:
    struct State {
        std::atomic_bool released{ false };
        std::atomic_bool written{ false };
    };
    std::shared_ptr<State> state_ = std::make_shared<State>();
    Hold hold_;
    int permille_;
};

/// A session on a fake host and a real catalog whose tab in front shows
/// kCapture converted; the confirmer and the file chooser answered by the
/// test.
struct Session {
    explicit Session( std::size_t apiSize = sizeof( LogSquirlHostApi ) )
        : host( apiSize )
    {
        REQUIRE( dir.isValid() );
        auto converted = convertPcap( kCapture, dir.path(), nullptr, {}, {} );
        REQUIRE( converted.status == ConversionResult::Status::Converted );
        textPath = converted.outputPath;
        QFile file( textPath );
        REQUIRE( file.open( QIODevice::ReadOnly ) );
        lines = QString::fromUtf8( file.readAll() ).split( '\n', Qt::SkipEmptyParts );
        catalog.openConverted( textPath, kCapture, std::move( converted.summary ),
                               std::move( converted.index ) );
        catalog.setFront( textPath );

        session = std::make_unique<ExportSession>( sessionHost, catalog );
        session->setConfirmer( [ this ]( ExportRequest& request ) {
            requests.push_back( request );
            if ( numbers ) {
                request.numbers = *numbers;
            }
            return confirm;
        } );
        session->setFileChooser( [ this ]( const ExportRequest& request ) {
            chosenFor.push_back( request );
            return outputPath;
        } );
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
        QObject::connect( session.get(), &ExportSession::stateChanged, &loop, check );
        QObject::connect( session.get(), &ExportSession::progressed, &loop, check );
        QObject::connect( session.get(), &ExportSession::finished, &loop, check );
        QTimer::singleShot( kHangGuardMs, &loop, &QEventLoop::quit );
        loop.exec();
        return met();
    }

    /// Run the event loop until the export has ended: outcome() is its.
    const ExportOutcome& waitForOutcome()
    {
        REQUIRE( waitUntil( [ this ] { return session->outcome().has_value(); } ) );
        return *session->outcome();
    }

    FakeHost host; // the selected lines, the log and the host's capabilities
    FakeSessionHost sessionHost;
    CaptureCatalog catalog{ sessionHost };
    QTemporaryDir dir;
    QString textPath;  ///< The converted capture's text, in front.
    QStringList lines; ///< The text's lines, the header first.
    std::unique_ptr<ExportSession> session;

    bool confirm = true;                                ///< What the confirmer answers.
    std::optional<PacketNumbers> numbers;               ///< The packets the user names instead.
    QString outputPath = dir.filePath( "export.pcap" ); ///< What the file chooser answers.
    std::vector<ExportRequest> requests;                ///< What the confirmer was asked.
    std::vector<ExportRequest> chosenFor;               ///< What the file chooser was asked for.
};

} // namespace

SCENARIO( "The packets of the selected lines are confirmed and exported in the background",
          "[export_session]" )
{
    Session s;

    GIVEN( "the header and three packet lines selected" )
    {
        s.host.selectedLines = { s.lines[ 0 ], s.lines[ 2 ], s.lines[ 5 ], s.lines[ 6 ] };

        WHEN( "they are exported" )
        {
            REQUIRE( s.session->start() );

            THEN( "the user confirmed their packets and chose the file, and the export runs" )
            {
                REQUIRE( s.requests.size() == 1 );
                const auto& request = s.requests.front();
                REQUIRE( request.numbers == std::vector<uint32_t>{ 2, 5, 6 } );
                REQUIRE( request.captureName == "mixed.pcap" );
                REQUIRE( request.format == CaptureFormat::Pcap );
                REQUIRE( request.selectedLines == 4 );
                REQUIRE_FALSE( request.truncated );
                REQUIRE( s.chosenFor.size() == 1 );
                REQUIRE( s.chosenFor.front().numbers == request.numbers );

                REQUIRE( s.session->state() == ExportSession::State::Exporting );
                REQUIRE( s.session->isBusy() );
                REQUIRE( s.session->label() == "Exporting 3 packets\xe2\x80\xa6" );
                REQUIRE( s.session->request().outputPath == s.outputPath );
                REQUIRE( s.host.logs.contains( "Exporting 3 packets of mixed.pcap to "
                                               + s.outputPath ) );
                s.waitForOutcome();
            }

            AND_WHEN( "the export is done" )
            {
                const auto& outcome = s.waitForOutcome();

                THEN( "the packets are in the file, and the user is told" )
                {
                    REQUIRE_FALSE( s.session->isBusy() );
                    REQUIRE( outcome.status == ExportOutcome::Status::Exported );
                    REQUIRE( outcome.packets == 3 );
                    REQUIRE( outcome.request.outputPath == s.outputPath );
                    REQUIRE( packetsIn( s.outputPath ) == 3 );
                    const auto told = "Exported 3 packets of mixed.pcap to "
                                      + QDir::toNativeSeparators( s.outputPath ) + ".";
                    REQUIRE( outcome.notification == told );
                    REQUIRE( s.sessionHost.notifications == QStringList{ told } );
                    REQUIRE( outcome.log == told );
                    REQUIRE( s.host.logs.contains( told ) );
                    REQUIRE( outcome.label == told );
                    REQUIRE( s.session->label() == told );
                }
            }
        }
    }

    GIVEN( "no line selected" )
    {
        WHEN( "the user names no packets" )
        {
            s.confirm = false;

            THEN( "the user was asked all the same, and nothing is exported unconfirmed" )
            {
                REQUIRE_FALSE( s.session->start() );
                REQUIRE( s.requests.size() == 1 );
                REQUIRE( s.requests.front().numbers.empty() );
                REQUIRE( s.chosenFor.empty() );
                REQUIRE_FALSE( s.session->isBusy() );
                REQUIRE_FALSE( QFile::exists( s.outputPath ) );
                REQUIRE( s.sessionHost.notifications.isEmpty() );
                REQUIRE_FALSE( s.session->outcome() );
            }
        }

        WHEN( "the user names packets in the Export dialog" )
        {
            s.numbers = PacketNumbers{ 1, 2 };
            REQUIRE( s.session->start() );

            THEN( "those are exported" )
            {
                REQUIRE( s.waitForOutcome().packets == 2 );
                REQUIRE( packetsIn( s.outputPath ) == 2 );
            }
        }
    }

    GIVEN( "packets confirmed, but no file chosen" )
    {
        s.host.selectedLines = { s.lines[ 1 ] };
        s.outputPath.clear();

        THEN( "nothing is exported, and nothing told" )
        {
            REQUIRE_FALSE( s.session->start() );
            REQUIRE( s.chosenFor.size() == 1 );
            REQUIRE_FALSE( s.session->isBusy() );
            REQUIRE( s.sessionHost.notifications.isEmpty() );
        }
    }
}

SCENARIO( "A selection LogSquirl told only the first lines of is said to be truncated",
          "[export_session]" )
{
    Session s;
    s.host.selectedLines = { s.lines[ 1 ], s.lines[ 2 ] };
    s.host.selectionResult = LOGSQUIRL_LOG_LINES_TRUNCATED;
    const auto note = QStringLiteral( "LogSquirl told only the first 2 selected lines" );

    WHEN( "its packets are exported" )
    {
        REQUIRE( s.session->start() );
        const auto& outcome = s.waitForOutcome();

        THEN( "the user is told, before in the dialog and after in the notification" )
        {
            REQUIRE( s.requests.front().truncated );
            REQUIRE( s.requests.front().selectedLines == 2 );
            REQUIRE( s.host.logs.contains( "Export packets: " + note ) );
            REQUIRE( outcome.request.truncated );
            REQUIRE( s.sessionHost.notifications.size() == 1 );
            REQUIRE( outcome.notification.contains(
                note
                + ": to export the packets of more, copy their lines and paste them in the "
                  "Export dialog." ) );
        }
    }

    WHEN( "the user names other packets instead" )
    {
        s.numbers = PacketNumbers{ 4 };
        REQUIRE( s.session->start() );
        const auto& outcome = s.waitForOutcome();

        THEN( "the truncation did not limit the export, and is not told after it" )
        {
            REQUIRE_FALSE( outcome.request.truncated );
            REQUIRE_FALSE( outcome.notification.contains( note ) );
        }
    }
}

SCENARIO( "An export that cannot start says why, and asks nothing", "[export_session]" )
{
    GIVEN( "a tab in front that shows no capture" )
    {
        Session s;
        s.catalog.setFront( QString() );

        THEN( "nothing is asked and the user is told" )
        {
            REQUIRE_FALSE( s.session->start() );
            REQUIRE( s.requests.empty() );
            REQUIRE( s.sessionHost.notifications
                     == QStringList{ "Export packets: the tab in front shows no capture opened by "
                                     "the tcpdump plugin." } );
        }
    }

    GIVEN( "a host older than 26.11, which does not tell the selected lines" )
    {
        Session s( LOGSQUIRL_HOST_API_BASE_SIZE );

        THEN( "nothing is asked and the user is told what it needs" )
        {
            REQUIRE_FALSE( s.session->start() );
            REQUIRE( s.requests.empty() );
            REQUIRE( s.sessionHost.notifications
                     == QStringList{ "Export packets needs LogSquirl 26.11 or later, which tells "
                                     "the selected lines." } );
        }
    }

    GIVEN( "a host that refuses to tell the selection" )
    {
        Session s;
        s.host.selectedLines = { s.lines[ 1 ] };
        s.host.selectionResult = LOGSQUIRL_LOG_LINES_NOT_ON_UI_THREAD;

        THEN( "nothing is asked and the user is told why" )
        {
            REQUIRE_FALSE( s.session->start() );
            REQUIRE( s.requests.empty() );
            REQUIRE( s.sessionHost.notifications
                     == QStringList{
                         "Export packets: LogSquirl did not tell the selected lines (-1)." } );
        }
    }

    GIVEN( "an export running" )
    {
        Session s;
        s.host.selectedLines = { s.lines[ 1 ] };
        HeldExporter held( HeldExporter::Hold::BeforeWriting );
        s.session->setExporter( held.exporter() );
        REQUIRE( s.session->start() );

        THEN( "another is refused with the Activity rule's reason, and nothing more asked" )
        {
            const auto why = refusalMessage( ActivityRefusal::Exporting );
            REQUIRE( s.session->refusal() == why );
            REQUIRE_FALSE( s.session->start() );
            REQUIRE( s.requests.size() == 1 );
            REQUIRE( s.sessionHost.notifications == QStringList{ why } );
            held.release();
            REQUIRE( s.waitForOutcome().status == ExportOutcome::Status::Exported );
        }
    }

    GIVEN( "a capture file being read and a live capture running" )
    {
        Session s;
        s.host.selectedLines = { s.lines[ 1 ] };
        s.sessionHost.running.converting = true;
        s.sessionHost.running.capturing = true;

        THEN( "packets may be exported all the same" )
        {
            REQUIRE( s.session->refusal().isEmpty() );
            REQUIRE( s.session->start() );
            REQUIRE( s.waitForOutcome().status == ExportOutcome::Status::Exported );
        }
    }
}

SCENARIO( "An export that fails is told, and leaves the file chosen as it was", "[export_session]" )
{
    Session s;
    s.host.selectedLines = { s.lines[ 1 ] };
    s.outputPath = s.dir.filePath( "no-such-directory/export.pcap" );

    WHEN( "the file cannot be written" )
    {
        REQUIRE( s.session->start() );
        const auto& outcome = s.waitForOutcome();

        THEN( "it failed, logged and told" )
        {
            REQUIRE( outcome.status == ExportOutcome::Status::Failed );
            REQUIRE_FALSE( outcome.error.isEmpty() );
            REQUIRE( outcome.log == "Exporting packets failed: " + outcome.error );
            REQUIRE( s.host.logs.contains( outcome.log ) );
            REQUIRE( outcome.notification == "Exporting packets failed: " + outcome.error );
            REQUIRE( s.sessionHost.notifications == QStringList{ outcome.notification } );
            REQUIRE( outcome.label == "Error: " + outcome.error );
            REQUIRE_FALSE( QFile::exists( s.outputPath ) );
        }
    }
}

SCENARIO( "A running export can be cancelled until it has written its file", "[export_session]" )
{
    Session s;
    s.host.selectedLines = { s.lines[ 1 ] };
    writeFile( s.outputPath, "the capture it replaces" );

    GIVEN( "an export that has not written its file yet" )
    {
        HeldExporter held( HeldExporter::Hold::BeforeWriting );
        s.session->setExporter( held.exporter() );
        REQUIRE( s.session->start() );

        WHEN( "the user cancels it" )
        {
            s.session->cancel();

            THEN( "the session says it is cancelling until the export has ended" )
            {
                REQUIRE( s.session->state() == ExportSession::State::Cancelling );
                REQUIRE( s.session->isBusy() );
                REQUIRE( s.session->label() == "Cancelling\xe2\x80\xa6" );
                s.waitForOutcome();
            }

            AND_WHEN( "the export ends" )
            {
                const auto& outcome = s.waitForOutcome();

                THEN( "the cancel wins: the file it would have replaced is as it was" )
                {
                    REQUIRE( outcome.status == ExportOutcome::Status::Cancelled );
                    REQUIRE( readAll( s.outputPath ) == "the capture it replaces" );
                }

                THEN( "it is logged, and nobody is told" )
                {
                    REQUIRE( outcome.label == "Cancelled." );
                    REQUIRE( s.session->label() == "Cancelled." );
                    REQUIRE( outcome.log
                             == "Cancelled exporting packets to "
                                    + QDir::toNativeSeparators( s.outputPath ) );
                    REQUIRE( s.host.logs.contains( outcome.log ) );
                    REQUIRE( outcome.notification.isEmpty() );
                    REQUIRE( s.sessionHost.notifications.isEmpty() );
                }

                THEN( "the next export may start" )
                {
                    REQUIRE_FALSE( s.session->isBusy() );
                    REQUIRE( s.session->refusal().isEmpty() );
                }
            }
        }
    }

    GIVEN( "an export that has written its file" )
    {
        HeldExporter held( HeldExporter::Hold::AfterWriting );
        s.session->setExporter( held.exporter() );
        REQUIRE( s.session->start() );
        REQUIRE( holdsSoon( [ & ] { return held.written(); } ) );

        WHEN( "the user cancels it" )
        {
            s.session->cancel();
            const auto& outcome = s.waitForOutcome();

            THEN( "the cancel came too late: the export is kept and reported" )
            {
                REQUIRE( outcome.status == ExportOutcome::Status::Exported );
                REQUIRE( packetsIn( s.outputPath ) == 1 );
                REQUIRE( s.sessionHost.notifications.size() == 1 );
                REQUIRE( s.sessionHost.notifications.first().startsWith( "Exported 1 packet" ) );
            }
        }

        WHEN( "the session is destroyed, as when the sidebar closes" )
        {
            bool told = false;
            QObject::connect( s.session.get(), &ExportSession::finished,
                              [ &told ]( const ExportOutcome& ) { told = true; } );
            s.session.reset();
            QCoreApplication::processEvents();

            THEN( "the cancel came too late: the export is kept, reported to no one" )
            {
                REQUIRE( packetsIn( s.outputPath ) == 1 );
                REQUIRE( s.sessionHost.notifications.isEmpty() );
                REQUIRE_FALSE( told );
            }
        }
    }

    GIVEN( "an export that fails while it is cancelled" )
    {
        s.session->setExporter( []( std::shared_ptr<const CaptureIndex>, const PacketNumbers&,
                                    const QString&, const std::atomic_bool* cancel,
                                    const std::function<void( int )>& ) {
            while ( !cancel->load() ) {
                std::this_thread::sleep_for( std::chrono::milliseconds( 1 ) );
            }
            ExportResult result;
            result.error = "the disk is full";
            return result;
        } );
        REQUIRE( s.session->start() );
        s.session->cancel();
        const auto& outcome = s.waitForOutcome();

        THEN( "it ends as a cancelled one does, without a notification" )
        {
            REQUIRE( outcome.status == ExportOutcome::Status::Cancelled );
            REQUIRE( s.sessionHost.notifications.isEmpty() );
            REQUIRE( readAll( s.outputPath ) == "the capture it replaces" );
        }
    }

    GIVEN( "an export that has not written its file, when the session is destroyed" )
    {
        HeldExporter held( HeldExporter::Hold::BeforeWriting );
        s.session->setExporter( held.exporter() );
        REQUIRE( s.session->start() );
        s.session.reset();
        QCoreApplication::processEvents();

        THEN( "it was cancelled and waited for: the file is as it was, nothing told" )
        {
            REQUIRE( readAll( s.outputPath ) == "the capture it replaces" );
            REQUIRE( s.sessionHost.notifications.isEmpty() );
        }
    }
}

SCENARIO( "An export tells its progress", "[export_session]" )
{
    Session s;
    s.host.selectedLines = { s.lines[ 1 ] };
    HeldExporter held( HeldExporter::Hold::BeforeWriting, 500 );
    s.session->setExporter( held.exporter() );
    REQUIRE( s.session->start() );
    REQUIRE( s.session->progress() == 0 );

    WHEN( "the export reports half of it done" )
    {
        REQUIRE( s.waitUntil( [ &s ] { return s.session->progress() == 500; } ) );

        THEN( "the session has it, still exporting" )
        {
            REQUIRE( s.session->state() == ExportSession::State::Exporting );
            held.release();
            s.waitForOutcome();
        }
    }
}

SCENARIO( "A session destroyed while the user confirms starts nothing", "[export_session]" )
{
    Session s;
    s.host.selectedLines = { s.lines[ 1 ] };
    s.session->setConfirmer( [ &s ]( ExportRequest& ) {
        // As when the sidebar closes while the Export dialog is open.
        s.session.reset();
        return true;
    } );

    // start() returns into a session that is gone, and must not touch it.
    auto* session = s.session.get();
    const bool started = session->start();

    THEN( "no file is asked for, and nothing exported" )
    {
        REQUIRE_FALSE( started );
        REQUIRE_FALSE( s.session );
        REQUIRE( s.chosenFor.empty() );
        REQUIRE_FALSE( QFile::exists( s.outputPath ) );
        REQUIRE( s.sessionHost.notifications.isEmpty() );
    }
}
