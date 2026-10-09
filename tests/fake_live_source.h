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
 * @file fake_live_source.h
 * @brief A Live Source Kind for tests: two interfaces, and a scripted
 *        synthetic capture.
 *
 * FakeSourceKind lists fake0 and fake1 (of any device; with devices, of
 * phoneA, as phoneB is unauthorized) and captures by handing out a
 * capture the test scripts (ScriptedSource): its bytes, then either nothing
 * until Stop, as a capture program waiting for traffic, or a failure.  It
 * records every choice it was asked to capture, so a test sees the filter
 * and snaplen the UI passed.  With a program set, it runs that program
 * instead (the default makeSource(), a Process Source), its arguments
 * `-i <interface> -s <snaplen> <filter>`.  With a listing program set, it
 * lists interfaces by running that (runListing()), as a real kind does.
 * With options on, its options widget is a line edit, "fakeNote", for the
 * option "note"; a note "bad" does not validate.
 */

#pragma once

#include "live_capture_form.h"
#include "live_source.h"
#include "pcapbuilder.h"

#include <QHBoxLayout>
#include <QLineEdit>
#include <QString>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace tcpdump_test {

/// Hands out its bytes, then waits until Stop, or breaks off with an error.
class ScriptedSource : public tcpdump::StreamSource {
public:
    ScriptedSource( Bytes bytes, std::string failure, const std::atomic_bool* stop )
        : StreamSource( stop )
        , bytes_( std::move( bytes ) )
        , failure_( std::move( failure ) )
    {
    }

protected:
    std::ptrdiff_t readFor( uint8_t* dst, size_t n, std::chrono::milliseconds timeout ) override
    {
        if ( at_ == bytes_.size() ) {
            if ( !failure_.empty() ) {
                error_ = failure_;
                return 0;
            }
            std::this_thread::sleep_for( std::min( timeout, std::chrono::milliseconds( 10 ) ) );
            return -1;
        }
        n = std::min( n, bytes_.size() - at_ );
        std::copy_n( bytes_.begin() + static_cast<std::ptrdiff_t>( at_ ), n, dst );
        at_ += n;
        return static_cast<std::ptrdiff_t>( n );
    }
    bool available() override
    {
        return at_ < bytes_.size() || !failure_.empty();
    }

private:
    Bytes bytes_;
    std::string failure_;
    size_t at_ = 0;
};

/// FakeSourceKind's options: a line edit for the option "note".
class FakeOptionsWidget : public tcpdump::LiveOptionsWidget {
public:
    FakeOptionsWidget()
    {
        auto* layout = new QHBoxLayout( this );
        layout->setContentsMargins( 0, 0, 0, 0 );
        note_ = new QLineEdit;
        note_->setObjectName( "fakeNote" );
        layout->addWidget( note_ );
        connect( note_, &QLineEdit::textChanged, this, &LiveOptionsWidget::changed );
    }

    void setOptions( const tcpdump::LiveOptions& options ) override
    {
        note_->setText( options.value( "note" ) );
    }
    tcpdump::LiveOptions options() const override
    {
        tcpdump::LiveOptions options;
        if ( !note_->text().isEmpty() ) {
            options.insert( "note", note_->text() );
        }
        return options;
    }

private:
    QLineEdit* note_ = nullptr;
};

class FakeSourceKind : public tcpdump::LiveSourceKind {
public:
    explicit FakeSourceKind( QString id = "fake", QString name = "Fake" )
        : id_( std::move( id ) )
        , name_( std::move( name ) )
    {
    }

    QString id() const override
    {
        return id_;
    }
    QString displayName() const override
    {
        return name_;
    }
    tcpdump::LiveAvailability availability() const override
    {
        if ( !unavailableReason.isEmpty() ) {
            return tcpdump::LiveAvailability::unavailable( unavailableReason );
        }
        return {};
    }
    Devices devices() const override
    {
        return deviceMode;
    }
    QString deviceLabel() const override
    {
        return "Phone";
    }
    tcpdump::LiveListing listDevices( std::chrono::milliseconds ) const override
    {
        tcpdump::LiveListing listing;
        listing.targets = { { "phoneB", {}, "unauthorized: accept the prompt on the phone" },
                            { "phoneA", "Pixel 9", {} } };
        return listing;
    }
    tcpdump::LiveListing listInterfaces( const QString& device,
                                         std::chrono::milliseconds timeout ) const override
    {
        {
            const std::lock_guard<std::mutex> lock( mutex_ );
            listedDevices_ << device;
        }
        ++interfaceListings;
        tcpdump::LiveListing listing;
        if ( !listingProgram.isEmpty() ) {
            const auto output = tcpdump::runListing( { listingProgram, {} }, timeout );
            listing.error = output.error;
            return listing;
        }
        listing.targets = { { "fake0", "Fake Ethernet", {} }, { "fake1", "Fake Wi-Fi", {} } };
        return listing;
    }
    tcpdump::ProcessCommand command( const tcpdump::LiveChoice& choice ) const override
    {
        QStringList arguments{ "-i", choice.interface, "-s", QString::number( choice.snaplen ) };
        if ( !choice.filter.isEmpty() ) {
            arguments << choice.filter; // one argument, as a real kind passes it
        }
        return { program.isEmpty() ? QString( "fakecap" ) : program, arguments };
    }
    tcpdump::LiveCapture::SourceFactory
    makeSource( const tcpdump::LiveChoice& choice ) const override
    {
        {
            const std::lock_guard<std::mutex> lock( mutex_ );
            started_.push_back( choice );
        }
        if ( !program.isEmpty() ) {
            return LiveSourceKind::makeSource( choice );
        }
        const auto bytes = capture;
        const auto error = failure;
        return [ bytes, error ]( const std::atomic_bool* stop,
                                 std::function<void( const QString& )> onStderrLine ) {
            if ( onStderrLine ) {
                onStderrLine( "fakecap: listening" );
            }
            return std::make_unique<ScriptedSource>( bytes, error, stop );
        };
    }
    tcpdump::LiveOptionsWidget* makeOptionsWidget() const override
    {
        return withOptions ? new FakeOptionsWidget : nullptr;
    }
    QString validate( const tcpdump::LiveChoice& choice ) const override
    {
        if ( choice.options.value( "note" ) == "bad" ) {
            return "The note is bad.";
        }
        return LiveSourceKind::validate( choice );
    }
    QString explainFailure( const QString& error ) const override
    {
        return error.contains( "permission" ) ? hint : QString();
    }

    /// The choices captured so far, in order.
    std::vector<tcpdump::LiveChoice> started() const
    {
        const std::lock_guard<std::mutex> lock( mutex_ );
        return started_;
    }

    /// The devices whose interfaces were listed, in order.
    QStringList listedDevices() const
    {
        const std::lock_guard<std::mutex> lock( mutex_ );
        return listedDevices_;
    }

    /// Whether it has devices: then phoneA, and phoneB, which is unauthorized.
    Devices deviceMode = Devices::None;
    QString unavailableReason; ///< Set: the kind is unavailable, for this reason.
    Bytes capture;             ///< What a capture hands out.
    std::string failure;       ///< Set: a capture breaks off with it afterwards.
    QString hint;              ///< What explainFailure() says to a permission error.
    QString program;           ///< Set: a capture runs this program.
    QString listingProgram;    ///< Set: listing the interfaces runs this program.
    bool withOptions = false;  ///< Whether it has an options widget.
    mutable std::atomic<int> interfaceListings{ 0 };

private:
    QString id_;
    QString name_;
    mutable std::mutex mutex_;
    mutable std::vector<tcpdump::LiveChoice> started_;
    mutable QStringList listedDevices_;
};

} // namespace tcpdump_test
