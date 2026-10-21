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
 * @file capture_sessions.h
 * @brief The plugin's sessions over one Capture Catalog, and what the user
 *        starts them with: Open pcap…, Start and Stop live capture, Export
 *        packets… and Save capture…, from the plugin menu or the sidebar.
 *
 * The plugin owns one, for as long as it is loaded; the sidebar is a view
 * of it (sidebarwidget.h).  It is the host of each session (session_host.h:
 * a notification, and what runs besides the session, for the Activity rule)
 * and the Capture Catalog's tab host (capture_catalog.h: the host's
 * open_file()), so that the plugin menu reaches the sessions without a
 * widget, and the sessions run whether the sidebar is open or not.
 *
 * What the user is asked, the file dialogs, the Start live capture dialog,
 * the Export dialog and whether to stop a running capture, is asked here,
 * over the dialog parent (the sidebar, setDialogParent()); tests replace
 * each with a function of their own.  The file dialogs start in the
 * directory browsed last, which Open pcap… and Save capture… set, and an
 * export does not.
 *
 * Destroying it ends the sessions as the plugin is unloaded: a conversion
 * and an export are cancelled and waited for, a live capture is stopped,
 * and the listings of the Start live capture dialog are cancelled, so that
 * no code of the plugin runs on a worker afterwards (but for the live
 * captures retired, which the plugin's shutdown joins).
 */

#pragma once

#include "activity.h"
#include "capture_catalog.h"
#include "export_session.h"
#include "file_conversion_session.h"
#include "live_capture_session.h"
#include "live_source.h"
#include "session_host.h"

#include <QObject>
#include <QPointer>
#include <QString>
#include <QThreadPool>
#include <QWidget>

#include <functional>
#include <memory>

namespace tcpdump {

class LiveCaptureDialog;

/// The File Conversion, Live Capture and Export sessions over one Capture
/// Catalog, and the actions the plugin menu and the sidebar start them with.
class CaptureSessions : public QObject, private SessionHost, private CaptureTabHost {
    Q_OBJECT

public:
    explicit CaptureSessions( QObject* parent = nullptr );
    ~CaptureSessions() override;

    CaptureSessions( const CaptureSessions& ) = delete;
    CaptureSessions& operator=( const CaptureSessions& ) = delete;

    /// The captures converted and captured so far, and which is in front.
    CaptureCatalog& catalog()
    {
        return catalog_;
    }
    const CaptureCatalog& catalog() const
    {
        return catalog_;
    }

    /// Opening a capture file, running or the last, and what it came to.
    FileConversionSession& conversionSession() const
    {
        return *conversion_;
    }

    /// The live capture, running or the last one, and what it came to.
    LiveCaptureSession& liveSession() const
    {
        return *live_;
    }

    /// Exporting packets, running or the last, and what it came to.
    ExportSession& exportSession() const
    {
        return *export_;
    }

    /// What runs now, which the Activity rule weighs before Open, Start
    /// live capture and Export packets start.
    RunningActivities runningActivities() const;

    /// Ask the user over @p parent from now on (the sidebar); none: over no
    /// window.
    void setDialogParent( QWidget* parent )
    {
        dialogParent_ = parent;
    }

    /// The widget the dialogs are shown over; null if it is gone or none.
    QWidget* dialogParent() const
    {
        return dialogParent_;
    }

    /// Create the temporary files below @p dir instead of the system's
    /// temporary directory (for tests).
    void setTempRoot( const QString& dir );

    /// The directory the temporary directories are created in.
    const QString& tempRoot() const
    {
        return tempRoot_;
    }

    /// Offer the kinds of @p sources in the Start live capture dialog (for
    /// tests; the plugin's own are builtInLiveSources()).
    void setLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// The kinds every CaptureSessions constructed afterwards offers until
    /// setLiveSources(): builtInLiveSources(), unless @p sources is set.
    /// The test runner sets an empty registry, so that no test runs a real
    /// capture program (tcpdump -D, adb) by constructing the sessions.
    static void setDefaultLiveSources( std::shared_ptr<const LiveSourceRegistry> sources );

    /// Open pcap…: ask for a capture in a file dialog and open it, through
    /// the File Conversion session.  While the Activity rule refuses
    /// opening a file, only a notification says why.
    void chooseAndOpen();

    /// Asks for a capture file: given the dialog's parent and the directory
    /// to start in, returns the chosen path, or an empty one if none was.
    using FileChooser = std::function<QString( QWidget* parent, const QString& dir )>;

    /// Ask with @p chooser instead of a file dialog (for tests).
    void setFileChooser( FileChooser chooser )
    {
        chooseFile_ = std::move( chooser );
    }

    /// Start live capture…: offer to stop a capture that runs, ask for a
    /// choice in the Start live capture dialog, and start it, once the
    /// running one has ended.  While the Activity rule refuses it for
    /// another reason, only a notification says why.
    void chooseAndStartLiveCapture();

    /// Asks the user for a live capture choice, given the one to show first;
    /// false if the user does not want to capture.
    using LiveChoiceAsker = std::function<bool( QWidget* parent, LiveChoice& choice )>;

    /// Ask with @p asker instead of the Start live capture dialog (for tests).
    void setLiveChoiceAsker( LiveChoiceAsker asker )
    {
        askLiveChoice_ = std::move( asker );
    }

    /// Asks whether to stop the live capture @p running; false: keep it.
    using StopConfirmer = std::function<bool( QWidget* parent, const QString& running )>;

    /// Ask with @p confirmer instead of a message box (for tests).
    void setStopConfirmer( StopConfirmer confirmer )
    {
        confirmStop_ = std::move( confirmer );
    }

    /// The Start live capture dialog as Start live capture… shows it: the
    /// choice last started, saved in settings.ini, and each other source
    /// with its own saved options.  It lists on these sessions' pool, so it
    /// goes before them.
    std::unique_ptr<LiveCaptureDialog> makeLiveCaptureDialog( QWidget* parent );

    /// Stop live capture: end the running live capture and keep what was
    /// captured; with none running, a notification says so.
    void stopLiveCapture();

    /// Export packets…: the packets of the lines selected in the tab in
    /// front, confirmed by the user in the Export dialog and written where
    /// the save dialog says, by the Export session.
    void exportSelectedPackets();

    /// Save capture…: ask where to save the raw capture of the tab in front,
    /// and copy it there.
    void saveCapture();

    /// Asks where to save a capture: given the dialog's parent and the
    /// suggested path, returns the chosen path, or an empty one.
    using SaveChooser = std::function<QString( QWidget* parent, const QString& suggested )>;

    /// Ask with @p chooser instead of a file dialog (for tests).
    void setSaveChooser( SaveChooser chooser )
    {
        chooseSaveFile_ = std::move( chooser );
    }

private:
    // The Capture Catalog's tab host.
    void openTab( const QString& logPath, bool follow ) override;
    // The sessions' host.
    void notify( const QString& message ) override;
    RunningActivities running() const override;

    /// The directory the dialogs start in: the one browsed last, or home.
    QString browseDir();
    /// The Start live capture dialog showing @p choice.
    std::unique_ptr<LiveCaptureDialog> makeLiveCaptureDialog( QWidget* parent,
                                                              const LiveChoice& choice );

    QPointer<QWidget> dialogParent_; ///< Where the dialogs are shown.
    QString lastDir_;                ///< Remembers the last browsed directory.
    FileChooser chooseFile_;         ///< Shows the Open dialog.
    SaveChooser chooseSaveFile_;     ///< Shows the Save capture dialog.
    LiveChoiceAsker askLiveChoice_;  ///< Shows the Start live capture dialog.
    StopConfirmer confirmStop_;      ///< Asks whether to stop the running capture.

    /// Where the private temporary directories are created.
    QString tempRoot_;
    /// The kinds of live sources offered.
    std::shared_ptr<const LiveSourceRegistry> liveSources_;
    /// Where the Start live capture dialog lists devices and interfaces;
    /// cancelled and waited for when the sessions go.
    QThreadPool listingPool_;

    /// The captures converted and captured so far, by the text file written
    /// for each, and which is in front; every session's catalog.  It opens
    /// their tabs through these sessions.
    CaptureCatalog catalog_{ *this };
    std::unique_ptr<FileConversionSession> conversion_;
    std::unique_ptr<LiveCaptureSession> live_;
    std::unique_ptr<ExportSession> export_;
};

} // namespace tcpdump
