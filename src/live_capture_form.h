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
 * @file live_capture_form.h
 * @brief The live capture UI's fields: source, device, interface, capture
 *        filter, snaplen; in the sidebar's Live capture section and in the
 *        Start live capture… dialog alike.
 *
 * The form lists the sources of a LiveSourceRegistry.  Choosing one shows
 * why it is unavailable, if it is, or lists its devices (if it has any) and
 * the interfaces of the device chosen, on a worker thread: a listing that
 * hangs (an adb waiting for a device) neither freezes LogSquirl nor keeps
 * the form from changing; a result for a source or device no longer chosen
 * is dropped.  The interface list can be typed in too, for an interface the
 * source does not list ("any").  Refresh lists anew.
 *
 * The listings run on a thread pool the form is given, or one of its own.
 * A listing touches nothing of the form, so a form with a given pool goes
 * at once, its listings' results dropped; the pool's owner waits for them
 * (the plugin must not be unloaded while one runs).  A form with its own
 * pool waits for them as it goes.  Either way the form cancels its listings
 * as it goes (ListingCancelScope): their programs are killed, so that
 * waiting for them takes moments, not a listing's timeout.
 *
 * A source with options of its own (an ssh's own port excluded, an extcap's
 * arguments) shows their widget below the snaplen while it is chosen; the
 * options of each source are kept apart, so that choosing another source
 * and back keeps them.
 *
 * problem() says why the choice cannot be captured, for the Start button
 * of whoever holds the form; changed() tells it to ask again.
 */

#pragma once

#include "live_source.h"

#include <QDialog>
#include <QThreadPool>
#include <QWidget>

#include <atomic>
#include <map>
#include <memory>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSpinBox;

namespace tcpdump {

/**
 * The fields of a Live Source Kind's own options, below the form's while
 * the kind is chosen (LiveSourceKind::makeOptionsWidget()): the form hands
 * it the options kept for its kind and reads them back for choice().  It
 * emits changed() when they change, so that problem() is asked again.
 */
class LiveOptionsWidget : public QWidget {
    Q_OBJECT

public:
    using QWidget::QWidget;

    /// Show @p options; names it does not know are ignored.
    virtual void setOptions( const LiveOptions& options ) = 0;
    /// The options the fields hold.
    virtual LiveOptions options() const = 0;

signals:
    void changed();
};

class LiveCaptureForm : public QWidget {
    Q_OBJECT

public:
    /// Lists on @p pool, or on a pool of its own if it is null.
    explicit LiveCaptureForm( QThreadPool* pool = nullptr, QWidget* parent = nullptr );
    /// Cancels its listings; with a pool of its own, waits for them to end.
    ~LiveCaptureForm() override;

    LiveCaptureForm( const LiveCaptureForm& ) = delete;
    LiveCaptureForm& operator=( const LiveCaptureForm& ) = delete;

    /// Offer the kinds of @p sources; the current choice is kept where it can be.
    void setSources( std::shared_ptr<const LiveSourceRegistry> sources );
    std::shared_ptr<const LiveSourceRegistry> sources() const
    {
        return sources_;
    }

    /// Show @p choice: its source, filter and snaplen at once, its device and
    /// interface once listed (a typed or unlisted interface as typed).
    void setChoice( const LiveChoice& choice );
    /// What the fields hold.
    LiveChoice choice() const;

    /// The options @p source starts with when it is chosen, until the user
    /// changes them or setChoice() gives others (the ones saved for it).
    void setSourceOptions( const QString& source, const LiveOptions& options );

    /// The source chosen, or null if there is none.
    std::shared_ptr<const LiveSourceKind> currentKind() const;

    /// Why choice() cannot be captured: no source, an unavailable one, a bad
    /// capture filter, or what the source's validate() says; empty if it can.
    QString problem() const;

    /// Whether a listing runs.
    bool isListing() const
    {
        return listing_ > 0;
    }

    /// List the devices (if the source has any) and the interfaces anew.
    void refresh();

signals:
    /// Something problem() depends on changed.
    void changed();

private:
    /// The source picked: show why it is unavailable, or list.
    void sourceChanged();
    /// List the devices of the current source.
    void listDevices();
    /// List the interfaces of the current source and device.
    void listInterfaces();
    /// Run @p listing on the worker, and @p done with its result here,
    /// unless the source or device changed meanwhile.
    void runListing( std::function<LiveListing()> listing,
                     std::function<void( const LiveListing& )> done );
    /// Fill @p box with @p listing's targets and select @p wanted if it is
    /// listed, else the one selected before, else the first usable one.
    void fill( QComboBox* box, const LiveListing& listing, const QString& wanted );
    /// The id of the target @p box shows (typed text for one not listed).
    static QString currentId( const QComboBox* box );
    /// Show the source's state: unavailable, listing, a listing's error.
    void showStatus( const QString& text );
    /// Show the capture filter's problem below it.
    void checkFilter();
    /// Keep the options widget's options for its source, and remove it.
    void dropOptionsWidget();
    /// Show the options widget of the current source, if it has one.
    void showOptionsWidget();

    std::shared_ptr<const LiveSourceRegistry> sources_;
    LiveChoice wanted_; ///< The choice setChoice() was given.
    QComboBox* source_ = nullptr;
    QLabel* status_ = nullptr;
    QLabel* deviceLabel_ = nullptr;
    QComboBox* device_ = nullptr;
    QComboBox* interface_ = nullptr;
    QPushButton* refresh_ = nullptr;
    QLineEdit* filter_ = nullptr;
    QLabel* filterHint_ = nullptr;
    QSpinBox* snaplen_ = nullptr;
    /// The current source's options, if it has any; owned by the form.
    LiveOptionsWidget* options_ = nullptr;
    QString optionsSource_; ///< The source options_ is of.
    /// The options of each source, as last shown or given.
    std::map<QString, LiveOptions> optionsBySource_;
    /// Counts the source and device changes: a listing's result is shown
    /// only if none came after it started.
    quint64 generation_ = 0;
    int listing_ = 0; ///< Listings running.
    /// Set as the form goes: cancels the listings it started.
    std::shared_ptr<std::atomic_bool> cancel_ = std::make_shared<std::atomic_bool>( false );
    std::unique_ptr<QThreadPool> ownPool_; ///< Without a pool given.
    QThreadPool* pool_ = nullptr;          ///< Where listings run.
};

/// Plugins > tcpdump > Start live capture…: the form in a dialog, its Start
/// button enabled when the choice can be captured.
class LiveCaptureDialog : public QDialog {
    Q_OBJECT

public:
    /// The form lists on @p pool (see LiveCaptureForm).
    LiveCaptureDialog( std::shared_ptr<const LiveSourceRegistry> sources, const LiveChoice& choice,
                       QWidget* parent = nullptr, QThreadPool* pool = nullptr );

    LiveCaptureForm* form() const
    {
        return form_;
    }

    LiveChoice choice() const;

private:
    LiveCaptureForm* form_ = nullptr;
};

} // namespace tcpdump
