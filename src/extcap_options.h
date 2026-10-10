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
 * @file extcap_options.h
 * @brief The form of an extcap interface's arguments, made from what its
 *        `--extcap-config` says.
 *
 * When the live capture form's extcap and interface change (setTarget()),
 * the widget asks the extcap for the interface's arguments and link types
 * on a thread of its own, bounded by the listing timeout and cancelled
 * when another interface is chosen or the widget goes; meanwhile problem()
 * keeps Start disabled.  Each argument becomes a field of its type: a line
 * edit (string, password not shown, numbers), a check box (boolean,
 * boolflag), a drop-down list (selector), radio buttons (radio), an
 * editable drop-down list (editselector), a list of check boxes
 * (multicheck), a path with Browse… (fileselect).
 *
 * A field starts with the value kept for it (options()), else the
 * extcap's default; what the fields hold is written to the options at
 * once, named by extcapOptionName(), so that the capture passes every
 * value the user sees, defaults too, as Wireshark does.  The options of
 * other interfaces are kept as they are; those of this interface that it
 * no longer takes are dropped.  Whether the values keep the arguments'
 * rules is not the widget's to say: the kind's validate() checks them
 * (extcapArgumentProblem()), with the arguments its listing was told.
 */

#pragma once

#include "extcap_source.h"
#include "live_capture_form.h"

#include <QThreadPool>

#include <atomic>
#include <functional>
#include <memory>
#include <vector>

class QFormLayout;
class QLabel;
class QTimer;

namespace tcpdump {

class ExtcapOptionsWidget : public LiveOptionsWidget {
    Q_OBJECT

public:
    /// How long setTarget() waits for the next change before it asks the
    /// extcap: an interface typed asks once.
    static constexpr int kSettleMs = 150;

    explicit ExtcapOptionsWidget( std::shared_ptr<const ExtcapSourceKind> kind,
                                  QWidget* parent = nullptr );
    /// Cancels its listing (its program is killed) and waits for it.
    ~ExtcapOptionsWidget() override;

    ExtcapOptionsWidget( const ExtcapOptionsWidget& ) = delete;
    ExtcapOptionsWidget& operator=( const ExtcapOptionsWidget& ) = delete;

    void setOptions( const LiveOptions& options ) override;
    LiveOptions options() const override;
    void setTarget( const QString& device, const QString& networkInterface ) override;
    QString problem() const override;

    /// Whether the extcap is being asked for its arguments.
    bool isListing() const
    {
        return listing_ || settling_;
    }

    /// The arguments shown, of the interface chosen.
    const ExtcapConfig& config() const
    {
        return config_;
    }

private:
    /// Ask the extcap for the arguments of the target.
    void list();
    /// Show @p config's fields, with the values kept or their defaults.
    void show( const ExtcapConfig& config );
    /// Make the field of @p arg, showing @p value; null for none.
    QWidget* makeField( const ExtcapArg& arg, const QString& value );
    /// The value @p arg starts with: the one kept, else its default.
    QString initialValue( const ExtcapArg& arg ) const;
    /// Keep @p value for @p arg, and say so.
    void store( const ExtcapArg& arg, const QString& value );
    /// Show @p text above the fields; empty hides it.
    void showStatus( const QString& text );

    std::shared_ptr<const ExtcapSourceKind> kind_;
    LiveOptions options_;
    QString device_;         ///< The extcap chosen.
    QString interface_;      ///< The interface chosen.
    QString shownDevice_;    ///< The extcap config_ is of.
    QString shownInterface_; ///< The interface config_ is of.
    ExtcapConfig config_;
    QLabel* status_ = nullptr;
    QWidget* fields_ = nullptr; ///< Remade for each config.
    QTimer* settle_ = nullptr;
    bool settling_ = false;
    bool listing_ = false;
    /// Counts the targets: a listing's result is shown only for the last.
    quint64 generation_ = 0;
    /// Cancels the listing running now.
    std::shared_ptr<std::atomic_bool> cancel_;
    QThreadPool pool_;
};

} // namespace tcpdump
