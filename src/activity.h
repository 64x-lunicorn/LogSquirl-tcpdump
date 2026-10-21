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
 * @file activity.h
 * @brief The Activity rule: whether opening a capture file, starting a live
 *        capture or exporting packets may start now, given what runs, and
 *        if not, why.
 *
 * The sidebar's Open, Start live capture and Export packets, its buttons'
 * enabling and the Live Capture Session's own refusal all ask here, so
 * that the same activities are refused for the same reasons, each said in
 * one message written once.
 */

#pragma once

#include <QString>

#include <optional>

namespace tcpdump {

/// What the user may start, each only when the Activity rule allows it.
enum class Activity {
    OpenFile,    ///< Open a capture file: it is converted in the background.
    LiveCapture, ///< Start a live capture.
    Export,      ///< Export packets to a new capture file.
};

/// What runs now, of what the Activity rule weighs.
struct RunningActivities {
    bool converting = false; ///< A capture file is being read.
    bool capturing = false;  ///< A live capture runs, or its choice is being checked.
    bool exporting = false;  ///< Packets are being exported.
};

/// Why an activity may not start: what runs that it waits for.
enum class ActivityRefusal {
    Converting, ///< A capture file is being read.
    Capturing,  ///< A live capture runs.
    Exporting,  ///< Packets are being exported.
};

/**
 * Why @p activity may not start while @p running runs, or nothing if it
 * may.  Opening a file and a live capture exclude each other and wait for
 * a conversion, which is named first; an export waits only for another
 * export, and neither waits for one.
 */
std::optional<ActivityRefusal> activityRefusal( Activity activity,
                                                const RunningActivities& running );

/// What the user is told of @p refusal: what runs, and what to do about it.
QString refusalMessage( ActivityRefusal refusal );

/// refusalMessage() of activityRefusal(), or empty if @p activity may start.
QString activityRefusalMessage( Activity activity, const RunningActivities& running );

} // namespace tcpdump
