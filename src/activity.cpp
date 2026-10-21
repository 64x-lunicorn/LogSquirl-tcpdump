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
 * @file activity.cpp
 * @brief The Activity rule.
 */

#include "activity.h"

namespace tcpdump {

std::optional<ActivityRefusal> activityRefusal( Activity activity,
                                                const RunningActivities& running )
{
    switch ( activity ) {
    case Activity::OpenFile:
    case Activity::LiveCapture:
        // One capture at a time, read or captured: each tab it opens is
        // the outcome of the one running.
        if ( running.converting ) {
            return ActivityRefusal::Converting;
        }
        if ( running.capturing ) {
            return ActivityRefusal::Capturing;
        }
        return std::nullopt;
    case Activity::Export:
        // An export reads a capture that is kept, whatever else runs.
        if ( running.exporting ) {
            return ActivityRefusal::Exporting;
        }
        return std::nullopt;
    }
    return std::nullopt;
}

QString refusalMessage( ActivityRefusal refusal )
{
    switch ( refusal ) {
    case ActivityRefusal::Converting:
        return QStringLiteral( "A capture is still being read: wait for it, or cancel it first." );
    case ActivityRefusal::Capturing:
        return QStringLiteral( "A live capture is still running: stop it first." );
    case ActivityRefusal::Exporting:
        return QStringLiteral(
            "Packets are still being exported: wait for it, or cancel it first." );
    }
    return {};
}

QString activityRefusalMessage( Activity activity, const RunningActivities& running )
{
    const auto refusal = activityRefusal( activity, running );
    return refusal ? refusalMessage( *refusal ) : QString();
}

} // namespace tcpdump
