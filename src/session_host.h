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
 * @file session_host.h
 * @brief Where a session (the Live Capture Session, the File Conversion
 *        session) tells the user, and learns what runs besides it.
 *
 * In the app the sidebar is the host of every session; in tests a fake
 * that records.  A session asks the Activity rule (activity.h) with what
 * runs elsewhere and what it runs itself, so that the host need not know
 * which session asks.
 */

#pragma once

#include "activity.h"

#include <QString>

namespace tcpdump {

/// Where a session tells the user: LogSquirl, through the sidebar, in the
/// app; a fake in tests.
class SessionHost {
public:
    virtual ~SessionHost() = default;

    /// Tell the user @p message in a notification.
    virtual void notify( const QString& message ) = 0;
    /// What runs, which the Activity rule weighs with the session's own
    /// activity; the session's own field (a conversion's @c converting, a
    /// live capture's @c capturing) is not read: the session knows it.
    virtual RunningActivities runningElsewhere() const
    {
        return {};
    }
};

} // namespace tcpdump
