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
 * @file fake_session_host.h
 * @brief The host of a session and of its catalog, recording, for tests.
 *
 * FakeSessionHost is the SessionHost of a Live Capture Session, a File
 * Conversion session or an Export session, and the CaptureTabHost of their
 * CaptureCatalog: it
 * records the tabs opened and the notifications, and can say what else
 * runs, which the Activity rule weighs.
 */

#pragma once

#include "capture_catalog.h"
#include "session_host.h"

#include <QString>
#include <QStringList>

namespace tcpdump_test {

/// A session's host, and its catalog's tab host, recording.
class FakeSessionHost : public tcpdump::SessionHost, public tcpdump::CaptureTabHost {
public:
    void openTab( const QString& logPath, bool follow ) override
    {
        openedTabs << logPath;
        openedFollowing << follow;
    }
    void notify( const QString& message ) override
    {
        notifications << message;
    }
    tcpdump::RunningActivities running() const override
    {
        return activities;
    }

    QStringList openedTabs;                ///< The text files opened in tabs, in order.
    QList<bool> openedFollowing;           ///< Whether each tab follows its file.
    QStringList notifications;             ///< What the user was told, in order.
    tcpdump::RunningActivities activities; ///< What running() says runs.
};

} // namespace tcpdump_test
