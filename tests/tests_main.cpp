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
 * @file tests_main.cpp
 * @brief Catch2 + QApplication runner for the logsquirl-tcpdump test suite.
 */

#define CATCH_CONFIG_RUNNER
#include <catch2/catch.hpp>

#include "live_source.h"
#include "sidebarwidget.h"

#include <QApplication>

#include <memory>

int main( int argc, char* argv[] )
{
    QApplication app( argc, argv );
    // Hermetic: a sidebar offers no kind a test did not give it, so none
    // runs a real capture program (tcpdump -D, adb devices) on this machine.
    tcpdump::SidebarWidget::setDefaultLiveSources(
        std::make_shared<tcpdump::LiveSourceRegistry>() );
    return Catch::Session().run( argc, argv );
}
