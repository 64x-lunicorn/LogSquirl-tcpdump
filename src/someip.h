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
 * @file someip.h
 * @brief How SOME/IP is told and named: the ports it is read on beyond
 *        SOME/IP-SD's, and a table of service, method and eventgroup names
 *        loaded from a file.
 *
 * The Payload Describer reads SOME/IP on port 30490 and, by its header,
 * on any port (describe_someip.cpp).  The ports and names the user
 * configured (ConversionOptions) are put in place for a conversion by a
 * SomeIpScope; without one, the defaults apply.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace tcpdump {

/// SOME/IP-SD's port, on which SOME/IP is read whatever its header.
constexpr uint16_t kSomeIpSdPort = 30490;

/// Most ports the user may name for SOME/IP.
constexpr size_t kMaxSomeIpPorts = 64;
/// Most names a name table holds, and bytes of one name.
constexpr size_t kMaxSomeIpNames = 4096;
constexpr size_t kMaxSomeIpNameBytes = 64;
/// Most bytes of a name table file read.
constexpr size_t kMaxSomeIpNamesFileBytes = 1024 * 1024;

/// What the user named SOME/IP's IDs.
struct SomeIpNames {
    std::map<uint16_t, std::string> services;
    /// By service << 16 | method (or event) ID.
    std::map<uint32_t, std::string> methods;
    /// By service << 16 | eventgroup ID.
    std::map<uint32_t, std::string> eventgroups;

    bool empty() const
    {
        return services.empty() && methods.empty() && eventgroups.empty();
    }
};

/// How SOME/IP is read in a conversion.
struct SomeIpConfig {
    /// Ports SOME/IP is read on besides kSomeIpSdPort, header or not.
    std::vector<uint16_t> ports;
    SomeIpNames names;
};

/**
 * The names in the text of a name table, one per line:
 *
 *     # comment
 *     service    0x1234        Navigation
 *     method     0x1234 0x0001 GetRoute
 *     event      0x1234 0x8001 RouteChanged
 *     eventgroup 0x1234 0x0010 Route
 *
 * IDs in hexadecimal with 0x, or decimal.  A line that is none of these is
 * skipped, and said in @p problems ("line 3: …"); a name is cut to
 * kMaxSomeIpNameBytes, a control character in it ends it.  At most
 * kMaxSomeIpNames names are kept.
 */
SomeIpNames parseSomeIpNames( const std::string& text,
                              std::vector<std::string>* problems = nullptr );

/// The name table in the file at @p path (UTF-8), at most
/// kMaxSomeIpNamesFileBytes of it; nothing if it cannot be read.
std::optional<SomeIpNames> loadSomeIpNames( const std::string& path,
                                            std::vector<std::string>* problems = nullptr );

/// The ports in @p text, "30501, 30502": numbers from 1 to 65535 separated
/// by commas or blanks, at most kMaxSomeIpPorts, each once; anything else is
/// skipped.
std::vector<uint16_t> parseSomeIpPorts( const std::string& text );

/// The ports as parseSomeIpPorts() reads them, "30501, 30502".
std::string someIpPortsText( const std::vector<uint16_t>& ports );

/**
 * While it lives, the Payload Describer on this thread reads SOME/IP with
 * @p config, which must outlive it; the one before it is put back after.
 */
class SomeIpScope {
public:
    explicit SomeIpScope( const SomeIpConfig& config );
    ~SomeIpScope();
    SomeIpScope( const SomeIpScope& ) = delete;
    SomeIpScope& operator=( const SomeIpScope& ) = delete;

private:
    const SomeIpConfig* previous_;
};

} // namespace tcpdump
