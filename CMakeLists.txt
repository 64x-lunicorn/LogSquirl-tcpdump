# ============================================================================
# logsquirl-tcpdump — tcpdump / pcap viewer plugin for LogSquirl
#
# This is a standalone CMake project.  It does NOT depend on the LogSquirl
# build tree — only on the vendored logsquirl_plugin_api.h header (MIT).
#
# Build:
#   cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
#   cmake --build build
#
# The output is a shared library (liblogsquirl_tcpdump.dylib / .so / .dll)
# that can be installed alongside its plugin.json into one of LogSquirl's
# plugin search directories.
# ============================================================================
cmake_minimum_required(VERSION 3.16)

project(logsquirl_tcpdump
    VERSION   0.3.0
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile_commands.json for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# The version logsquirl_plugin_get_info() reports: project(VERSION), which CI
# requires to equal plugin.json's version.
add_compile_definitions(LOGSQUIRL_PLUGIN_VERSION="${PROJECT_VERSION}")

# ── Find Qt6 ──────────────────────────────────────────────────────────────
find_package(Qt6 REQUIRED COMPONENTS Core Concurrent Widgets)
qt_standard_project_setup()

# ── Plugin shared library ─────────────────────────────────────────────────
add_library(logsquirl_tcpdump SHARED
    src/plugin.cpp
    src/capture_reader.cpp
    src/capture_source.cpp
    src/process_source.cpp
    src/pcap_parser.cpp
    src/packet_layers.cpp
    src/icmp.cpp
    src/link_layers.cpp
    src/pcapng_reader.cpp
    src/payload_describer.cpp
    src/describe_text.cpp
    src/describe_http.cpp
    src/describe_nmea.cpp
    src/describe_dns.cpp
    src/describe_dhcp_ntp.cpp
    src/describe_tls.cpp
    src/describe_quic.cpp
    src/describe_socks.cpp
    src/describe_mqtt.cpp
    src/describe_sip.cpp
    src/describe_rtp.cpp
    src/describe_someip.cpp
    src/describe_doip.cpp
    src/describe_ssh.cpp
    src/media_expectations.cpp
    src/protocol_names.cpp
    src/packet_formatter.cpp
    src/stream_tracker.cpp
    src/stream_labels.cpp
    src/tcp_analysis.cpp
    src/byte_stream_orderer.cpp
    src/tcp_reassembly.cpp
    src/capture_stats.cpp
    src/conversations.cpp
    src/capture_file.cpp
    src/capture_index.cpp
    src/packet_export.cpp
    src/pcap_converter.cpp
    src/tempdirs.cpp
    src/settings.cpp
    src/configdialog.cpp
    src/export_dialog.cpp
    src/conversation_table.cpp
    src/packet_panel.cpp
    src/live_capture.cpp
    src/sidebarwidget.cpp
    src/follow_stream.cpp
    src/stream_content.cpp
    src/stream_content_view.cpp
    src/regex_lab.cpp
    src/display_filter.cpp
    src/display_filter_dialog.cpp
)

# Qt MOC needs to know about our Q_OBJECT classes
set_target_properties(logsquirl_tcpdump PROPERTIES
    AUTOMOC ON
    POSITION_INDEPENDENT_CODE ON
)

# Default symbol visibility: hidden.  Only LOGSQUIRL_PLUGIN_EXPORT symbols
# are visible (matches the __attribute__((visibility("default"))) macro).
if(NOT WIN32)
    target_compile_options(logsquirl_tcpdump PRIVATE -fvisibility=hidden)
endif()

target_include_directories(logsquirl_tcpdump
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"   # Vendored SDK header
        "${CMAKE_CURRENT_SOURCE_DIR}/src"        # Internal headers
)

target_link_libraries(logsquirl_tcpdump
    PRIVATE
        Qt6::Core
        Qt6::Concurrent
        Qt6::Widgets
)

# ── Install rule ──────────────────────────────────────────────────────────
include(GNUInstallDirs)

set(PLUGIN_INSTALL_DIR
    "${CMAKE_INSTALL_DATADIR}/LogSquirl/plugins/io.github.logsquirl.tcpdump"
    CACHE PATH "Plugin installation directory"
)

install(TARGETS logsquirl_tcpdump LIBRARY DESTINATION "${PLUGIN_INSTALL_DIR}")
install(FILES   plugin.json               DESTINATION "${PLUGIN_INSTALL_DIR}")
# The Log Format of the converted text, next to the library; LogSquirl reads
# it only from its formats directory, where the user copies it (README).
install(FILES   formats/tcpdump_log.json  DESTINATION "${PLUGIN_INSTALL_DIR}")
# The highlighter set and filter group, for LogSquirl's Import (README).
install(FILES   presets/tcpdump_highlighter.conf presets/tcpdump_filter.conf
        DESTINATION "${PLUGIN_INSTALL_DIR}")

# ── Tests (opt-in) ────────────────────────────────────────────────────────
option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
