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
    LANGUAGES C CXX
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

# ── zlib, for gzip-compressed captures ────────────────────────────────────
# Fetched as the release tarball, pinned by its SHA-256, and built here as a
# static library of the files the plugin needs (zlib's own CMakeLists would
# add a shared library, examples and install rules).  Qt does not offer gzip
# streaming publicly (qUncompress() takes a whole zlib-format buffer), and a
# system zlib is not there on every CI platform (Windows).  Z_PREFIX renames
# its symbols to z_*, and they are hidden, so that it cannot clash with the
# zlib Qt or the host loads.  Licence: NOTICE.
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW) # extracted files get the extraction time
endif()
FetchContent_Declare(tcpdump_zlib
    URL      https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
    URL_HASH SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
    # No CMakeLists.txt there: the sources are fetched, not added as a project.
    SOURCE_SUBDIR not-a-cmake-project
)
FetchContent_MakeAvailable(tcpdump_zlib)

add_library(tcpdump_zlib STATIC
    "${tcpdump_zlib_SOURCE_DIR}/adler32.c"
    "${tcpdump_zlib_SOURCE_DIR}/crc32.c"
    "${tcpdump_zlib_SOURCE_DIR}/deflate.c"    # the tests write gzip files
    "${tcpdump_zlib_SOURCE_DIR}/inffast.c"
    "${tcpdump_zlib_SOURCE_DIR}/inflate.c"
    "${tcpdump_zlib_SOURCE_DIR}/inftrees.c"
    "${tcpdump_zlib_SOURCE_DIR}/trees.c"
    "${tcpdump_zlib_SOURCE_DIR}/zutil.c"
)
target_include_directories(tcpdump_zlib SYSTEM PUBLIC "${tcpdump_zlib_SOURCE_DIR}")
target_compile_definitions(tcpdump_zlib PUBLIC Z_PREFIX)
set_target_properties(tcpdump_zlib PROPERTIES
    C_VISIBILITY_PRESET hidden
    POSITION_INDEPENDENT_CODE ON
)
if(MSVC)
    target_compile_definitions(tcpdump_zlib PRIVATE _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE)
    target_compile_options(tcpdump_zlib PRIVATE /W0)
else()
    target_compile_options(tcpdump_zlib PRIVATE -w)
endif()

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
    src/gzip_source.cpp
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
    src/live_source.cpp
    src/live_capture_form.cpp
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
        tcpdump_zlib
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
