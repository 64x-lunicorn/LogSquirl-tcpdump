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

# ── Mbed TLS ──────────────────────────────────────────────────────────────
# The cryptography of the TLS Decryption (tls_crypto.cpp): AES-GCM, AES-CBC,
# ChaCha20-Poly1305, HMAC and HKDF of Mbed TLS (Apache-2.0 or
# GPL-2.0-or-later, NOTICE): the 3.6 LTS release below, fetched by its hash
# and built here as a static library with only those
# (third_party/mbedtls_config.h).  Its symbols stay hidden in the plugin,
# and its warnings do not fail the build.
include(FetchContent)
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW) # extracted files get the time of extraction
endif()
set(MBEDTLS_URL
    https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2)
set(MBEDTLS_SHA256 a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6)
set(MBEDTLS_CONFIG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/third_party/mbedtls_config.h"
    CACHE FILEPATH "Mbed TLS configuration of the plugin" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(GEN_FILES OFF CACHE BOOL "" FORCE)
set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
# Linked into a shared library: position independent, and nothing of it
# exported (the plugin exports its entry points only).
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
# Out of the default build and the install: only mbedcrypto is built, as
# the plugin links it, and nothing of Mbed TLS is installed.
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.28)
    FetchContent_Declare(mbedtls URL ${MBEDTLS_URL} URL_HASH SHA256=${MBEDTLS_SHA256}
                         EXCLUDE_FROM_ALL)
    FetchContent_MakeAvailable(mbedtls)
else()
    FetchContent_Declare(mbedtls URL ${MBEDTLS_URL} URL_HASH SHA256=${MBEDTLS_SHA256})
    FetchContent_GetProperties(mbedtls)
    if(NOT mbedtls_POPULATED)
        FetchContent_Populate(mbedtls)
        add_subdirectory("${mbedtls_SOURCE_DIR}" "${mbedtls_BINARY_DIR}" EXCLUDE_FROM_ALL)
    endif()
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
    src/hpack.cpp
    src/protocol_names.cpp
    src/packet_formatter.cpp
    src/stream_tracker.cpp
    src/stream_labels.cpp
    src/tcp_analysis.cpp
    src/byte_stream_orderer.cpp
    src/tcp_reassembly.cpp
    src/tls_crypto.cpp
    src/tls_key_log.cpp
    src/tls_decryption.cpp
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
# Nor anything of the static libraries linked in (Mbed TLS), where the
# linker can be told so.
if(UNIX AND NOT APPLE)
    target_link_options(logsquirl_tcpdump PRIVATE "LINKER:--exclude-libs,ALL")
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
        mbedcrypto
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
