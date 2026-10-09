# ============================================================================
# Unit tests for logsquirl-tcpdump
#
# Uses Catch2 v2 (BDD style) to match the host project's test conventions.
# ============================================================================

include(FetchContent)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG        v2.13.10
)
FetchContent_MakeAvailable(Catch2)

# ── Test executable ───────────────────────────────────────────────────────

add_executable(logsquirl_tcpdump_tests
    tests_main.cpp
    plugininfo_test.cpp
    pcap_parser_test.cpp
    pcapng_reader_test.cpp
    pcap_layers_test.cpp
    socks_test.cpp
    tls_test.cpp
    dns_test.cpp
    icmp_test.cpp
    dhcp_ntp_test.cpp
    http_test.cpp
    quic_test.cpp
    streaming_test.cpp
    plugin_test.cpp
    sidebarwidget_test.cpp
    corpus_test.cpp
    conversion_options_test.cpp
    settings_test.cpp
    configdialog_test.cpp
    logformat_test.cpp
    packet_formatter_test.cpp
    payload_describer_test.cpp
    protocol_names_test.cpp
    stream_tracker_test.cpp
    stream_labels_test.cpp
    tcp_analysis_test.cpp
    wire_bytes_test.cpp
)

set_target_properties(logsquirl_tcpdump_tests PROPERTIES
    AUTOMOC ON
)

target_include_directories(logsquirl_tcpdump_tests
    PRIVATE
        "${CMAKE_SOURCE_DIR}/include"   # logsquirl_plugin_api.h
        "${CMAKE_SOURCE_DIR}/src"       # Internal headers
)

target_link_libraries(logsquirl_tcpdump_tests
    PRIVATE
        Catch2::Catch2
        Qt6::Core
        Qt6::Concurrent
        Qt6::Widgets
)

# Compile plugin sources into the test binary
target_sources(logsquirl_tcpdump_tests
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src/plugin.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_reader.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcap_parser.cpp"
        "${CMAKE_SOURCE_DIR}/src/icmp.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcapng_reader.cpp"
        "${CMAKE_SOURCE_DIR}/src/payload_describer.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_names.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_formatter.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_tracker.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_labels.cpp"
        "${CMAKE_SOURCE_DIR}/src/tcp_analysis.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_stats.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcap_converter.cpp"
        "${CMAKE_SOURCE_DIR}/src/tempdirs.cpp"
        "${CMAKE_SOURCE_DIR}/src/settings.cpp"
        "${CMAKE_SOURCE_DIR}/src/configdialog.cpp"
        "${CMAKE_SOURCE_DIR}/src/sidebarwidget.cpp"
)

# Captures and their expected text, for corpus_test.cpp, and the Log Format
# that reads that text, for logformat_test.cpp
target_compile_definitions(logsquirl_tcpdump_tests
    PRIVATE
        TCPDUMP_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/corpus"
        TCPDUMP_FORMAT_FILE="${CMAKE_SOURCE_DIR}/formats/tcpdump_log.json"
)

# ── Register with CTest ──────────────────────────────────────────────────
add_test(NAME logsquirl_tcpdump_tests COMMAND logsquirl_tcpdump_tests)
