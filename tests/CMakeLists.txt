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
    packet_layers_test.cpp
    capture_index_test.cpp
    packet_export_test.cpp
    link_layers_test.cpp
    socks_test.cpp
    mqtt_test.cpp
    someip_test.cpp
    doip_test.cpp
    smb_test.cpp
    ssh_test.cpp
    websocket_test.cpp
    sip_test.cpp
    tls_test.cpp
    dns_test.cpp
    icmp_test.cpp
    dhcp_ntp_test.cpp
    http_test.cpp
    quic_test.cpp
    streaming_test.cpp
    capture_source_test.cpp
    live_conversion_test.cpp
    live_capture_test.cpp
    live_source_test.cpp
    live_capture_ui_test.cpp
    process_source_test.cpp
    plugin_test.cpp
    sidebarwidget_test.cpp
    packet_panel_test.cpp
    conversation_table_test.cpp
    follow_stream_test.cpp
    stream_content_test.cpp
    regex_lab_test.cpp
    display_filter_test.cpp
    corpus_test.cpp
    conversion_options_test.cpp
    settings_test.cpp
    configdialog_test.cpp
    logformat_test.cpp
    presets_test.cpp
    packet_formatter_test.cpp
    payload_describer_test.cpp
    protocol_names_test.cpp
    stream_tracker_test.cpp
    conversations_test.cpp
    stream_labels_test.cpp
    tcp_analysis_test.cpp
    tcp_options_test.cpp
    byte_stream_orderer_test.cpp
    tcp_reassembly_test.cpp
    hpack_test.cpp
    tls_crypto_test.cpp
    tls_key_log_test.cpp
    tls_decryption_test.cpp
    tunnels_test.cpp
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
        mbedcrypto
)

# Compile plugin sources into the test binary
target_sources(logsquirl_tcpdump_tests
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src/plugin.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_reader.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_source.cpp"
        "${CMAKE_SOURCE_DIR}/src/process_source.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcap_parser.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_layers.cpp"
        "${CMAKE_SOURCE_DIR}/src/icmp.cpp"
        "${CMAKE_SOURCE_DIR}/src/link_layers.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcapng_reader.cpp"
        "${CMAKE_SOURCE_DIR}/src/payload_describer.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_text.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_http.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_nmea.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_dns.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_dhcp_ntp.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_tls.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_quic.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_socks.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_mqtt.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_sip.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_rtp.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_someip.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_doip.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_smb.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_ssh.cpp"
        "${CMAKE_SOURCE_DIR}/src/describe_websocket.cpp"
        "${CMAKE_SOURCE_DIR}/src/media_expectations.cpp"
        "${CMAKE_SOURCE_DIR}/src/hpack.cpp"
        "${CMAKE_SOURCE_DIR}/src/protocol_names.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_formatter.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_tracker.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_labels.cpp"
        "${CMAKE_SOURCE_DIR}/src/tcp_analysis.cpp"
        "${CMAKE_SOURCE_DIR}/src/byte_stream_orderer.cpp"
        "${CMAKE_SOURCE_DIR}/src/tcp_reassembly.cpp"
        "${CMAKE_SOURCE_DIR}/src/tls_crypto.cpp"
        "${CMAKE_SOURCE_DIR}/src/tls_key_log.cpp"
        "${CMAKE_SOURCE_DIR}/src/tls_decryption.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_stats.cpp"
        "${CMAKE_SOURCE_DIR}/src/conversations.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_file.cpp"
        "${CMAKE_SOURCE_DIR}/src/capture_index.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_export.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcap_converter.cpp"
        "${CMAKE_SOURCE_DIR}/src/tempdirs.cpp"
        "${CMAKE_SOURCE_DIR}/src/settings.cpp"
        "${CMAKE_SOURCE_DIR}/src/configdialog.cpp"
        "${CMAKE_SOURCE_DIR}/src/export_dialog.cpp"
        "${CMAKE_SOURCE_DIR}/src/conversation_table.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_panel.cpp"
        "${CMAKE_SOURCE_DIR}/src/live_capture.cpp"
        "${CMAKE_SOURCE_DIR}/src/live_source.cpp"
        "${CMAKE_SOURCE_DIR}/src/live_capture_form.cpp"
        "${CMAKE_SOURCE_DIR}/src/sidebarwidget.cpp"
        "${CMAKE_SOURCE_DIR}/src/follow_stream.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_content.cpp"
        "${CMAKE_SOURCE_DIR}/src/stream_content_view.cpp"
        "${CMAKE_SOURCE_DIR}/src/regex_lab.cpp"
        "${CMAKE_SOURCE_DIR}/src/display_filter.cpp"
        "${CMAKE_SOURCE_DIR}/src/display_filter_dialog.cpp"
)

# Captures and their expected text, for corpus_test.cpp, and the Log Format
# that reads that text, for logformat_test.cpp, and the highlighter set and
# filter group that colour and filter it, for presets_test.cpp
target_compile_definitions(logsquirl_tcpdump_tests
    PRIVATE
        TCPDUMP_CORPUS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/corpus"
        TCPDUMP_FORMAT_FILE="${CMAKE_SOURCE_DIR}/formats/tcpdump_log.json"
        TCPDUMP_PRESETS_DIR="${CMAKE_SOURCE_DIR}/presets"
)

# ── Register with CTest ──────────────────────────────────────────────────
add_test(NAME logsquirl_tcpdump_tests COMMAND logsquirl_tcpdump_tests)
