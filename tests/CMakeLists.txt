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
    packet_formatter_test.cpp
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
        Qt6::Widgets
)

# Compile plugin sources into the test binary
target_sources(logsquirl_tcpdump_tests
    PRIVATE
        "${CMAKE_SOURCE_DIR}/src/plugin.cpp"
        "${CMAKE_SOURCE_DIR}/src/pcap_parser.cpp"
        "${CMAKE_SOURCE_DIR}/src/packet_formatter.cpp"
        "${CMAKE_SOURCE_DIR}/src/sidebarwidget.cpp"
)

# ── Register with CTest ──────────────────────────────────────────────────
add_test(NAME logsquirl_tcpdump_tests COMMAND logsquirl_tcpdump_tests)
