# Bazarish project (c) 2026
#
# Builds libi2pd_bazarish: a single static library with only what the embedded
# I2P transport needs - the i2pd router core (libi2pd) plus i18n - compiled from
# the pristine PurpleI2P/i2pd submodule. The client-bridge library (SAM, BOB,
# SOCKS, HTTP/SOCKS proxy, I2CP server, addressbook, client tunnels) and the
# daemon (webconsole, I2PControl, UPnP) are simply never compiled here.
#
# The submodule stays byte-for-byte upstream so it is trivial to bump; the only
# local change is one reviewable patch (a callback log sink) applied at configure
# time. Floodfill-server and transit remain config-gated in the upstream sources.

set(I2PD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/i2pd)
set(I2PD_PATCH_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/i2pd-patches)

if(NOT EXISTS ${I2PD_DIR}/libi2pd/api.h)
    message(FATAL_ERROR
        "i2pd submodule not initialised at ${I2PD_DIR}. "
        "Run: git submodule update --init --recursive")
endif()

find_package(Git REQUIRED)

# Apply each patch idempotently: skip if a reverse-apply check succeeds (already
# applied), otherwise apply it. This keeps the submodule pristine in git terms
# while overlaying our changes on the working tree for the build.
file(GLOB I2PD_PATCHES ${I2PD_PATCH_DIR}/*.patch)
list(SORT I2PD_PATCHES)
foreach(patch ${I2PD_PATCHES})
    execute_process(
        COMMAND ${GIT_EXECUTABLE} -C ${I2PD_DIR} apply --reverse --check ${patch}
        RESULT_VARIABLE _reverse_ok OUTPUT_QUIET ERROR_QUIET)
    if(NOT _reverse_ok EQUAL 0)
        execute_process(
            COMMAND ${GIT_EXECUTABLE} -C ${I2PD_DIR} apply ${patch}
            RESULT_VARIABLE _apply_rc)
        if(NOT _apply_rc EQUAL 0)
            message(FATAL_ERROR "Failed to apply i2pd patch: ${patch}")
        endif()
        message(STATUS "Applied i2pd patch: ${patch}")
    else()
        message(STATUS "i2pd patch already applied: ${patch}")
    endif()
endforeach()

# Dependencies. Boost headers (asio) are header-only; only program_options needs
# a library. Prefer the CMake package; fall back to find_library for systems that
# ship the runtime library without the CMake config.
find_package(Threads REQUIRED)
find_package(Boost QUIET CONFIG COMPONENTS program_options)
if(TARGET Boost::program_options)
    set(I2PD_BOOST_PO Boost::program_options)
else()
    # No CMake config (or no -dev symlink): take the unversioned .so, then fall
    # back to a versioned runtime .so (systems that ship runtime-only Boost).
    find_library(I2PD_BOOST_PO_LIB NAMES boost_program_options)
    if(NOT I2PD_BOOST_PO_LIB)
        file(GLOB _bpo_versioned
            /usr/lib/*/libboost_program_options.so.*
            /usr/lib/libboost_program_options.so.*
            /usr/local/lib/libboost_program_options.so.*)
        if(_bpo_versioned)
            list(GET _bpo_versioned 0 I2PD_BOOST_PO_LIB)
        endif()
    endif()
    if(NOT I2PD_BOOST_PO_LIB)
        message(FATAL_ERROR
            "Boost program_options not found. Install libboost-program-options-dev.")
    endif()
    set(I2PD_BOOST_PO ${I2PD_BOOST_PO_LIB})
    message(STATUS "Boost::program_options config not found; linking ${I2PD_BOOST_PO_LIB}")
endif()

file(GLOB I2PD_CORE_SRC CONFIGURE_DEPENDS ${I2PD_DIR}/libi2pd/*.cpp)
file(GLOB I2PD_LANG_SRC CONFIGURE_DEPENDS ${I2PD_DIR}/i18n/*.cpp)

add_library(i2pd_bazarish STATIC ${I2PD_CORE_SRC} ${I2PD_LANG_SRC})
add_library(Bazarish::I2pd ALIAS i2pd_bazarish)

# Upstream headers are exposed to embedders; SYSTEM keeps their warnings out of
# our -Werror builds.
target_include_directories(i2pd_bazarish SYSTEM PUBLIC
    ${I2PD_DIR}/libi2pd
    ${I2PD_DIR}/libi2pd_client
    ${I2PD_DIR}/i18n)
if(Boost_INCLUDE_DIRS)
    target_include_directories(i2pd_bazarish SYSTEM PUBLIC ${Boost_INCLUDE_DIRS})
endif()

target_compile_features(i2pd_bazarish PUBLIC cxx_std_20)
# Vendored upstream code: do not lint it (and never inherit our -Werror).
# The forced include is for Boost.Asio 1.81 (Debian 12), whose awaitable.hpp uses
# std::exchange without including <utility>: with libstdc++ 12 that is a hard
# error in a system header, and it is not ours to patch.
target_compile_options(i2pd_bazarish PRIVATE -w -include utility)

target_link_libraries(i2pd_bazarish PUBLIC
    OpenSSL::SSL OpenSSL::Crypto ZLIB::ZLIB ${I2PD_BOOST_PO} Threads::Threads atomic)
