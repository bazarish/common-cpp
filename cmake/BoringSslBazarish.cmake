# Bazarish project (c) 2026
# BoringSSL for the TLS of the gateway link alone, built from the pristine submodule's
# generated source lists. Never installed and never exported: find_package(OpenSSL) must not see it.

option(BAZARISH_GATEWAY_TLS_OPENSSL
    "Windows only, until BoringSSL builds there: the gateway link over OpenSSL, without a browser's ClientHello"
    OFF)

if(BAZARISH_GATEWAY_TLS_OPENSSL AND NOT WIN32)
    message(FATAL_ERROR "BAZARISH_GATEWAY_TLS_OPENSSL is for Windows only")
endif()
if(WIN32 AND NOT BAZARISH_GATEWAY_TLS_OPENSSL)
    message(FATAL_ERROR
        "BoringSSL is not built for Windows yet. Configure with -DBAZARISH_GATEWAY_TLS_OPENSSL=ON: "
        "the gateway link then shows OpenSSL's ClientHello, not a browser's")
endif()

if(BAZARISH_GATEWAY_TLS_OPENSSL)
    message(WARNING "The gateway link is built over OpenSSL: its ClientHello is not a browser's")
    add_library(bazarish_gateway_tls STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/OpenSslTlsEngine.cpp)
    target_link_libraries(bazarish_gateway_tls PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(bazarish_gateway_tls PRIVATE -Wall -Wextra -Werror)
    return()
endif()

set(BORINGSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl)
# The pinned commit is the one Chrome 157.0.8103.78 builds with (its DEPS, boringssl_revision).
set(BAZARISH_BORINGSSL_PREFIX BZB)

if(NOT EXISTS ${BORINGSSL_DIR}/gen/sources.cmake)
    message(FATAL_ERROR
        "BoringSSL submodule not initialised at ${BORINGSSL_DIR}. "
        "Run: git submodule update --init --recursive")
endif()

enable_language(C)
enable_language(ASM)
include(${BORINGSSL_DIR}/gen/sources.cmake)

set(BORINGSSL_BAZARISH_SOURCES
    ${BCM_SOURCES} ${CRYPTO_SOURCES} ${SSL_SOURCES} ${BCM_SOURCES_ASM} ${CRYPTO_SOURCES_ASM})
list(TRANSFORM BORINGSSL_BAZARISH_SOURCES PREPEND ${BORINGSSL_DIR}/)

add_library(boringssl_bazarish STATIC ${BORINGSSL_BAZARISH_SOURCES})
set_target_properties(boringssl_bazarish PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_include_directories(boringssl_bazarish BEFORE PRIVATE ${BORINGSSL_DIR}/include)
target_compile_definitions(boringssl_bazarish PRIVATE
    BORINGSSL_IMPLEMENTATION BORINGSSL_PREFIX=${BAZARISH_BORINGSSL_PREFIX})
# Vendored code is not linted; the flags are BoringSSL's own.
target_compile_options(boringssl_bazarish PRIVATE
    "$<$<COMPILE_LANGUAGE:C,CXX>:-w;-fno-strict-aliasing;-fno-common;-fvisibility=hidden>"
    "$<$<COMPILE_LANGUAGE:CXX>:-fno-exceptions;-fno-rtti>"
    "$<$<COMPILE_LANGUAGE:ASM>:-Wa,--noexecstack>")
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_definitions(boringssl_bazarish PRIVATE $<$<COMPILE_LANGUAGE:C>:_XOPEN_SOURCE=700>)
endif()
if(NOT ANDROID)
    target_link_libraries(boringssl_bazarish PRIVATE Threads::Threads)
endif()

find_path(BROTLI_INCLUDE_DIR NAMES brotli/decode.h REQUIRED)
find_library(BROTLIDEC_LIBRARY NAMES brotlidec brotlidec-static REQUIRED)
find_library(BROTLICOMMON_LIBRARY NAMES brotlicommon brotlicommon-static REQUIRED)

# The one translation unit that sees BoringSSL's headers: no Boost and no bazarish header beside them.
add_library(bazarish_gateway_tls STATIC ${CMAKE_CURRENT_SOURCE_DIR}/src/ChromeTlsEngine.cpp)
target_include_directories(bazarish_gateway_tls BEFORE PRIVATE ${BORINGSSL_DIR}/include)
target_include_directories(bazarish_gateway_tls PRIVATE ${BROTLI_INCLUDE_DIR})
target_compile_definitions(bazarish_gateway_tls PRIVATE
    BORINGSSL_PREFIX=${BAZARISH_BORINGSSL_PREFIX})
target_compile_options(bazarish_gateway_tls PRIVATE -Wall -Wextra -Werror)
target_link_libraries(bazarish_gateway_tls PRIVATE
    boringssl_bazarish ${BROTLIDEC_LIBRARY} ${BROTLICOMMON_LIBRARY})
