# Bazarish project (c) 2026
# BoringSSL for the TLS of the gateway link alone, built from the pristine submodule's
# generated source lists. Never installed and never exported: find_package(OpenSSL) must not see it.

set(BORINGSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/boringssl)
# The pinned commit is the one Chrome 157.0.8103.78 builds with (its DEPS, boringssl_revision).
set(BAZARISH_BORINGSSL_PREFIX BZB)

if(NOT EXISTS ${BORINGSSL_DIR}/gen/sources.cmake)
    message(FATAL_ERROR
        "BoringSSL submodule not initialised at ${BORINGSSL_DIR}. "
        "Run: git submodule update --init --recursive")
endif()

enable_language(C)
include(${BORINGSSL_DIR}/gen/sources.cmake)

# The x86 assembly in the .S files is ELF and Mach-O only; COFF on x86 takes BoringSSL's NASM output.
if(WIN32 AND CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64|amd64|x86|i[3-6]86")
    enable_language(ASM_NASM)
    set(CMAKE_ASM_NASM_FLAGS
        "${CMAKE_ASM_NASM_FLAGS} -DBORINGSSL_PREFIX=${BAZARISH_BORINGSSL_PREFIX} -I${BORINGSSL_DIR}/gen/")
    set(BORINGSSL_BAZARISH_ASM ${BCM_SOURCES_NASM} ${CRYPTO_SOURCES_NASM})
else()
    enable_language(ASM)
    set(BORINGSSL_BAZARISH_ASM ${BCM_SOURCES_ASM} ${CRYPTO_SOURCES_ASM})
endif()

set(BORINGSSL_BAZARISH_SOURCES
    ${BCM_SOURCES} ${CRYPTO_SOURCES} ${SSL_SOURCES} ${BORINGSSL_BAZARISH_ASM})
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
if(WIN32)
    target_compile_definitions(boringssl_bazarish PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
    target_link_libraries(boringssl_bazarish PRIVATE ws2_32)
elseif(NOT ANDROID)
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
