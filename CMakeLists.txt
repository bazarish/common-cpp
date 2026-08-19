# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-common CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(ZLIB REQUIRED)

# Embedded I2P transport. ON by default: I2P is the transport, so every consumer
# of common needs it. Requires the i2pd submodule (recursive init) and Boost
# program_options. Turn OFF only for builds that never touch the network, e.g.
# air-gapped offline key tools: -DBAZARISH_WITH_I2PD=OFF.
option(BAZARISH_WITH_I2PD "Build the embedded libi2pd_bazarish target" ON)
if(BAZARISH_WITH_I2PD)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/I2pdBazarish.cmake)
endif()

add_library(bazarish_common STATIC
    src/Auth.cpp
    src/Bytes.cpp
    src/Crypto.cpp
    src/Cms.cpp
    src/Certificates.cpp
    src/Tokens.cpp
    src/Errors.cpp
    src/Address.cpp
    src/I2pAddress.cpp
    src/Descriptor.cpp
    src/ServerDescriptor.cpp
    src/Resolve.cpp
    src/I2pHttp.cpp
    src/Log.cpp
    src/Health.cpp
    src/HttpClient.cpp
    src/HttpServer.cpp
    src/Hmac.cpp
    src/Portal.cpp
    src/PortalSession.cpp
    src/LoginChallenge.cpp
    src/Captcha.cpp
    src/SelfHostedCaptcha.cpp
)
add_library(Bazarish::Common ALIAS bazarish_common)

target_include_directories(bazarish_common
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(bazarish_common SYSTEM
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_link_libraries(bazarish_common PUBLIC OpenSSL::Crypto ZLIB::ZLIB)
target_compile_options(bazarish_common PRIVATE -Wall -Wextra -Werror)

# The I2P transport wrapper compiles only against the embedded engine. Its i2pd
# and Boost includes arrive (as SYSTEM) through Bazarish::I2pd, so they stay out
# of our -Werror surface.
if(BAZARISH_WITH_I2PD)
    target_sources(bazarish_common PRIVATE src/I2p.cpp)
    target_link_libraries(bazarish_common PUBLIC Bazarish::I2pd)
    # Manual end-to-end smoke over live I2P (not a unit test - needs the network).
    add_executable(i2p_smoke tests/I2pSmoke.cpp)
    target_link_libraries(i2p_smoke PRIVATE bazarish_common)
    target_compile_options(i2p_smoke PRIVATE -Wall -Wextra)
endif()

enable_testing()

function(bazarish_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_common)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_add_test(TestAuth)
bazarish_add_test(TestBytes)
bazarish_add_test(TestCrypto)
bazarish_add_test(TestCms)
bazarish_add_test(TestCertificates)
bazarish_add_test(TestTokens)
bazarish_add_test(TestErrors)
bazarish_add_test(TestAddress)
bazarish_add_test(TestI2pAddress)
bazarish_add_test(TestDescriptor)
bazarish_add_test(TestServerDescriptor)
bazarish_add_test(TestResolve)
bazarish_add_test(TestI2pHttp)
bazarish_add_test(TestLog)
bazarish_add_test(TestHealth)
bazarish_add_test(TestLoginChallenge)
bazarish_add_test(TestCaptcha)
