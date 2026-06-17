# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-common CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL 3.0 REQUIRED)
find_package(ZLIB REQUIRED)

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
    src/Resolve.cpp
    src/Sam.cpp
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
bazarish_add_test(TestResolve)
bazarish_add_test(TestSam)
