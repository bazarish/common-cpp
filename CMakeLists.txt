# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-common CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 3.5 is where ML-DSA and ML-KEM arrived, and every signature and every sealed
# envelope in this protocol is hybrid: an older OpenSSL builds a server that
# cannot verify or open anything, so it is refused here rather than at the first
# request. Distributions that ship an older one (Debian 12 has 3.0) need one
# built alongside: -DOPENSSL_ROOT_DIR=/path/to/openssl-3.5.
find_package(OpenSSL 3.5 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# Embedded I2P transport. ON by default: I2P is the transport, so every consumer
# of common needs it. Requires the i2pd submodule (recursive init) and Boost
# program_options. Turn OFF only for builds that never touch the network, e.g.
# air-gapped offline key tools: -DBAZARISH_WITH_I2PD=OFF.
option(BAZARISH_WITH_I2PD "Build the embedded libi2pd_bazarish target" ON)
if(BAZARISH_WITH_I2PD)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/I2pdBazarish.cmake)
endif()

# The client core: everything a Bazarish client is, with no user interface in it
# - accounts and their encrypted store, the session, the courier, invites, calls
# and the bot framework. It lives here because it has two consumers, the desktop
# application and the daemon, and neither owns it. Servers do not need it, so
# they build with -DBAZARISH_WITH_CLIENT=OFF and pay for none of it.
option(BAZARISH_WITH_CLIENT "Build the client core library" ON)

add_library(bazarish_common STATIC
    src/Auth.cpp
    src/Bytes.cpp
    src/Crypto.cpp
    src/Cms.cpp
    src/Tunnel.cpp
    src/Certificates.cpp
    src/Pass.cpp
    src/Padding.cpp
    src/ConfigFile.cpp
    src/WebAssets.cpp
    src/Errors.cpp
    src/FederationFrame.cpp
    src/Address.cpp
    src/I2pAddress.cpp
    src/Sam.cpp
    src/I2p.cpp
    src/I2pSam.cpp
    src/Descriptor.cpp
    src/ServerDescriptor.cpp
    src/Resolve.cpp
    src/AliasMaintenance.cpp
    src/I2pHttp.cpp
    src/Reactions.cpp
    src/Log.cpp
    src/ReseedSu3.cpp
    src/Health.cpp
    src/Restart.cpp
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
target_link_libraries(bazarish_common PUBLIC OpenSSL::Crypto OpenSSL::SSL ZLIB::ZLIB)
# The SAM client speaks to the router over a socket of its own, and on Windows
# that is a library rather than the C runtime.
if(WIN32)
    # Sockets, and the process counters the health report reads.
    target_link_libraries(bazarish_common PUBLIC ws2_32 psapi)
endif()
target_compile_options(bazarish_common PRIVATE -Wall -Wextra -Werror)

# Asio allocates a coroutine's frame through its own allocator and frees it the
# same way. Once GCC 14 inlines that frame (-O2 and up) it pairs the allocation
# with the plain operator delete and calls the result a mismatch. The pairing is
# the compiler's, not ours, so the false positive is silenced where the
# coroutines live rather than across the library.
set_source_files_properties(src/HttpServer.cpp src/HttpClient.cpp PROPERTIES
    COMPILE_OPTIONS -Wno-mismatched-new-delete)

# The I2P transport wrapper compiles only against the embedded engine. Its i2pd
# and Boost includes arrive (as SYSTEM) through Bazarish::I2pd, so they stay out
# of our -Werror surface.
if(BAZARISH_WITH_I2PD)
    target_sources(bazarish_common PRIVATE src/I2pEmbedded.cpp)
    target_compile_definitions(bazarish_common PUBLIC BAZARISH_WITH_I2PD)
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
bazarish_add_test(TestTunnel)
bazarish_add_test(TestReseedSu3)
bazarish_add_test(TestCertificates)
bazarish_add_test(TestPass)
bazarish_add_test(TestPadding)
bazarish_add_test(TestErrors)
bazarish_add_test(TestAddress)
bazarish_add_test(TestI2pAddress)
bazarish_add_test(TestI2pKeyBlob)

# Live end-to-end over an external router reached by SAM (not a unit test - it
# needs a running i2pd and the network), the counterpart of i2p_smoke.
add_executable(sam_streams tests/SamStreams.cpp)
target_link_libraries(sam_streams PRIVATE bazarish_common)
target_compile_options(sam_streams PRIVATE -Wall -Wextra -Werror)
add_executable(sam_smoke tests/SamSmoke.cpp)
target_link_libraries(sam_smoke PRIVATE bazarish_common)
target_compile_options(sam_smoke PRIVATE -Wall -Wextra -Werror)
bazarish_add_test(TestDescriptor)
bazarish_add_test(TestServerDescriptor)
bazarish_add_test(TestResolve)
bazarish_add_test(TestAliasMaintenance)
bazarish_add_test(TestLog)
bazarish_add_test(TestHealth)
bazarish_add_test(TestRestart)
bazarish_add_test(TestHttpClient)
bazarish_add_test(TestLoginChallenge)
bazarish_add_test(TestCaptcha)
bazarish_add_test(TestConfigFile)
bazarish_add_test(TestWebAssets)

# These three play the far end over POSIX sockets of their own - socketpair,
# read and write on a descriptor. What they cover is portable; the harness is
# not, and Windows is a client-only target where they run on the primary
# platform instead.
if(NOT WIN32)
    bazarish_add_test(TestFederationFrame)
    bazarish_add_test(TestSam)
    bazarish_add_test(TestI2pHttp)
endif()

# The client core and its tests. Its own dependencies are looked for only when
# it is wanted: a server build asks for none of them.
if(BAZARISH_WITH_CLIENT)
    # The account store is SQLCipher (an encrypted SQLite): one file per account,
    # unreadable without its key. It is a fork of SQLite exporting the same
    # symbols, so nothing in this project may link plain libsqlite3 next to it.
    find_library(SQLCIPHER_LIBRARY NAMES sqlcipher REQUIRED)
    find_path(SQLCIPHER_INCLUDE_DIR NAMES sqlcipher/sqlite3.h REQUIRED)
    # libqrencode renders contact invites as QR codes (multi-symbol structured
    # append for the full self-verifying chain).
    find_library(QRENCODE_LIBRARY NAMES qrencode REQUIRED)
    find_path(QRENCODE_INCLUDE_DIR NAMES qrencode.h REQUIRED)
    # libopus encodes call audio (48 kHz mono, 20 ms frames). The media rides I2P
    # datagrams; this is only the codec, so it stays private to the library.
    find_library(OPUS_LIBRARY NAMES opus REQUIRED)
    find_path(OPUS_INCLUDE_DIR NAMES opus/opus.h REQUIRED)

    add_library(bazarish_client STATIC
        client/AccountDb.cpp
        client/AccountKey.cpp
        client/AccountManager.cpp
        client/ApiClient.cpp
        client/AudioCodec.cpp
        client/Authorship.cpp
        client/LoginSigner.cpp
        client/AudioIo.cpp
        client/Bot.cpp
        client/CallMedia.cpp
        client/Client.cpp
        client/FederationFetch.cpp
        client/FileTransfer.cpp
        client/I2pKeys.cpp
        client/I2pRouter.cpp
        client/Invite.cpp
        client/OutboundCourier.cpp
        client/OutboundLeases.cpp
        client/Qr.cpp
        client/Session.cpp
        client/WarmDestPool.cpp
        client/WireLog.cpp
    )
    add_library(Bazarish::Client ALIAS bazarish_client)
    # The headers sit beside their sources and are included by name, which is how
    # both front-ends already spell them.
    target_include_directories(bazarish_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/client)
    target_include_directories(bazarish_client PRIVATE
        ${QRENCODE_INCLUDE_DIR} ${OPUS_INCLUDE_DIR})
    target_link_libraries(bazarish_client PUBLIC bazarish_common Threads::Threads
        ${SQLCIPHER_LIBRARY})
    target_link_libraries(bazarish_client PRIVATE ${QRENCODE_LIBRARY} ${OPUS_LIBRARY})
    target_compile_options(bazarish_client PRIVATE -Wall -Wextra -Werror)

    function(bazarish_client_add_test name)
        add_executable(${name} client/tests/${name}.cpp)
        target_link_libraries(${name} PRIVATE bazarish_client)
        target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    bazarish_client_add_test(TestAccount)
    bazarish_client_add_test(TestAuthorship)
    bazarish_client_add_test(TestApiClient)
    bazarish_client_add_test(TestBot)
    bazarish_client_add_test(TestCallMedia)
    bazarish_client_add_test(TestClient)

    # Live end-to-end against a running resolver over real I2P: the coordinate a
    # build ships with, the frame on the real transport, and the chain checked
    # against the root this binary was built with. Needs the network and a
    # resolver that is up, so it is run by hand rather than by ctest.
    add_executable(alias_smoke client/tests/AliasSmoke.cpp)
    target_link_libraries(alias_smoke PRIVATE bazarish_client)
    target_compile_options(alias_smoke PRIVATE -Wall -Wextra -Werror)
    bazarish_client_add_test(TestClientFacade)
    bazarish_client_add_test(TestFileTransfer)
    bazarish_client_add_test(TestI2pKeys)
    bazarish_client_add_test(TestI2pProxy)
    bazarish_client_add_test(TestInvite)
    bazarish_client_add_test(TestLogin)
    bazarish_client_add_test(TestOutboundCourier)
    bazarish_client_add_test(TestDeliveryPass)
    bazarish_client_add_test(TestWireLog)
endif()
