# Bazarish project (c) 2026
cmake_minimum_required(VERSION 3.20)
project(bazarish-common CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ML-DSA and ML-KEM arrived in 3.5; over an older system one pass -DOPENSSL_ROOT_DIR.
find_package(OpenSSL 3.5 REQUIRED)
find_package(ZLIB REQUIRED)
find_package(Threads REQUIRED)

# The embedded I2P transport, in every build: the i2pd submodule and Boost program_options.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/I2pdBazarish.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/GitVersion.cmake)

# The client core of the desktop client and of bazarish-bot; servers build it OFF.
option(BAZARISH_WITH_CLIENT "Build the client core library" ON)

add_library(bazarish_common STATIC
    src/Auth.cpp
    src/Bytes.cpp
    src/AccountKind.cpp
    src/Crypto.cpp
    src/Cms.cpp
    src/Hybrid.cpp
    src/Tunnel.cpp
    src/Certificates.cpp
    src/Pass.cpp
    src/Padding.cpp
    src/ConfigFile.cpp
    src/PrivateFile.cpp
    src/WebAssets.cpp
    src/Errors.cpp
    src/FederationFrame.cpp
    src/Address.cpp
    src/Argon2.cpp
    src/I2pAddress.cpp
    src/Sam.cpp
    src/I2p.cpp
    src/I2pGateway.cpp
    src/I2pSam.cpp
    src/Descriptor.cpp
    src/ServerDescriptor.cpp
    src/PairLink.cpp
    src/Resolve.cpp
    src/ResolvePuzzle.cpp
    src/AliasMaintenance.cpp
    src/I2pHttp.cpp
    src/Reactions.cpp
    src/PlainText.cpp
    src/Log.cpp
    src/ReseedSu3.cpp
    src/HttpClient.cpp
    src/GatewayProtocol.cpp
    src/GatewayStreamBook.cpp
    src/RawPathChooser.cpp
    src/HttpServer.cpp
    src/WebSocketClient.cpp
    src/Hmac.cpp
    src/Portal.cpp
    src/PortalSession.cpp
    src/LoginChallenge.cpp
    src/Tls.cpp
)
add_library(Bazarish::Common ALIAS bazarish_common)

target_include_directories(bazarish_common
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(bazarish_common SYSTEM
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
target_link_libraries(bazarish_common PUBLIC OpenSSL::Crypto OpenSSL::SSL ZLIB::ZLIB)
# On Windows the SAM client's sockets are a library rather than the C runtime.
if(WIN32)
    target_link_libraries(bazarish_common PUBLIC ws2_32)
endif()
target_compile_options(bazarish_common PRIVATE -Wall -Wextra -Werror)

# GCC 14 pairs Asio's inlined coroutine frame with plain delete: a false positive, silenced here.
set_source_files_properties(src/HttpServer.cpp src/HttpClient.cpp PROPERTIES
    COMPILE_OPTIONS -Wno-mismatched-new-delete)

# Its i2pd and Boost includes arrive as SYSTEM through Bazarish::I2pd, out of -Werror.
target_sources(bazarish_common PRIVATE src/I2pEmbedded.cpp)
target_link_libraries(bazarish_common PUBLIC Bazarish::I2pd)
# Manual end-to-end smoke over live I2P (not a unit test - needs the network).
add_executable(i2p_smoke tests/I2pSmoke.cpp)
target_link_libraries(i2p_smoke PRIVATE bazarish_common)
target_compile_options(i2p_smoke PRIVATE -Wall -Wextra)

enable_testing()

function(bazarish_add_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE bazarish_common)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

bazarish_add_test(TestAuth)
bazarish_add_test(TestBytes)
bazarish_add_test(TestCarryReturn)
bazarish_add_test(TestCrypto)
bazarish_add_test(TestTls)
bazarish_add_test(TestCms)
bazarish_add_test(TestHybrid)
bazarish_add_test(TestTunnel)
bazarish_add_test(TestReseedSu3)
bazarish_add_test(TestCertificates)
bazarish_add_test(TestPass)
bazarish_add_test(TestPadding)
bazarish_add_test(TestErrors)
bazarish_add_test(TestAddress)
bazarish_add_test(TestResolvePuzzle)
bazarish_add_test(TestI2pAddress)
bazarish_add_test(TestI2pDelegation)
bazarish_add_test(TestI2pKeyBlob)

# Live end-to-end over an external router by SAM: needs a running i2pd, so not a unit test.
add_executable(sam_streams tests/SamStreams.cpp)
target_link_libraries(sam_streams PRIVATE bazarish_common)
target_compile_options(sam_streams PRIVATE -Wall -Wextra -Werror)
add_executable(sam_smoke tests/SamSmoke.cpp)
target_link_libraries(sam_smoke PRIVATE bazarish_common)
target_compile_options(sam_smoke PRIVATE -Wall -Wextra -Werror)
bazarish_add_test(TestDescriptor)
bazarish_add_test(TestServerDescriptor)
bazarish_add_test(TestPairLink)
bazarish_add_test(TestResolve)
bazarish_add_test(TestAliasMaintenance)
bazarish_add_test(TestLog)
bazarish_add_test(TestHttpClient)
bazarish_add_test(TestGatewayProtocol)
bazarish_add_test(TestGatewayStreamBook)
bazarish_add_test(TestRawPathChooser)
bazarish_add_test(TestWebSocket)
bazarish_add_test(TestWebSocketClient)
bazarish_add_test(TestLoginChallenge)
bazarish_add_test(TestConfigFile)
bazarish_add_test(TestWebAssets)

# These four fake the far end over POSIX sockets; Windows is a client-only target.
if(NOT WIN32)
    bazarish_add_test(TestFederationFrame)
    bazarish_add_test(TestSam)
    bazarish_add_test(TestI2pHttp)
    bazarish_add_test(TestWebSocketTlsDuplex)
endif()

# A server build looks for none of the client core's dependencies.
if(BAZARISH_WITH_CLIENT)
    # SQLCipher exports SQLite's symbols: nothing here may link plain libsqlite3 beside it.
    find_library(SQLCIPHER_LIBRARY NAMES sqlcipher REQUIRED)
    find_path(SQLCIPHER_INCLUDE_DIR NAMES sqlcipher/sqlite3.h REQUIRED)
    # libopus is only the call codec, so it stays private to the library.
    find_library(OPUS_LIBRARY NAMES opus REQUIRED)
    find_path(OPUS_INCLUDE_DIR NAMES opus/opus.h REQUIRED)

    add_library(bazarish_client STATIC
        client/AccountDb.cpp
        client/AccountKey.cpp
        client/AccountManager.cpp
        client/ApiClient.cpp
        client/AudioCodec.cpp
        client/Authorship.cpp
        client/BotMenu.cpp
        client/LoginSigner.cpp
        client/AudioIo.cpp
        client/CallMedia.cpp
        client/Client.cpp
        client/FederationFetch.cpp
        client/FileTransfer.cpp
        client/DevicePairing.cpp
        client/I2pKeys.cpp
        client/GatewayAddress.cpp
        client/I2pRouter.cpp
        client/Invite.cpp
        client/OutboundCourier.cpp
        client/OutboundLeases.cpp
        client/Presence.cpp
        client/Session.cpp
        client/SocksProxy.cpp
        client/WarmDestPool.cpp
        client/WireLog.cpp
    )
    add_library(Bazarish::Client ALIAS bazarish_client)
    # Headers sit beside their sources and are included by name, as both front-ends spell them.
    target_include_directories(bazarish_client PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/client)
    target_include_directories(bazarish_client PRIVATE
        ${SQLCIPHER_INCLUDE_DIR} ${OPUS_INCLUDE_DIR})
    target_link_libraries(bazarish_client PUBLIC bazarish_common Threads::Threads
        ${SQLCIPHER_LIBRARY})
    target_link_libraries(bazarish_client PRIVATE ${OPUS_LIBRARY})
    target_compile_options(bazarish_client PRIVATE -Wall -Wextra -Werror)

    function(bazarish_client_add_test name)
        add_executable(${name} client/tests/${name}.cpp)
        target_link_libraries(${name} PRIVATE bazarish_client)
        target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
        target_compile_options(${name} PRIVATE -Wall -Wextra -Werror)
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    bazarish_client_add_test(TestAccount)
if(NOT WIN32)
    # Its fakes are a socketpair and SIGPIPE, which MinGW does not carry.
    bazarish_client_add_test(TestDevicePairing)
endif()
    bazarish_client_add_test(TestAuthorship)
    bazarish_client_add_test(TestBotMenu)
    bazarish_client_add_test(TestApiClient)
    bazarish_client_add_test(TestCallMedia)
    bazarish_client_add_test(TestCallWindow)
    bazarish_client_add_test(TestClient)
    bazarish_client_add_test(TestPresence)

    # Live against a running resolver over real I2P, so run by hand rather than by ctest.
    add_executable(alias_smoke client/tests/AliasSmoke.cpp)
    target_link_libraries(alias_smoke PRIVATE bazarish_client)
    target_compile_options(alias_smoke PRIVATE -Wall -Wextra -Werror)
    # What a send costs against a real account and server: needs the network, not a unit test.
    add_executable(send_smoke client/tests/SendSmoke.cpp)
    target_link_libraries(send_smoke PRIVATE bazarish_client)
    target_compile_options(send_smoke PRIVATE -Wall -Wextra -Werror)
    add_executable(pair_smoke client/tests/PairSmoke.cpp)
    target_link_libraries(pair_smoke PRIVATE bazarish_client)
    target_compile_options(pair_smoke PRIVATE -Wall -Wextra -Werror)
    bazarish_client_add_test(TestClientFacade)
    bazarish_client_add_test(TestFileTransfer)
    bazarish_client_add_test(TestGatewayAddress)
    bazarish_client_add_test(TestI2pKeys)
    bazarish_client_add_test(TestI2pProxy)
    bazarish_client_add_test(TestI2pReseed)
    bazarish_client_add_test(TestInvite)
    bazarish_client_add_test(TestLogin)
    bazarish_client_add_test(TestOutboundCourier)
    bazarish_client_add_test(TestSocksProxy)
    bazarish_client_add_test(TestDeliveryPass)
    bazarish_client_add_test(TestWireLog)
endif()
