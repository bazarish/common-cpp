// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string>

namespace bazarish::http {

// A browser offers a fresh WebSocket connection http/1.1 alone; a page connection h2 first.
enum class TlsProfile { eWebSocket, ePage };

enum class TlsWant { eNothing, eOutput, eOutputAndRetry, eInputAndRetry, eClosed, eFailed };

// No TLS library's type crosses this header: callers and engine may use different libraries.
class TlsEngine {
public:
    // An empty serverName sends no SNI; resumption is kept per sessionKey.
    TlsEngine(const std::string& serverName, const std::string& sessionKey, TlsProfile profile);
    ~TlsEngine();
    TlsEngine(const TlsEngine&) = delete;
    TlsEngine& operator=(const TlsEngine&) = delete;

    TlsWant handshake();
    TlsWant read(std::span<unsigned char> into, std::size_t& got);
    TlsWant write(std::span<const unsigned char> from, std::size_t& put);

    std::size_t takeOutput(std::span<unsigned char> into);
    std::size_t giveInput(std::span<const unsigned char> from);

    std::string protocol() const;
    const std::string& failure() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace bazarish::http
