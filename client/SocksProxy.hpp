// Bazarish project (c) 2026
#pragma once

#include <string>

namespace bazarish::client {

enum class SocksAnswer {
    eAccepted,
    eUnreachable,
    eNotSocks5,
    eNeedsAuthentication,
};

struct SocksCheck {
    SocksAnswer answer = SocksAnswer::eUnreachable;
    std::string error;
};

SocksCheck checkSocksProxy(const std::string& host, int port);

}  // namespace bazarish::client
