// Bazarish project (c) 2026
#pragma once

#include <boost/asio/ssl/context.hpp>

#include <string>

namespace bazarish::tls {

// TLS 1.3 at least, wherever the project speaks TLS for its own protection. A certificate,
// when given, is the one this side shows.
boost::asio::ssl::context clientContext(
    const std::string& certificate = {}, const std::string& key = {});
boost::asio::ssl::context serverContext(const std::string& certificate, const std::string& key);

}  // namespace bazarish::tls
