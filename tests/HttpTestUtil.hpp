// Bazarish project (c) 2026
#pragma once

#include <bazarish/Auth.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/HttpClient.hpp>

#include <map>
#include <string>

namespace testutil {

using Headers = std::map<std::string, std::string>;

inline constexpr char kLoopback[] = "127.0.0.1";

inline bazarish::http::ClientResponse call(const int port, const std::string& method,
    const std::string& target, const Headers& headers = {}, const std::string& body = {},
    const bazarish::http::ClientOptions& options = {})
{
    bazarish::http::ClientRequest request;
    request.method = method;
    request.target = target;
    request.headers = headers;
    request.body = body;
    if (!body.empty()) {
        request.contentType = "application/json";
    }
    return bazarish::http::request(kLoopback, port, request, options);
}

inline bazarish::http::ClientResponse callTls(const int port, const std::string& pin,
    const std::string& method, const std::string& target, const Headers& headers = {},
    const std::string& body = {})
{
    bazarish::http::ClientOptions options;
    options.tls = true;
    options.pin = pin;
    return call(port, method, target, headers, body, options);
}

inline Headers signedHeaders(const bazarish::Identity& identity, const std::string& method,
    const std::string& path, const std::string& body)
{
    const bazarish::auth::Headers signature = bazarish::auth::signRequest(identity,
        bazarish::nowSeconds(), method, path, bazarish::Bytes(body.begin(), body.end()));
    return Headers(signature.begin(), signature.end());
}

inline Headers deviceHeaders(const bazarish::DeviceCredential& device, const std::string& method,
    const std::string& path, const std::string& body)
{
    const bazarish::auth::Headers signature = bazarish::auth::signDeviceRequest(device,
        bazarish::nowSeconds(), method, path, bazarish::Bytes(body.begin(), body.end()));
    return Headers(signature.begin(), signature.end());
}

}  // namespace testutil
