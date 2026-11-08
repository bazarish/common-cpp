// Bazarish project (c) 2026
#include "bazarish/TlsContext.hpp"

#include <openssl/ssl.h>

#include <stdexcept>

namespace bazarish::tls {

namespace ssl = boost::asio::ssl;

namespace {

ssl::context contextOf(const ssl::context::method method, const std::string& certificate,
    const std::string& key)
{
    ssl::context context(method);
    if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_3_VERSION) != 1) {
        throw std::runtime_error("tls: TLS 1.3 cannot be required");
    }
    if (!certificate.empty()) {
        context.use_certificate_chain_file(certificate);
        context.use_private_key_file(key, ssl::context::pem);
    }
    return context;
}

}  // namespace

ssl::context clientContext(const std::string& certificate, const std::string& key)
{
    return contextOf(ssl::context::tls_client, certificate, key);
}

ssl::context serverContext(const std::string& certificate, const std::string& key)
{
    if (certificate.empty()) {
        throw std::invalid_argument("tls: a server shows a certificate");
    }
    return contextOf(ssl::context::tls_server, certificate, key);
}

}  // namespace bazarish::tls
