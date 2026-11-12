// Bazarish project (c) 2026
#include "TlsEngine.hpp"

#include "OpenSslHandles.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <climits>
#include <stdexcept>

namespace bazarish::http {

namespace {

// As much as one TLS record with its overhead.
constexpr std::size_t kBioPairBytes = 17 * 1024;
// ERR_error_string(3): a buffer of at least 256 bytes holds any message.
constexpr std::size_t kErrorTextBytes = 256;

using SslPtr = std::unique_ptr<SSL, ossl::Freer<&SSL_free>>;
using SslContextPtr = std::unique_ptr<SSL_CTX, ossl::Freer<&SSL_CTX_free>>;

std::string lastError(const char* const what)
{
    const unsigned long code = ERR_get_error();
    if (code == 0) {
        return what;
    }
    std::array<char, kErrorTextBytes> text{};
    ERR_error_string_n(code, text.data(), text.size());
    return std::string(what) + ": " + text.data();
}

void require(const bool done, const char* const what)
{
    if (!done) {
        throw std::runtime_error(lastError(what));
    }
}

}  // namespace

// The gateway link on Windows until BoringSSL builds there: OpenSSL's own ClientHello.
struct TlsEngine::Impl {
    SslContextPtr context;
    SslPtr ssl;
    ossl::BioPtr outer;
    std::string failure;

    TlsWant settle(const int result)
    {
        const int code = SSL_get_error(ssl.get(), result);
        if (code == SSL_ERROR_ZERO_RETURN) {
            return TlsWant::eClosed;
        }
        if (code == SSL_ERROR_WANT_WRITE) {
            return TlsWant::eOutputAndRetry;
        }
        if (code != SSL_ERROR_NONE && code != SSL_ERROR_WANT_READ) {
            failure = lastError("the TLS session failed");
            return TlsWant::eFailed;
        }
        if (BIO_ctrl_pending(outer.get()) > 0) {
            return code == SSL_ERROR_WANT_READ ? TlsWant::eOutputAndRetry : TlsWant::eOutput;
        }
        return code == SSL_ERROR_WANT_READ ? TlsWant::eInputAndRetry : TlsWant::eNothing;
    }
};

TlsEngine::TlsEngine(const std::string& serverName, const std::string&, const TlsProfile)
    : impl_(std::make_unique<Impl>())
{
    impl_->context.reset(SSL_CTX_new(TLS_client_method()));
    require(impl_->context != nullptr, "tls: cannot make a context");
    // The gateway is authenticated by its own key inside the channel; TLS here is cover.
    SSL_CTX_set_verify(impl_->context.get(), SSL_VERIFY_NONE, nullptr);
    impl_->ssl.reset(SSL_new(impl_->context.get()));
    require(impl_->ssl != nullptr, "tls: cannot make a connection");
    BIO* inner = nullptr;
    BIO* outer = nullptr;
    require(BIO_new_bio_pair(&inner, kBioPairBytes, &outer, kBioPairBytes) == 1,
        "tls: cannot make the memory pipe");
    impl_->outer.reset(outer);
    SSL_set_bio(impl_->ssl.get(), inner, inner);
    if (!serverName.empty()) {
        require(SSL_set_tlsext_host_name(impl_->ssl.get(), serverName.c_str()) == 1,
            "tls: the name would not go in the handshake");
    }
    SSL_set_connect_state(impl_->ssl.get());
}

TlsEngine::~TlsEngine() = default;

TlsWant TlsEngine::handshake()
{
    ERR_clear_error();
    return impl_->settle(SSL_do_handshake(impl_->ssl.get()));
}

TlsWant TlsEngine::read(const std::span<unsigned char> into, std::size_t& got)
{
    ERR_clear_error();
    const int asked = static_cast<int>(std::min<std::size_t>(into.size(), INT_MAX));
    const int result = SSL_read(impl_->ssl.get(), into.data(), asked);
    got = result > 0 ? static_cast<std::size_t>(result) : 0;
    return impl_->settle(result);
}

TlsWant TlsEngine::write(const std::span<const unsigned char> from, std::size_t& put)
{
    ERR_clear_error();
    const int offered = static_cast<int>(std::min<std::size_t>(from.size(), INT_MAX));
    const int result = SSL_write(impl_->ssl.get(), from.data(), offered);
    put = result > 0 ? static_cast<std::size_t>(result) : 0;
    return impl_->settle(result);
}

std::size_t TlsEngine::takeOutput(const std::span<unsigned char> into)
{
    const int asked = static_cast<int>(std::min<std::size_t>(into.size(), INT_MAX));
    const int taken = BIO_read(impl_->outer.get(), into.data(), asked);
    return taken > 0 ? static_cast<std::size_t>(taken) : 0;
}

std::size_t TlsEngine::giveInput(const std::span<const unsigned char> from)
{
    const int offered = static_cast<int>(std::min<std::size_t>(from.size(), INT_MAX));
    const int given = BIO_write(impl_->outer.get(), from.data(), offered);
    return given > 0 ? static_cast<std::size_t>(given) : 0;
}

std::string TlsEngine::protocol() const
{
    const unsigned char* name = nullptr;
    unsigned length = 0;
    SSL_get0_alpn_selected(impl_->ssl.get(), &name, &length);
    return name == nullptr ? std::string() : std::string(name, name + length);
}

const std::string& TlsEngine::failure() const
{
    return impl_->failure;
}

}  // namespace bazarish::http
