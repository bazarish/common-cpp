// Bazarish project (c) 2026
#include <openssl/is_boringssl.h>

#include "TlsEngine.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pool.h>
#include <openssl/ssl.h>

#include <brotli/decode.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <ctime>
#include <map>
#include <mutex>
#include <stdexcept>
#include <utility>

#if !defined(OPENSSL_IS_BORINGSSL)
#error "the gateway link's TLS engine is built against BoringSSL only"
#endif

namespace bazarish::http {

namespace {

// Chrome's own settings, from net/socket/ssl_client_socket_impl.cc and net/ssl at 157.0.8103.78.
constexpr char kCipherRule[] = "ALL:!aPSK:!ECDSA+SHA1:!3DES";
constexpr std::uint32_t kSessionLifetimeSeconds = 60 * 60;
constexpr std::array<std::uint16_t, 4> kGroups{
    SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};
constexpr std::array<std::uint16_t, 2> kKeyShares{SSL_GROUP_X25519_MLKEM768, SSL_GROUP_X25519};
constexpr std::array<std::uint16_t, 11> kVerifyPrefs{
    SSL_SIGN_ML_DSA_44,
    SSL_SIGN_ML_DSA_65,
    SSL_SIGN_ML_DSA_87,
    SSL_SIGN_ECDSA_SECP256R1_SHA256,
    SSL_SIGN_RSA_PSS_RSAE_SHA256,
    SSL_SIGN_RSA_PKCS1_SHA256,
    SSL_SIGN_ECDSA_SECP384R1_SHA384,
    SSL_SIGN_RSA_PSS_RSAE_SHA384,
    SSL_SIGN_RSA_PKCS1_SHA384,
    SSL_SIGN_RSA_PSS_RSAE_SHA512,
    SSL_SIGN_RSA_PKCS1_SHA512,
};
// ALPN wire format, RFC 7301 3.1: each name after its one-byte length.
constexpr std::array<std::uint8_t, 9> kAlpnWebSocket{
    0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
constexpr std::array<std::uint8_t, 12> kAlpnPage{
    0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
constexpr std::array<std::uint8_t, 2> kAlpsProtocol{'h', '2'};
// Chrome 157.0.8103.78 (Linux) Trust Anchor IDs, captured 2026-11-12; equal for every host tried.
constexpr std::array<std::uint8_t, 184> kTrustAnchorIds{
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x01, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x06,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0d, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x0e,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x0f, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x12,
    0x05, 0x82, 0xdf, 0x13, 0x02, 0x13, 0x05, 0x82, 0xdf, 0x13, 0x02, 0x14,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07, 0x08, 0x83, 0x9a,
    0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b,
    0x2d, 0x01, 0x09, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b, 0x08, 0x83, 0x9a,
    0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b,
    0x2d, 0x01, 0x0d, 0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12,
    0x08, 0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13, 0x04, 0xd6, 0x79,
    0x09, 0x01, 0x04, 0xd6, 0x79, 0x09, 0x04, 0x04, 0xd6, 0x79, 0x09, 0x05,
    0x04, 0xd6, 0x79, 0x09, 0x06, 0x04, 0xd6, 0x79, 0x09, 0x07, 0x04, 0xd6,
    0x79, 0x09, 0x08, 0x04, 0xd6, 0x79, 0x09, 0x0a, 0x04, 0xd6, 0x79, 0x09,
    0x0b, 0x04, 0xd6, 0x79, 0x09, 0x0c, 0x04, 0xd6, 0x79, 0x09, 0x0d, 0x04,
    0xd6, 0x79, 0x09, 0x0f,
};
// Chrome's kDefaultOpenSSLBufferSize: one full record and its overhead.
constexpr std::size_t kBioPairBytes = 17 * 1024;
// A record carries at most 2^14 bytes of plaintext, RFC 8446 5.1.
constexpr std::size_t kMaxPlaintextRecord = 16384;
// Chrome keeps two TLS 1.3 tickets per host and spends one per connection.
constexpr std::size_t kTicketsPerHost = 2;

int decompressBrotli(SSL*, CRYPTO_BUFFER** out, const std::size_t uncompressedLength,
    const std::uint8_t* const in, const std::size_t inLength)
{
    std::uint8_t* data = nullptr;
    bssl::UniquePtr<CRYPTO_BUFFER> decompressed(CRYPTO_BUFFER_alloc(&data, uncompressedLength));
    if (!decompressed) {
        return 0;
    }
    std::size_t produced = uncompressedLength;
    if (BrotliDecoderDecompress(inLength, in, &produced, data) != BROTLI_DECODER_RESULT_SUCCESS
        || produced != uncompressedLength) {
        return 0;
    }
    *out = decompressed.release();
    return 1;
}

// The gateway is authenticated by its own key inside the channel; TLS here is cover.
ssl_verify_result_t acceptChain(SSL*, std::uint8_t*)
{
    return ssl_verify_ok;
}

bool expired(const SSL_SESSION& session)
{
    const std::uint64_t now = static_cast<std::uint64_t>(std::time(nullptr));
    const std::uint64_t issued = SSL_SESSION_get_time(&session);
    return now < issued || now >= issued + SSL_SESSION_get_timeout(&session);
}

class SessionCache {
public:
    bssl::UniquePtr<SSL_SESSION> take(const std::string& key)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        const auto found = sessions_.find(key);
        if (found == sessions_.end()) {
            return nullptr;
        }
        Held& held = found->second;
        if (!held.front() || expired(*held.front())) {
            sessions_.erase(found);
            return nullptr;
        }
        if (SSL_SESSION_up_ref(held.front().get()) != 1) {
            throw std::runtime_error("tls: a session cannot be shared");
        }
        bssl::UniquePtr<SSL_SESSION> taken(held.front().get());
        if (SSL_SESSION_should_be_single_use(taken.get()) == 1) {
            std::rotate(held.begin(), std::next(held.begin()), held.end());
            held.back().reset();
        }
        return taken;
    }

    void keep(const std::string& key, bssl::UniquePtr<SSL_SESSION> session)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        Held& held = sessions_[key];
        if (held.front() && SSL_SESSION_should_be_single_use(held.front().get()) == 1) {
            std::rotate(held.rbegin(), std::next(held.rbegin()), held.rend());
        }
        held.front() = std::move(session);
    }

private:
    using Held = std::array<bssl::UniquePtr<SSL_SESSION>, kTicketsPerHost>;

    std::mutex mutex_;
    std::map<std::string, Held> sessions_;
};

int sessionArrived(SSL* ssl, SSL_SESSION* session);

class Context {
public:
    Context()
        : keyIndex_(SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr))
        , context_(SSL_CTX_new(TLS_with_buffers_method()))
    {
        if (keyIndex_ < 0) {
            throw std::runtime_error("tls: no room for a session key beside a connection");
        }
        if (!context_) {
            throw std::runtime_error("tls: cannot make a context");
        }
        SSL_CTX* const context = context_.get();
        SSL_CTX_set_custom_verify(context, SSL_VERIFY_PEER, acceptChain);
        SSL_CTX_set_session_cache_mode(
            context, SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL);
        SSL_CTX_sess_set_new_cb(context, sessionArrived);
        SSL_CTX_set_timeout(context, kSessionLifetimeSeconds);
        SSL_CTX_set_grease_enabled(context, 1);
        SSL_CTX_set_grease_sigalgs_enabled(context, 1);
        if (SSL_CTX_add_cert_compression_alg(
                context, TLSEXT_cert_compression_brotli, nullptr, decompressBrotli)
            != 1) {
            throw std::runtime_error("tls: cannot take compressed certificates");
        }
    }

    SSL_CTX* get() const { return context_.get(); }
    int keyIndex() const { return keyIndex_; }
    SessionCache& sessions() { return sessions_; }

private:
    const int keyIndex_;
    const bssl::UniquePtr<SSL_CTX> context_;
    SessionCache sessions_;
};

// One context for the process, as Chrome has.
Context& context()
{
    static Context shared;
    return shared;
}

int sessionArrived(SSL* const ssl, SSL_SESSION* const session)
{
    const std::string* const key
        = static_cast<const std::string*>(SSL_get_ex_data(ssl, context().keyIndex()));
    if (key == nullptr) {
        return 0;
    }
    context().sessions().keep(*key, bssl::UniquePtr<SSL_SESSION>(session));
    return 1;
}

std::string lastError(const char* const what)
{
    const std::uint32_t code = ERR_get_error();
    if (code == 0) {
        return what;
    }
    std::array<char, ERR_ERROR_STRING_BUF_LEN> text{};
    ERR_error_string_n(code, text.data(), text.size());
    return std::string(what) + ": " + text.data();
}

}  // namespace

struct TlsEngine::Impl {
    bssl::UniquePtr<SSL> ssl;
    bssl::UniquePtr<BIO> outer;
    std::string sessionKey;
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

namespace {

void require(const bool done, const char* const what)
{
    if (!done) {
        throw std::runtime_error(lastError(what));
    }
}

}  // namespace

TlsEngine::TlsEngine(
    const std::string& serverName, const std::string& sessionKey, const TlsProfile profile)
    : impl_(std::make_unique<Impl>())
{
    Context& shared = context();
    impl_->sessionKey = sessionKey;
    impl_->ssl.reset(SSL_new(shared.get()));
    require(impl_->ssl != nullptr, "tls: cannot make a connection");
    SSL* const ssl = impl_->ssl.get();
    require(SSL_set_ex_data(ssl, shared.keyIndex(), &impl_->sessionKey) == 1,
        "tls: cannot tie the session key to its connection");

    BIO* inner = nullptr;
    BIO* outer = nullptr;
    require(BIO_new_bio_pair(&inner, kBioPairBytes, &outer, kBioPairBytes) == 1,
        "tls: cannot make the memory pipe");
    impl_->outer.reset(outer);
    SSL_set_bio(ssl, inner, inner);

    if (!serverName.empty()) {
        require(SSL_set_tlsext_host_name(ssl, serverName.c_str()) == 1,
            "tls: the name would not go in the handshake");
    }
    require(SSL_set1_group_ids(ssl, kGroups.data(), kGroups.size()) == 1, "tls: groups refused");
    require(SSL_set1_client_key_shares(ssl, kKeyShares.data(), kKeyShares.size()) == 1,
        "tls: key shares refused");
    const bssl::UniquePtr<SSL_SESSION> resumed = shared.sessions().take(sessionKey);
    if (resumed) {
        require(SSL_set_session(ssl, resumed.get()) == 1, "tls: the session would not resume");
    }
    require(SSL_set_min_proto_version(ssl, TLS1_2_VERSION) == 1
            && SSL_set_max_proto_version(ssl, TLS1_3_VERSION) == 1,
        "tls: versions refused");
    SSL_set_early_data_enabled(ssl, 0);
    SSL_set_options(ssl, SSL_OP_LEGACY_SERVER_CONNECT);
    SSL_set_mode(ssl, SSL_MODE_CBC_RECORD_SPLITTING | SSL_MODE_ENABLE_FALSE_START);
    require(SSL_set_strict_cipher_list(ssl, kCipherRule) == 1, "tls: ciphers refused");
    require(SSL_set_verify_algorithm_prefs(ssl, kVerifyPrefs.data(), kVerifyPrefs.size()) == 1,
        "tls: signature algorithms refused");
    SSL_set_alps_use_new_codepoint(ssl, 1);
    const bool page = profile == TlsProfile::ePage;
    // Unlike the rest of the API, zero means success here.
    require(page ? SSL_set_alpn_protos(ssl, kAlpnPage.data(), kAlpnPage.size()) == 0
                 : SSL_set_alpn_protos(ssl, kAlpnWebSocket.data(), kAlpnWebSocket.size()) == 0,
        "tls: ALPN refused");
    if (page) {
        require(SSL_add_application_settings(
                    ssl, kAlpsProtocol.data(), kAlpsProtocol.size(), nullptr, 0)
                == 1,
            "tls: ALPS refused");
    }
    SSL_enable_signed_cert_timestamps(ssl);
    SSL_enable_ocsp_stapling(ssl);
    SSL_set_renegotiate_mode(ssl, ssl_renegotiate_explicit);
    SSL_set_shed_handshake_config(ssl, 1);
    SSL_set_enable_ech_grease(ssl, 1);
    SSL_set_permute_extensions(ssl, 1);
    require(SSL_set1_requested_trust_anchors(ssl, kTrustAnchorIds.data(), kTrustAnchorIds.size())
            == 1,
        "tls: trust anchor IDs refused");
    SSL_set_connect_state(ssl);
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
    const int offered = static_cast<int>(std::min(from.size(), kMaxPlaintextRecord));
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
    const std::uint8_t* name = nullptr;
    unsigned length = 0;
    SSL_get0_alpn_selected(impl_->ssl.get(), &name, &length);
    return name == nullptr ? std::string() : std::string(name, name + length);
}

const std::string& TlsEngine::failure() const
{
    return impl_->failure;
}

}  // namespace bazarish::http
