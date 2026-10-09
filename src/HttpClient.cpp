// Bazarish project (c) 2026
#include <bazarish/HttpClient.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/Log.hpp>
#include "bazarish/Tls.hpp"

#include <utility>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <exception>
#include <stdexcept>
#include <utility>
#include <vector>

namespace bazarish::http {

Url parseUrl(const std::string& url)
{
    std::string rest = url;
    Url parsed;
    if (const std::string scheme = "https://"; rest.rfind(scheme, 0) == 0) {
        rest = rest.substr(scheme.size());
        parsed.tls = true;
        parsed.port = kDefaultHttpsPort;
    } else if (const std::string plain = "http://"; rest.rfind(plain, 0) == 0) {
        rest = rest.substr(plain.size());
    }
    if (const auto slash = rest.find('/'); slash != std::string::npos) {
        parsed.path = rest.substr(slash);
        rest = rest.substr(0, slash);
    }
    if (const auto colon = rest.find(':'); colon == std::string::npos) {
        parsed.host = rest;
    } else {
        parsed.host = rest.substr(0, colon);
        parsed.port = std::stoi(rest.substr(colon + 1));
    }
    return parsed;
}

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beasthttp = boost::beast::http;
namespace ssl = boost::asio::ssl;
using asio::ip::tcp;

// HTTP/1.1, as an integer, the way Beast spells a version.
constexpr int kHttpVersion11 = 11;
constexpr std::size_t kUploadChunkBytes = 64 * 1024;
constexpr int kUnauthorizedStatus = 401;
constexpr const char* kFirstNonceCount = "00000001";
constexpr std::size_t kClientNonceBytes = 8;

std::string lowercased(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
        [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

enum class Phase { eConnect, eWrite, eRead };

template <class Body>
void applyHead(beasthttp::request<Body>& out, const std::string& host,
    const ClientRequest& request, const bool keepAlive)
{
    const beasthttp::verb verb = beasthttp::string_to_verb(request.method);
    if (verb == beasthttp::verb::unknown) {
        out.method_string(request.method);
    } else {
        out.method(verb);
    }
    out.target(request.target);
    out.version(kHttpVersion11);
    out.set(beasthttp::field::host, host);
    out.keep_alive(keepAlive);
    for (const auto& [name, value] : request.headers) {
        out.set(name, value);
    }
    if (!request.contentType.empty()) {
        out.set(beasthttp::field::content_type, request.contentType);
    }
}

ClientResponse fromBeast(const beasthttp::response<beasthttp::string_body>& in)
{
    ClientResponse out;
    out.status = static_cast<int>(in.result_int());
    out.body = in.body();
    for (const auto& field : in) {
        out.headers[lowercased(std::string(field.name_string()))] = std::string(field.value());
    }
    if (in.count(beasthttp::field::content_type) > 0) {
        out.contentType = std::string(in[beasthttp::field::content_type]);
    }
    return out;
}

template <class Stream>
asio::awaitable<ClientResponse> exchangeOn(Stream& stream, const std::string& host,
    const ClientRequest& request, const ClientOptions& options, const std::uint64_t length,
    const BodyProvider* const provider, Phase& phase, beast::flat_buffer& buffer,
    const bool keepAlive)
{
    phase = Phase::eWrite;
    beast::get_lowest_layer(stream).expires_after(options.writeTimeout);
    if (provider == nullptr) {
        beasthttp::request<beasthttp::string_body> out;
        applyHead(out, host, request, keepAlive);
        out.body() = request.body;
        out.prepare_payload();
        co_await beasthttp::async_write(stream, out, asio::use_awaitable);
    } else {
        beasthttp::request<beasthttp::buffer_body> out;
        applyHead(out, host, request, keepAlive);
        out.content_length(length);
        out.body().data = nullptr;
        out.body().more = true;

        beasthttp::request_serializer<beasthttp::buffer_body> serializer(out);
        boost::system::error_code error;
        co_await beasthttp::async_write_header(
            stream, serializer, asio::redirect_error(asio::use_awaitable, error));
        if (error) {
            throw boost::system::system_error(error);
        }

        std::array<char, kUploadChunkBytes> chunk{};
        std::uint64_t remaining = length;
        while (remaining > 0) {
            const std::size_t want
                = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk.size()));
            const std::size_t got = (*provider)(chunk.data(), want);
            if (got == 0) {
                throw std::runtime_error("upload body ended early");
            }
            remaining -= got;
            out.body().data = chunk.data();
            out.body().size = got;
            out.body().more = remaining > 0;
            beast::get_lowest_layer(stream).expires_after(options.writeTimeout);
            co_await beasthttp::async_write(
                stream, serializer, asio::redirect_error(asio::use_awaitable, error));
            // Beast reports a consumed buffer as need_buffer: it is asking for the next chunk, not failing.
            if (error && error != beasthttp::error::need_buffer) {
                throw boost::system::system_error(error);
            }
            error.clear();
        }
    }

    phase = Phase::eRead;
    beasthttp::response<beasthttp::string_body> in;
    beast::get_lowest_layer(stream).expires_after(options.readTimeout);
    co_await beasthttp::async_read(stream, buffer, in, asio::use_awaitable);
    co_return fromBeast(in);
}

std::string md5Hex(const std::string& text)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_Digest(text.data(), text.size(), digest.data(), &size, EVP_md5(), nullptr) != 1) {
        throw std::runtime_error("could not compute the digest challenge response");
    }
    return toHex(Bytes(digest.begin(), digest.begin() + size));
}

std::map<std::string, std::string> challengeFields(const std::string& header)
{
    std::map<std::string, std::string> fields;
    const std::size_t scheme = header.find(' ');
    if (scheme == std::string::npos) {
        return fields;
    }
    std::string rest = header.substr(scheme + 1);
    while (!rest.empty()) {
        const std::size_t comma = rest.find(',');
        std::string pair = rest.substr(0, comma);
        const std::size_t eq = pair.find('=');
        if (eq != std::string::npos) {
            std::string key = pair.substr(0, eq);
            std::string value = pair.substr(eq + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            fields[key] = value;
        }
        if (comma == std::string::npos) {
            break;
        }
        rest = rest.substr(comma + 1);
    }
    return fields;
}

std::string digestAuthorization(const ClientOptions& options, const std::string& method,
    const std::string& target, const std::map<std::string, std::string>& fields)
{
    const auto value = [&fields](const std::string& key) {
        const auto found = fields.find(key);
        return found == fields.end() ? std::string() : found->second;
    };
    const std::string realm = value("realm");
    const std::string nonce = value("nonce");
    const std::string qop = value("qop");
    const std::string opaque = value("opaque");
    const std::string cnonce = toHex(randomBytes(kClientNonceBytes));
    const std::string ha1 = md5Hex(options.digestUser + ":" + realm + ":" + options.digestPassword);
    const std::string ha2 = md5Hex(method + ":" + target);
    const std::string answer = qop.empty()
        ? md5Hex(ha1 + ":" + nonce + ":" + ha2)
        : md5Hex(ha1 + ":" + nonce + ":" + kFirstNonceCount + ":" + cnonce + ":auth:" + ha2);

    std::string header = "Digest username=\"" + options.digestUser + "\", realm=\"" + realm
        + "\", nonce=\"" + nonce + "\", uri=\"" + target + "\", response=\"" + answer + "\"";
    if (!qop.empty()) {
        header += ", qop=auth, nc=" + std::string(kFirstNonceCount) + ", cnonce=\"" + cnonce + "\"";
    }
    if (!opaque.empty()) {
        header += ", opaque=\"" + opaque + "\"";
    }
    return header;
}

template <class Stream>
asio::awaitable<ClientResponse> exchangeAuthorized(Stream& stream, const std::string& host,
    const ClientRequest& request, const ClientOptions& options, const std::uint64_t length,
    const BodyProvider* const provider, Phase& phase)
{
    beast::flat_buffer buffer;
    const bool answerable = provider == nullptr && !options.digestUser.empty();
    ClientResponse answer = co_await exchangeOn(
        stream, host, request, options, length, provider, phase, buffer, answerable);
    if (!answerable || answer.status != kUnauthorizedStatus) {
        co_return answer;
    }
    const auto challenge = answer.headers.find("www-authenticate");
    if (challenge == answer.headers.end() || challenge->second.rfind("Digest", 0) != 0) {
        co_return answer;
    }
    ClientRequest authorized = request;
    authorized.headers["Authorization"] = digestAuthorization(
        options, request.method, request.target, challengeFields(challenge->second));
    co_return co_await exchangeOn(
        stream, host, authorized, options, length, provider, phase, buffer, false);
}

asio::awaitable<ClientResponse> exchange(asio::any_io_executor executor, const std::string& host,
    const int port, const ClientRequest& request, const ClientOptions& options,
    const std::uint64_t length, const BodyProvider* const provider)
{
    ClientResponse answer;
    Phase phase = Phase::eConnect;
    try {
        tcp::resolver resolver(executor);
        const auto endpoints
            = co_await resolver.async_resolve(host, std::to_string(port), asio::use_awaitable);
        if (options.tls) {
            ssl::context context(ssl::context::tls_client);
            context.set_options(ssl::context::default_workarounds | ssl::context::no_sslv2
                | ssl::context::no_sslv3);
            if (!options.certificate.empty()) {
                context.use_certificate_chain_file(options.certificate);
                context.use_private_key_file(options.key, ssl::context::pem);
            }
            beast::ssl_stream<beast::tcp_stream> stream(executor, context);
            if (!options.pin.empty()) {
                stream.set_verify_mode(ssl::verify_none);
            } else if (options.verifyPeer) {
                context.set_default_verify_paths();
                stream.set_verify_mode(ssl::verify_peer);
                stream.set_verify_callback(ssl::host_name_verification(host));
            } else {
                stream.set_verify_mode(ssl::verify_none);
            }
            if (SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()) != 1) {
                throw std::runtime_error("could not set the TLS server name for " + host);
            }
            beast::get_lowest_layer(stream).expires_after(options.connectTimeout);
            co_await beast::get_lowest_layer(stream).async_connect(endpoints, asio::use_awaitable);
            co_await stream.async_handshake(ssl::stream_base::client, asio::use_awaitable);
            if (!options.pin.empty()
                && bazarish::tls::pinOf(stream.native_handle()) != options.pin) {
                throw std::runtime_error("the peer's key is not the pinned one");
            }
            answer = co_await exchangeAuthorized(
                stream, host, request, options, length, provider, phase);
            boost::system::error_code ignored;
            co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, ignored));
        } else {
            beast::tcp_stream stream(executor);
            stream.expires_after(options.connectTimeout);
            co_await stream.async_connect(endpoints, asio::use_awaitable);
            answer = co_await exchangeAuthorized(
                stream, host, request, options, length, provider, phase);
            boost::system::error_code ignored;
            stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        }
    } catch (const boost::system::system_error& error) {
        answer = ClientResponse{};
        answer.error = error.code().message();
        answer.readTimedOut = phase == Phase::eRead;
    } catch (const std::exception& error) {
        answer = ClientResponse{};
        answer.error = error.what();
        answer.readTimedOut = phase == Phase::eRead;
    }
    co_return answer;
}

ClientResponse runOnce(const std::string& host, const int port, const ClientRequest& request,
    const ClientOptions& options, const std::uint64_t length, const BodyProvider* const provider)
{
    asio::io_context loop;
    ClientResponse answer;
    asio::co_spawn(loop, exchange(loop.get_executor(), host, port, request, options, length,
                             provider),
        [&answer](const std::exception_ptr error, ClientResponse result) {
            if (error) {
                try {
                    std::rethrow_exception(error);
                } catch (const std::exception& thrown) {
                    answer.error = thrown.what();
                }
                return;
            }
            answer = std::move(result);
        });
    loop.run();
    return answer;
}

}  // namespace

asio::awaitable<Response> fetch(asio::any_io_executor executor, const std::string& host,
    const int port, ClientRequest request, const std::chrono::seconds timeout)
{
    ClientOptions options;
    options.connectTimeout = timeout;
    options.readTimeout = timeout;
    options.writeTimeout = timeout;
    const ClientResponse result
        = co_await exchange(executor, host, port, request, options, 0, nullptr);
    if (result.status == 0) {
        bazarish::log::warn("upstream {}:{} failed: {}", host, port, result.error);
    }
    Response answer;
    answer.status = result.status;
    answer.body = result.body;
    answer.contentType = result.contentType;
    co_return answer;
}

ClientResponse request(const std::string& host, const int port, const ClientRequest& request,
    const ClientOptions& options)
{
    ClientRequest outgoing = request;
    if (!options.basicUser.empty()) {
        const std::string pair = options.basicUser + ":" + options.basicPassword;
        outgoing.headers["Authorization"]
            = "Basic " + toBase64(Bytes(pair.begin(), pair.end()));
    }
    return runOnce(host, port, outgoing, options, 0, nullptr);
}

ClientResponse upload(const std::string& host, const int port, const ClientRequest& request,
    const std::uint64_t length, const BodyProvider& provider, const ClientOptions& options)
{
    return runOnce(host, port, request, options, length, &provider);
}

}  // namespace bazarish::http
