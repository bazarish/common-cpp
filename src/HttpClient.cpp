// Bazarish project (c) 2026
#include <bazarish/HttpClient.hpp>

#include <bazarish/Bytes.hpp>
#include <bazarish/Log.hpp>

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

namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace beasthttp = boost::beast::http;
namespace ssl = boost::asio::ssl;
using asio::ip::tcp;

// HTTP/1.1, as an integer, the way Beast spells a version.
constexpr int kHttpVersion11 = 11;
// Bytes handed to the body provider per write while streaming an upload.
constexpr std::size_t kUploadChunkBytes = 64 * 1024;
// The status a server answers with when it wants credentials.
constexpr int kUnauthorizedStatus = 401;
// A digest exchange is one request per set of credentials, so the nonce count
// never advances past the first.
constexpr const char* kFirstNonceCount = "00000001";
constexpr std::size_t kClientNonceBytes = 8;

std::string lowercased(std::string text)
{
    std::transform(text.begin(), text.end(), text.begin(),
        [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// Which part of the exchange was running, so a timeout is reported as the thing
// it actually was: a backend that never answered is not an unreachable host.
enum class Phase { eConnect, eWrite, eRead };

template <class Body>
void applyHead(beasthttp::request<Body>& out, const std::string& host, const ClientRequest& request)
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
    out.keep_alive(false);
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

// Everything after the connection is up, for either kind of stream: write the
// request (from memory or from the provider), read the answer.
template <class Stream>
asio::awaitable<ClientResponse> exchangeOn(Stream& stream, const std::string& host,
    const ClientRequest& request, const ClientOptions& options, const std::uint64_t length,
    const BodyProvider* const provider, Phase& phase)
{
    phase = Phase::eWrite;
    beast::get_lowest_layer(stream).expires_after(options.writeTimeout);
    if (provider == nullptr) {
        beasthttp::request<beasthttp::string_body> out;
        applyHead(out, host, request);
        out.body() = request.body;
        out.prepare_payload();
        co_await beasthttp::async_write(stream, out, asio::use_awaitable);
    } else {
        beasthttp::request<beasthttp::buffer_body> out;
        applyHead(out, host, request);
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
            // Beast reports a consumed buffer as need_buffer: it is asking for the
            // next chunk, not failing.
            if (error && error != beasthttp::error::need_buffer) {
                throw boost::system::system_error(error);
            }
            error.clear();
        }
    }

    phase = Phase::eRead;
    beast::flat_buffer buffer;
    beasthttp::response<beasthttp::string_body> in;
    beast::get_lowest_layer(stream).expires_after(options.readTimeout);
    co_await beasthttp::async_read(stream, buffer, in, asio::use_awaitable);
    co_return fromBeast(in);
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
            beast::ssl_stream<beast::tcp_stream> stream(executor, context);
            if (options.verifyPeer) {
                context.set_default_verify_paths();
                stream.set_verify_mode(ssl::verify_peer);
                stream.set_verify_callback(ssl::host_name_verification(host));
            } else {
                stream.set_verify_mode(ssl::verify_none);
            }
            // Without SNI a virtual host answers with the wrong certificate, and
            // some fronts refuse the handshake outright.
            if (SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()) != 1) {
                throw std::runtime_error("could not set the TLS server name for " + host);
            }
            beast::get_lowest_layer(stream).expires_after(options.connectTimeout);
            co_await beast::get_lowest_layer(stream).async_connect(endpoints, asio::use_awaitable);
            co_await stream.async_handshake(ssl::stream_base::client, asio::use_awaitable);
            answer = co_await exchangeOn(stream, host, request, options, length, provider, phase);
            boost::system::error_code ignored;
            co_await stream.async_shutdown(asio::redirect_error(asio::use_awaitable, ignored));
        } else {
            beast::tcp_stream stream(executor);
            stream.expires_after(options.connectTimeout);
            co_await stream.async_connect(endpoints, asio::use_awaitable);
            answer = co_await exchangeOn(stream, host, request, options, length, provider, phase);
            boost::system::error_code ignored;
            stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        }
    } catch (const boost::system::system_error& error) {
        // The code's own message ("Connection refused"), not what(): Beast puts
        // the throwing source location in there, which is noise in a log line.
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

// Hex MD5, the one digest RFC 7616 names for its default algorithm. Used only
// to answer a server's authentication challenge, never to protect anything.
std::string md5Hex(const std::string& text)
{
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned int size = 0;
    if (EVP_Digest(text.data(), text.size(), digest.data(), &size, EVP_md5(), nullptr) != 1) {
        throw std::runtime_error("could not compute the digest challenge response");
    }
    return toHex(Bytes(digest.begin(), digest.begin() + size));
}

// The comma-separated "key=value" pairs of a WWW-Authenticate: Digest header.
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

// The Authorization header that answers a Digest challenge (RFC 7616 section
// 3.4, MD5 with qop=auth). One exchange per credentials, so the nonce count is
// always the first.
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
        // Status 0 is "the backend did not answer", which the caller turns into a
        // gateway failure - not a protocol error of its own.
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
    const ClientResponse first = runOnce(host, port, request, options, 0, nullptr);
    if (first.status != kUnauthorizedStatus || options.digestUser.empty()) {
        return first;
    }
    const auto challenge = first.headers.find("www-authenticate");
    if (challenge == first.headers.end() || challenge->second.rfind("Digest", 0) != 0) {
        return first;
    }
    // The challenge is what the credentials are computed against, so this second
    // attempt is the first one that could carry them.
    ClientRequest authorized = request;
    authorized.headers["Authorization"] = digestAuthorization(options, request.method,
        request.target, challengeFields(challenge->second));
    return runOnce(host, port, authorized, options, 0, nullptr);
}

ClientResponse upload(const std::string& host, const int port, const ClientRequest& request,
    const std::uint64_t length, const BodyProvider& provider, const ClientOptions& options)
{
    return runOnce(host, port, request, options, length, &provider);
}

}  // namespace bazarish::http
