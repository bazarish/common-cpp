// Bazarish project (c) 2026
#include "bazarish/DnsMessage.hpp"
#include "bazarish/HostCache.hpp"

#include <boost/asio/io_context.hpp>

#include <algorithm>
#include <string>

#if defined(__ANDROID__)
#include <android/multinetwork.h>
#include <poll.h>

#include <boost/asio/ip/udp.hpp>

#include <array>
#include <cerrno>
#include <cstring>
#include <deque>
#include <stdexcept>
#include <system_error>
#else
#include <boost/asio/ip/tcp.hpp>
#endif

namespace bazarish::dns {

#if defined(__ANDROID__)

namespace {

// Chrome's kResponseBufferSize, net/dns/dns_platform_android_attempt.cc.
constexpr std::size_t kAnswerBufferBytes = 8 * 1024;
// Chrome's IPv6 probe, net/dns/host_resolver_manager.cc: kIPv6ProbeAddress, connected on 443.
constexpr boost::asio::ip::address_v6::bytes_type kIpv6ProbeAddress{
    0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88};
constexpr unsigned short kIpv6ProbePort = 443;
// RFC 4380 2.6.
constexpr std::array<unsigned char, 4> kTeredoPrefix{0x20, 0x01, 0, 0};
constexpr int kPollForever = -1;

bool ipv6Reachable()
{
    namespace asio = boost::asio;
    asio::io_context loop;
    asio::ip::udp::socket probe(loop);
    boost::system::error_code error;
    probe.open(asio::ip::udp::v6(), error);
    if (error) {
        return false;
    }
    probe.connect(
        asio::ip::udp::endpoint(asio::ip::address_v6(kIpv6ProbeAddress), kIpv6ProbePort), error);
    if (error) {
        return false;
    }
    const asio::ip::udp::endpoint local = probe.local_endpoint(error);
    if (error) {
        return false;
    }
    const asio::ip::address_v6 address = local.address().to_v6();
    const asio::ip::address_v6::bytes_type bytes = address.to_bytes();
    return !address.is_link_local()
        && !std::equal(kTeredoPrefix.begin(), kTeredoPrefix.end(), bytes.begin());
}

std::string errorText(const int negative)
{
    return std::system_category().message(-negative);
}

// android_res_nquery and its kin came in API 29.
class __INTRODUCED_IN(29) Query {
public:
    Query(const std::string& name, const std::uint16_t type, const bool address)
        : type_(type)
        , address_(address)
        , fd_(android_res_nquery(NETWORK_UNSPECIFIED, name.c_str(), kClassIn, type, 0))
    {
        if (fd_ < 0) {
            outcome_.error = errorText(fd_);
        }
    }

    ~Query()
    {
        if (!done()) {
            android_res_cancel(fd_);
        }
    }

    Query(const Query&) = delete;
    Query& operator=(const Query&) = delete;

    bool done() const { return fd_ < 0; }
    bool address() const { return address_; }
    int fd() const { return fd_; }
    const Outcome& outcome() const { return outcome_; }

    // android_res_nresult closes the descriptor whatever it returns.
    void read()
    {
        std::vector<unsigned char> buffer(kAnswerBufferBytes);
        int rcode = 0;
        const int got = android_res_nresult(fd_, &rcode, buffer.data(), buffer.size());
        fd_ = -1;
        if (got < 0) {
            outcome_.error = errorText(got);
            return;
        }
        outcome_.answer = parseAnswer(
            std::span<const unsigned char>(buffer).first(static_cast<std::size_t>(got)), type_);
        if (!outcome_.answer) {
            outcome_.error = "the answer is malformed";
        }
    }

    void cancel()
    {
        android_res_cancel(fd_);
        fd_ = -1;
    }

private:
    const std::uint16_t type_;
    const bool address_;
    int fd_;
    Outcome outcome_;
};

Resolved askPlatform(const std::string& host, const int port) __INTRODUCED_IN(29);

Resolved askPlatform(const std::string& host, const int port)
{
    using Clock = std::chrono::steady_clock;
    const Clock::time_point started = Clock::now();
    // Chrome's order: HTTPS first, then AAAA, then A (net/dns/host_resolver_dns_task.cc).
    std::deque<Query> queries;
    queries.emplace_back(httpsQueryName(host, port), kTypeHttps, false);
    if (ipv6Reachable()) {
        queries.emplace_back(host, kTypeAaaa, true);
    }
    queries.emplace_back(host, kTypeA, true);

    std::optional<Clock::time_point> httpsDeadline;
    for (;;) {
        std::vector<pollfd> watched;
        bool addressesPending = false;
        for (const Query& query : queries) {
            if (!query.done()) {
                watched.push_back(pollfd{query.fd(), POLLIN, 0});
                addressesPending = addressesPending || query.address();
            }
        }
        if (watched.empty()) {
            break;
        }
        int timeout = kPollForever;
        if (!addressesPending) {
            const Clock::time_point now = Clock::now();
            if (!httpsDeadline) {
                httpsDeadline = now
                    + httpsExtraWait(
                        std::chrono::duration_cast<std::chrono::milliseconds>(now - started));
            }
            if (now >= *httpsDeadline) {
                for (Query& query : queries) {
                    if (!query.done()) {
                        query.cancel();
                    }
                }
                break;
            }
            timeout = static_cast<int>(
                std::chrono::ceil<std::chrono::milliseconds>(*httpsDeadline - now).count());
        }
        if (::poll(watched.data(), watched.size(), timeout) < 0) {
            if (errno == EINTR) {
                continue;
            }
            throw std::system_error(errno, std::system_category(), "dns: poll");
        }
        for (const pollfd& entry : watched) {
            if (entry.revents == 0) {
                continue;
            }
            for (Query& query : queries) {
                if (!query.done() && query.fd() == entry.fd) {
                    query.read();
                }
            }
        }
    }

    std::vector<Outcome> addresses;
    for (const Query& query : queries) {
        if (query.address()) {
            addresses.push_back(query.outcome());
        }
    }
    return addressesOf(addresses);
}

}  // namespace

Resolved platformLookup(const std::string& host, const int port)
{
    if (__builtin_available(android 29, *)) {
        return askPlatform(host, port);
    }
    throw std::runtime_error("dns: android_res_nquery needs Android 10");
}

#else

Resolved platformLookup(const std::string& host, const int port)
{
    namespace asio = boost::asio;
    asio::io_context loop;
    asio::ip::tcp::resolver resolver(loop);
    boost::system::error_code error;
    const asio::ip::tcp::resolver::results_type found
        = resolver.resolve(host, std::to_string(port), error);
    Resolved resolved;
    if (error) {
        resolved.error = error.message();
        return resolved;
    }
    for (const asio::ip::tcp::resolver::results_type::value_type& entry : found) {
        const asio::ip::address address = entry.endpoint().address();
        if (std::find(resolved.addresses.begin(), resolved.addresses.end(), address)
            == resolved.addresses.end()) {
            resolved.addresses.push_back(address);
        }
    }
    resolved.ttl = kSystemAnswerTtl;
    return resolved;
}

#endif

}  // namespace bazarish::dns
