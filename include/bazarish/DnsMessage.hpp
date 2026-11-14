// Bazarish project (c) 2026
#pragma once

#include "bazarish/HostCache.hpp"

#include <boost/asio/ip/address.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bazarish::dns {

// RFC 1035 3.2.2 and 3.2.4, RFC 3596 2.1, RFC 9460.
inline constexpr std::uint16_t kTypeA = 1;
inline constexpr std::uint16_t kTypeAaaa = 28;
inline constexpr std::uint16_t kTypeHttps = 65;
inline constexpr std::uint16_t kClassIn = 1;
inline constexpr std::uint16_t kRcodeNoError = 0;
inline constexpr std::uint16_t kRcodeNameError = 3;
inline constexpr int kHttpsPort = 443;

// Chrome's UseDnsHttpsSvcbInsecureExtraTime{Percent,Min,Max}, net/base/features.cc.
inline constexpr int kHttpsExtraPercent = 20;
inline constexpr std::chrono::milliseconds kHttpsExtraMin{5};
inline constexpr std::chrono::milliseconds kHttpsExtraMax{50};

struct Answer {
    std::uint16_t rcode = 0;
    bool truncated = false;
    std::vector<boost::asio::ip::address> addresses;
    std::optional<std::chrono::seconds> ttl;
};

// Nothing for what is not a well-formed response; addresses only of the type asked.
std::optional<Answer> parseAnswer(std::span<const unsigned char> message, std::uint16_t type);

struct Outcome {
    std::optional<Answer> answer;
    std::string error;
};

// Every address answered, in the order asked; the shortest TTL, never under kMinimumAnswerTtl.
Resolved addressesOf(const std::vector<Outcome>& outcomes);

// RFC 9460: a port other than 443 is named in front of the host.
std::string httpsQueryName(const std::string& host, int port);

// How long an HTTPS query may still run once the addresses took this long.
std::chrono::milliseconds httpsExtraWait(std::chrono::milliseconds addressesTook);

}  // namespace bazarish::dns
