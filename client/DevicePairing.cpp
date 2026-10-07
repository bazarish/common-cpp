// Bazarish project (c) 2026
#include "DevicePairing.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/Log.hpp>

#include <cctype>
#include <limits>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

constexpr char kPairPath[] = "/hello";
constexpr char kPairMethod[] = "GET";
constexpr char kPairCodeHeader[] = "X-Bazarish-Pair";
constexpr char kPairCodeHeaderKey[] = "x-bazarish-pair";
constexpr char kPairTriesLeftHeader[] = "X-Bazarish-Pair-Left";
constexpr char kPairTriesLeftHeaderKey[] = "x-bazarish-pair-left";
constexpr char kPairBundleContentType[] = "application/octet-stream";
constexpr int kPairTunnelQuantity = 2;
constexpr char kPairDestLabel[] = "Device pairing";

constexpr unsigned pairCodeSpace()
{
    unsigned space = 1;
    for (std::size_t digit = 0; digit < kPairCodeDigits; ++digit) {
        space *= 10;
    }
    return space;
}

constexpr unsigned kPairCodeSpace = pairCodeSpace();
constexpr unsigned kPairCodeDraws
    = static_cast<unsigned>(std::numeric_limits<std::uint16_t>::max()) + 1U;
constexpr unsigned kPairCodeRejectFrom = kPairCodeDraws / kPairCodeSpace * kPairCodeSpace;

static_assert(kPairCodeSpace <= kPairCodeDraws);
static_assert(kPairCodeRejectFrom % kPairCodeSpace == 0);

std::shared_ptr<bazarish::i2p::Endpoint> pairEndpoint(bazarish::i2p::Router& router,
    const bazarish::i2p::Privacy privacy, const std::string& owner, const bool published)
{
    bazarish::i2p::EndpointConfig config;
    config.privacy = privacy;
    config.tunnelQuantity = kPairTunnelQuantity;
    config.published = published;
    config.label = kPairDestLabel;
    config.owner = owner;
    config.bulk = true;
    return router.createEndpoint(config);
}

}  // namespace

void notePairingTrouble(const std::string& reason)
{
    log::debug("pair: {}", reason);
}

std::string newPairCode()
{
    unsigned draw = kPairCodeRejectFrom;
    while (draw >= kPairCodeRejectFrom) {
        const Bytes drawn = randomBytes(sizeof(std::uint16_t));
        draw = (static_cast<unsigned>(drawn[0]) << CHAR_BIT) | drawn[1];
    }
    std::string code = std::to_string(draw % kPairCodeSpace);
    code.insert(code.begin(), kPairCodeDigits - code.size(), '0');
    return code;
}

bool isPairCode(const std::string& text)
{
    if (text.size() != kPairCodeDigits) {
        return false;
    }
    return std::all_of(text.begin(), text.end(),
        [](const unsigned char c) { return std::isdigit(c) != 0; });
}

PairVerdict pairVerdict(const std::string& method, const std::string& target,
    const std::map<std::string, std::string>& headers, const std::string& code)
{
    if (method != kPairMethod || target != kPairPath) {
        return {kI2pHttpNotFound, false};
    }
    const auto given = headers.find(kPairCodeHeaderKey);
    if (given == headers.end()) {
        return {kI2pHttpBadRequest, false};
    }
    if (!service::constantTimeEqual(given->second, code)) {
        return {kI2pHttpForbidden, true};
    }
    return {kI2pHttpOk, false};
}

std::string pairRequest(const std::string& dest, const std::string& code)
{
    return buildI2pHttpRequest(kPairMethod, dest, kPairPath, {{kPairCodeHeader, code}}, 0);
}

std::string pairRefusal(const int status, const int triesLeft)
{
    if (status != kI2pHttpForbidden) {
        return buildI2pHttpResponse(status, {}, 0);
    }
    return buildI2pHttpResponse(
        status, {{kPairTriesLeftHeader, std::to_string(triesLeft)}}, 0);
}

std::string pairBundleHead(const std::size_t size)
{
    return buildI2pHttpResponse(kI2pHttpOk, {{"Content-Type", kPairBundleContentType}}, size);
}

int pairTriesLeft(const std::map<std::string, std::string>& headers)
{
    const auto left = headers.find(kPairTriesLeftHeaderKey);
    if (left == headers.end()) {
        throw std::runtime_error(
            "the other device refused without saying how many tries are left");
    }
    return std::stoi(left->second);
}

bool applyLinkReseed(const fs::path& i2pDataDir, const std::vector<std::string>& reseeds)
{
    if (reseeds.empty() || knownRouterCount(i2pDataDir) >= kMinKnownRouters) {
        return false;
    }
    if (sharedI2pRouterIfRunning() != nullptr) {
        return false;
    }
    setReseedUrls(reseeds);
    return true;
}

std::shared_ptr<bazarish::i2p::Endpoint> publishPairDest(bazarish::i2p::Router& router,
    const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    return pairEndpoint(router, privacy, owner, /*published=*/true);
}

std::shared_ptr<bazarish::i2p::Endpoint> openPairLink(bazarish::i2p::Router& router,
    const bazarish::i2p::Privacy privacy, const std::string& owner)
{
    return pairEndpoint(router, privacy, owner, /*published=*/false);
}

}  // namespace bazarish::client
