// Bazarish project (c) 2026
#include "DevicePairing.hpp"

#include "I2pRouter.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Log.hpp>

#include <cctype>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

constexpr char kPairPath[] = "/hello";
constexpr char kPairMethod[] = "POST";
constexpr char kPairHelloLabel[] = "bazarish pairing hello v1";
constexpr char kPairBundleLabel[] = "bazarish pairing bundle v1";
constexpr char kPairTriesLeftHeader[] = "X-Bazarish-Pair-Left";
constexpr char kPairTriesLeftHeaderKey[] = "x-bazarish-pair-left";
constexpr char kPairBundleContentType[] = "application/octet-stream";
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

std::shared_ptr<bazarish::i2p::Endpoint> pairEndpoint(bazarish::i2p::Router& router,
    const bazarish::i2p::Privacy privacy, const std::string& owner, const bool published)
{
    bazarish::i2p::EndpointConfig config;
    config.privacy = privacy;
    config.tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
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
    std::string code = std::to_string(randomBelow(kPairCodeSpace));
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

PairVerdict pairVerdict(const std::string& method, const std::string& target, const Bytes& hello,
    const std::string& code, const Bytes& key)
{
    if (method != kPairMethod || target != kPairPath) {
        return {kI2pHttpNotFound, false};
    }
    const std::optional<Bytes> given = KeyedSeal(key, kPairHelloLabel).open(hello);
    if (!given.has_value()) {
        return {kI2pHttpBadRequest, false};
    }
    if (!service::constantTimeEqual(std::string(given->begin(), given->end()), code)) {
        return {kI2pHttpForbidden, true};
    }
    return {kI2pHttpOk, false};
}

std::string pairRequest(const std::string& dest, const std::string& code, const Bytes& key)
{
    const Bytes hello = KeyedSeal(key, kPairHelloLabel).seal(Bytes(code.begin(), code.end()));
    return buildI2pHttpRequest(kPairMethod, dest, kPairPath,
               {{"Content-Type", kPairBundleContentType}}, hello.size())
        + std::string(hello.begin(), hello.end());
}

Bytes sealPairBundle(const Bytes& key, const Bytes& bundle)
{
    return KeyedSeal(key, kPairBundleLabel).seal(bundle);
}

Bytes openPairBundle(const Bytes& key, const Bytes& sealed)
{
    const std::optional<Bytes> bundle = KeyedSeal(key, kPairBundleLabel).open(sealed);
    if (!bundle.has_value()) {
        throw std::runtime_error("the account came sealed under another key than the link's");
    }
    return *bundle;
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
    if (sharedI2pRouterIfRunning().has_value()) {
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
