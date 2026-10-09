// Bazarish project (c) 2026
#include "bazarish/ServerDescriptor.hpp"

#include "bazarish/Links.hpp"
#include "bazarish/Address.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/I2p.hpp"

#include <atomic>
#include <stdexcept>
#include <string_view>

namespace {

constexpr std::string_view kPrefix = bazarish::kServerUri;

}  // namespace

namespace bazarish {

namespace {
std::atomic<bool> g_selfHostedFacadeOnLoopback{false};
std::atomic<bool> g_allowFacadeWithoutI2p{false};
}  // namespace

void setAllowFacadeWithoutI2pForDevPurposes(const bool allow)
{
    g_allowFacadeWithoutI2p.store(allow);
}
void setSelfHostedFacadeOnLoopback(const bool own)
{
    g_selfHostedFacadeOnLoopback.store(own);
}

bool selfHostedFacadeOnLoopback()
{
    return g_selfHostedFacadeOnLoopback.load();
}

bool allowFacadeWithoutI2pForDevPurposes()
{
    return g_allowFacadeWithoutI2p.load();
}

bool isI2pFacadeUrl(const std::string& url)
{
    static const std::string kSuffix = ".b32.i2p";
    const std::size_t schemeEnd = url.find("://");
    const std::size_t hostStart = schemeEnd == std::string::npos ? 0 : schemeEnd + 3;
    const std::size_t hostEnd = url.find_first_of(":/", hostStart);
    const std::string host = url.substr(
        hostStart, hostEnd == std::string::npos ? std::string::npos : hostEnd - hostStart);
    return host.size() >= kSuffix.size()
        && host.compare(host.size() - kSuffix.size(), kSuffix.size(), kSuffix) == 0;
}

std::string encodeServerDescriptor(const ServerDescriptor& descriptor)
{
    std::string uri = std::string(kPrefix) + "v=1&fp=" + descriptor.fingerprint;
    for (const std::string& facade : descriptor.facades) {
        uri += "&facade=" + facade;
    }
    for (const std::string& reseed : descriptor.reseeds) {
        uri += "&reseed=" + reseed;
    }
    return uri;
}

ServerDescriptor parseServerDescriptor(const std::string& uri)
{
    if (uri.size() <= kPrefix.size() || uri.compare(0, kPrefix.size(), kPrefix) != 0) {
        throw std::invalid_argument("not a bazarish://server descriptor");
    }

    ServerDescriptor descriptor;
    std::string version;
    bool haveVersion = false;
    bool haveFingerprint = false;

    const std::string query = uri.substr(kPrefix.size());
    std::size_t pos = 0;
    while (pos < query.size()) {
        const std::size_t amp = query.find('&', pos);
        const std::string pair = query.substr(pos, amp == std::string::npos ? amp : amp - pos);
        const std::size_t eq = pair.find('=');
        if (eq == std::string::npos) {
            throw std::invalid_argument("malformed server descriptor query");
        }
        const std::string key = pair.substr(0, eq);
        const std::string value = pair.substr(eq + 1);
        if (key == "v") {
            version = value;
            haveVersion = true;
        } else if (key == "fp") {
            descriptor.fingerprint = value;
            haveFingerprint = true;
        } else if (key == "facade") {
            if (!value.empty()) {
                if (!isI2pFacadeUrl(value) && !allowFacadeWithoutI2pForDevPurposes()) {
                    throw std::invalid_argument(
                        "a facade must be an I2P address: the client talks to its server over"
                        " nothing else (" + value + ")");
                }
                descriptor.facades.push_back(value);
            }
        } else if (key == "reseed") {
            if (!value.empty()) {
                if (!i2p::isReseedUrl(value)) {
                    throw std::invalid_argument("a reseed is an https URL (" + value + ")");
                }
                if (isI2pFacadeUrl(value) && !allowFacadeWithoutI2pForDevPurposes()) {
                    throw std::invalid_argument(
                        "a reseed must not be an I2P address: it is what a client without a"
                        " router asks first (" + value + ")");
                }
                descriptor.reseeds.push_back(value);
            }
        }
        if (amp == std::string::npos) {
            break;
        }
        pos = amp + 1;
    }

    if (!haveVersion || version != "1") {
        throw std::invalid_argument("unsupported server descriptor version");
    }
    if (!haveFingerprint || !isFingerprint(descriptor.fingerprint)) {
        throw std::invalid_argument("server descriptor fp is not a 52-char base32 fingerprint");
    }
    return descriptor;
}

}  // namespace bazarish
