// Bazarish project (c) 2026
#include "bazarish/ServerDescriptor.hpp"
#include "bazarish/Percent.hpp"

#include "bazarish/I2pAddress.hpp"

#include "bazarish/Links.hpp"
#include "bazarish/Address.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/I2p.hpp"

#include <atomic>
#include <stdexcept>

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

bool isI2pUrl(const std::string& url)
{
    const std::size_t schemeEnd = url.find("://");
    const std::size_t hostStart = schemeEnd == std::string::npos ? 0 : schemeEnd + 3;
    const std::size_t hostEnd = url.find_first_of(":/", hostStart);
    return isB32I2pHost(url.substr(
        hostStart, hostEnd == std::string::npos ? std::string::npos : hostEnd - hostStart));
}

bool isI2pFacadeAddress(const std::string& address)
{
    return address.find('/') == std::string::npos
        && isB32I2pHost(address.substr(0, address.find(':')));
}

std::string encodeServerDescriptor(const ServerDescriptor& descriptor)
{
    std::string query = "v=1&fp=" + descriptor.fingerprint;
    for (const std::string& facade : descriptor.facades) {
        query += "&facade=" + facade;
    }
    for (const std::string& reseed : descriptor.reseeds) {
        query += "&reseed=" + reseed;
    }
    return webLink(std::string(kServerKind) + query);
}

ServerDescriptor parseServerDescriptor(const std::string& uri)
{
    const std::string query = linkQuery(uri, kServerKind);
    if (query.empty()) {
        throw std::invalid_argument("not a server link");
    }

    ServerDescriptor descriptor;
    std::string version;
    bool haveVersion = false;
    bool haveFingerprint = false;

    const std::optional<std::vector<QueryField>> fields = queryFields(query);
    if (!fields.has_value()) {
        throw std::invalid_argument("malformed server descriptor query");
    }
    for (const auto& [key, value] : *fields) {
        if (key == "v") {
            version = value;
            haveVersion = true;
        } else if (key == "fp") {
            descriptor.fingerprint = value;
            haveFingerprint = true;
        } else if (key == "facade") {
            if (!value.empty()) {
                if (value.find('/') != std::string::npos) {
                    throw std::invalid_argument(
                        "a facade is an address, with no scheme and no path");
                }
                if (!isI2pFacadeAddress(value) && !allowFacadeWithoutI2pForDevPurposes()) {
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
                if (isI2pUrl(value) && !allowFacadeWithoutI2pForDevPurposes()) {
                    throw std::invalid_argument(
                        "a reseed must not be an I2P address: it is what a client without a"
                        " router asks first (" + value + ")");
                }
                descriptor.reseeds.push_back(value);
            }
        }
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
