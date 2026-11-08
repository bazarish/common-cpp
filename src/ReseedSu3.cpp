// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"
#include "bazarish/Zip.hpp"

#include <iterator>

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

namespace bazarish::i2p {

namespace {

constexpr std::uint8_t kSu3Magic[] = {'I', '2', 'P', 's', 'u', '3', 0};
constexpr std::uint8_t kSu3FormatVersion = 0;
constexpr std::uint16_t kSignatureType = 0;
constexpr std::uint16_t kSignatureLength = 0;
constexpr std::uint8_t kFileTypeZip = 0x00;
constexpr std::uint8_t kContentTypeReseed = 0x03;
constexpr std::size_t kMinVersionBytes = 16;
constexpr std::size_t kUnusedAfterContentType = 12;
constexpr std::size_t kHeaderBytes = 40;
constexpr unsigned kRouterInfoMode = 0644;

void putBytes(Bytes& out, const std::string& text)
{
    out.insert(out.end(), text.begin(), text.end());
}

}  // namespace

Bytes packReseedSu3(const std::vector<Bytes>& routers, const std::string& signerId)
{
    std::vector<ZipEntry> entries;
    for (const Bytes& router : routers) {
        if (router.empty()) {
            continue;
        }
        entries.push_back(
            {"routerInfo-" + std::to_string(entries.size()) + ".dat", router, kRouterInfoMode});
    }
    const Bytes zip = zipStored(entries);

    std::string version = std::to_string(static_cast<std::int64_t>(std::time(nullptr)));
    version.resize(std::max(version.size(), kMinVersionBytes), '\0');

    Bytes out;
    out.reserve(kHeaderBytes + version.size() + signerId.size() + zip.size());
    for (const std::uint8_t byte : kSu3Magic) {
        out.push_back(byte);
    }
    out.push_back(kSu3FormatVersion);
    appendBigEndian(out, kSignatureType, sizeof(kSignatureType));
    appendBigEndian(out, kSignatureLength, sizeof(kSignatureLength));
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(version.size()));
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(signerId.size()));
    appendBigEndian(out, zip.size(), sizeof(std::uint64_t));
    out.push_back(0);
    out.push_back(kFileTypeZip);
    out.push_back(0);
    out.push_back(kContentTypeReseed);
    out.insert(out.end(), kUnusedAfterContentType, 0);
    putBytes(out, version);
    putBytes(out, signerId);
    out.insert(out.end(), zip.begin(), zip.end());
    return out;
}

}  // namespace bazarish::i2p
