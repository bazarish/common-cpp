// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include <zlib.h>

#include <iterator>

#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>

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

constexpr std::uint32_t kZipLocalSignature = 0x04034B50;
constexpr std::uint32_t kZipCentralSignature = 0x02014B50;
constexpr std::uint32_t kZipEndSignature = 0x06054B50;
constexpr std::uint16_t kZipVersion = 20;
constexpr std::uint16_t kZipMethodStored = 0;

void putLe16(Bytes& out, const std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
}

void putLe32(Bytes& out, const std::uint32_t value)
{
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

void putBe16(Bytes& out, const std::uint16_t value)
{
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void putBe64(Bytes& out, const std::uint64_t value)
{
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

void putBytes(Bytes& out, const std::string& text)
{
    out.insert(out.end(), text.begin(), text.end());
}

}  // namespace

Bytes packReseedSu3(const std::vector<Bytes>& routers, const std::string& signerId)
{
    Bytes zip;
    Bytes central;
    std::uint16_t entries = 0;
    for (const Bytes& router : routers) {
        if (router.empty()) {
            continue;
        }
        const std::string name = "routerInfo-" + std::to_string(entries) + ".dat";
        const std::uint32_t crc = static_cast<std::uint32_t>(
            ::crc32(0, router.data(), static_cast<uInt>(router.size())));
        const std::uint32_t offset = static_cast<std::uint32_t>(zip.size());
        putLe32(zip, kZipLocalSignature);
        putLe16(zip, kZipVersion);
        putLe16(zip, 0);
        putLe16(zip, kZipMethodStored);
        putLe16(zip, 0);
        putLe16(zip, 0);
        putLe32(zip, crc);
        putLe32(zip, static_cast<std::uint32_t>(router.size()));
        putLe32(zip, static_cast<std::uint32_t>(router.size()));
        putLe16(zip, static_cast<std::uint16_t>(name.size()));
        putLe16(zip, 0);
        putBytes(zip, name);
        zip.insert(zip.end(), router.begin(), router.end());

        putLe32(central, kZipCentralSignature);
        putLe16(central, kZipVersion);
        putLe16(central, kZipVersion);
        putLe16(central, 0);
        putLe16(central, kZipMethodStored);
        putLe16(central, 0);
        putLe16(central, 0);
        putLe32(central, crc);
        putLe32(central, static_cast<std::uint32_t>(router.size()));
        putLe32(central, static_cast<std::uint32_t>(router.size()));
        putLe16(central, static_cast<std::uint16_t>(name.size()));
        putLe16(central, 0);
        putLe16(central, 0);
        putLe16(central, 0);
        putLe16(central, 0);
        putLe32(central, 0);
        putLe32(central, offset);
        putBytes(central, name);
        ++entries;
    }
    const std::uint32_t centralOffset = static_cast<std::uint32_t>(zip.size());
    zip.insert(zip.end(), central.begin(), central.end());
    putLe32(zip, kZipEndSignature);
    putLe16(zip, 0);
    putLe16(zip, 0);
    putLe16(zip, entries);
    putLe16(zip, entries);
    putLe32(zip, static_cast<std::uint32_t>(central.size()));
    putLe32(zip, centralOffset);
    putLe16(zip, 0);

    std::string version = std::to_string(static_cast<std::int64_t>(std::time(nullptr)));
    version.resize(std::max(version.size(), kMinVersionBytes), '\0');

    Bytes out;
    out.reserve(kHeaderBytes + version.size() + signerId.size() + zip.size());
    for (const std::uint8_t byte : kSu3Magic) {
        out.push_back(byte);
    }
    out.push_back(kSu3FormatVersion);
    putBe16(out, kSignatureType);
    putBe16(out, kSignatureLength);
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(version.size()));
    out.push_back(0);
    out.push_back(static_cast<std::uint8_t>(signerId.size()));
    putBe64(out, static_cast<std::uint64_t>(zip.size()));
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
