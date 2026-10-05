// Bazarish project (c) 2026
//
// The reseed archive this server hands out is read by routers, not by us, so
// what is checked here is the shape the format promises: the container's header,
// and a ZIP whose stored entries carry the routers back byte for byte.
#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include "TestUtil.hpp"

#include <zlib.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::uint16_t le16(const bazarish::Bytes& b, const std::size_t at)
{
    return static_cast<std::uint16_t>(b.at(at) | (b.at(at + 1) << 8));
}

std::uint32_t le32(const bazarish::Bytes& b, const std::size_t at)
{
    std::uint32_t value = 0;
    for (int i = 3; i >= 0; --i) {
        value = (value << 8) | b.at(at + static_cast<std::size_t>(i));
    }
    return value;
}

std::uint64_t be64(const bazarish::Bytes& b, const std::size_t at)
{
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | b.at(at + i);
    }
    return value;
}

}  // namespace

int main()
{
    using namespace bazarish;

    std::vector<Bytes> routers;
    for (int i = 0; i < 3; ++i) {
        const std::string body = "routerinfo-body-" + std::to_string(i) + std::string(200, 'x');
        routers.emplace_back(body.begin(), body.end());
    }
    const std::string signer = "bazarish@example";
    const Bytes su3 = i2p::packReseedSu3(routers, signer);

    // The header, field by field, exactly where a router looks for it.
    CHECK(std::memcmp(su3.data(), "I2Psu3", 6) == 0);
    CHECK(su3.at(6) == 0);
    // Where a router looks, counted the way its reader walks the header: magic
    // and a zero (7), format version, signature type and length, then the four
    // one-byte fields with an unused byte before each of the last three.
    constexpr std::size_t kVersionLengthAt = 13;
    constexpr std::size_t kSignerLengthAt = 15;
    constexpr std::size_t kContentLengthAt = 16;
    constexpr std::size_t kFileTypeAt = 25;
    constexpr std::size_t kContentTypeAt = 27;
    constexpr std::size_t kHeaderBytes = 40;  // through the twelve unused bytes
    CHECK(su3.at(kFileTypeAt) == 0x00);     // zip
    CHECK(su3.at(kContentTypeAt) == 0x03);  // reseed
    const std::size_t versionLength = su3.at(kVersionLengthAt);
    const std::size_t signerLength = su3.at(kSignerLengthAt);
    CHECK(versionLength >= 16);
    CHECK(signerLength == signer.size());
    const std::uint64_t contentLength = be64(su3, kContentLengthAt);
    const std::size_t zipAt = kHeaderBytes + versionLength + signerLength;
    CHECK(std::string(su3.begin() + static_cast<long>(zipAt - signerLength),
              su3.begin() + static_cast<long>(zipAt))
        == signer);
    // Nothing after the content: the archive is not signed, and says so with a
    // zero-length signature rather than by being short.
    CHECK(su3.size() == zipAt + contentLength);

    // The ZIP: one stored entry per router, each carrying its bytes unchanged.
    std::size_t at = zipAt;
    for (std::size_t i = 0; i < routers.size(); ++i) {
        CHECK(le32(su3, at) == 0x04034B50);
        CHECK(le16(su3, at + 8) == 0);  // stored, never deflated
        const std::uint32_t crc = le32(su3, at + 14);
        const std::uint32_t size = le32(su3, at + 18);
        const std::size_t nameLength = le16(su3, at + 26);
        CHECK(size == routers[i].size());
        CHECK(crc
            == static_cast<std::uint32_t>(
                ::crc32(0, routers[i].data(), static_cast<uInt>(routers[i].size()))));
        const std::size_t body = at + 30 + nameLength;
        CHECK(Bytes(su3.begin() + static_cast<long>(body),
                  su3.begin() + static_cast<long>(body + size))
            == routers[i]);
        at = body + size;
    }
    // And then the central directory, which is where a reader stops.
    CHECK(le32(su3, at) == 0x02014B50);

    // An empty netDb makes an empty archive, not a malformed one.
    const Bytes none = i2p::packReseedSu3({}, signer);
    CHECK(std::memcmp(none.data(), "I2Psu3", 6) == 0);

    std::fprintf(stderr, "TestReseedSu3 passed (%zu bytes for %zu routers)\n", su3.size(),
        routers.size());
    return 0;
}
