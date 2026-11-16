// Bazarish project (c) 2026
#include "bazarish/DnsMessage.hpp"

#include <algorithm>
#include <array>
#include <cstddef>

namespace bazarish::dns {

namespace {

// RFC 1035 4.1.1 to 4.1.4.
constexpr std::uint16_t kFlagResponse = 0x8000;
constexpr std::uint16_t kFlagTruncated = 0x0200;
constexpr std::uint16_t kRcodeMask = 0x000f;
constexpr unsigned char kLabelKindMask = 0xc0;
constexpr unsigned char kPointerKind = 0xc0;
constexpr std::size_t kPointerBytes = 2;
constexpr std::size_t kQuestionTailBytes = 4;
constexpr std::size_t kIpv4Bytes = 4;
constexpr std::size_t kIpv6Bytes = 16;
constexpr unsigned kBitsPerByte = 8;
// RFC 2181 8: a TTL with its top bit set counts as zero.
constexpr std::uint32_t kTtlTopBit = 0x80000000U;
constexpr int kPercent = 100;

class Reader {
public:
    explicit Reader(const std::span<const unsigned char> bytes)
        : bytes_(bytes)
    {
    }

    std::optional<std::uint16_t> u16()
    {
        const std::optional<std::span<const unsigned char>> two = take(sizeof(std::uint16_t));
        if (!two) {
            return std::nullopt;
        }
        return static_cast<std::uint16_t>(((*two)[0] << kBitsPerByte) | (*two)[1]);
    }

    std::optional<std::uint32_t> u32()
    {
        const std::optional<std::uint16_t> high = u16();
        const std::optional<std::uint16_t> low = high ? u16() : std::nullopt;
        if (!low) {
            return std::nullopt;
        }
        return (static_cast<std::uint32_t>(*high) << (2 * kBitsPerByte)) | *low;
    }

    std::optional<std::span<const unsigned char>> take(const std::size_t count)
    {
        if (count > bytes_.size() - at_) {
            return std::nullopt;
        }
        const std::span<const unsigned char> taken = bytes_.subspan(at_, count);
        at_ += count;
        return taken;
    }

    bool skipName()
    {
        for (;;) {
            const std::optional<std::span<const unsigned char>> head = take(1);
            if (!head) {
                return false;
            }
            const unsigned char length = (*head)[0];
            if (length == 0) {
                return true;
            }
            if ((length & kLabelKindMask) == kPointerKind) {
                return take(kPointerBytes - 1).has_value();
            }
            if ((length & kLabelKindMask) != 0 || !take(length)) {
                return false;
            }
        }
    }

private:
    std::span<const unsigned char> bytes_;
    std::size_t at_ = 0;
};

std::optional<boost::asio::ip::address> addressIn(
    const std::span<const unsigned char> data, const std::uint16_t type)
{
    if (type == kTypeA && data.size() == kIpv4Bytes) {
        boost::asio::ip::address_v4::bytes_type bytes{};
        std::copy(data.begin(), data.end(), bytes.begin());
        return boost::asio::ip::address_v4(bytes);
    }
    if (type == kTypeAaaa && data.size() == kIpv6Bytes) {
        boost::asio::ip::address_v6::bytes_type bytes{};
        std::copy(data.begin(), data.end(), bytes.begin());
        return boost::asio::ip::address_v6(bytes);
    }
    return std::nullopt;
}

std::string failureOf(const Outcome& outcome)
{
    if (!outcome.error.empty()) {
        return outcome.error;
    }
    if (outcome.answer->truncated) {
        return "the answer came truncated";
    }
    if (outcome.answer->rcode == kRcodeNameError) {
        return "no such name";
    }
    if (outcome.answer->rcode != kRcodeNoError) {
        return "the server answered rcode " + std::to_string(outcome.answer->rcode);
    }
    return "no address";
}

}  // namespace

std::optional<Answer> parseAnswer(
    const std::span<const unsigned char> message, const std::uint16_t type)
{
    Reader reader(message);
    const std::optional<std::uint16_t> id = reader.u16();
    const std::optional<std::uint16_t> flags = reader.u16();
    const std::optional<std::uint16_t> questions = reader.u16();
    const std::optional<std::uint16_t> answers = reader.u16();
    const std::optional<std::uint16_t> authorities = reader.u16();
    const std::optional<std::uint16_t> additionals = reader.u16();
    if (!id || !flags || !questions || !answers || !authorities || !additionals
        || (*flags & kFlagResponse) == 0) {
        return std::nullopt;
    }
    Answer answer;
    answer.rcode = *flags & kRcodeMask;
    answer.truncated = (*flags & kFlagTruncated) != 0;
    for (std::uint16_t question = 0; question < *questions; ++question) {
        if (!reader.skipName() || !reader.take(kQuestionTailBytes)) {
            return std::nullopt;
        }
    }
    for (std::uint16_t record = 0; record < *answers; ++record) {
        if (!reader.skipName()) {
            return std::nullopt;
        }
        const std::optional<std::uint16_t> recordType = reader.u16();
        const std::optional<std::uint16_t> recordClass = recordType ? reader.u16() : std::nullopt;
        const std::optional<std::uint32_t> ttl = recordClass ? reader.u32() : std::nullopt;
        const std::optional<std::uint16_t> length = ttl ? reader.u16() : std::nullopt;
        const std::optional<std::span<const unsigned char>> data
            = length ? reader.take(*length) : std::nullopt;
        if (!data) {
            return std::nullopt;
        }
        if (*recordType != type || *recordClass != kClassIn) {
            continue;
        }
        const std::optional<boost::asio::ip::address> address = addressIn(*data, type);
        if (!address) {
            return std::nullopt;
        }
        answer.addresses.push_back(*address);
        const std::chrono::seconds lasts((*ttl & kTtlTopBit) != 0 ? 0 : *ttl);
        answer.ttl = answer.ttl ? std::min(*answer.ttl, lasts) : lasts;
    }
    return answer;
}

Resolved addressesOf(const std::vector<Outcome>& outcomes)
{
    Resolved resolved;
    std::optional<std::chrono::seconds> shortest;
    for (const Outcome& outcome : outcomes) {
        const bool usable = outcome.error.empty() && !outcome.answer->truncated
            && outcome.answer->rcode == kRcodeNoError && !outcome.answer->addresses.empty();
        if (!usable) {
            if (resolved.error.empty()) {
                resolved.error = failureOf(outcome);
            }
            continue;
        }
        resolved.addresses.insert(resolved.addresses.end(), outcome.answer->addresses.begin(),
            outcome.answer->addresses.end());
        shortest = shortest ? std::min(*shortest, *outcome.answer->ttl) : *outcome.answer->ttl;
    }
    if (resolved.addresses.empty()) {
        return resolved;
    }
    resolved.error.clear();
    resolved.ttl = std::max(*shortest, kMinimumAnswerTtl);
    return resolved;
}

std::string httpsQueryName(const std::string& host, const int port)
{
    if (port == kHttpsPort) {
        return host;
    }
    std::string name("_");
    name += std::to_string(port);
    name += "._https.";
    name += host;
    return name;
}

std::chrono::milliseconds httpsExtraWait(const std::chrono::milliseconds addressesTook)
{
    return std::clamp(addressesTook * kHttpsExtraPercent / kPercent, kHttpsExtraMin, kHttpsExtraMax);
}

}  // namespace bazarish::dns
