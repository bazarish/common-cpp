// Bazarish project (c) 2026
#include "bazarish/DnsMessage.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::dns;
namespace ip = boost::asio::ip;

namespace {

constexpr std::uint16_t kId = 0x1234;
constexpr std::uint16_t kAnswered = 0x8180;
constexpr std::uint16_t kNoSuchName = 0x8183;
constexpr std::uint16_t kTruncatedAnswer = 0x8380;
constexpr std::uint16_t kQueryFlags = 0x0100;
constexpr std::uint16_t kTypeCname = 5;
constexpr std::uint16_t kToQuestion = 0xc00c;
constexpr unsigned char kReservedLabel = 0x40;
constexpr std::uint32_t kCnameTtl = 600;
constexpr std::uint32_t kLongTtl = 300;
constexpr std::uint32_t kShortTtl = 120;
constexpr std::uint32_t kTopBitTtl = 0x80000010U;
constexpr std::chrono::seconds kBriefTtl{30};
constexpr std::chrono::seconds kHourTtl{3600};
constexpr std::chrono::seconds kMinuteAndHalf{100};
constexpr int kOtherPort = 8443;
constexpr unsigned kBitsPerByte = 8;
constexpr unsigned kByteMask = 0xff;
constexpr std::size_t kIpv4Bytes = 4;
constexpr std::size_t kIpv6Bytes = 16;
const char* const kHost = "gw.example";

class Message {
public:
    Message& u16(const std::uint16_t value)
    {
        bytes.push_back(static_cast<unsigned char>(value >> kBitsPerByte));
        bytes.push_back(static_cast<unsigned char>(value & kByteMask));
        return *this;
    }
    Message& u32(const std::uint32_t value)
    {
        u16(static_cast<std::uint16_t>(value >> (2 * kBitsPerByte)));
        return u16(static_cast<std::uint16_t>(value));
    }
    Message& name(const std::string& dotted)
    {
        std::size_t from = 0;
        while (from <= dotted.size()) {
            const std::size_t dot = std::min(dotted.find('.', from), dotted.size());
            bytes.push_back(static_cast<unsigned char>(dot - from));
            for (std::size_t at = from; at < dot; ++at) {
                bytes.push_back(static_cast<unsigned char>(dotted[at]));
            }
            from = dot + 1;
        }
        bytes.push_back(0);
        return *this;
    }
    Message& raw(const std::vector<unsigned char>& more)
    {
        for (const unsigned char byte : more) {
            bytes.push_back(byte);
        }
        return *this;
    }
    Message& header(const std::uint16_t flags, const std::uint16_t answers)
    {
        return u16(kId).u16(flags).u16(1).u16(answers).u16(0).u16(0);
    }
    Message& question(const std::uint16_t type) { return name(kHost).u16(type).u16(kClassIn); }
    Message& record(const std::uint16_t type, const std::uint32_t ttl,
        const std::vector<unsigned char>& data)
    {
        u16(kToQuestion).u16(type).u16(kClassIn).u32(ttl);
        return u16(static_cast<std::uint16_t>(data.size())).raw(data);
    }

    std::vector<unsigned char> bytes;
};

std::vector<unsigned char> cnameData()
{
    Message target;
    target.name("edge.example");
    return target.bytes;
}

std::vector<unsigned char> v4(const ip::address_v4& address)
{
    const ip::address_v4::bytes_type bytes = address.to_bytes();
    return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

std::vector<unsigned char> v6(const ip::address_v6& address)
{
    const ip::address_v6::bytes_type bytes = address.to_bytes();
    return std::vector<unsigned char>(bytes.begin(), bytes.end());
}

const ip::address_v4 kFirst = ip::make_address_v4("192.0.2.1");
const ip::address_v4 kSecond = ip::make_address_v4("192.0.2.2");
const ip::address_v6 kSix = ip::make_address_v6("2001:db8::1");

std::vector<unsigned char> answeredA()
{
    Message message;
    message.header(kAnswered, 3).question(kTypeA);
    message.record(kTypeCname, kCnameTtl, cnameData());
    message.record(kTypeA, kLongTtl, v4(kFirst));
    message.record(kTypeA, kShortTtl, v4(kSecond));
    return message.bytes;
}

Outcome answered(const std::vector<ip::address>& addresses, const std::chrono::seconds ttl)
{
    Outcome outcome;
    outcome.answer = Answer{};
    outcome.answer->addresses = addresses;
    outcome.answer->ttl = ttl;
    return outcome;
}

void checkParse()
{
    const std::vector<unsigned char> message = answeredA();
    const std::optional<Answer> a = parseAnswer(message, kTypeA);
    CHECK(a.has_value());
    CHECK(a->rcode == kRcodeNoError);
    CHECK(!a->truncated);
    CHECK(a->addresses == (std::vector<ip::address>{kFirst, kSecond}));
    CHECK(a->ttl == std::chrono::seconds(kShortTtl));

    const std::optional<Answer> none = parseAnswer(message, kTypeAaaa);
    CHECK(none.has_value());
    CHECK(none->addresses.empty());
    CHECK(!none->ttl.has_value());

    for (std::size_t cut = 0; cut < message.size(); ++cut) {
        const std::vector<unsigned char> part(message.begin(), message.begin() + cut);
        CHECK(!parseAnswer(part, kTypeA).has_value());
    }

    Message six;
    six.header(kAnswered, 1).question(kTypeAaaa).record(kTypeAaaa, kLongTtl, v6(kSix));
    const std::optional<Answer> aaaa = parseAnswer(six.bytes, kTypeAaaa);
    CHECK(aaaa.has_value());
    CHECK(aaaa->addresses == (std::vector<ip::address>{kSix}));

    Message missing;
    missing.header(kNoSuchName, 0).question(kTypeA);
    const std::optional<Answer> nx = parseAnswer(missing.bytes, kTypeA);
    CHECK(nx.has_value());
    CHECK(nx->rcode == kRcodeNameError);
    CHECK(nx->addresses.empty());

    Message cut;
    cut.header(kTruncatedAnswer, 0).question(kTypeA);
    CHECK(parseAnswer(cut.bytes, kTypeA)->truncated);

    Message asked;
    asked.header(kQueryFlags, 0).question(kTypeA);
    CHECK(!parseAnswer(asked.bytes, kTypeA).has_value());

    Message wide;
    std::vector<unsigned char> five = v4(kFirst);
    five.push_back(0);
    wide.header(kAnswered, 1).question(kTypeA).record(kTypeA, kLongTtl, five);
    CHECK(!parseAnswer(wide.bytes, kTypeA).has_value());

    Message narrow;
    narrow.header(kAnswered, 1).question(kTypeAaaa).record(kTypeAaaa, kLongTtl, v4(kFirst));
    CHECK(!parseAnswer(narrow.bytes, kTypeAaaa).has_value());

    Message reserved;
    reserved.header(kAnswered, 0).raw({kReservedLabel, 'a', 0}).u16(kTypeA).u16(kClassIn);
    CHECK(!parseAnswer(reserved.bytes, kTypeA).has_value());

    Message topBit;
    topBit.header(kAnswered, 1).question(kTypeA).record(kTypeA, kTopBitTtl, v4(kFirst));
    CHECK(parseAnswer(topBit.bytes, kTypeA)->ttl == std::chrono::seconds(0));

    CHECK(v4(kFirst).size() == kIpv4Bytes);
    CHECK(v6(kSix).size() == kIpv6Bytes);
}

void checkAddressesOf()
{
    const Resolved both = addressesOf(
        {answered({kSix}, kBriefTtl), answered({kFirst, kSecond}, kHourTtl)});
    CHECK(both.error.empty());
    CHECK(both.addresses == (std::vector<ip::address>{kSix, kFirst, kSecond}));
    CHECK(both.ttl == kMinimumAnswerTtl);

    Outcome lost;
    lost.error = "timed out";
    const Resolved one = addressesOf({lost, answered({kFirst}, kMinuteAndHalf)});
    CHECK(one.error.empty());
    CHECK(one.addresses == (std::vector<ip::address>{kFirst}));
    CHECK(one.ttl == kMinuteAndHalf);

    Outcome nx;
    nx.answer = Answer{};
    nx.answer->rcode = kRcodeNameError;
    const Resolved failed = addressesOf({lost, nx});
    CHECK(failed.addresses.empty());
    CHECK(failed.error == "timed out");
    CHECK(addressesOf({nx}).error == "no such name");
    CHECK(addressesOf({answered({}, kHourTtl)}).error == "no address");
}

void checkHttpsQuery()
{
    CHECK(httpsQueryName(kHost, kHttpsPort) == kHost);
    CHECK(httpsQueryName(kHost, kOtherPort) == std::string("_8443._https.") + kHost);
    CHECK(httpsExtraWait(std::chrono::milliseconds(0)) == kHttpsExtraMin);
    CHECK(httpsExtraWait(std::chrono::milliseconds(100)) == std::chrono::milliseconds(20));
    CHECK(httpsExtraWait(std::chrono::seconds(1)) == kHttpsExtraMax);
}

}  // namespace

int main()
{
    checkParse();
    checkAddressesOf();
    checkHttpsQuery();
    std::puts("TestDnsMessage ok");
    return 0;
}
