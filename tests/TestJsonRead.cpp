// Bazarish project (c) 2026
#include "bazarish/JsonRead.hpp"

#include "TestUtil.hpp"

#include <string>

using namespace bazarish;

namespace {

constexpr std::size_t kHostileDepth = 1 << 20;
constexpr unsigned char kCborArrayOfOne = 0x81;
constexpr unsigned char kCborZero = 0x00;

Bytes nestedCbor(const std::size_t depth)
{
    Bytes bytes(depth, kCborArrayOfOne);
    bytes.push_back(kCborZero);
    return bytes;
}

std::string nestedJson(const std::size_t depth)
{
    return std::string(depth, '[') + std::string(depth, ']');
}

bool refusedAsParseError(const auto& parse)
{
    try {
        (void)parse();
    } catch (const nlohmann::json::parse_error&) {
        return true;
    }
    return false;
}

}  // namespace

int main()
{
    const nlohmann::json sample = {{"type", "text"}, {"items", {1, 2, {{"k", "v"}}}}};
    const std::string text = sample.dump();
    CHECK(parseJson(text) == sample);
    CHECK(parseJson(Bytes(text.begin(), text.end())) == sample);
    CHECK(parseCbor(nlohmann::json::to_cbor(sample)) == sample);
    CHECK(parseJsonWithComments("{\"a\": 1 // note\n}") == nlohmann::json({{"a", 1}}));

    nlohmann::json button = nlohmann::json::object();
    button["text"] = "Yes";
    button["data"] = "y";
    nlohmann::json message = nlohmann::json::object();
    message["type"] = "text";
    message["keyboard"] = nlohmann::json::array({nlohmann::json::array({button})});
    nlohmann::json wrapper = nlohmann::json::object();
    wrapper["type"] = "device.message";
    wrapper["message"] = message;
    const nlohmann::json echo = nlohmann::json::array({wrapper});
    CHECK(parseCbor(nlohmann::json::to_cbor(echo)) == echo);
    nlohmann::json deeper = echo;
    deeper[0]["message"]["keyboard"][0][0]["extra"] = nlohmann::json::array();
    CHECK(refusedAsParseError([&deeper] { return parseCbor(nlohmann::json::to_cbor(deeper)); }));

    CHECK(parseJson(nestedJson(kMaxJsonDepth)).is_array());
    CHECK(parseCbor(nestedCbor(kMaxJsonDepth)).is_array());
    CHECK(refusedAsParseError([] { return parseJson(nestedJson(kMaxJsonDepth + 1)); }));
    CHECK(refusedAsParseError([] { return parseCbor(nestedCbor(kMaxJsonDepth + 1)); }));

    CHECK(refusedAsParseError([] { return parseCbor(nestedCbor(kHostileDepth)); }));
    CHECK(refusedAsParseError([] { return parseJson(nestedJson(kHostileDepth)); }));
    CHECK(parseCborOrDiscarded(nestedCbor(kHostileDepth)).is_discarded());
    CHECK(parseJsonOrDiscarded(nestedJson(kHostileDepth)).is_discarded());

    CHECK(refusedAsParseError([] { return parseJson("{\"a\":"); }));
    CHECK(refusedAsParseError([] { return parseCbor(Bytes{kCborArrayOfOne}); }));
    CHECK(parseJsonOrDiscarded("{\"a\":").is_discarded());
    CHECK(parseCborOrDiscarded(Bytes{kCborArrayOfOne}).is_discarded());
    return 0;
}
