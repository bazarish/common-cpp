// Bazarish project (c) 2026
#include "bazarish/JsonRead.hpp"

#include <iterator>
#include <string>
#include <string_view>
#include <utility>

namespace bazarish {

namespace {

// nlohmann's own id for a syntax error, so callers that catch parse_error see one kind.
constexpr int kParseErrorId = 101;

using Sax = nlohmann::json_sax<nlohmann::json>;

class DepthGauge final : public Sax {
public:
    bool null() override { return true; }
    bool boolean(bool) override { return true; }
    bool number_integer(number_integer_t) override { return true; }
    bool number_unsigned(number_unsigned_t) override { return true; }
    bool number_float(number_float_t, const string_t&) override { return true; }
    bool string(string_t&) override { return true; }
    bool binary(binary_t&) override { return true; }
    bool key(string_t&) override { return true; }
    bool start_object(std::size_t) override { return enter(); }
    bool end_object() override { return leave(); }
    bool start_array(std::size_t) override { return enter(); }
    bool end_array() override { return leave(); }
    bool parse_error(std::size_t, const std::string&, const nlohmann::json::exception&) override
    {
        return false;
    }

    bool tooDeep() const { return tooDeep_; }

private:
    bool enter()
    {
        ++depth_;
        if (depth_ > kMaxJsonDepth) {
            tooDeep_ = true;
            return false;
        }
        return true;
    }

    bool leave()
    {
        --depth_;
        return true;
    }

    std::size_t depth_ = 0;
    bool tooDeep_ = false;
};

[[noreturn]] void refuseDepth()
{
    throw nlohmann::json::parse_error::create(kParseErrorId, 0,
        "nesting deeper than " + std::to_string(kMaxJsonDepth) + " levels", nullptr);
}

template<typename Input>
bool jsonTooDeep(Input&& input, const bool comments)
{
    DepthGauge gauge;
    nlohmann::json::sax_parse(
        std::forward<Input>(input), &gauge, nlohmann::json::input_format_t::json, true, comments);
    return gauge.tooDeep();
}

template<typename Input>
bool cborTooDeep(Input&& input)
{
    DepthGauge gauge;
    nlohmann::json::sax_parse(
        std::forward<Input>(input), &gauge, nlohmann::json::input_format_t::cbor, true);
    return gauge.tooDeep();
}

}  // namespace

nlohmann::json parseJson(const std::string_view text)
{
    if (jsonTooDeep(text, false)) {
        refuseDepth();
    }
    return nlohmann::json::parse(text);
}

nlohmann::json parseJson(std::istream& in)
{
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    return parseJson(std::string_view(text));
}

nlohmann::json parseJson(const Bytes& bytes)
{
    if (jsonTooDeep(bytes, false)) {
        refuseDepth();
    }
    return nlohmann::json::parse(bytes);
}

nlohmann::json parseJsonWithComments(const std::string_view text)
{
    if (jsonTooDeep(text, true)) {
        refuseDepth();
    }
    return nlohmann::json::parse(text, nullptr, true, true);
}

nlohmann::json parseJsonOrDiscarded(const std::string_view text)
{
    if (jsonTooDeep(text, false)) {
        return nlohmann::json(nlohmann::json::value_t::discarded);
    }
    return nlohmann::json::parse(text, nullptr, false);
}

nlohmann::json parseJsonOrDiscarded(const Bytes& bytes)
{
    if (jsonTooDeep(bytes, false)) {
        return nlohmann::json(nlohmann::json::value_t::discarded);
    }
    return nlohmann::json::parse(bytes, nullptr, false);
}

nlohmann::json parseCbor(const Bytes& bytes)
{
    if (cborTooDeep(bytes)) {
        refuseDepth();
    }
    return nlohmann::json::from_cbor(bytes);
}

nlohmann::json parseCbor(const std::string_view bytes)
{
    if (cborTooDeep(bytes)) {
        refuseDepth();
    }
    return nlohmann::json::from_cbor(bytes);
}

nlohmann::json parseCborOrDiscarded(const Bytes& bytes)
{
    if (cborTooDeep(bytes)) {
        return nlohmann::json(nlohmann::json::value_t::discarded);
    }
    return nlohmann::json::from_cbor(bytes, true, false);
}

}  // namespace bazarish
