// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <istream>
#include <string_view>
#include <vector>

namespace bazarish {

// The protocol's deepest document: body[] > device.message{} > message{} > keyboard[] > row[] > button{}.
inline constexpr std::size_t kMaxJsonDepth = 6;

nlohmann::json parseJson(std::string_view text);

nlohmann::json parseJson(const Bytes& bytes);

nlohmann::json parseJson(std::istream& in);

nlohmann::json parseJsonWithComments(std::string_view text);

nlohmann::json parseJsonOrDiscarded(std::string_view text);

nlohmann::json parseJsonOrDiscarded(const Bytes& bytes);

nlohmann::json parseCbor(const Bytes& bytes);

nlohmann::json parseCbor(std::string_view bytes);

nlohmann::json parseCborOrDiscarded(const Bytes& bytes);

// Overwrites every string and byte string value in `value` in place.
void wipeJson(nlohmann::json& value);

// A document holding secrets, wiped when it goes out of scope.
struct SecretJson {
    nlohmann::json value;

    SecretJson() = default;
    explicit SecretJson(nlohmann::json held);
    SecretJson(const SecretJson&) = delete;
    SecretJson& operator=(const SecretJson&) = delete;
    ~SecretJson();
};

// Wipes every document of a list it does not own when it goes out of scope.
class JsonWipe {
public:
    explicit JsonWipe(std::vector<nlohmann::json>& held);
    JsonWipe(const JsonWipe&) = delete;
    JsonWipe& operator=(const JsonWipe&) = delete;
    ~JsonWipe();

private:
    std::vector<nlohmann::json>& held_;
};

}  // namespace bazarish
