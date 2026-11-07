// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <istream>
#include <string_view>

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

}  // namespace bazarish
