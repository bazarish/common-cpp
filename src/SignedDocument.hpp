// Bazarish project (c) 2026
#pragma once

#include "bazarish/Hybrid.hpp"

#include <nlohmann/json.hpp>

#include <set>
#include <string>
#include <string_view>

namespace bazarish::document {

hybrid::VerifiedJson verifyTagged(const Bytes& der, const char* type);
void requireSigner(const hybrid::VerifiedJson& verified, const std::string& expectedFingerprint);
void requireExactFields(const nlohmann::json& body, const std::set<std::string_view>& fields);

}  // namespace bazarish::document
