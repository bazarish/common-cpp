// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

namespace bazarish::client {

inline constexpr const char* kAuthorshipField = "auth";

// SPKI DER.
struct IdentityKeys {
    Bytes classicalDer;
    Bytes pqDer;

    bool empty() const { return classicalDer.empty() || pqDer.empty(); }
};

void signAuthorship(nlohmann::json& content, const Identity& identity, bool withKeys);

IdentityKeys keysIn(const nlohmann::json& content);

std::string authorOf(const nlohmann::json& content, const IdentityKeys& known = {});

}  // namespace bazarish::client
