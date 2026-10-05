// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>

namespace bazarish::client {

inline constexpr const char* kAuthorshipField = "auth";

// The keys an author signs with, as SubjectPublicKeyInfo DER.
struct IdentityKeys {
    Bytes classicalDer;
    Bytes pqDer;

    bool empty() const { return classicalDer.empty() || pqDer.empty(); }
};

inline constexpr std::size_t kAuthorshipBytes = 5120;
inline constexpr std::size_t kAuthorshipWithKeysBytes = 8192;

void signAuthorship(nlohmann::json& content, const Identity& identity, bool withKeys);

IdentityKeys keysIn(const nlohmann::json& content);

// The fingerprint whose keys signed this content, taken as received (block included).
std::string authorOf(const nlohmann::json& content, const IdentityKeys& known = {});

}  // namespace bazarish::client
