// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <cstddef>
#include <optional>
#include <string>

namespace bazarish {

inline constexpr std::size_t kLinkKeyBytes = 32;

Bytes newLinkKey();

// A link key as it travels in a link: unpadded base64url of exactly kLinkKeyBytes.
std::string linkKeyText(const Bytes& key);
Bytes linkKeyFromText(const std::string& text);

// ChaCha20-Poly1305 under HKDF(secret, label); every message carries its own random nonce.
class KeyedSeal {
public:
    KeyedSeal(const Bytes& secret, const std::string& label);

    Bytes seal(const Bytes& plaintext) const;
    std::optional<Bytes> open(const Bytes& message) const;

private:
    Bytes key_;
};

}  // namespace bazarish
