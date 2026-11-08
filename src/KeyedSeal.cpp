// Bazarish project (c) 2026
#include "bazarish/KeyedSeal.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>

namespace bazarish {

Bytes newLinkKey()
{
    return randomBytes(kLinkKeyBytes);
}

std::string linkKeyText(const Bytes& key)
{
    if (key.size() != kLinkKeyBytes) {
        throw std::invalid_argument("a link key is not " + std::to_string(kLinkKeyBytes) + " bytes");
    }
    return toBase64Url(key);
}

Bytes linkKeyFromText(const std::string& text)
{
    Bytes key;
    try {
        key = fromBase64Url(text);
    } catch (const std::exception& error) {
        throw std::invalid_argument(std::string("a link key is not base64url: ") + error.what());
    }
    if (key.size() != kLinkKeyBytes || toBase64Url(key) != text) {
        throw std::invalid_argument("a link key is not " + std::to_string(kLinkKeyBytes)
            + " bytes of unpadded base64url");
    }
    return key;
}

KeyedSeal::KeyedSeal(const Bytes& secret, const std::string& label)
    : key_(hkdfSha256(secret, {}, label, kAeadKeyBytes))
{
}

Bytes KeyedSeal::seal(const Bytes& plaintext) const
{
    Bytes message = randomBytes(kAeadNonceBytes);
    const Bytes sealed = chachaSeal(key_, message, plaintext);
    message.insert(message.end(), sealed.begin(), sealed.end());
    return message;
}

std::optional<Bytes> KeyedSeal::open(const Bytes& message) const
{
    if (message.size() < kAeadNonceBytes + kAeadTagBytes) {
        return std::nullopt;
    }
    const Bytes nonce(message.begin(), message.begin() + kAeadNonceBytes);
    const Bytes sealed(message.begin() + kAeadNonceBytes, message.end());
    return chachaOpen(key_, nonce, sealed);
}

}  // namespace bazarish
