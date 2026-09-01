// Bazarish project (c) 2026
#include "Authorship.hpp"

#include <stdexcept>

namespace bazarish::client {

namespace {

// The content as it travels: CBOR, the same encoding the message itself is
// carried in, so what is signed is byte-for-byte what is sent.
Bytes encodedContent(const nlohmann::json& content)
{
    return nlohmann::json::to_cbor(content);
}

// Keys and signatures ride as CBOR byte strings. Base64 inside a CBOR document
// would be a third bigger for nothing, and this block is the largest thing on
// most messages.
nlohmann::json asBytes(const Bytes& data)
{
    return nlohmann::json::binary(data);
}

Bytes fromBytes(const nlohmann::json& value)
{
    if (!value.is_binary()) {
        throw std::runtime_error("the authorship block is malformed");
    }
    const nlohmann::json::binary_t& binary = value.get_binary();
    return Bytes(binary.begin(), binary.end());
}

}  // namespace

void signAuthorship(nlohmann::json& content, const Identity& identity, const bool withKeys)
{
    const Bytes signedBytes = encodedContent(content);
    nlohmann::json block = {
        {"c", asBytes(sign(identity.classical(), signedBytes))},
        {"p", asBytes(sign(identity.pq(), signedBytes))},
    };
    if (withKeys) {
        block["kc"] = asBytes(identity.classical().publicDer());
        block["kp"] = asBytes(identity.pq().publicDer());
    }
    content[kAuthorshipField] = std::move(block);
}

IdentityKeys keysIn(const nlohmann::json& content)
{
    if (!content.contains(kAuthorshipField)) {
        return {};
    }
    const nlohmann::json& block = content.at(kAuthorshipField);
    if (!block.contains("kc") || !block.contains("kp")) {
        return {};
    }
    return IdentityKeys{fromBytes(block.at("kc")), fromBytes(block.at("kp"))};
}

std::string authorOf(const nlohmann::json& content, const IdentityKeys& known)
{
    const nlohmann::json& block = content.at(kAuthorshipField);
    const IdentityKeys carried = keysIn(content);
    const IdentityKeys& keys = carried.empty() ? known : carried;
    if (keys.empty()) {
        throw std::runtime_error("no keys to check this author against");
    }

    nlohmann::json signedPart = content;
    signedPart.erase(kAuthorshipField);
    const Bytes signedBytes = encodedContent(signedPart);

    const Key classical = Key::fromPublicDer(keys.classicalDer);
    const Key pq = Key::fromPublicDer(keys.pqDer);
    // Key-type checks close the downgrade hole, exactly as the request auth does.
    if (!classical.isA("EC")) {
        throw std::runtime_error("author's classical key is not EC");
    }
    if (!pq.isA("ML-DSA-65")) {
        throw std::runtime_error("author's pq key is not ML-DSA-65");
    }
    if (!verify(classical, signedBytes, fromBytes(block.at("c")))) {
        throw std::runtime_error("the author's classical signature does not verify");
    }
    if (!verify(pq, signedBytes, fromBytes(block.at("p")))) {
        throw std::runtime_error("the author's post-quantum signature does not verify");
    }
    return hybridFingerprint(keys.classicalDer, keys.pqDer);
}

}  // namespace bazarish::client
