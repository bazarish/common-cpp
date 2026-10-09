// Bazarish project (c) 2026
#include "Authorship.hpp"

#include <stdexcept>

namespace bazarish::client {

namespace {

Bytes encodedContent(const nlohmann::json& content)
{
    return nlohmann::json::to_cbor(content);
}

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
    if (!classical.isA(kClassicalSigningAlgorithm)) {
        throw std::runtime_error("author's classical key is not Ed25519");
    }
    if (!pq.isA(kPqSigningAlgorithm)) {
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
