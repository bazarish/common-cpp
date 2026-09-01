// Bazarish project (c) 2026
#include "Authorship.hpp"

#include <bazarish/Bytes.hpp>

#include <stdexcept>

namespace bazarish::client {

namespace {

// The content as it travels: CBOR, the same encoding the message itself is
// carried in, so what is signed is byte-for-byte what is sent.
Bytes encodedContent(const nlohmann::json& content)
{
    return nlohmann::json::to_cbor(content);
}

}  // namespace

void signAuthorship(nlohmann::json& content, const Identity& identity)
{
    const Bytes signedBytes = encodedContent(content);
    const nlohmann::json keys = {
        {"c", toBase64(identity.classical().publicDer())},
        {"pq", toBase64(identity.pq().publicDer())},
    };
    const std::string keysText = keys.dump();
    content[kAuthorshipField] = {
        {"k", toBase64(Bytes(keysText.begin(), keysText.end()))},
        {"c", toBase64(sign(identity.classical(), signedBytes))},
        {"p", toBase64(sign(identity.pq(), signedBytes))},
    };
}

// Whose signature this envelope carries. Throws when it carries none, when a key
// is not of the two kinds this protocol signs with, or when either signature
// fails - a caller that cannot name the author must not show the message.
std::string authorOf(const nlohmann::json& content)
{
    const nlohmann::json& block = content.at(kAuthorshipField);
    nlohmann::json signedPart = content;
    signedPart.erase(kAuthorshipField);
    const Bytes signedBytes = encodedContent(signedPart);

    const Bytes keysRaw = fromBase64(block.at("k").get<std::string>());
    const nlohmann::json keys = nlohmann::json::parse(keysRaw.begin(), keysRaw.end());
    const Bytes classicalDer = fromBase64(keys.at("c").get<std::string>());
    const Bytes pqDer = fromBase64(keys.at("pq").get<std::string>());
    const Key classical = Key::fromPublicDer(classicalDer);
    const Key pq = Key::fromPublicDer(pqDer);
    // Key-type checks close the downgrade hole, exactly as the request auth does.
    if (!classical.isA("EC")) {
        throw std::runtime_error("author's classical key is not EC");
    }
    if (!pq.isA("ML-DSA-65")) {
        throw std::runtime_error("author's pq key is not ML-DSA-65");
    }
    if (!verify(classical, signedBytes, fromBase64(block.at("c").get<std::string>()))) {
        throw std::runtime_error("the author's classical signature does not verify");
    }
    if (!verify(pq, signedBytes, fromBase64(block.at("p").get<std::string>()))) {
        throw std::runtime_error("the author's post-quantum signature does not verify");
    }
    return hybridFingerprint(classicalDer, pqDer);
}

}  // namespace bazarish::client
