// Bazarish project (c) 2026
#include "SignedDocument.hpp"

#include "bazarish/Certificates.hpp"

#include <stdexcept>

namespace bazarish::document {

hybrid::VerifiedJson verifyTagged(const Bytes& der, const char* const type)
{
    hybrid::VerifiedJson verified = hybrid::verifyJson(der);
    if (verified.body.value("t", std::string()) != type) {
        throw std::runtime_error(std::string("wrong document type: expected ") + type);
    }
    if (verified.body.at("v").get<int>() != kCertificateFormatVersion) {
        throw std::runtime_error("unsupported certificate format version");
    }
    return verified;
}

void requireSigner(const hybrid::VerifiedJson& verified, const std::string& expectedFingerprint)
{
    if (verified.identityFingerprint != expectedFingerprint) {
        throw std::runtime_error("certificate signer does not match the claimed identity");
    }
}

void requireExactFields(const nlohmann::json& body, const std::set<std::string_view>& fields)
{
    if (!body.is_object() || body.size() != fields.size()) {
        throw std::runtime_error("a document must carry exactly the fields of its type");
    }
    for (const auto& [name, value] : body.items()) {
        if (!fields.contains(name)) {
            throw std::runtime_error("a document carries a field its type does not have: " + name);
        }
        if (value.is_string() && value.get_ref<const std::string&>().empty()) {
            throw std::runtime_error("a document carries an empty field: " + name);
        }
    }
}

}  // namespace bazarish::document
