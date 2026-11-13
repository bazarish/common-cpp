// Bazarish project (c) 2026
#include "Authorship.hpp"

#include <optional>
#include <stdexcept>

namespace bazarish::client {

namespace {

constexpr char kDeviceField[] = "d";
constexpr char kClassicalField[] = "c";
constexpr char kPqField[] = "p";
constexpr char kCertField[] = "cert";

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

const nlohmann::json& blockOf(const nlohmann::json& content)
{
    if (!content.contains(kAuthorshipField) || !content.at(kAuthorshipField).is_object()) {
        throw std::runtime_error("this letter names no author");
    }
    return content.at(kAuthorshipField);
}

}  // namespace

void signAuthorship(nlohmann::json& content, const DeviceCredential& device, const bool withCert)
{
    const Bytes signedBytes = encodedContent(content);
    nlohmann::json block = {
        {kDeviceField, device.device()},
        {kClassicalField, asBytes(sign(device.signing().classical(), signedBytes))},
        {kPqField, asBytes(sign(device.signing().pq(), signedBytes))},
    };
    if (withCert) {
        block[kCertField] = asBytes(device.certDer());
    }
    content[kAuthorshipField] = std::move(block);
}

std::string authorDevice(const nlohmann::json& content)
{
    const std::string device = blockOf(content).at(kDeviceField).get<std::string>();
    requireDeviceId(device);
    return device;
}

Bytes carriedCert(const nlohmann::json& content)
{
    const nlohmann::json& block = blockOf(content);
    return block.contains(kCertField) ? fromBytes(block.at(kCertField)) : Bytes{};
}

Author authorOf(const nlohmann::json& content, const DeviceBook& known)
{
    const nlohmann::json& block = blockOf(content);
    const std::string device = authorDevice(content);
    const Bytes carried = carriedCert(content);
    std::optional<DeviceCertificate> cert;
    if (!carried.empty()) {
        cert = DeviceCertificate::verify(carried);
        if (!known.empty() && cert->root != known.root()) {
            throw std::runtime_error("the carried certificate is of another account");
        }
        if (known.revoked(cert->device)) {
            throw std::runtime_error("the author's device was revoked");
        }
    } else {
        cert = known.active(device);
    }
    if (!cert.has_value()) {
        throw std::runtime_error("the author's device is not one this account holds");
    }
    if (cert->device != device) {
        throw std::runtime_error("the carried certificate is of another device");
    }

    nlohmann::json signedPart = content;
    signedPart.erase(kAuthorshipField);
    cert->requireSigned(
        encodedContent(signedPart), fromBytes(block.at(kClassicalField)), fromBytes(block.at(kPqField)));
    return Author{cert->root, cert->device};
}

}  // namespace bazarish::client
