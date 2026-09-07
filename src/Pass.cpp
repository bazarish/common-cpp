// Bazarish project (c) 2026
#include "bazarish/Pass.hpp"

#include "bazarish/Crypto.hpp"

#include <stdexcept>

namespace bazarish {

Bytes deliveryPass(const Bytes& deliverySecret, const std::string& peerFingerprint)
{
    if (deliverySecret.size() != kDeliverySecretSize) {
        throw std::invalid_argument("delivery secret has wrong size");
    }
    if (peerFingerprint.empty()) {
        throw std::invalid_argument("a delivery pass needs a correspondent");
    }
    Bytes material = deliverySecret;
    material.insert(material.end(), peerFingerprint.begin(), peerFingerprint.end());
    return sha256(material);
}

Bytes deliveryPassHandle(const Bytes& pass)
{
    if (pass.size() != kDeliveryPassSize) {
        throw std::invalid_argument("delivery pass has wrong size");
    }
    return sha256(pass);
}

}  // namespace bazarish
