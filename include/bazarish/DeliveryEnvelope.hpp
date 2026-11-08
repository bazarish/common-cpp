// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <optional>
#include <string>

namespace bazarish {

// What a delivery tells the server that holds the mailbox, sealed to that server's key.
struct DeliveryEnvelope {
    std::string deliveryClass;
    std::string mailbox;
    std::string deliveryId;
    // A content delivery carries the mailbox's pass; a contact request carries none.
    std::optional<Bytes> pass;
};

Bytes sealDeliveryEnvelope(const DeliveryEnvelope& envelope, const Key& recipientSealingKey);
// Throws when it does not open or names a field wrongly.
DeliveryEnvelope openDeliveryEnvelope(const Bytes& sealed, const Key& sealingKey);

}  // namespace bazarish
