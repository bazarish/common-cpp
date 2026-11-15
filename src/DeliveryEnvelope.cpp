// Bazarish project (c) 2026
#include "bazarish/DeliveryEnvelope.hpp"

#include "bazarish/Hybrid.hpp"
#include "bazarish/JsonRead.hpp"

#include <nlohmann/json.hpp>

namespace bazarish {

Bytes sealDeliveryEnvelope(const DeliveryEnvelope& envelope, const Key& recipientSealingKey)
{
    nlohmann::json inner = {
        {"class", envelope.deliveryClass},
        {"mailbox", envelope.mailbox},
        {"deliveryId", envelope.deliveryId},
    };
    if (envelope.pass.has_value()) {
        inner["pass"] = toBase64(*envelope.pass);
    }
    const std::string text = inner.dump();
    return hybrid::seal(Bytes(text.begin(), text.end()), recipientSealingKey, {});
}

DeliveryEnvelope openDeliveryEnvelope(const Bytes& sealed, const Key& sealingKey)
{
    const SecretJson held(parseJson(hybrid::unseal(sealed, sealingKey).bytes()));
    const nlohmann::json& inner = held.value;
    DeliveryEnvelope envelope;
    envelope.deliveryClass = inner.at("class").get<std::string>();
    envelope.mailbox = inner.at("mailbox").get<std::string>();
    envelope.deliveryId = inner.at("deliveryId").get<std::string>();
    if (inner.contains("pass")) {
        envelope.pass = fromBase64(inner.at("pass").get<std::string>());
    }
    return envelope;
}

}  // namespace bazarish
