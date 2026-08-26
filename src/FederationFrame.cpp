// Bazarish project (c) 2026
#include <bazarish/FederationFrame.hpp>

#include <nlohmann/json.hpp>

namespace bazarish {

std::string buildFederationDeliverHeader(const Bytes& sealed, const std::size_t payloadLen)
{
    const nlohmann::json header = {
        {"op", "deliver"},
        {"sealed", toBase64(sealed)},
        {"len", payloadLen},
    };
    return header.dump();
}

FederationDeliverResult parseFederationDeliverReply(const std::string& line)
{
    const nlohmann::json reply = nlohmann::json::parse(line);
    FederationDeliverResult result;
    result.delivered = reply.at("delivered").get<bool>();
    if (reply.contains("errorCode")) {
        result.errorCode = reply.at("errorCode").get<std::string>();
    }
    if (reply.contains("errorMessage")) {
        result.errorMessage = reply.at("errorMessage").get<std::string>();
    }
    if (reply.contains("deliveryId")) {
        result.deliveryId = reply.at("deliveryId").get<std::string>();
    }
    if (reply.contains("signerPub")) {
        result.signerPublicDer = fromBase64(reply.at("signerPub").get<std::string>());
    }
    if (reply.contains("sig")) {
        result.signature = fromBase64(reply.at("sig").get<std::string>());
    }
    return result;
}

std::string buildFederationFetchHeader(const std::string& op, const Bytes& sealed)
{
    const nlohmann::json header = {{"op", op}, {"sealed", toBase64(sealed)}};
    return header.dump();
}

FederationFetchResult parseFederationFetchReply(const std::string& line)
{
    const nlohmann::json reply = nlohmann::json::parse(line);
    FederationFetchResult result;
    result.ok = reply.at("ok").get<bool>();
    if (reply.contains("sealed")) {
        result.sealed = fromBase64(reply.at("sealed").get<std::string>());
    }
    if (reply.contains("errorCode")) {
        result.errorCode = reply.at("errorCode").get<std::string>();
    }
    if (reply.contains("errorMessage")) {
        result.errorMessage = reply.at("errorMessage").get<std::string>();
    }
    return result;
}

}  // namespace bazarish
