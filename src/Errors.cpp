// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include <array>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::array<std::pair<bazarish::ErrorCode, std::string_view>, 14> kErrorNames = {{
    {bazarish::ErrorCode::eQuotaExceeded, "QUOTA_EXCEEDED"},
    {bazarish::ErrorCode::eStorageFull, "STORAGE_FULL"},
    {bazarish::ErrorCode::eRecipientServerUnreachable, "RECIPIENT_SERVER_UNREACHABLE"},
    {bazarish::ErrorCode::eDeliveryTimeout, "DELIVERY_TIMEOUT"},
    {bazarish::ErrorCode::eAttemptUnknown, "ATTEMPT_UNKNOWN"},
    {bazarish::ErrorCode::eDeliveryRejected, "DELIVERY_REJECTED"},
    {bazarish::ErrorCode::eContactRequestTooLarge, "CONTACT_REQUEST_TOO_LARGE"},
    {bazarish::ErrorCode::eMessageTooLarge, "MESSAGE_TOO_LARGE"},
    {bazarish::ErrorCode::eAliasTaken, "ALIAS_TAKEN"},
    {bazarish::ErrorCode::eAliasUnknown, "ALIAS_UNKNOWN"},
    {bazarish::ErrorCode::eClientUnregistered, "CLIENT_UNREGISTERED"},
    {bazarish::ErrorCode::eSessionInvalid, "SESSION_INVALID"},
    {bazarish::ErrorCode::eI2pUnavailable, "I2P_UNAVAILABLE"},
    {bazarish::ErrorCode::eAccountPendingApproval, "ACCOUNT_PENDING_APPROVAL"},
}};

}  // namespace

namespace bazarish {

std::string_view toString(const ErrorCode code)
{
    for (const auto& [knownCode, name] : kErrorNames) {
        if (knownCode == code) {
            return name;
        }
    }
    // All enumerators are present in the table; reaching here is a bug.
    throw std::logic_error("unmapped error code");
}

std::optional<ErrorCode> errorCodeFromString(const std::string_view text)
{
    for (const auto& [code, name] : kErrorNames) {
        if (name == text) {
            return code;
        }
    }
    return std::nullopt;
}

nlohmann::json makeErrorEnvelope(
    const ErrorCode code, const std::string& message, const nlohmann::json& details)
{
    nlohmann::json error = {
        {"code", toString(code)},
        {"message", message},
    };
    if (!details.is_null()) {
        error["details"] = details;
    }
    return nlohmann::json{{"error", std::move(error)}};
}

std::optional<ParsedError> parseErrorEnvelope(const nlohmann::json& document)
{
    if (!document.is_object() || !document.contains("error")) {
        return std::nullopt;
    }
    const nlohmann::json& error = document.at("error");
    if (!error.is_object() || !error.contains("code") || !error.at("code").is_string()) {
        return std::nullopt;
    }
    const std::optional<ErrorCode> code
        = errorCodeFromString(error.at("code").get<std::string>());
    if (!code.has_value()) {
        return std::nullopt;
    }
    ParsedError parsed;
    parsed.code = code.value();
    if (error.contains("message") && error.at("message").is_string()) {
        parsed.message = error.at("message").get<std::string>();
    }
    if (error.contains("details")) {
        parsed.details = error.at("details");
    }
    return parsed;
}

}  // namespace bazarish
