// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include <array>
#include <stdexcept>
#include <utility>

namespace {

constexpr std::array<std::pair<bazarish::ErrorCode, std::string_view>, 13> kErrorNames = {{
    {bazarish::ErrorCode::kQuotaExceeded, "QUOTA_EXCEEDED"},
    {bazarish::ErrorCode::kStorageFull, "STORAGE_FULL"},
    {bazarish::ErrorCode::kSubscriptionExpired, "SUBSCRIPTION_EXPIRED"},
    {bazarish::ErrorCode::kSubscriptionTermTooLong, "SUBSCRIPTION_TERM_TOO_LONG"},
    {bazarish::ErrorCode::kRecipientServerUnreachable, "RECIPIENT_SERVER_UNREACHABLE"},
    {bazarish::ErrorCode::kDeliveryTimeout, "DELIVERY_TIMEOUT"},
    {bazarish::ErrorCode::kAttemptUnknown, "ATTEMPT_UNKNOWN"},
    {bazarish::ErrorCode::kDeliveryRejected, "DELIVERY_REJECTED"},
    {bazarish::ErrorCode::kContactRequestTooLarge, "CONTACT_REQUEST_TOO_LARGE"},
    {bazarish::ErrorCode::kAliasTaken, "ALIAS_TAKEN"},
    {bazarish::ErrorCode::kAliasUnknown, "ALIAS_UNKNOWN"},
    {bazarish::ErrorCode::kClientUnregistered, "CLIENT_UNREGISTERED"},
    {bazarish::ErrorCode::kSamUnavailable, "SAM_UNAVAILABLE"},
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
