// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include <array>
#include <stdexcept>
#include <utility>

namespace {

// Sized to what is in it. Declared wider, the spare slots were value-initialised
// to {ErrorCode(0), ""} - so errorCodeFromString("") matched one of them and
// answered QUOTA_EXCEEDED.
constexpr std::array<std::pair<bazarish::ErrorCode, std::string_view>, 13> kErrorNames = {{
    {bazarish::ErrorCode::eQuotaExceeded, "QUOTA_EXCEEDED"},
    {bazarish::ErrorCode::eStorageFull, "STORAGE_FULL"},
    {bazarish::ErrorCode::eRecipientServerUnreachable, "RECIPIENT_SERVER_UNREACHABLE"},
    {bazarish::ErrorCode::eDeliveryRejected, "DELIVERY_REJECTED"},
    {bazarish::ErrorCode::eContactRequestTooLarge, "CONTACT_REQUEST_TOO_LARGE"},
    {bazarish::ErrorCode::eContactRateLimited, "CONTACT_RATE_LIMITED"},
    {bazarish::ErrorCode::eMessageTooLarge, "MESSAGE_TOO_LARGE"},
    {bazarish::ErrorCode::eAliasTaken, "ALIAS_TAKEN"},
    {bazarish::ErrorCode::eAliasUnknown, "ALIAS_UNKNOWN"},
    {bazarish::ErrorCode::eClientUnregistered, "CLIENT_UNREGISTERED"},
    {bazarish::ErrorCode::eSessionInvalid, "SESSION_INVALID"},
    {bazarish::ErrorCode::eI2pUnavailable, "I2P_UNAVAILABLE"},
    {bazarish::ErrorCode::eAccountPendingApproval, "ACCOUNT_PENDING_APPROVAL"},
}};

// What each fault reads as on a screen, kept beside the wire names so the two
// are edited together. A code with no sentence here throws, the same way an
// unmapped name does, rather than reaching a person as SCREAMING_SNAKE_CASE.
constexpr std::array<std::pair<bazarish::ErrorCode, std::string_view>, 13> kErrorTexts = {{
    {bazarish::ErrorCode::eQuotaExceeded, "There is no room left for this on the server."},
    {bazarish::ErrorCode::eStorageFull, "The server has run out of storage."},
    {bazarish::ErrorCode::eRecipientServerUnreachable, "Their server did not answer."},
    {bazarish::ErrorCode::eDeliveryRejected, "Their server refused to take this."},
    {bazarish::ErrorCode::eContactRequestTooLarge, "The contact request is too long."},
    {bazarish::ErrorCode::eContactRateLimited,
        "Too many contact requests at once. Wait a little and try again."},
    {bazarish::ErrorCode::eMessageTooLarge, "The message is too large to send."},
    {bazarish::ErrorCode::eAliasTaken, "That alias is already held by somebody else."},
    {bazarish::ErrorCode::eAliasUnknown,
        "Nobody answers to that alias. Either it is not registered, or its owner has not "
        "pointed it at an identity yet."},
    {bazarish::ErrorCode::eClientUnregistered, "This account is not registered on the server."},
    {bazarish::ErrorCode::eSessionInvalid,
        "The session with the server has lapsed; it will be opened again."},
    {bazarish::ErrorCode::eI2pUnavailable, "I2P is not ready yet."},
    {bazarish::ErrorCode::eAccountPendingApproval,
        "This account is waiting for the server's operator to let it in."},
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

std::string_view readable(const ErrorCode code)
{
    for (const auto& [knownCode, text] : kErrorTexts) {
        if (knownCode == code) {
            return text;
        }
    }
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
