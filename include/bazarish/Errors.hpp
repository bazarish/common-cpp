// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace bazarish {

enum class ErrorCode {
    eStorageFull,
    eRecipientServerUnreachable,
    eDeliveryRejected,
    eContactRequestTooLarge,
    eContactRateLimited,
    eMessageTooLarge,
    eAliasTaken,
    eAliasUnknown,
    eClientUnregistered,
    eSessionInvalid,
    eAccountPendingApproval,
};

std::string_view toString(ErrorCode code);
std::optional<ErrorCode> errorCodeFromString(std::string_view text);

std::string_view readable(ErrorCode code);

nlohmann::json makeErrorEnvelope(
    ErrorCode code, const std::string& message, const nlohmann::json& details = nullptr);

struct ParsedError {
    ErrorCode code;
    std::string message;
    nlohmann::json details;
};

std::optional<ParsedError> parseErrorEnvelope(const nlohmann::json& document);

}  // namespace bazarish
