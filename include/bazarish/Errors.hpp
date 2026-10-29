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
    eAccountUnknown,
    eUpstreamUnavailable,
    eRequestFailed,
};

std::string_view toString(ErrorCode code);
std::optional<ErrorCode> errorCodeFromString(std::string_view text);

std::string_view readable(ErrorCode code);

nlohmann::json makeErrorEnvelope(ErrorCode code, const std::string& message);

struct ParsedError {
    ErrorCode code;
    std::string message;
};

std::optional<ParsedError> parseErrorEnvelope(const nlohmann::json& document);

}  // namespace bazarish
