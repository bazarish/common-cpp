// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

namespace bazarish {

// Typed error codes. Codes are append-only and never reused; the wire form
// is the SCREAMING_SNAKE_CASE string, not the enum value.
enum class ErrorCode {
    eQuotaExceeded,
    eStorageFull,
    eRecipientServerUnreachable,
    eDeliveryRejected,
    eContactRequestTooLarge,
    eContactRateLimited,
    eMessageTooLarge,
    eAliasTaken,
    eAliasUnknown,
    eClientUnregistered,
    // The session a request authenticated with is gone, lapsed or out of step.
    // Distinct from a rejected identity: the client answers it by opening a new
    // session, and must never treat it as a reason to retry the same way.
    eSessionInvalid,
    eI2pUnavailable,
    eAccountPendingApproval,
};

std::string_view toString(ErrorCode code);
std::optional<ErrorCode> errorCodeFromString(std::string_view text);

// The standard error envelope:
// { "error": { "code": "...", "message": "...", "details": {...} } }
nlohmann::json makeErrorEnvelope(
    ErrorCode code, const std::string& message, const nlohmann::json& details = nullptr);

struct ParsedError {
    ErrorCode code;
    std::string message;
    nlohmann::json details;
};

// Returns nullopt when the document is not an error envelope (including
// envelopes with unknown codes - unknown codes from newer peers must not
// be silently coerced into known ones).
std::optional<ParsedError> parseErrorEnvelope(const nlohmann::json& document);

}  // namespace bazarish
