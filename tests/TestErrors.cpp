// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    // String mapping round trip for every code.
    const ErrorCode codes[] = {
        ErrorCode::eQuotaExceeded,
        ErrorCode::eStorageFull,
        ErrorCode::eRecipientServerUnreachable,
        ErrorCode::eDeliveryTimeout,
        ErrorCode::eAttemptUnknown,
        ErrorCode::eDeliveryRejected,
        ErrorCode::eContactRequestTooLarge,
        ErrorCode::eContactRateLimited,
        ErrorCode::eAliasTaken,
        ErrorCode::eAliasUnknown,
        ErrorCode::eClientUnregistered,
        ErrorCode::eI2pUnavailable,
    };
    for (const ErrorCode code : codes) {
        const std::optional<ErrorCode> back = errorCodeFromString(toString(code));
        CHECK(back.has_value());
        CHECK(back.value() == code);
    }
    CHECK(toString(ErrorCode::eQuotaExceeded) == "QUOTA_EXCEEDED");
    CHECK(!errorCodeFromString("NO_SUCH_CODE").has_value());

    // Envelope round trip with details.
    const nlohmann::json details = {{"limit", 10485760}, {"size", 12582912}};
    const nlohmann::json envelope
        = makeErrorEnvelope(ErrorCode::eQuotaExceeded, "blob too large", details);
    const std::optional<ParsedError> parsed = parseErrorEnvelope(envelope);
    CHECK(parsed.has_value());
    CHECK(parsed->code == ErrorCode::eQuotaExceeded);
    CHECK(parsed->message == "blob too large");
    CHECK(parsed->details == details);

    // Envelope without details.
    const nlohmann::json bare = makeErrorEnvelope(ErrorCode::eAttemptUnknown, "expired");
    CHECK(!bare.at("error").contains("details"));
    const std::optional<ParsedError> bareParsed = parseErrorEnvelope(bare);
    CHECK(bareParsed.has_value());
    CHECK(bareParsed->code == ErrorCode::eAttemptUnknown);

    // Non-error documents and unknown codes are not coerced.
    CHECK(!parseErrorEnvelope(nlohmann::json{{"ok", true}}).has_value());
    CHECK(!parseErrorEnvelope(nlohmann::json::array()).has_value());
    const nlohmann::json unknownCode = {{"error", {{"code", "FUTURE_CODE"}, {"message", "?"}}}};
    CHECK(!parseErrorEnvelope(unknownCode).has_value());

    return 0;
}
