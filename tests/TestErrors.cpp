// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    // String mapping round trip for every code.
    const ErrorCode codes[] = {
        ErrorCode::kQuotaExceeded,
        ErrorCode::kStorageFull,
        ErrorCode::kSubscriptionExpired,
        ErrorCode::kSubscriptionTermTooLong,
        ErrorCode::kRecipientServerUnreachable,
        ErrorCode::kDeliveryTimeout,
        ErrorCode::kAttemptUnknown,
        ErrorCode::kDeliveryRejected,
        ErrorCode::kContactRequestTooLarge,
        ErrorCode::kAliasTaken,
        ErrorCode::kAliasUnknown,
        ErrorCode::kClientUnregistered,
        ErrorCode::kSamUnavailable,
    };
    for (const ErrorCode code : codes) {
        const std::optional<ErrorCode> back = errorCodeFromString(toString(code));
        CHECK(back.has_value());
        CHECK(back.value() == code);
    }
    CHECK(toString(ErrorCode::kQuotaExceeded) == "QUOTA_EXCEEDED");
    CHECK(!errorCodeFromString("NO_SUCH_CODE").has_value());

    // Envelope round trip with details.
    const nlohmann::json details = {{"limit", 10485760}, {"size", 12582912}};
    const nlohmann::json envelope
        = makeErrorEnvelope(ErrorCode::kQuotaExceeded, "blob too large", details);
    const std::optional<ParsedError> parsed = parseErrorEnvelope(envelope);
    CHECK(parsed.has_value());
    CHECK(parsed->code == ErrorCode::kQuotaExceeded);
    CHECK(parsed->message == "blob too large");
    CHECK(parsed->details == details);

    // Envelope without details.
    const nlohmann::json bare = makeErrorEnvelope(ErrorCode::kAttemptUnknown, "expired");
    CHECK(!bare.at("error").contains("details"));
    const std::optional<ParsedError> bareParsed = parseErrorEnvelope(bare);
    CHECK(bareParsed.has_value());
    CHECK(bareParsed->code == ErrorCode::kAttemptUnknown);

    // Non-error documents and unknown codes are not coerced.
    CHECK(!parseErrorEnvelope(nlohmann::json{{"ok", true}}).has_value());
    CHECK(!parseErrorEnvelope(nlohmann::json::array()).has_value());
    const nlohmann::json unknownCode = {{"error", {{"code", "FUTURE_CODE"}, {"message", "?"}}}};
    CHECK(!parseErrorEnvelope(unknownCode).has_value());

    return 0;
}
