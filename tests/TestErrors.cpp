// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    const ErrorCode codes[] = {
        ErrorCode::eQuotaExceeded,
        ErrorCode::eStorageFull,
        ErrorCode::eRecipientServerUnreachable,
        ErrorCode::eDeliveryRejected,
        ErrorCode::eContactRequestTooLarge,
        ErrorCode::eContactRateLimited,
        ErrorCode::eMessageTooLarge,
        ErrorCode::eAliasTaken,
        ErrorCode::eAliasUnknown,
        ErrorCode::eClientUnregistered,
        ErrorCode::eSessionInvalid,
        ErrorCode::eI2pUnavailable,
        ErrorCode::eAccountPendingApproval,
    };
    for (const ErrorCode code : codes) {
        const std::optional<ErrorCode> back = errorCodeFromString(toString(code));
        CHECK(back.has_value());
        CHECK(back.value() == code);
    }
    CHECK(toString(ErrorCode::eQuotaExceeded) == "QUOTA_EXCEEDED");
    CHECK(!errorCodeFromString("NO_SUCH_CODE").has_value());

    for (const ErrorCode code : codes) {
        const std::string_view text = readable(code);
        CHECK(!text.empty());
        CHECK(text != toString(code));
        CHECK(text.find('_') == std::string_view::npos);
        CHECK(text.back() == '.');
    }
    CHECK(readable(ErrorCode::eAliasUnknown).find("Nobody answers") == 0);

    const nlohmann::json details = {{"limit", 10485760}, {"size", 12582912}};
    const nlohmann::json envelope
        = makeErrorEnvelope(ErrorCode::eQuotaExceeded, "blob too large", details);
    const std::optional<ParsedError> parsed = parseErrorEnvelope(envelope);
    CHECK(parsed.has_value());
    CHECK(parsed->code == ErrorCode::eQuotaExceeded);
    CHECK(parsed->message == "blob too large");
    CHECK(parsed->details == details);

    const nlohmann::json bare
        = makeErrorEnvelope(ErrorCode::eClientUnregistered, "register this device first");
    CHECK(!bare.at("error").contains("details"));
    const std::optional<ParsedError> bareParsed = parseErrorEnvelope(bare);
    CHECK(bareParsed.has_value());
    CHECK(bareParsed->code == ErrorCode::eClientUnregistered);

    CHECK(!parseErrorEnvelope(nlohmann::json{{"ok", true}}).has_value());
    CHECK(!parseErrorEnvelope(nlohmann::json::array()).has_value());
    const nlohmann::json unknownCode = {{"error", {{"code", "FUTURE_CODE"}, {"message", "?"}}}};
    CHECK(!parseErrorEnvelope(unknownCode).has_value());

    return 0;
}
