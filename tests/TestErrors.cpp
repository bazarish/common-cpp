// Bazarish project (c) 2026
#include "bazarish/Errors.hpp"

#include "TestUtil.hpp"

using namespace bazarish;

int main()
{
    const ErrorCode codes[] = {
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
        ErrorCode::eAccountPendingApproval,
        ErrorCode::eAccountUnknown,
        ErrorCode::eUpstreamUnavailable,
        ErrorCode::eRequestFailed,
    };
    for (const ErrorCode code : codes) {
        const std::optional<ErrorCode> back = errorCodeFromString(toString(code));
        CHECK(back.has_value());
        CHECK(back.value() == code);
    }
    CHECK(toString(ErrorCode::eStorageFull) == "STORAGE_FULL");
    CHECK(!errorCodeFromString("NO_SUCH_CODE").has_value());

    for (const ErrorCode code : codes) {
        const std::string_view text = readable(code);
        CHECK(!text.empty());
        CHECK(text != toString(code));
        CHECK(text.find('_') == std::string_view::npos);
        CHECK(text.back() == '.');
    }
    CHECK(readable(ErrorCode::eAliasUnknown).find("Nobody answers") == 0);

    const nlohmann::json envelope
        = makeErrorEnvelope(ErrorCode::eMessageTooLarge, "blob too large");
    const std::optional<ParsedError> parsed = parseErrorEnvelope(envelope);
    CHECK(parsed.has_value());
    CHECK(parsed->code == ErrorCode::eMessageTooLarge);
    CHECK(parsed->message == "blob too large");
    CHECK(envelope.at("error").size() == 2);

    CHECK(!parseErrorEnvelope(nlohmann::json{{"ok", true}}).has_value());
    CHECK(!parseErrorEnvelope(nlohmann::json::array()).has_value());
    const nlohmann::json unknownCode = {{"error", {{"code", "FUTURE_CODE"}, {"message", "?"}}}};
    CHECK(!parseErrorEnvelope(unknownCode).has_value());

    return 0;
}
