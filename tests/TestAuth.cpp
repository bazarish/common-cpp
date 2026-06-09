// Bazarish project (c) 2026
#include "bazarish/Auth.hpp"

#include "TestUtil.hpp"

#include <stdexcept>

using namespace bazarish;

namespace {

constexpr std::int64_t kNow = 1780000000;

}  // namespace

int main()
{
    const Identity identity = Identity::generate();
    const Bytes body = {'{', '}'};

    // Round trip: the verifier recovers the caller's fingerprint.
    const auth::Headers headers
        = auth::signRequest(identity, kNow, "POST", "/v1/messaging/tokens", body);
    CHECK(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/tokens", body)
        == identity.fingerprint());

    // Freshness window: skew inside the window passes, outside fails.
    CHECK(auth::verifyRequest(headers, kNow + auth::kAuthFreshnessWindowSeconds, "POST",
              "/v1/messaging/tokens", body)
        == identity.fingerprint());
    CHECK_THROWS(auth::verifyRequest(headers, kNow + auth::kAuthFreshnessWindowSeconds + 1,
        "POST", "/v1/messaging/tokens", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow - auth::kAuthFreshnessWindowSeconds - 1,
        "POST", "/v1/messaging/tokens", body));

    // Any mismatch of the signed material must fail.
    CHECK_THROWS(auth::verifyRequest(headers, kNow, "DELETE", "/v1/messaging/tokens", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/clients", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/tokens",
        Bytes{'{', ' ', '}'}));

    // Missing or corrupted headers must fail.
    for (const char* const name : {auth::kHeaderKeys, auth::kHeaderTimestamp,
             auth::kHeaderSignatureClassical, auth::kHeaderSignaturePq}) {
        auth::Headers broken = headers;
        broken.erase(name);
        CHECK_THROWS(auth::verifyRequest(broken, kNow, "POST", "/v1/messaging/tokens", body));
    }
    {
        auth::Headers broken = headers;
        std::string& sig = broken[auth::kHeaderSignaturePq];
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        CHECK_THROWS(auth::verifyRequest(broken, kNow, "POST", "/v1/messaging/tokens", body));
    }

    // A different identity signing the same request yields a different UID.
    const Identity other = Identity::generate();
    const auth::Headers otherHeaders
        = auth::signRequest(other, kNow, "POST", "/v1/messaging/tokens", body);
    CHECK(auth::verifyRequest(otherHeaders, kNow, "POST", "/v1/messaging/tokens", body)
        != identity.fingerprint());

    return 0;
}
