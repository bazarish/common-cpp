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

    // Digest-based signing/verification (used so a large streamed body is never
    // held in memory) is interchangeable with the body-based path: the canonical
    // string commits only to hex(sha256(body)).
    {
        const std::string bodyDigest = toHex(sha256(body));
        // Digest-signed headers verify against the actual body...
        const auth::Headers digestHeaders
            = auth::signRequestDigest(identity, kNow, "PUT", "/v1/storage/blob", bodyDigest);
        CHECK(auth::verifyRequest(digestHeaders, kNow, "PUT", "/v1/storage/blob", body)
            == identity.fingerprint());
        // ...and body-signed headers verify against the digest.
        const auth::Headers bodyHeaders
            = auth::signRequest(identity, kNow, "PUT", "/v1/storage/blob", body);
        CHECK(auth::verifyRequestDigest(bodyHeaders, kNow, "PUT", "/v1/storage/blob", bodyDigest)
            == identity.fingerprint());
        // A digest that is not the one signed must fail.
        CHECK_THROWS(auth::verifyRequestDigest(
            bodyHeaders, kNow, "PUT", "/v1/storage/blob", toHex(sha256(Bytes{'x'}))));
    }

    // Replay cache: a verified request is accepted once; a verbatim replay
    // (identical signature) is rejected, while genuinely distinct requests pass.
    {
        auth::ReplayCache cache;
        const auth::Headers first
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK(auth::verifyRequest(first, kNow, "POST", "/v1/messaging/ack", body, cache)
            == identity.fingerprint());
        // The same request bytes again is a replay.
        CHECK_THROWS(auth::verifyRequest(first, kNow, "POST", "/v1/messaging/ack", body, cache));
        // A different request (different path) is not a replay.
        const auth::Headers other
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/clients", body);
        CHECK(auth::verifyRequest(other, kNow, "POST", "/v1/messaging/clients", body, cache)
            == identity.fingerprint());
        // Re-signing the identical request yields a different signature (ECDSA is
        // randomized), so a legitimate resend is accepted, not mistaken for a
        // replay.
        const auth::Headers resigned
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK(auth::verifyRequest(resigned, kNow, "POST", "/v1/messaging/ack", body, cache)
            == identity.fingerprint());
        // Once the timestamp ages out of the window the freshness check rejects
        // the replay regardless of the cache (and the entry is evicted).
        CHECK_THROWS(auth::verifyRequest(first, kNow + auth::kAuthFreshnessWindowSeconds + 1,
            "POST", "/v1/messaging/ack", body, cache));
        // The digest overload shares the same cache behaviour.
        const std::string blobDigest = toHex(sha256(body));
        const auth::Headers blob
            = auth::signRequestDigest(identity, kNow, "PUT", "/v1/storage/blob", blobDigest);
        CHECK(auth::verifyRequestDigest(blob, kNow, "PUT", "/v1/storage/blob", blobDigest, cache)
            == identity.fingerprint());
        CHECK_THROWS(
            auth::verifyRequestDigest(blob, kNow, "PUT", "/v1/storage/blob", blobDigest, cache));
    }

    // Authorize: a signed request from an authorized fingerprint passes; an
    // unauthorized signer or an empty allow-list is rejected; a tampered
    // signature is rejected (it delegates to verifyRequest).
    {
        const auth::Headers signedHeaders
            = auth::signRequest(identity, kNow, "GET", "/healthz", Bytes{});
        CHECK(auth::authorizeRequest(signedHeaders, kNow, "GET", "/healthz", Bytes{},
                  {other.fingerprint(), identity.fingerprint()})
            == identity.fingerprint());
        CHECK_THROWS(auth::authorizeRequest(
            signedHeaders, kNow, "GET", "/healthz", Bytes{}, {other.fingerprint()}));
        CHECK_THROWS(
            auth::authorizeRequest(signedHeaders, kNow, "GET", "/healthz", Bytes{}, {}));
        auth::Headers tampered = signedHeaders;
        std::string& sig = tampered[auth::kHeaderSignatureClassical];
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        CHECK_THROWS(auth::authorizeRequest(
            tampered, kNow, "GET", "/healthz", Bytes{}, {identity.fingerprint()}));
    }

    return 0;
}
