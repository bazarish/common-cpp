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

    // The device a request speaks for is signed with it. This is what stops
    // anything in the middle from re-labelling a request as another device of the
    // same account - the server picks a mail queue by that label.
    {
        const auth::Headers named
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body, "dev-a");
        CHECK(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body, "dev-a")
            == identity.fingerprint());
        // Swapped for another device of the same account: refused.
        CHECK_THROWS(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body, "dev-b"));
        // Stripped altogether: also refused, rather than falling back to the
        // shape a device-less request signs.
        CHECK_THROWS(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body));
        // And the reverse: a request that named no device does not verify as one.
        const auth::Headers anonymous
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK_THROWS(
            auth::verifyRequest(anonymous, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        // A request that names no device signs exactly what it always signed, so
        // an operator push or a login blob is unaffected by any of this.
        CHECK(auth::makeCanonicalString(kNow, "GET", "/healthz", body)
            == auth::makeCanonicalString(kNow, "GET", "/healthz", body, std::string()));
        CHECK(auth::makeCanonicalString(kNow, "GET", "/healthz", body, "dev-a")
            != auth::makeCanonicalString(kNow, "GET", "/healthz", body));
        // The digest path carries the device too (a streamed upload is signed
        // through its digest and is still one device's request).
        const std::string bodyDigest = toHex(sha256(body));
        const auth::Headers streamed = auth::signRequestDigest(
            identity, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-a");
        CHECK(auth::verifyRequestDigest(
                  streamed, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-a")
            == identity.fingerprint());
        CHECK_THROWS(auth::verifyRequestDigest(
            streamed, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-b"));
    }

    // --- Session authentication ---
    //
    // What every request after the first one carries: a MAC over the same
    // canonical string, and a handle that says nothing to anybody but the server
    // holding the secret.
    {
        const Bytes secret = randomBytes(32);
        const std::string sessionId = toHex(sha256(secret)).substr(0, 32);
        const Bytes key = auth::deriveSessionKey(secret, sessionId);

        // Both halves fix the key: neither side alone decides it.
        CHECK(auth::deriveSessionKey(secret, sessionId) == key);
        CHECK(auth::deriveSessionKey(randomBytes(32), sessionId) != key);
        CHECK(auth::deriveSessionKey(secret, "00000000000000000000000000000000") != key);

        // The handle is per request, not per session: two requests of one session
        // share nothing a facade could tie together, and neither is derivable
        // without the secret.
        const std::string handle1 = auth::sessionHandle(secret, 1);
        const std::string handle2 = auth::sessionHandle(secret, 2);
        CHECK(handle1 != handle2);
        CHECK(auth::sessionHandle(secret, 1) == handle1);  // and it is reproducible
        CHECK(auth::sessionHandle(randomBytes(32), 1) != handle1);

        constexpr std::uint64_t kSeq = 7;
        const auth::Headers maced = auth::macRequest(
            auth::sessionHandle(secret, kSeq), key, kSeq, kNow, "POST", "/v1/messaging/ack", body,
            "dev-a");
        CHECK(auth::hasSessionHeaders(maced));
        CHECK(!auth::hasSessionHeaders(
            auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body)));
        CHECK(auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/ack", body, "dev-a")
            == kSeq);

        // Everything the MAC covers, one at a time.
        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "GET", "/v1/messaging/ack", body, "dev-a"));
        CHECK_THROWS(
            auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/pending", body, "dev-a"));
        CHECK_THROWS(auth::verifyMac(
            maced, key, kNow, "POST", "/v1/messaging/ack", Bytes{'x'}, "dev-a"));
        // The device, which is the whole point of signing it.
        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/ack", body, "dev-b"));
        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/ack", body));
        // A different session key.
        CHECK_THROWS(auth::verifyMac(maced, auth::deriveSessionKey(randomBytes(32), sessionId),
            kNow, "POST", "/v1/messaging/ack", body, "dev-a"));

        // The sequence rides inside the MAC, so a replay under another counter
        // does not verify - the server's own seq check is the second half of it.
        {
            auth::Headers renumbered = maced;
            renumbered[auth::kHeaderSeq] = "8";
            CHECK_THROWS(
                auth::verifyMac(renumbered, key, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        }

        // The freshness window is the same one the signature path uses.
        CHECK(auth::verifyMac(maced, key, kNow + auth::kAuthFreshnessWindowSeconds, "POST",
                  "/v1/messaging/ack", body, "dev-a")
            == kSeq);
        CHECK_THROWS(auth::verifyMac(maced, key, kNow + auth::kAuthFreshnessWindowSeconds + 1,
            "POST", "/v1/messaging/ack", body, "dev-a"));
        CHECK_THROWS(auth::verifyMac(maced, key, kNow - auth::kAuthFreshnessWindowSeconds - 1,
            "POST", "/v1/messaging/ack", body, "dev-a"));

        // The handle is not part of the MAC: it is what the server looks the
        // session up by, and a request without one is not a session request at
        // all - which is the check that governs it.
        {
            auth::Headers broken = maced;
            broken.erase(auth::kHeaderSession);
            CHECK(!auth::hasSessionHeaders(broken));
        }

        // What the MAC itself needs. Missing or corrupted, it must fail.
        for (const char* const name :
            {auth::kHeaderSeq, auth::kHeaderTimestamp, auth::kHeaderMac}) {
            auth::Headers broken = maced;
            broken.erase(name);
            CHECK_THROWS(
                auth::verifyMac(broken, key, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        }
        {
            auth::Headers broken = maced;
            std::string& mac = broken[auth::kHeaderMac];
            mac[0] = mac[0] == 'a' ? 'b' : 'a';
            CHECK_THROWS(
                auth::verifyMac(broken, key, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        }
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
