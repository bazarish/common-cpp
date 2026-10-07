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

    const auth::Headers headers
        = auth::signRequest(identity, kNow, "POST", "/v1/messaging/tokens", body);
    CHECK(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/tokens", body)
        == identity.fingerprint());

    CHECK(auth::verifyRequest(headers, kNow + auth::kAuthFreshnessWindowSeconds, "POST",
              "/v1/messaging/tokens", body)
        == identity.fingerprint());
    CHECK_THROWS(auth::verifyRequest(headers, kNow + auth::kAuthFreshnessWindowSeconds + 1,
        "POST", "/v1/messaging/tokens", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow - auth::kAuthFreshnessWindowSeconds - 1,
        "POST", "/v1/messaging/tokens", body));

    CHECK_THROWS(auth::verifyRequest(headers, kNow, "DELETE", "/v1/messaging/tokens", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/clients", body));
    CHECK_THROWS(auth::verifyRequest(headers, kNow, "POST", "/v1/messaging/tokens",
        Bytes{'{', ' ', '}'}));

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

    const Identity other = Identity::generate();
    const auth::Headers otherHeaders
        = auth::signRequest(other, kNow, "POST", "/v1/messaging/tokens", body);
    CHECK(auth::verifyRequest(otherHeaders, kNow, "POST", "/v1/messaging/tokens", body)
        != identity.fingerprint());

    {
        const std::string bodyDigest = toHex(sha256(body));
        const auth::Headers digestHeaders
            = auth::signRequestDigest(identity, kNow, "PUT", "/v1/storage/blob", bodyDigest);
        CHECK(auth::verifyRequest(digestHeaders, kNow, "PUT", "/v1/storage/blob", body)
            == identity.fingerprint());
        const auth::Headers bodyHeaders
            = auth::signRequest(identity, kNow, "PUT", "/v1/storage/blob", body);
        CHECK(auth::verifyRequestDigest(bodyHeaders, kNow, "PUT", "/v1/storage/blob", bodyDigest)
            == identity.fingerprint());
        CHECK_THROWS(auth::verifyRequestDigest(
            bodyHeaders, kNow, "PUT", "/v1/storage/blob", toHex(sha256(Bytes{'x'}))));
    }

    {
        auth::ReplayCache cache;
        const auth::Headers first
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK(auth::verifyRequest(first, kNow, "POST", "/v1/messaging/ack", body, cache)
            == identity.fingerprint());
        CHECK_THROWS(auth::verifyRequest(first, kNow, "POST", "/v1/messaging/ack", body, cache));
        const auth::Headers other
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/clients", body);
        CHECK(auth::verifyRequest(other, kNow, "POST", "/v1/messaging/clients", body, cache)
            == identity.fingerprint());
        const auth::Headers resigned
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK(auth::verifyRequest(resigned, kNow, "POST", "/v1/messaging/ack", body, cache)
            == identity.fingerprint());
        CHECK(resigned.at(auth::kHeaderNonce) != first.at(auth::kHeaderNonce));

        auth::Headers renonced = first;
        renonced[auth::kHeaderNonce] = resigned.at(auth::kHeaderNonce);
        CHECK_THROWS(
            auth::verifyRequest(renonced, kNow, "POST", "/v1/messaging/ack", body, cache));
        CHECK_THROWS(auth::verifyRequest(first, kNow + auth::kAuthFreshnessWindowSeconds + 1,
            "POST", "/v1/messaging/ack", body, cache));
        const std::string blobDigest = toHex(sha256(body));
        const auth::Headers blob
            = auth::signRequestDigest(identity, kNow, "PUT", "/v1/storage/blob", blobDigest);
        CHECK(auth::verifyRequestDigest(blob, kNow, "PUT", "/v1/storage/blob", blobDigest, cache)
            == identity.fingerprint());
        CHECK_THROWS(
            auth::verifyRequestDigest(blob, kNow, "PUT", "/v1/storage/blob", blobDigest, cache));
    }

    {
        const auth::Headers named
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body, "dev-a");
        CHECK(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body, "dev-a")
            == identity.fingerprint());
        CHECK_THROWS(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body, "dev-b"));
        CHECK_THROWS(auth::verifyRequest(named, kNow, "POST", "/v1/messaging/ack", body));
        const auth::Headers anonymous
            = auth::signRequest(identity, kNow, "POST", "/v1/messaging/ack", body);
        CHECK_THROWS(
            auth::verifyRequest(anonymous, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        CHECK(auth::makeCanonicalString(kNow, "GET", "/healthz", body)
            == auth::makeCanonicalString(kNow, "GET", "/healthz", body, std::string()));
        CHECK(auth::makeCanonicalString(kNow, "GET", "/healthz", body, "dev-a")
            != auth::makeCanonicalString(kNow, "GET", "/healthz", body));
        const std::string bodyDigest = toHex(sha256(body));
        const auth::Headers streamed = auth::signRequestDigest(
            identity, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-a");
        CHECK(auth::verifyRequestDigest(
                  streamed, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-a")
            == identity.fingerprint());
        CHECK_THROWS(auth::verifyRequestDigest(
            streamed, kNow, "PUT", "/v1/messaging/self", bodyDigest, "dev-b"));
    }

    {
        const Bytes secret = randomBytes(32);
        const std::string sessionId = toHex(sha256(secret)).substr(0, 32);
        const Bytes key = auth::deriveSessionKey(secret, sessionId);

        CHECK(auth::deriveSessionKey(secret, sessionId) == key);
        CHECK(auth::deriveSessionKey(randomBytes(32), sessionId) != key);
        CHECK(auth::deriveSessionKey(secret, "00000000000000000000000000000000") != key);

        const std::string handle1 = auth::sessionHandle(secret, 1);
        const std::string handle2 = auth::sessionHandle(secret, 2);
        CHECK(handle1 != handle2);
        CHECK(auth::sessionHandle(secret, 1) == handle1);
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

        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "GET", "/v1/messaging/ack", body, "dev-a"));
        CHECK_THROWS(
            auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/pending", body, "dev-a"));
        CHECK_THROWS(auth::verifyMac(
            maced, key, kNow, "POST", "/v1/messaging/ack", Bytes{'x'}, "dev-a"));
        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/ack", body, "dev-b"));
        CHECK_THROWS(auth::verifyMac(maced, key, kNow, "POST", "/v1/messaging/ack", body));
        CHECK_THROWS(auth::verifyMac(maced, auth::deriveSessionKey(randomBytes(32), sessionId),
            kNow, "POST", "/v1/messaging/ack", body, "dev-a"));

        {
            auth::Headers renumbered = maced;
            renumbered[auth::kHeaderSeq] = "8";
            CHECK_THROWS(
                auth::verifyMac(renumbered, key, kNow, "POST", "/v1/messaging/ack", body, "dev-a"));
        }

        CHECK(auth::verifyMac(maced, key, kNow + auth::kAuthFreshnessWindowSeconds, "POST",
                  "/v1/messaging/ack", body, "dev-a")
            == kSeq);
        CHECK_THROWS(auth::verifyMac(maced, key, kNow + auth::kAuthFreshnessWindowSeconds + 1,
            "POST", "/v1/messaging/ack", body, "dev-a"));
        CHECK_THROWS(auth::verifyMac(maced, key, kNow - auth::kAuthFreshnessWindowSeconds - 1,
            "POST", "/v1/messaging/ack", body, "dev-a"));

        {
            auth::Headers broken = maced;
            broken.erase(auth::kHeaderSession);
            CHECK(!auth::hasSessionHeaders(broken));
        }

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
