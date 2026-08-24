// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Descriptor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace bazarish {

// Wire bodies shared by the client, the serving server and the central resolver
// (api/FederatedResolve.md). These are pure (de)serializers - sealing/signing and
// destination validation are the callers' responsibility.

// --- Card fetch (fingerprint known -> contact card) ---------------------

// Query to a serving server, sealed to its serving sealing key.
struct CardFetchQuery {
    std::string fingerprint;  // whose contact card is requested
    // The `view` from the descriptor being redeemed: the capability the serving
    // server issued for reading this user's card. It is what shows the asker was
    // given the descriptor; a wrong one and an unknown user get the same
    // refusal, so nothing is learnt by asking.
    std::string view;
};

// Response from the serving server. Both directions travel in the clear: the
// fetch is direct over I2P, whose stream is already encrypted and authenticated
// to the destination, and no other path is allowed (relaying it through one's
// own server would tell that server who is being added).
struct CardFetchResponse {
    Bytes cardDer;  // the user-signed contact card
};

nlohmann::json toJson(const CardFetchQuery& query);
CardFetchQuery cardFetchQueryFromJson(const nlohmann::json& body);
nlohmann::json toJson(const CardFetchResponse& response);
CardFetchResponse cardFetchResponseFromJson(const nlohmann::json& body);

// --- Alias resolution (alias -> descriptor) -----------------------------

// Query to the central resolver, sealed to its serving sealing key (so the relay
// on the proxy path cannot read which alias is looked up).
struct ResolveQuery {
    std::string alias;     // the name to resolve (normalized: a-z0-9, lowercase)
    Bytes responseKeyDer;  // ephemeral SPKI the response is sealed to
};

// Response from the resolver, sealed to the query's responseKey. Carries the
// signed record and the delegation certificate that anchors it to the root.
struct ResolveResponse {
    Bytes recordDer;      // signResolveRecord(...) output (hybrid-signed record)
    Bytes delegationDer;  // the delegation certificate (delegated key <- root)
};

nlohmann::json toJson(const ResolveQuery& query);
ResolveQuery resolveQueryFromJson(const nlohmann::json& body);
nlohmann::json toJson(const ResolveResponse& response);
ResolveResponse resolveResponseFromJson(const nlohmann::json& body);

// The resolver's record body, signed by its delegated key (see the delegation
// chain in api/AliasResolver.md). Self-verifying and cacheable up to notAfter.
struct ResolveRecord {
    std::string alias;
    Descriptor descriptor;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;
};

nlohmann::json toJson(const ResolveRecord& record);
ResolveRecord resolveRecordFromJson(const nlohmann::json& body);

// The descriptor as a JSON object { fp, srv, srv_key } - for embedding in a
// record, distinct from the bazarish://invite URI form (Descriptor.hpp). The key
// is standard base64 (a JSON binary field), not base64url (a URI field).
nlohmann::json descriptorToJson(const Descriptor& descriptor);
Descriptor descriptorFromJson(const nlohmann::json& body);

// Signs a resolve record with the resolver's delegated identity (hybrid).
Bytes signResolveRecord(const ResolveRecord& record, const Identity& delegatedIdentity);

// Verifies a signed resolve record against a trusted (hardcoded) resolver root
// fingerprint: the delegation must be signed by that root and unexpired, the
// record must be signed by the identity that delegation authorizes, and the
// record itself must be unexpired. Returns the verified record; throws on any
// failure (DelegationCertificate is the chain link, api/FederatedResolve.md).
ResolveRecord verifyResolveRecord(const Bytes& recordDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, std::int64_t now);

}  // namespace bazarish
