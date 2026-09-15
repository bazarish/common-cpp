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

// Query to the central resolver. Both directions travel in the clear: the client
// dials the resolver's destination directly over I2P, whose stream is already
// encrypted and authenticated to it, and no relayed path exists to hide the name
// from. The resolver holds no encryption key at all - what a record is worth
// rests on its signature, not on who could read the question.
struct ResolveQuery {
    std::string alias;  // the name to resolve (normalized: a-z0-9, lowercase)
};

// Response from the resolver. Carries the signed record and the delegation
// certificate that anchors it to the root.
struct ResolveResponse {
    Bytes recordDer;      // signResolveRecord(...) output (hybrid-signed record)
    Bytes delegationDer;  // the delegation certificate (delegated key <- root)
    // The owner's own certificate over the name (AliasCertificate). Without it a
    // resolve rests entirely on the registry's word, and the registry could point
    // a name at somebody who never asked for it. With it, the asker sees the
    // owner's signature saying "I am this alias" and checks for themselves that
    // the descriptor they are about to use belongs to that same owner.
    Bytes aliasCertDer;
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
//
// Two signatures, and they answer different questions. The registry's says "this
// name resolves here"; the owner's alias certificate says "I am this name", and
// is checked to be over the same name and by the same identity the descriptor
// names. The second is what the registry cannot forge: it may refuse to answer,
// and it decides who holds a name, but it cannot bind one to a person who never
// signed for it. An answer without the owner's certificate is refused.
ResolveRecord verifyResolveRecord(const Bytes& recordDer, const Bytes& delegationDer,
    const Bytes& aliasCertDer, const std::string& trustedRootFingerprint, std::int64_t now);

}  // namespace bazarish
