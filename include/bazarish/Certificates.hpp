// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

inline constexpr int kCertificateFormatVersion = 1;

// All times are unix seconds, UTC.

// Contact card: signed by the user, saying "this is where you reach me". It is
// what a contact fetches and what an invite points at, so it names nothing but
// the user's own routing - never the server that operates the destination, which
// would tell every contact who hosts them and let two cards be compared for
// co-location.
//
// Nothing in it is a trust anchor except the signature: the fingerprint is the
// anchor, and a wrong dest or key only makes delivery fail. It carries no
// validity window either - routing that moved is repaired by the `routing` field
// every message carries, which needs one message in any direction.
// What one user hands another so they can be written to: where to deliver, what
// to seal to, and - from the signature itself - who they are.
//
// There is no version member: the format version travels on the wire and a body
// that does not carry this build's is refused when it is read, so a parsed card
// can only ever hold the one number. Keeping it would be a field that says
// nothing and can never be false.
//
// Every certificate here says what it is. Without that, one signed document can
// be read as another whenever the fields it lacks are optional - a subscription
// certificate parsed as a contact card, say - and the only thing standing in the
// way is which fields the reader happens to look at. The tag is checked before
// anything else in the body is believed.
//
// There is no subject member either. A card is a statement its signer makes
// about themselves, so the subject IS the signer: `fingerprint()` below is taken
// from the keys that signed it. A separate claim beside them would be a second
// place for the same fact, and the only thing a second place can add is a
// disagreement between the two.
struct ContactCard {
    // The I2P destination a contact delivers to (dest_U).
    std::string dest;
    // The user's sealing public key (SubjectPublicKeyInfo DER): a prekey that
    // contacts use to E2E-encrypt the first message before any token exchange.
    // Empty when not published yet.
    Bytes sealingPublicKeyDer;
    // When this card was signed. Two cards of one person are ordered by it and
    // by nothing else: without it the newest card is whichever was published
    // last, so a device that kept an old copy could republish it and quietly put
    // the account's routing back to what it used to be.
    std::int64_t issuedAt = 0;
    // SubjectPublicKeyInfo DER of the serving sealing key (sealingKey_U): the
    // public key the delivery envelope's admission header (mailbox + token) is
    // sealed to, whose private half the user's server holds. NOT a signature.
    // Empty when not published yet.
    Bytes servingSealingKeyDer;
    // The identity keys that signed this card (SPKI DER). A card is where a
    // correspondent's identity is met; every message of theirs is verified
    // against these, so the reader keeps them rather than the fingerprint alone.
    Bytes identityClassicalDer;
    Bytes identityPqDer;

    // Whose card this is, derived from the keys that signed it.
    std::string fingerprint() const;

    static Bytes issue(const Identity& userIdentity, std::int64_t issuedAt,
        const std::string& dest = {}, const Bytes& sealingPublicKeyDer = {},
        const Bytes& servingSealingKeyDer = {});
    // Verifies the CMS signature and that the signer is body.user.
    static ContactCard verify(const Bytes& der);

    // The sealing prekey as a usable Key. Throws when none was published.
    Key sealingKey() const;
    // The serving sealing key as a usable Key. Throws when none was published.
    Key servingSealingKey() const;
};

// Alias certificate: signed by the user, asserts "I am alias X".
struct AliasCertificate {
    int v = kCertificateFormatVersion;
    std::string alias;
    std::string user;
    std::int64_t issuedAt = 0;
    // Absent means unlimited (the default per server policy).
    std::optional<std::int64_t> notAfter;

    static Bytes issue(const Identity& userIdentity, const std::string& alias, std::int64_t issuedAt,
        std::optional<std::int64_t> notAfter);
    // Verifies the CMS signature and that the signer is body.user.
    static AliasCertificate verify(const Bytes& der);
};

// Server card: signed by the server root key; maps the server fingerprint
// to transport endpoints and the sealing key.
struct ServerCard {
    int v = kCertificateFormatVersion;
    std::string server;
    // Typed entries, e.g. "i2p:<destination>".
    std::vector<std::string> endpoints;
    // SubjectPublicKeyInfo DER of the sealing key.
    Bytes sealingPublicKeyDer;
    // Newer cards supersede older ones.
    std::int64_t issuedAt = 0;

    static Bytes issue(const Identity& serverRootIdentity, const std::vector<std::string>& endpoints,
        const Key& sealingPublicKey, std::int64_t issuedAt);
    // Verifies the CMS signature and that the signer is body.server.
    static ServerCard verify(const Bytes& der);

    Key sealingKey() const;
};

// Delegation certificate: signed by a root identity, authorizes a short-lived
// delegated identity to sign on its behalf until notAfter. The central alias
// resolver signs its resolve records with a delegated key and ships this cert;
// clients verify the chain record -> delegated -> root against a hardcoded root
// fingerprint (api/AliasResolver.md, api/FederatedResolve.md). The root key stays
// offline; only the delegated key lives on the production box, so a prod
// compromise is bounded to the delegation window.
struct DelegationCertificate {
    int v = kCertificateFormatVersion;
    std::string root;                   // the signing root identity's fingerprint
    Bytes delegatedClassicalPublicDer;  // the delegated identity's classical SPKI
    Bytes delegatedPqPublicDer;         // the delegated identity's ML-DSA SPKI
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;

    static Bytes issue(const Identity& rootIdentity, const Identity& delegatedIdentity,
        std::int64_t issuedAt, std::int64_t notAfter);
    // Verifies the CMS signature and that the signer is body.root.
    static DelegationCertificate verify(const Bytes& der);

    // The fingerprint of the delegated identity (covers both delegated keys); a
    // record signed by the delegated identity must verify to this.
    std::string delegatedFingerprint() const;
};

}  // namespace bazarish
