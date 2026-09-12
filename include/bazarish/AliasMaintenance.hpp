// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Descriptor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace bazarish {

// The owner-facing half of the central alias resolver: the frames a client sends
// to keep its own name working, and the answer it may hand to its other devices.
// They ride the same I2P face and the same frame protocol as a resolve.
//
// Both directions are signed and neither is encrypted. A request is signed by the
// owner's identity, so the signature is what names the owner - no request carries
// a fingerprint field that anyone could simply fill in, and there is no way to
// ask about somebody else. An answer is signed by the resolver's delegated key
// and travels with its delegation certificate, so a device handed the answer by a
// sibling device checks it against the same baked-in root as a record it fetched
// itself, rather than taking the sibling's word.

// How long a signed maintenance request stays acceptable. Replaying a captured
// request after this is refused; within it the worst a replay achieves is to set
// the binding the owner had just asked for anyway.
inline constexpr std::int64_t kAliasRequestFreshnessSeconds = 300;

// How long a signed status answer may stand in for a freshly fetched one. It has
// to outlast the client's polling window, or a device handed one by a sibling
// would have to go and ask for itself anyway - which is the traffic the relay
// exists to avoid.
inline constexpr std::int64_t kAliasStatusValiditySeconds = 36 * 3600;

// The ops a maintenance frame may carry.
inline constexpr const char* kAliasStatusOp = "alias.status";
inline constexpr const char* kAliasUpdateOp = "alias.update";
inline constexpr const char* kAliasRenewOp = "alias.renew";
inline constexpr const char* kAliasAutoRenewOp = "alias.autorenew";

// One maintenance request. `alias` and `descriptor` belong to alias.update;
// alias.status leaves them empty and asks about every name the signer owns.
struct AliasMaintenanceRequest {
    std::string op;
    std::string alias;
    Descriptor descriptor;
    // What alias.autorenew is asking for; ignored by every other op.
    bool flag = false;
    std::int64_t issuedAt = 0;
};

// One owned name, as the resolver reports it.
struct AliasStatusEntry {
    std::string alias;
    std::int64_t notAfter = 0;
    bool autoRenew = true;
};

// The resolver's answer to alias.status. `owner` says whose names these are, so a
// device receiving it from a sibling can tell it is about this account; notAfter
// bounds how long it may stand in for a freshly fetched one.
struct AliasStatus {
    std::string owner;
    std::vector<AliasStatusEntry> names;
    // Whether the deposit covers everything of this account's falling due soon.
    // Per account, not per name: several names renewing in the same week can each
    // look affordable while their sum is not, and a flag that reads "fine" there
    // is worse than no flag. The balance itself never leaves the service.
    bool depositCoversRenewals = true;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;
};

nlohmann::json toJson(const AliasMaintenanceRequest& request);
AliasMaintenanceRequest aliasMaintenanceRequestFromJson(const nlohmann::json& body);
nlohmann::json toJson(const AliasStatus& status);
AliasStatus aliasStatusFromJson(const nlohmann::json& body);

// Signs a request with the owner's identity (hybrid).
Bytes signAliasMaintenanceRequest(const AliasMaintenanceRequest& request, const Identity& owner);

// A request whose signature checked out, together with the fingerprint that
// signed it - which is the only place the owner's name comes from.
struct VerifiedAliasRequest {
    std::string owner;
    AliasMaintenanceRequest request;
};

// Verifies the signature and the freshness window. Throws on either failure:
// there is nothing sensible to do with a request whose author or age is unknown.
VerifiedAliasRequest verifyAliasMaintenanceRequest(const Bytes& der, std::int64_t now);

// Signs a status answer with the resolver's delegated identity (hybrid).
Bytes signAliasStatus(const AliasStatus& status, const Identity& delegatedIdentity);

// Verifies a status answer against the trusted resolver root exactly as a resolve
// record is verified: the delegation comes from that root and is unexpired, the
// answer is signed by the key that delegation authorizes, and the answer itself
// has not expired. Returns the verified answer; throws on any failure.
AliasStatus verifyAliasStatus(const Bytes& statusDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, std::int64_t now);

}  // namespace bazarish
