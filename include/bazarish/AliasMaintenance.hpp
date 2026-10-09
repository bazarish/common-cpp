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

inline constexpr std::int64_t kAliasRequestFreshnessSeconds = 300;

inline constexpr std::int64_t kAliasStatusValiditySeconds = 36 * 3600;

inline constexpr const char* kAliasStatusOp = "alias.status";
inline constexpr const char* kAliasUpdateOp = "alias.update";
inline constexpr const char* kAliasRenewOp = "alias.renew";
inline constexpr const char* kAliasAutoRenewOp = "alias.autorenew";
inline constexpr const char* kAliasBindingOp = "alias.binding";
inline constexpr const char* kAliasTransferAcceptOp = "alias.transfer.accept";

struct AliasMaintenanceRequest {
    std::string op;
    std::string alias;
    Descriptor descriptor;
    bool flag = false;
    Bytes aliasCertDer;
    std::int64_t issuedAt = 0;
};

struct AliasStatusEntry {
    std::string alias;
    std::int64_t notAfter = 0;
    bool autoRenew = true;
    bool bindingWanted = false;
    bool bound = false;
    bool inApp = false;
};

struct AliasStatus {
    std::string owner;
    std::vector<AliasStatusEntry> names;
    bool depositCoversRenewals = true;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;
};

nlohmann::json toJson(const AliasMaintenanceRequest& request);
AliasMaintenanceRequest aliasMaintenanceRequestFromJson(const nlohmann::json& body);
nlohmann::json toJson(const AliasStatus& status);
AliasStatus aliasStatusFromJson(const nlohmann::json& body);

Bytes signAliasMaintenanceRequest(const AliasMaintenanceRequest& request, const Identity& owner);

struct VerifiedAliasRequest {
    std::string owner;
    AliasMaintenanceRequest request;
};

VerifiedAliasRequest verifyAliasMaintenanceRequest(const Bytes& der, std::int64_t now);

Bytes signAliasStatus(const AliasStatus& status, const Identity& delegatedIdentity);

AliasStatus verifyAliasStatus(const Bytes& statusDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, std::int64_t now);

}  // namespace bazarish
