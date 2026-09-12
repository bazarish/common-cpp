// Bazarish project (c) 2026
#include "bazarish/AliasMaintenance.hpp"

#include "bazarish/Certificates.hpp"
#include "bazarish/Cms.hpp"
#include "bazarish/Resolve.hpp"

#include <cstdlib>
#include <stdexcept>

namespace {

// The one wire version these frames speak.
constexpr int kAliasMaintenanceVersion = 1;

void requireVersion(const nlohmann::json& body, const char* what)
{
    if (body.at("v").get<int>() != kAliasMaintenanceVersion) {
        throw std::invalid_argument(std::string("unsupported ") + what + " version");
    }
}

}  // namespace

namespace bazarish {

nlohmann::json toJson(const AliasMaintenanceRequest& request)
{
    return {
        {"v", kAliasMaintenanceVersion},
        {"op", request.op},
        {"alias", request.alias},
        {"descriptor", descriptorToJson(request.descriptor)},
        {"flag", request.flag},
        {"issuedAt", request.issuedAt},
    };
}

AliasMaintenanceRequest aliasMaintenanceRequestFromJson(const nlohmann::json& body)
{
    requireVersion(body, "alias maintenance request");
    AliasMaintenanceRequest request;
    request.op = body.at("op").get<std::string>();
    request.alias = body.at("alias").get<std::string>();
    request.descriptor = descriptorFromJson(body.at("descriptor"));
    request.flag = body.value("flag", false);
    request.issuedAt = body.at("issuedAt").get<std::int64_t>();
    return request;
}

nlohmann::json toJson(const AliasStatus& status)
{
    nlohmann::json names = nlohmann::json::array();
    for (const AliasStatusEntry& entry : status.names) {
        names.push_back({{"alias", entry.alias}, {"notAfter", entry.notAfter},
            {"autoRenew", entry.autoRenew}});
    }
    return {
        {"v", kAliasMaintenanceVersion},
        {"owner", status.owner},
        {"names", names},
        {"depositCoversRenewals", status.depositCoversRenewals},
        {"issuedAt", status.issuedAt},
        {"notAfter", status.notAfter},
    };
}

AliasStatus aliasStatusFromJson(const nlohmann::json& body)
{
    requireVersion(body, "alias status");
    AliasStatus status;
    status.owner = body.at("owner").get<std::string>();
    for (const nlohmann::json& entry : body.at("names")) {
        status.names.push_back(AliasStatusEntry{entry.at("alias").get<std::string>(),
            entry.at("notAfter").get<std::int64_t>(), entry.value("autoRenew", true)});
    }
    status.depositCoversRenewals = body.value("depositCoversRenewals", true);
    status.issuedAt = body.at("issuedAt").get<std::int64_t>();
    status.notAfter = body.at("notAfter").get<std::int64_t>();
    return status;
}

Bytes signAliasMaintenanceRequest(const AliasMaintenanceRequest& request, const Identity& owner)
{
    return cms::signJsonHybrid(toJson(request), owner);
}

VerifiedAliasRequest verifyAliasMaintenanceRequest(const Bytes& der, const std::int64_t now)
{
    const cms::VerifiedHybridJson verified = cms::verifyJsonHybrid(der);
    VerifiedAliasRequest out;
    out.owner = verified.identityFingerprint;
    out.request = aliasMaintenanceRequestFromJson(verified.body);
    const std::int64_t age = now - out.request.issuedAt;
    if (age > kAliasRequestFreshnessSeconds || -age > kAliasRequestFreshnessSeconds) {
        throw std::runtime_error("alias maintenance request is outside its freshness window");
    }
    return out;
}

Bytes signAliasStatus(const AliasStatus& status, const Identity& delegatedIdentity)
{
    return cms::signJsonHybrid(toJson(status), delegatedIdentity);
}

AliasStatus verifyAliasStatus(const Bytes& statusDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, const std::int64_t now)
{
    const DelegationCertificate delegation = DelegationCertificate::verify(delegationDer);
    if (delegation.root != trustedRootFingerprint) {
        throw std::runtime_error("alias status: delegation is not from the trusted root");
    }
    if (now > delegation.notAfter) {
        throw std::runtime_error("alias status: delegation has expired");
    }

    const cms::VerifiedHybridJson verified = cms::verifyJsonHybrid(statusDer);
    if (verified.identityFingerprint != delegation.delegatedFingerprint()) {
        throw std::runtime_error("alias status: signer is not the delegated key");
    }

    AliasStatus status = aliasStatusFromJson(verified.body);
    if (now > status.notAfter) {
        throw std::runtime_error("alias status: answer has expired");
    }
    return status;
}

}  // namespace bazarish
