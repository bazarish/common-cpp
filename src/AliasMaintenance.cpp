// Bazarish project (c) 2026
#include "bazarish/AliasMaintenance.hpp"

#include "bazarish/Certificates.hpp"
#include "bazarish/Hybrid.hpp"
#include "bazarish/Resolve.hpp"

#include <cstdlib>
#include <stdexcept>

namespace {

constexpr int kAliasMaintenanceVersion = 1;

const char* const kAliasRequestType = "alias-request";
const char* const kAliasStatusType = "alias-status";

void requireTypeAndVersion(const nlohmann::json& body, const char* type, const char* what)
{
    if (body.value("t", std::string()) != type) {
        throw std::invalid_argument(std::string("this is not an ") + what);
    }
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
        {"t", kAliasRequestType},
        {"op", request.op},
        {"alias", request.alias},
        {"descriptor", descriptorToJson(request.descriptor)},
        {"flag", request.flag},
        {"aliasCert", toBase64(request.aliasCertDer)},
        {"issuedAt", request.issuedAt},
    };
}

AliasMaintenanceRequest aliasMaintenanceRequestFromJson(const nlohmann::json& body)
{
    requireTypeAndVersion(body, kAliasRequestType, "alias maintenance request");
    AliasMaintenanceRequest request;
    request.op = body.at("op").get<std::string>();
    request.alias = body.at("alias").get<std::string>();
    request.descriptor = descriptorFromJson(body.at("descriptor"));
    request.flag = body.value("flag", false);
    request.aliasCertDer = fromBase64(body.value("aliasCert", std::string()));
    request.issuedAt = body.at("issuedAt").get<std::int64_t>();
    return request;
}

nlohmann::json toJson(const AliasStatus& status)
{
    nlohmann::json names = nlohmann::json::array();
    for (const AliasStatusEntry& entry : status.names) {
        names.push_back({{"alias", entry.alias}, {"notAfter", entry.notAfter},
            {"autoRenew", entry.autoRenew}, {"bindingWanted", entry.bindingWanted},
            {"bound", entry.bound}});
    }
    return {
        {"v", kAliasMaintenanceVersion},
        {"t", kAliasStatusType},
        {"owner", status.owner},
        {"names", names},
        {"depositCoversRenewals", status.depositCoversRenewals},
        {"issuedAt", status.issuedAt},
        {"notAfter", status.notAfter},
    };
}

AliasStatus aliasStatusFromJson(const nlohmann::json& body)
{
    requireTypeAndVersion(body, kAliasStatusType, "alias status");
    AliasStatus status;
    status.owner = body.at("owner").get<std::string>();
    for (const nlohmann::json& entry : body.at("names")) {
        AliasStatusEntry one;
        one.alias = entry.at("alias").get<std::string>();
        one.notAfter = entry.at("notAfter").get<std::int64_t>();
        one.autoRenew = entry.value("autoRenew", true);
        one.bindingWanted = entry.value("bindingWanted", false);
        one.bound = entry.value("bound", false);
        status.names.push_back(std::move(one));
    }
    status.depositCoversRenewals = body.value("depositCoversRenewals", true);
    status.issuedAt = body.at("issuedAt").get<std::int64_t>();
    status.notAfter = body.at("notAfter").get<std::int64_t>();
    return status;
}

Bytes signAliasMaintenanceRequest(const AliasMaintenanceRequest& request, const Identity& owner)
{
    return hybrid::signJson(toJson(request), owner);
}

VerifiedAliasRequest verifyAliasMaintenanceRequest(const Bytes& der, const std::int64_t now)
{
    const hybrid::VerifiedJson verified = hybrid::verifyJson(der);
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
    return hybrid::signJson(toJson(status), delegatedIdentity);
}

AliasStatus verifyAliasStatus(const Bytes& statusDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, const std::int64_t now)
{
    const DelegationCertificate delegation = DelegationCertificate::verify(delegationDer);
    if (delegation.root != trustedRootFingerprint) {
        throw std::runtime_error("alias status: delegation is not from the trusted root");
    }
    if (delegation.issuedAt > now + kClockSkewSeconds) {
        throw std::runtime_error("alias status: delegation is dated in the future");
    }
    if (now > delegation.notAfter) {
        throw std::runtime_error("alias status: delegation has expired");
    }

    const hybrid::VerifiedJson verified = hybrid::verifyJson(statusDer);
    if (verified.identityFingerprint != delegation.delegatedFingerprint()) {
        throw std::runtime_error("alias status: signer is not the delegated key");
    }

    AliasStatus status = aliasStatusFromJson(verified.body);
    if (status.issuedAt > now + kClockSkewSeconds) {
        throw std::runtime_error("alias status: answer is dated in the future");
    }
    if (status.notAfter > status.issuedAt + kAliasStatusValiditySeconds) {
        throw std::runtime_error("alias status: answer claims a longer life than the protocol's");
    }
    if (now > status.notAfter) {
        throw std::runtime_error("alias status: answer has expired");
    }
    return status;
}

}  // namespace bazarish
