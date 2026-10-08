// Bazarish project (c) 2026
#include "bazarish/Resolve.hpp"

#include "bazarish/Address.hpp"
#include "bazarish/Certificates.hpp"
#include "bazarish/Hybrid.hpp"
#include "bazarish/I2pAddress.hpp"

#include <stdexcept>

namespace {

const char* const kResolveRecordType = "resolve-record";

void requireTypeAndVersion(const nlohmann::json& body, const char* type, const char* what)
{
    if (body.value("t", std::string()) != type) {
        throw std::invalid_argument(std::string("this is not a ") + what);
    }
    if (body.at("v").get<int>() != 1) {
        throw std::invalid_argument(std::string("unsupported ") + what + " version");
    }
}

void requireVersion(const nlohmann::json& body, const char* what)
{
    if (body.at("v").get<int>() != 1) {
        throw std::invalid_argument(std::string("unsupported ") + what + " version");
    }
}

}  // namespace

namespace bazarish {

nlohmann::json descriptorToJson(const Descriptor& descriptor)
{
    return {
        {"fp", descriptor.fingerprint},
        {"dest", descriptor.dest},
    };
}

Descriptor descriptorFromJson(const nlohmann::json& body)
{
    Descriptor descriptor;
    descriptor.fingerprint = body.at("fp").get<std::string>();
    descriptor.dest = body.at("dest").get<std::string>();
    if (descriptor.fingerprint.empty() && descriptor.dest.empty()) {
        return descriptor;
    }
    if (!isFingerprint(descriptor.fingerprint)) {
        throw std::invalid_argument("descriptor: that is not a fingerprint");
    }
    validateB32I2pHost(descriptor.dest);
    return descriptor;
}

nlohmann::json toJson(const CardFetchQuery& query)
{
    return {
        {"v", 1},
        {"fp", query.fingerprint},
    };
}

CardFetchQuery cardFetchQueryFromJson(const nlohmann::json& body)
{
    requireVersion(body, "card-fetch query");
    CardFetchQuery query;
    query.fingerprint = body.at("fp").get<std::string>();
    return query;
}

nlohmann::json toJson(const CardFetchResponse& response)
{
    return {
        {"v", 1},
        {"card", toBase64(response.cardDer)},
    };
}

CardFetchResponse cardFetchResponseFromJson(const nlohmann::json& body)
{
    requireVersion(body, "card-fetch response");
    CardFetchResponse response;
    response.cardDer = fromBase64(body.at("card").get<std::string>());
    return response;
}

nlohmann::json toJson(const ResolveQuery& query)
{
    return {
        {"v", 1},
        {"alias", query.alias},
    };
}

ResolveQuery resolveQueryFromJson(const nlohmann::json& body)
{
    requireVersion(body, "resolve query");
    ResolveQuery query;
    query.alias = body.at("alias").get<std::string>();
    return query;
}

nlohmann::json toJson(const ResolveResponse& response)
{
    return {
        {"v", 1},
        {"record", toBase64(response.recordDer)},
        {"delegation", toBase64(response.delegationDer)},
        {"aliasCert", toBase64(response.aliasCertDer)},
    };
}

ResolveResponse resolveResponseFromJson(const nlohmann::json& body)
{
    requireVersion(body, "resolve response");
    ResolveResponse response;
    response.recordDer = fromBase64(body.at("record").get<std::string>());
    response.delegationDer = fromBase64(body.at("delegation").get<std::string>());
    response.aliasCertDer = fromBase64(body.value("aliasCert", std::string()));
    return response;
}

nlohmann::json toJson(const ResolveRecord& record)
{
    return {
        {"v", 1},
        {"t", kResolveRecordType},
        {"alias", record.alias},
        {"descriptor", descriptorToJson(record.descriptor)},
        {"issuedAt", record.issuedAt},
        {"notAfter", record.notAfter},
    };
}

ResolveRecord resolveRecordFromJson(const nlohmann::json& body)
{
    requireTypeAndVersion(body, kResolveRecordType, "resolve record");
    ResolveRecord record;
    record.alias = body.at("alias").get<std::string>();
    record.descriptor = descriptorFromJson(body.at("descriptor"));
    record.issuedAt = body.at("issuedAt").get<std::int64_t>();
    record.notAfter = body.at("notAfter").get<std::int64_t>();
    return record;
}

Bytes signResolveRecord(const ResolveRecord& record, const Identity& delegatedIdentity)
{
    return hybrid::signJson(toJson(record), delegatedIdentity);
}

namespace {

std::string foldAlias(const std::string& alias)
{
    std::string folded;
    folded.reserve(alias.size());
    for (const char c : alias) {
        folded.push_back((c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    }
    return folded;
}

}  // namespace

ResolveRecord verifyResolveRecord(const Bytes& recordDer, const Bytes& delegationDer,
    const Bytes& aliasCertDer, const std::string& trustedRootFingerprint, const std::int64_t now)
{
    const DelegationCertificate delegation = DelegationCertificate::verify(delegationDer);
    if (delegation.root != trustedRootFingerprint) {
        throw std::runtime_error("resolve record: delegation is not from the trusted root");
    }
    if (delegation.issuedAt > now + kClockSkewSeconds) {
        throw std::runtime_error("resolve record: delegation is dated in the future");
    }
    if (now > delegation.notAfter) {
        throw std::runtime_error("resolve record: delegation has expired");
    }

    const hybrid::VerifiedJson verified = hybrid::verifyJson(recordDer);
    if (verified.identityFingerprint != delegation.delegatedFingerprint()) {
        throw std::runtime_error("resolve record: signer is not the delegated key");
    }

    ResolveRecord record = resolveRecordFromJson(verified.body);
    if (record.issuedAt > now + kClockSkewSeconds) {
        throw std::runtime_error("resolve record: record is dated in the future");
    }
    if (now > record.notAfter) {
        throw std::runtime_error("resolve record: record has expired");
    }

    const AliasCertificate claim = AliasCertificate::verify(aliasCertDer);
    if (claim.issuedAt > now + kClockSkewSeconds) {
        throw std::runtime_error("resolve record: the owner's certificate is dated in the future");
    }
    if (foldAlias(claim.alias) != foldAlias(record.alias)) {
        throw std::runtime_error("resolve record: the owner's certificate is over another alias");
    }
    if (claim.user != record.descriptor.fingerprint) {
        throw std::runtime_error("resolve record: the alias is claimed by somebody other than "
                                 "the descriptor's owner");
    }
    return record;
}

}  // namespace bazarish
