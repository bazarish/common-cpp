// Bazarish project (c) 2026
#include "bazarish/Resolve.hpp"

#include "bazarish/Certificates.hpp"
#include "bazarish/Cms.hpp"

#include <stdexcept>

namespace {

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
        {"key", toBase64(descriptor.keyDer)},
    };
}

Descriptor descriptorFromJson(const nlohmann::json& body)
{
    Descriptor descriptor;
    descriptor.fingerprint = body.at("fp").get<std::string>();
    descriptor.dest = body.at("dest").get<std::string>();
    descriptor.keyDer = fromBase64(body.at("key").get<std::string>());
    return descriptor;
}

nlohmann::json toJson(const CardFetchQuery& query)
{
    return {
        {"v", 1},
        {"fp", query.fingerprint},
        {"key", toBase64(query.keyDer)},
        {"responseKey", toBase64(query.responseKeyDer)},
    };
}

CardFetchQuery cardFetchQueryFromJson(const nlohmann::json& body)
{
    requireVersion(body, "card-fetch query");
    CardFetchQuery query;
    query.fingerprint = body.at("fp").get<std::string>();
    query.keyDer = fromBase64(body.at("key").get<std::string>());
    query.responseKeyDer = fromBase64(body.at("responseKey").get<std::string>());
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
        {"responseKey", toBase64(query.responseKeyDer)},
    };
}

ResolveQuery resolveQueryFromJson(const nlohmann::json& body)
{
    requireVersion(body, "resolve query");
    ResolveQuery query;
    query.alias = body.at("alias").get<std::string>();
    query.responseKeyDer = fromBase64(body.at("responseKey").get<std::string>());
    return query;
}

nlohmann::json toJson(const ResolveResponse& response)
{
    return {
        {"v", 1},
        {"record", toBase64(response.recordDer)},
        {"delegation", toBase64(response.delegationDer)},
    };
}

ResolveResponse resolveResponseFromJson(const nlohmann::json& body)
{
    requireVersion(body, "resolve response");
    ResolveResponse response;
    response.recordDer = fromBase64(body.at("record").get<std::string>());
    response.delegationDer = fromBase64(body.at("delegation").get<std::string>());
    return response;
}

nlohmann::json toJson(const ResolveRecord& record)
{
    return {
        {"v", 1},
        {"alias", record.alias},
        {"descriptor", descriptorToJson(record.descriptor)},
        {"issuedAt", record.issuedAt},
        {"notAfter", record.notAfter},
    };
}

ResolveRecord resolveRecordFromJson(const nlohmann::json& body)
{
    requireVersion(body, "resolve record");
    ResolveRecord record;
    record.alias = body.at("alias").get<std::string>();
    record.descriptor = descriptorFromJson(body.at("descriptor"));
    record.issuedAt = body.at("issuedAt").get<std::int64_t>();
    record.notAfter = body.at("notAfter").get<std::int64_t>();
    return record;
}

Bytes signResolveRecord(const ResolveRecord& record, const Identity& delegatedIdentity)
{
    return cms::signJsonHybrid(toJson(record), delegatedIdentity);
}

ResolveRecord verifyResolveRecord(const Bytes& recordDer, const Bytes& delegationDer,
    const std::string& trustedRootFingerprint, const std::int64_t now)
{
    const DelegationCertificate delegation = DelegationCertificate::verify(delegationDer);
    if (delegation.root != trustedRootFingerprint) {
        throw std::runtime_error("resolve record: delegation is not from the trusted root");
    }
    if (now > delegation.notAfter) {
        throw std::runtime_error("resolve record: delegation has expired");
    }

    const cms::VerifiedHybridJson verified = cms::verifyJsonHybrid(recordDer);
    if (verified.identityFingerprint != delegation.delegatedFingerprint()) {
        throw std::runtime_error("resolve record: signer is not the delegated key");
    }

    ResolveRecord record = resolveRecordFromJson(verified.body);
    if (now > record.notAfter) {
        throw std::runtime_error("resolve record: record has expired");
    }
    return record;
}

}  // namespace bazarish
