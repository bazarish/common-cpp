// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Descriptor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace bazarish {

struct CardFetchQuery {
    std::string fingerprint;
};

nlohmann::json toJson(const CardFetchQuery& query);
CardFetchQuery cardFetchQueryFromJson(const nlohmann::json& body);

struct ResolveQuery {
    std::string alias;
    std::string word{};
    // A solved puzzle when the resolver asked for one: its stamp in hex and the nonce.
    std::string stamp{};
    std::uint64_t nonce = 0;
};

struct ResolveResponse {
    Bytes recordDer;
    Bytes delegationDer;
    Bytes aliasCertDer;
};

nlohmann::json toJson(const ResolveQuery& query);
ResolveQuery resolveQueryFromJson(const nlohmann::json& body);
nlohmann::json toJson(const ResolveResponse& response);
ResolveResponse resolveResponseFromJson(const nlohmann::json& body);

struct ResolveRecord {
    std::string alias;
    Descriptor descriptor;
    std::int64_t issuedAt = 0;
    std::int64_t notAfter = 0;
};

nlohmann::json toJson(const ResolveRecord& record);
ResolveRecord resolveRecordFromJson(const nlohmann::json& body);

nlohmann::json descriptorToJson(const Descriptor& descriptor);
Descriptor descriptorFromJson(const nlohmann::json& body);

Bytes signResolveRecord(const ResolveRecord& record, const Identity& delegatedIdentity);

ResolveRecord verifyResolveRecord(const Bytes& recordDer, const Bytes& delegationDer,
    const Bytes& aliasCertDer, const std::string& trustedRootFingerprint, std::int64_t now);

}  // namespace bazarish
