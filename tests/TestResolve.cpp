// Bazarish project (c) 2026
#include "bazarish/Resolve.hpp"

#include "bazarish/Certificates.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish;

int main()
{
    const Descriptor descriptor{
        "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq",
        "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p",
        Bytes{0x30, 0x59, 0x01, 0xAB, 0xCD, 0xEF, 0x00, 0x7F},
    };

    // Descriptor <-> JSON (the embedded object form).
    const Descriptor d2 = descriptorFromJson(descriptorToJson(descriptor));
    CHECK(d2.fingerprint == descriptor.fingerprint);
    CHECK(d2.srv == descriptor.srv);
    CHECK(d2.srvKeyDer == descriptor.srvKeyDer);

    // Card-fetch query round-trip.
    const CardFetchQuery query{"dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq",
        Bytes{0x01, 0x02, 0x03, 0x04, 0x05}};
    const CardFetchQuery q2 = cardFetchQueryFromJson(toJson(query));
    CHECK(q2.fingerprint == query.fingerprint);
    CHECK(q2.responseKeyDer == query.responseKeyDer);

    // Card-fetch response round-trip.
    const CardFetchResponse response{Bytes{0xDE, 0xAD, 0xBE, 0xEF, 0x42}};
    const CardFetchResponse r2 = cardFetchResponseFromJson(toJson(response));
    CHECK(r2.subscriptionCertDer == response.subscriptionCertDer);

    // Resolve query round-trip (alias + ephemeral response key).
    const ResolveQuery rq{"alice", Bytes{0x11, 0x22, 0x33, 0x44}};
    const ResolveQuery rq2 = resolveQueryFromJson(toJson(rq));
    CHECK(rq2.alias == rq.alias);
    CHECK(rq2.responseKeyDer == rq.responseKeyDer);

    // Resolve response round-trip (signed record + delegation certificate).
    const ResolveResponse rr{Bytes{0xAA, 0xBB, 0xCC}, Bytes{0xDD, 0xEE, 0xFF, 0x01}};
    const ResolveResponse rr2 = resolveResponseFromJson(toJson(rr));
    CHECK(rr2.recordDer == rr.recordDer);
    CHECK(rr2.delegationDer == rr.delegationDer);

    // Resolve record round-trip.
    const ResolveRecord record{"alice", descriptor, 1718600000, 1750136000};
    const ResolveRecord rec2 = resolveRecordFromJson(toJson(record));
    CHECK(rec2.alias == record.alias);
    CHECK(rec2.descriptor.fingerprint == descriptor.fingerprint);
    CHECK(rec2.descriptor.srv == descriptor.srv);
    CHECK(rec2.descriptor.srvKeyDer == descriptor.srvKeyDer);
    CHECK(rec2.issuedAt == record.issuedAt);
    CHECK(rec2.notAfter == record.notAfter);

    // A bad version is rejected.
    const auto rejects = [](const nlohmann::json& body) {
        try {
            (void)resolveRecordFromJson(body);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    nlohmann::json bad = toJson(record);
    bad["v"] = 2;
    CHECK(rejects(bad));

    // Delegation chain: record -> delegated identity -> root (the hardcoded anchor).
    const std::int64_t now = 1718600000;
    const std::int64_t week = 7 * 24 * 3600;
    const Identity root = Identity::generate();
    const Identity delegated = Identity::generate();

    const Bytes delegationDer = DelegationCertificate::issue(root, delegated, now, now + week);
    const DelegationCertificate del = DelegationCertificate::verify(delegationDer);
    CHECK(del.root == root.fingerprint());
    CHECK(del.delegatedFingerprint() == delegated.fingerprint());

    const ResolveRecord signedRec{"alice", descriptor, now, now + week};
    const Bytes recordDer = signResolveRecord(signedRec, delegated);
    const ResolveRecord okRec = verifyResolveRecord(recordDer, delegationDer, root.fingerprint(), now);
    CHECK(okRec.alias == "alice");
    CHECK(okRec.descriptor.fingerprint == descriptor.fingerprint);
    CHECK(okRec.descriptor.srvKeyDer == descriptor.srvKeyDer);

    const auto chainRejects = [&](const Bytes& rDer, const Bytes& dDer, const std::string& rootFp,
                                  std::int64_t t) {
        try {
            (void)verifyResolveRecord(rDer, dDer, rootFp, t);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    CHECK(chainRejects(recordDer, delegationDer, delegated.fingerprint(), now));        // wrong root
    CHECK(chainRejects(recordDer, delegationDer, root.fingerprint(), now + week + 1));   // delegation expired

    // A record signed by an identity the delegation does not authorize.
    const Identity impostor = Identity::generate();
    const Bytes forged = signResolveRecord(signedRec, impostor);
    CHECK(chainRejects(forged, delegationDer, root.fingerprint(), now));

    // The delegation is still valid but the record itself has expired.
    const ResolveRecord shortRec{"bob", descriptor, now, now + 10};
    const Bytes shortDer = signResolveRecord(shortRec, delegated);
    CHECK(chainRejects(shortDer, delegationDer, root.fingerprint(), now + 100));

    std::printf("TestResolve: all checks passed\n");
    return 0;
}
