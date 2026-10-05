// Bazarish project (c) 2026
#include "bazarish/Resolve.hpp"

#include "bazarish/Certificates.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

using namespace bazarish;

int main()
{
    const Descriptor descriptor{
        "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq",
        "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p",
        "0123456789abcdef0123456789abcdef",
    };

    const Descriptor d2 = descriptorFromJson(descriptorToJson(descriptor));
    CHECK(d2.fingerprint == descriptor.fingerprint);
    CHECK(d2.dest == descriptor.dest);
    CHECK(d2.view == descriptor.view);

    const CardFetchQuery query{"dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq",
        "0123456789abcdef0123456789abcdef"};
    const CardFetchQuery q2 = cardFetchQueryFromJson(toJson(query));
    CHECK(q2.fingerprint == query.fingerprint);
    CHECK(q2.view == query.view);

    const CardFetchResponse response{Bytes{0xDE, 0xAD, 0xBE, 0xEF, 0x42}};
    const CardFetchResponse r2 = cardFetchResponseFromJson(toJson(response));
    CHECK(r2.cardDer == response.cardDer);

    const ResolveQuery rq{"alice"};
    const ResolveQuery rq2 = resolveQueryFromJson(toJson(rq));
    CHECK(rq2.alias == rq.alias);
    CHECK(!toJson(rq).contains("responseKey"));

    const ResolveResponse rr{
        Bytes{0xAA, 0xBB, 0xCC}, Bytes{0xDD, 0xEE, 0xFF, 0x01}, Bytes{0x11, 0x22}};
    const ResolveResponse rr2 = resolveResponseFromJson(toJson(rr));
    CHECK(rr2.recordDer == rr.recordDer);
    CHECK(rr2.delegationDer == rr.delegationDer);
    CHECK(rr2.aliasCertDer == rr.aliasCertDer);

    const ResolveRecord record{"alice", descriptor, 1718600000, 1750136000};
    const ResolveRecord rec2 = resolveRecordFromJson(toJson(record));
    CHECK(rec2.alias == record.alias);
    CHECK(rec2.descriptor.fingerprint == descriptor.fingerprint);
    CHECK(rec2.descriptor.dest == descriptor.dest);
    CHECK(rec2.descriptor.view == descriptor.view);
    CHECK(rec2.issuedAt == record.issuedAt);
    CHECK(rec2.notAfter == record.notAfter);

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

    const std::int64_t now = 1718600000;
    const std::int64_t week = 7 * 24 * 3600;
    const Identity root = Identity::generate();
    const Identity delegated = Identity::generate();

    const Bytes delegationDer = DelegationCertificate::issue(root, delegated, now, now + week);
    const DelegationCertificate del = DelegationCertificate::verify(delegationDer);
    CHECK(del.root == root.fingerprint());
    CHECK(del.delegatedFingerprint() == delegated.fingerprint());

    const Identity owner = Identity::generate();
    const Descriptor owned{owner.fingerprint(), descriptor.dest, descriptor.view};
    const Bytes ownerCert = AliasCertificate::issue(owner, "alice", now);

    const ResolveRecord signedRec{"alice", owned, now, now + week};
    const Bytes recordDer = signResolveRecord(signedRec, delegated);
    const ResolveRecord okRec
        = verifyResolveRecord(recordDer, delegationDer, ownerCert, root.fingerprint(), now);
    CHECK(okRec.alias == "alice");
    CHECK(okRec.descriptor.fingerprint == owner.fingerprint());
    CHECK(okRec.descriptor.view == descriptor.view);

    const auto chainRejects = [&](const Bytes& rDer, const Bytes& dDer, const Bytes& certDer,
                                  const std::string& rootFp, std::int64_t t) {
        try {
            (void)verifyResolveRecord(rDer, dDer, certDer, rootFp, t);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    CHECK(chainRejects(recordDer, delegationDer, ownerCert, delegated.fingerprint(), now));
    CHECK(chainRejects(recordDer, delegationDer, ownerCert, root.fingerprint(), now + week + 1));

    const Identity impostor = Identity::generate();
    const Bytes forged = signResolveRecord(signedRec, impostor);
    CHECK(chainRejects(forged, delegationDer, ownerCert, root.fingerprint(), now));

    const ResolveRecord shortRec{"bob", owned, now, now + 10};
    const Bytes shortDer = signResolveRecord(shortRec, delegated);
    CHECK(chainRejects(
        shortDer, delegationDer, AliasCertificate::issue(owner, "bob", now),
        root.fingerprint(), now + 100));

    CHECK(chainRejects(recordDer, delegationDer, AliasCertificate::issue(owner, "elsewhere", now),
        root.fingerprint(), now));
    const Identity stranger = Identity::generate();
    CHECK(chainRejects(recordDer, delegationDer, AliasCertificate::issue(stranger, "alice", now),
        root.fingerprint(), now));
    CHECK(chainRejects(recordDer, delegationDer, Bytes{}, root.fingerprint(), now));

    const Bytes aheadDelegation
        = DelegationCertificate::issue(root, delegated, now + 2 * kClockSkewSeconds, now + week);
    CHECK(chainRejects(recordDer, aheadDelegation, ownerCert, root.fingerprint(), now));
    const ResolveRecord aheadRec{
        "alice", owned, now + 2 * kClockSkewSeconds, now + week};
    CHECK(chainRejects(signResolveRecord(aheadRec, delegated), delegationDer, ownerCert,
        root.fingerprint(), now));
    CHECK(chainRejects(recordDer, delegationDer,
        AliasCertificate::issue(owner, "alice", now + 2 * kClockSkewSeconds),
        root.fingerprint(), now));
    const ResolveRecord skewedRec{"alice", owned, now + kClockSkewSeconds / 2, now + week};
    CHECK(!chainRejects(signResolveRecord(skewedRec, delegated), delegationDer, ownerCert,
        root.fingerprint(), now));

    const auto descriptorRejects = [](const nlohmann::json& body) {
        try {
            (void)descriptorFromJson(body);
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    CHECK(descriptorRejects({{"fp", "not-a-fingerprint"}, {"dest", descriptor.dest},
        {"view", descriptor.view}}));
    CHECK(descriptorRejects({{"fp", descriptor.fingerprint}, {"dest", "nowhere.example"},
        {"view", descriptor.view}}));
    CHECK(descriptorRejects(
        {{"fp", descriptor.fingerprint}, {"dest", descriptor.dest}, {"view", "short"}}));
    CHECK(descriptorRejects({{"fp", descriptor.fingerprint}, {"dest", ""}, {"view", ""}}));
    CHECK(!descriptorRejects({{"fp", ""}, {"dest", ""}, {"view", ""}}));

    CHECK(!chainRejects(recordDer, delegationDer, AliasCertificate::issue(owner, "Alice", now),
        root.fingerprint(), now));

    std::printf("TestResolve: all checks passed\n");
    return 0;
}
