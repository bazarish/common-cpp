// Bazarish project (c) 2026
#include "bazarish/AliasMaintenance.hpp"

#include "bazarish/Certificates.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <functional>
#include <string>

using namespace bazarish;

namespace {

bool throws(const std::function<void()>& fn)
{
    try {
        fn();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

}  // namespace

int main()
{
    const std::int64_t now = 1'700'000'000;
    const std::int64_t week = 7 * 24 * 3600;

    const Descriptor descriptor{
        "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq",
        "elkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p",
        "0123456789abcdef0123456789abcdef",
    };

    // --- Request: round trip, and the signature is what names the owner ---
    const Identity alice = Identity::generate();
    AliasMaintenanceRequest update;
    update.op = kAliasUpdateOp;
    update.alias = "alice";
    update.descriptor = descriptor;
    update.aliasCertDer = Bytes{0x30, 0x31};
    update.issuedAt = now;
    const AliasMaintenanceRequest back = aliasMaintenanceRequestFromJson(toJson(update));
    CHECK(back.op == update.op);
    CHECK(back.alias == update.alias);
    CHECK(back.descriptor.view == descriptor.view);
    CHECK(back.issuedAt == update.issuedAt);
    CHECK(back.aliasCertDer == update.aliasCertDer);

    const Bytes signed_ = signAliasMaintenanceRequest(update, alice);
    const VerifiedAliasRequest verified = verifyAliasMaintenanceRequest(signed_, now);
    CHECK(verified.owner == alice.fingerprint());
    CHECK(verified.request.alias == "alice");
    CHECK(verified.request.descriptor.dest == descriptor.dest);

    // A request carries no fingerprint field to disagree with the signature, so
    // there is no way to ask about anyone but oneself.
    CHECK(!toJson(update).contains("owner"));
    CHECK(!toJson(update).contains("fingerprint"));

    // --- Freshness: a captured request does not keep working ---
    CHECK(throws([&] {
        (void)verifyAliasMaintenanceRequest(signed_, now + kAliasRequestFreshnessSeconds + 1);
    }));
    CHECK(throws([&] {
        (void)verifyAliasMaintenanceRequest(signed_, now - kAliasRequestFreshnessSeconds - 1);
    }));
    // Inside the window it still verifies, at either edge.
    CHECK(verifyAliasMaintenanceRequest(signed_, now + kAliasRequestFreshnessSeconds).owner
        == alice.fingerprint());

    // A tampered body no longer verifies.
    CHECK(throws([&] {
        Bytes damaged = signed_;
        damaged[damaged.size() / 2] ^= 0xFF;
        (void)verifyAliasMaintenanceRequest(damaged, now);
    }));

    // --- Status: signed by the delegated key, anchored to the root ---
    const Identity root = Identity::generate();
    const Identity delegated = Identity::generate();
    const Bytes delegationDer = DelegationCertificate::issue(root, delegated, now, now + week);

    AliasStatus status;
    status.owner = alice.fingerprint();
    status.names.push_back(AliasStatusEntry{"alice", now + week, true});
    status.names.push_back(AliasStatusEntry{"al", now + 2 * week, false});
    status.issuedAt = now;
    status.notAfter = now + 3600;

    const AliasStatus roundTrip = aliasStatusFromJson(toJson(status));
    CHECK(roundTrip.owner == status.owner);
    CHECK(roundTrip.names.size() == 2);
    CHECK(roundTrip.names[1].alias == "al");
    CHECK(roundTrip.names[1].notAfter == now + 2 * week);

    const Bytes statusDer = signAliasStatus(status, delegated);
    const AliasStatus checked
        = verifyAliasStatus(statusDer, delegationDer, root.fingerprint(), now);
    CHECK(checked.owner == alice.fingerprint());
    CHECK(checked.names.size() == 2);
    // Whether a name pays for itself, and whether the deposit covers what falls
    // due, both survive the round trip - the balance itself never does.
    CHECK(checked.names[0].autoRenew);
    CHECK(!checked.names[1].autoRenew);
    CHECK(checked.depositCoversRenewals);
    CHECK(!toJson(status).contains("balance"));

    // Another root does not vouch for it: this is what lets one device accept an
    // answer relayed by a sibling without taking the sibling's word for it.
    CHECK(throws([&] {
        (void)verifyAliasStatus(
            statusDer, delegationDer, Identity::generate().fingerprint(), now);
    }));

    // An answer past its own notAfter is refused, so a relayed one cannot be
    // replayed forever.
    CHECK(throws(
        [&] { (void)verifyAliasStatus(statusDer, delegationDer, root.fingerprint(), now + 3601); }));

    // A key the root never delegated cannot answer at all.
    CHECK(throws([&] {
        const Identity impostor = Identity::generate();
        (void)verifyAliasStatus(
            signAliasStatus(status, impostor), delegationDer, root.fingerprint(), now);
    }));

    // An expired delegation stops vouching even for a fresh answer.
    CHECK(throws([&] {
        AliasStatus later = status;
        later.notAfter = now + week + 3600;
        (void)verifyAliasStatus(signAliasStatus(later, delegated), delegationDer,
            root.fingerprint(), now + week + 1);
    }));

    std::printf("TestAliasMaintenance: all checks passed\n");
    return 0;
}
