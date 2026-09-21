// Bazarish project (c) 2026
//
// The delegation a user hands their server: an offline transient for the
// LeaseSet itself, plus one blinded-key-authorized transient per day for the
// outer layer of the encrypted LeaseSet. Without the second kind a server
// cannot publish the address at all, so what is checked here is that a
// delegation carries both and says truthfully how long it lasts.
#include "bazarish/I2p.hpp"

#include "bazarish/I2pAddress.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>
#include <exception>
#include <ctime>

using namespace bazarish;

namespace {

constexpr int kTermDays = 3;
constexpr std::int64_t kSecondsPerDay = 24 * 60 * 60;

}  // namespace

int main()
{
    const i2p::Keys master = i2p::Keys::generate();
    CHECK(!master.isOffline());
    CHECK(master.transientExpires() == 0);
    CHECK(master.b33OfflineKeyDays() == 0);

    // Counting the days also verifies the current day's key against that day's
    // blinded key, so this is what says the batch was generated correctly.
    const i2p::Keys delegation = master.issueTransient(kTermDays);
    CHECK(delegation.isOffline());
    CHECK(delegation.b33OfflineKeyDays() == kTermDays);

    // The term is whole UTC days counted from the current one, so it ends at a
    // midnight - which is also where each day's blinded key hands over.
    const std::int64_t expires = delegation.transientExpires();
    CHECK(expires % kSecondsPerDay == 0);
    const std::int64_t midnight
        = (static_cast<std::int64_t>(std::time(nullptr)) / kSecondsPerDay) * kSecondsPerDay;
    CHECK(expires == midnight + kTermDays * kSecondsPerDay);

    // Delegation withholds the master signing key and keeps the address: a
    // contact's card goes on working across a renewal, and across a move to
    // another server.
    CHECK(delegation.publicBase64() == master.publicBase64());
    CHECK(i2p::routingHost(delegation.publicBase64()) == i2p::routingHost(master.publicBase64()));
    const i2p::Keys renewed = master.issueTransient(kTermDays);
    CHECK(renewed.blob() != delegation.blob());
    CHECK(i2p::routingHost(renewed.publicBase64()) == i2p::routingHost(master.publicBase64()));

    // Only the destination's own key can delegate, and only for a term the batch
    // can hold: blinding a delegation's transient would publish an address that
    // is not this one.
    const auto refused = [](const auto& call) {
        try {
            call();
        } catch (const std::exception&) {
            return true;
        }
        return false;
    };
    CHECK(refused([&] { (void)delegation.issueTransient(kTermDays); }));
    CHECK(refused([&] { (void)master.issueTransient(0); }));

    std::printf("TestI2pDelegation ok\n");
    return 0;
}
