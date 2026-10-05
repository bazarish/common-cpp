// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "bazarish/I2pAddress.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <cstdio>
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

    const i2p::Keys delegation = master.issueTransient(kTermDays);
    CHECK(delegation.isOffline());
    CHECK(delegation.b33OfflineKeyDays() == kTermDays);

    const std::int64_t midnight
        = (static_cast<std::int64_t>(std::time(nullptr)) / kSecondsPerDay) * kSecondsPerDay;
    CHECK(delegation.transientExpires() == midnight + kTermDays * kSecondsPerDay);

    CHECK(delegation.publicBase64() == master.publicBase64());
    CHECK(i2p::routingHost(delegation.publicBase64()) == i2p::routingHost(master.publicBase64()));
    const i2p::Keys renewed = master.issueTransient(kTermDays);
    CHECK(renewed.blob() != delegation.blob());
    CHECK(renewed.publicBase64() == master.publicBase64());

    CHECK_THROWS(delegation.issueTransient(kTermDays));
    CHECK_THROWS(master.issueTransient(0));

    std::printf("TestI2pDelegation ok\n");
    return 0;
}
