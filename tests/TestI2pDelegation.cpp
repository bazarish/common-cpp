// Bazarish project (c) 2026
#include "bazarish/I2p.hpp"

#include "bazarish/I2pAddress.hpp"

#include "TestUtil.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <ctime>

using namespace bazarish;

namespace {

constexpr int kTermDays = 3;
constexpr int kLongTermDays = 30;
constexpr std::int64_t kSecondsPerDay = 24 * 60 * 60;
constexpr std::int64_t kInsideLapseSeconds = 30;

i2p::Keys todayOnly(const i2p::Keys& master)
{
    const Bytes longTerm = master.issueTransient(kLongTermDays).blob();
    const Bytes oneDay = master.issueTransient(1).blob();
    const std::size_t perDay = (longTerm.size() - oneDay.size()) / (kLongTermDays - 1);
    return i2p::Keys::fromBlob(
        Bytes(longTerm.begin(), longTerm.end() - static_cast<std::ptrdiff_t>(perDay * (kLongTermDays - 1))));
}

}  // namespace

int main()
{
    const i2p::Keys master = i2p::Keys::generate();
    CHECK(!master.isOffline());
    CHECK(master.transientExpires() == 0);
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    CHECK(!master.b33OfflineKeysCover(now, now + kSecondsPerDay));
    CHECK_THROWS(i2p::requireUsableDelegation(master, now));

    const i2p::Keys delegation = master.issueTransient(kTermDays);
    CHECK(delegation.isOffline());
    CHECK(delegation.b33OfflineKeysCover(now, delegation.transientExpires()));
    i2p::requireUsableDelegation(delegation, now);
    CHECK_THROWS(i2p::requireUsableDelegation(delegation, delegation.transientExpires() - kInsideLapseSeconds));

    const i2p::Keys forged = todayOnly(master);
    CHECK(forged.isOffline());
    CHECK(forged.transientExpires() == master.issueTransient(kLongTermDays).transientExpires());
    CHECK(forged.b33OfflineKeysCover(now, now + 1));
    CHECK(!forged.b33OfflineKeysCover(now, forged.transientExpires()));
    CHECK_THROWS(i2p::requireUsableDelegation(forged, now));

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
