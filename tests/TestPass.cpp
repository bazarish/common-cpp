// Bazarish project (c) 2026
#include "bazarish/Pass.hpp"

#include "bazarish/Bytes.hpp"

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <stdexcept>
#include <string>

using namespace bazarish;

namespace {

const std::string kAlice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const std::string kBob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

constexpr int kRepeats = 64;

bool throws(const std::function<void()>& what)
{
    try {
        what();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

}  // namespace

int main()
{
    const Bytes secret = randomBytes(kDeliverySecretSize);
    const Bytes other = randomBytes(kDeliverySecretSize);

    const Bytes forBob = deliveryPass(secret, kBob);
    CHECK(forBob.size() == kDeliveryPassSize);
    for (int i = 0; i < kRepeats; ++i) {
        CHECK(deliveryPass(secret, kBob) == forBob);
    }
    CHECK(deliveryPass(secret, kAlice) != forBob);
    CHECK(deliveryPass(other, kBob) != forBob);

    CHECK(throws([&]() { deliveryPass(Bytes{1, 2, 3}, kBob); }));
    CHECK(throws([&]() { deliveryPass(secret, ""); }));

    const Bytes handle = deliveryPassHandle(forBob);
    CHECK(handle.size() == kDeliveryPassSize);
    CHECK(handle != forBob);
    CHECK(deliveryPassHandle(forBob) == handle);
    CHECK(deliveryPassHandle(deliveryPass(secret, kAlice)) != handle);
    CHECK(throws([&]() { deliveryPassHandle(Bytes{1, 2, 3}); }));

    std::printf("TestPass: ok\n");
    return 0;
}
