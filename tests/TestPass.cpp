// Bazarish project (c) 2026
#include "bazarish/Pass.hpp"

#include "bazarish/Bytes.hpp"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <stdexcept>
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

namespace {

const std::string kAlice = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const std::string kBob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// How many times the same pass is asked for, to show it is the same answer every
// time. A token was never repeated; this is the property that replaces it.
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

    // A pass is the account's secret and one correspondent, and nothing else.
    // Ask for it as often as you like and it is the same answer: that is what
    // lets every device of a correspondent present one value.
    const Bytes forBob = deliveryPass(secret, kBob);
    CHECK(forBob.size() == kDeliveryPassSize);
    for (int i = 0; i < kRepeats; ++i) {
        CHECK(deliveryPass(secret, kBob) == forBob);
    }
    CHECK(deliveryPass(secret, kAlice) != forBob);
    CHECK(deliveryPass(other, kBob) != forBob);

    CHECK(throws([&]() { deliveryPass(Bytes{1, 2, 3}, kBob); }));
    CHECK(throws([&]() { deliveryPass(secret, ""); }));

    // What the server registers is the hash: it can recognise a pass presented
    // to it and cannot produce one from what it holds.
    const Bytes handle = deliveryPassHandle(forBob);
    CHECK(handle.size() == kDeliveryPassSize);
    CHECK(handle != forBob);
    CHECK(deliveryPassHandle(forBob) == handle);
    CHECK(deliveryPassHandle(deliveryPass(secret, kAlice)) != handle);
    CHECK(throws([&]() { deliveryPassHandle(Bytes{1, 2, 3}); }));

    std::printf("TestPass: ok\n");
    return 0;
}
