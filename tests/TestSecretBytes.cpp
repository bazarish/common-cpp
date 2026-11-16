// Bazarish project (c) 2026
#include "bazarish/SecretBytes.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <cstdio>
#include <stdexcept>
#include <utility>

using namespace bazarish;

namespace {

constexpr std::size_t kSecretBytes = 32;
constexpr std::size_t kShorter = 16;

bool allZero(const Bytes& bytes)
{
    return std::all_of(bytes.begin(), bytes.end(), [](const unsigned char b) { return b == 0; });
}

}  // namespace

int main()
try {
    const Bytes value = randomBytes(kSecretBytes);
    CHECK(!allZero(value));

    {
        SecretBytes secret(value);
        CHECK(secret.bytes() == value);
        secret.wipe();
        CHECK(secret.size() == kSecretBytes);
        CHECK(allZero(secret.bytes()));
    }

    {
        SecretBytes secret(value);
        const unsigned char* const held = secret.bytes().data();
        SecretBytes taken(std::move(secret));
        CHECK(taken.bytes().data() == held);
        CHECK(secret.empty());
        SecretBytes assigned;
        assigned = std::move(taken);
        CHECK(assigned.bytes() == value);
        CHECK(taken.empty());
        assigned = SecretBytes(randomBytes(kSecretBytes));
        CHECK(assigned.bytes() != value);
        assigned.clear();
        CHECK(assigned.empty());
    }

    {
        SecretBytes secret(value);
        const SecretBytes copy = secret;
        CHECK(copy == secret);
        secret.resize(kShorter);
        CHECK(secret.bytes() == Bytes(value.begin(), value.begin() + kShorter));
        CHECK_THROWS(secret.resize(kSecretBytes));
        CHECK(!(copy == secret));
    }

    {
        SecretBytes secret(value);
        const Bytes released = secret.release();
        CHECK(released == value);
        CHECK(secret.empty());
    }

    {
        const SecretBytes secret(Bytes{0x0a, 0xff});
        const SecretBytes line = secretHexLine(secret, "|tail");
        const std::string expected = toHex(secret.bytes()) + "|tail";
        CHECK(line.bytes() == Bytes(expected.begin(), expected.end()));
    }

    {
        for (std::size_t length = 0; length <= kSecretBytes; ++length) {
            const Bytes data = randomBytes(length);
            const std::string expected = toBase64(data);
            CHECK(secretBase64(data).bytes() == Bytes(expected.begin(), expected.end()));
        }
        SecretBytes grown(Bytes{'a'});
        grown.append(Bytes{'b', 'c'});
        CHECK(grown.bytes() == (Bytes{'a', 'b', 'c'}));
    }

    std::printf("TestSecretBytes OK\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
