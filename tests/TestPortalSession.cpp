// Bazarish project (c) 2026
#include "bazarish/PortalSession.hpp"

#include "TestUtil.hpp"

#include <cstdint>
#include <string>

using bazarish::service::PortalSession;

namespace {

constexpr std::int64_t kTtl = 60;
constexpr std::int64_t kNow = 1000;

}  // namespace

int main()
{
    PortalSession sessions("secret", kTtl);
    const std::string first = sessions.issue("alice", kNow);
    const std::string second = sessions.issue("alice", kNow + 1);
    CHECK(sessions.verify(first, kNow) == "alice");

    sessions.revoke(first, kNow);
    CHECK_THROWS((void)sessions.verify(first, kNow));
    CHECK(sessions.verify(second, kNow + 1) == "alice");

    sessions.revoke("not.a-token", kNow);
    sessions.revoke(second, kNow + kTtl + 1);
    CHECK(sessions.verify(second, kNow + 1) == "alice");
    return 0;
}
