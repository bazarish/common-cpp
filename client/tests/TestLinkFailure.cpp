// Bazarish project (c) 2026
#include "Client.hpp"
#include "FailureCause.hpp"
#include "LinkFailure.hpp"

#include "TestUtil.hpp"

#include <bazarish/I2p.hpp>
#include <bazarish/I2pHttp.hpp>

#include <cstdio>
#include <stdexcept>

using namespace bazarish::client;

namespace {

constexpr int kOk = 200;
constexpr int kUnauthorized = 401;
constexpr int kServiceUnavailable = 503;

LinkAttempt reaching(const LinkStage stage, const bool viaGateway = false)
{
    LinkAttempt attempt;
    attempt.reached = stage;
    attempt.viaGateway = viaGateway;
    attempt.gatewayReady = viaGateway;
    return attempt;
}

LinkAttempt answered(const int status)
{
    LinkAttempt attempt = reaching(LinkStage::eExchange);
    attempt.status = status;
    return attempt;
}

}  // namespace

int main()
try {
    CHECK(causeOf(FetchFailed(FetchFailure::eLeaseSetNotFound, "no lease set"))
        == linkCause(LinkFailure::eServerUnreachable));
    CHECK(causeOf(FetchFailed(FetchFailure::eProtocol, "does not read"))
        == linkCause(LinkFailure::eServerMalformed));
    CHECK(causeOf(LinkError(LinkFailure::eTunnelsBuilding, "building"))
        == linkCause(LinkFailure::eTunnelsBuilding));
    CHECK(causeOf(LinkError(LinkFailure::eNone, "the answer's own word"))
        == linkCause(LinkFailure::eServerRefused));
    CHECK(!carriedCause(LinkError(LinkFailure::eNone, "the answer's own word")).has_value());
    CHECK(causeOf(bazarish::i2p::GatewayRefusal("no")) == linkCause(LinkFailure::eGatewayRefused));
    CHECK(causeOf(LocalError(LocalFailure::eFileGone, "gone")) == localCause(LocalFailure::eFileGone));
    CHECK(causeOf(std::runtime_error("anything else")) == localCause(LocalFailure::eInternal));
    CHECK(!carriedCause(std::runtime_error("anything else")).has_value());
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eRouter)) == LinkFailure::eI2pUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eLink)) == LinkFailure::eI2pUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eTunnels))
        == LinkFailure::eTunnelsBuilding);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eDial))
        == LinkFailure::eServerUnreachable);
    LinkAttempt notFound = reaching(LinkStage::eDial);
    notFound.dialEndedEarly = true;
    CHECK(classifyLinkFailure(false, notFound) == LinkFailure::eAddressNotFound);
    CHECK(classifyLinkFailure(true, notFound) == LinkFailure::eNoNetwork);
    LinkAttempt brokeLate = reaching(LinkStage::eExchange);
    brokeLate.dialEndedEarly = true;
    CHECK(classifyLinkFailure(false, brokeLate) == LinkFailure::eServerUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eExchange))
        == LinkFailure::eServerUnreachable);

    CHECK(classifyLinkFailure(false, answered(bazarish::kI2pHttpBadGateway))
        == LinkFailure::eServerDown);
    CHECK(classifyLinkFailure(false, answered(kServiceUnavailable))
        == LinkFailure::eServerRefused);
    CHECK(classifyLinkFailure(false, answered(kUnauthorized)) == LinkFailure::eServerRefused);
    CHECK(classifyLinkFailure(false, answered(kOk)) == LinkFailure::eNone);

    CHECK(classifyLinkFailure(false, reaching(LinkStage::eLink, true))
        == LinkFailure::eGatewayUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eTunnels, true))
        == LinkFailure::eTunnelsBuilding);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eDial, true))
        == LinkFailure::eServerUnreachable);
    {
        LinkAttempt gatewayGone = reaching(LinkStage::eDial, true);
        gatewayGone.gatewayReady = false;
        CHECK(classifyLinkFailure(false, gatewayGone) == LinkFailure::eGatewayUnreachable);
    }
    {
        LinkAttempt refused = reaching(LinkStage::eLink, true);
        refused.gatewayRefused = true;
        CHECK(classifyLinkFailure(false, refused) == LinkFailure::eGatewayRefused);
    }

    {
        LinkAttempt unreadable = reaching(LinkStage::eExchange);
        unreadable.malformed = true;
        CHECK(classifyLinkFailure(false, unreadable) == LinkFailure::eServerMalformed);
        CHECK(classifyLinkFailure(true, unreadable) == LinkFailure::eNoNetwork);
        unreadable.gatewayRefused = true;
        CHECK(classifyLinkFailure(false, unreadable) == LinkFailure::eGatewayRefused);
    }

    CHECK(classifyLinkFailure(true, answered(bazarish::kI2pHttpBadGateway))
        == LinkFailure::eNoNetwork);
    CHECK(classifyLinkFailure(true, reaching(LinkStage::eTunnels)) == LinkFailure::eNoNetwork);

    std::printf("TestLinkFailure ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
