// Bazarish project (c) 2026
#include "LinkFailure.hpp"

#include "TestUtil.hpp"

#include <bazarish/I2pHttp.hpp>

#include <cstdio>

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
{
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eRouter)) == LinkFailure::eI2pUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eLink)) == LinkFailure::eI2pUnreachable);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eTunnels))
        == LinkFailure::eTunnelsBuilding);
    CHECK(classifyLinkFailure(false, reaching(LinkStage::eDial))
        == LinkFailure::eServerUnreachable);
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

    CHECK(classifyLinkFailure(true, answered(bazarish::kI2pHttpBadGateway))
        == LinkFailure::eNoNetwork);
    CHECK(classifyLinkFailure(true, reaching(LinkStage::eTunnels)) == LinkFailure::eNoNetwork);

    std::printf("TestLinkFailure ok\n");
    return 0;
}
