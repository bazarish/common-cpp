// Bazarish project (c) 2026

#include "Client.hpp"
#include "FederationFetch.hpp"
#include "ResolverConfig.hpp"

#include <bazarish/AliasMaintenance.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Errors.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <ctime>
#include <exception>
#include <string>
#include <thread>

using namespace bazarish;
using namespace bazarish::client;

namespace {

constexpr int kRouterWaitSeconds = 300;

std::int64_t nowSeconds()
{
    return static_cast<std::int64_t>(std::time(nullptr));
}

}  // namespace

int main(const int argc, const char** argv)
{
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    const std::string alias = argc > 1 ? argv[1] : "nobodyhasthis";
    const ResolverCoordinate resolver = defaultResolverCoordinate();
    if (!resolver.configured()) {
        std::printf("[alias] no resolver coordinate compiled in\n");
        return 2;
    }
    std::printf("[alias] root=%s\n[alias] dest=%s\n", resolver.rootFingerprint.c_str(),
        resolver.dest.c_str());

    const std::string dataDir = argc > 2 ? argv[2] : "/tmp/baz-alias-smoke";
    bazarish::i2p::RouterConfig routerConfig;
    routerConfig.dataDir = dataDir;
    routerConfig.role = bazarish::i2p::Role::eClient;
    bazarish::i2p::Router router(routerConfig);
    std::printf("[alias] waiting for router in %s...\n", dataDir.c_str());
    router.waitReady(std::chrono::seconds(kRouterWaitSeconds));
    if (!router.ready()) {
        std::printf("[alias] router never became ready\n");
        return 1;
    }
    std::printf("[alias] router ready, knownRouters=%d\n", router.knownRouters());

    const FetchTransport transport = [&router](const std::string& host, const std::string& op,
                                         const Bytes& body) {
        return resolverFetchOverI2p(router, host, op, body, bazarish::i2p::Privacy::eMinimal,
            "alias-smoke");
    };

    int failures = 0;

    try {
        const Descriptor descriptor
            = Client::resolveAlias(alias, resolver, nowSeconds(), transport);
        std::printf("[alias] RESOLVE ok: %s -> %s at %s\n", alias.c_str(),
            descriptor.fingerprint.c_str(), descriptor.dest.c_str());
    } catch (const std::exception& error) {
        const std::string what = error.what();
        if (what == readable(ErrorCode::eAliasUnknown)) {
            std::printf("[alias] RESOLVE reached the daemon: %s is not registered\n",
                alias.c_str());
        } else {
            std::printf("[alias] RESOLVE FAILED: %s\n", what.c_str());
            ++failures;
        }
    }

    try {
        const Identity me = Identity::generate();
        AliasMaintenanceRequest asking;
        asking.op = kAliasStatusOp;
        asking.issuedAt = nowSeconds();
        const Bytes request = signAliasMaintenanceRequest(asking, me);

        const FetchOutcome outcome = transport(resolver.dest, kAliasStatusOp, request);
        if (!outcome.ok) {
            std::printf("[alias] STATUS refused: %s\n",
                outcome.errorCode.empty() ? "no answer" : outcome.errorCode.c_str());
            ++failures;
        } else {
            const ResolveResponse answer
                = resolveResponseFromJson(nlohmann::json::parse(outcome.sealed));
            const AliasStatus status = verifyAliasStatus(answer.recordDer, answer.delegationDer,
                resolver.rootFingerprint, nowSeconds());
            if (status.owner != me.fingerprint()) {
                std::printf("[alias] STATUS FAILED: answered about somebody else\n");
                ++failures;
            } else {
                std::printf("[alias] STATUS ok: signed by the delegated key, verified against the "
                            "compiled-in root, %zu name(s)\n",
                    status.names.size());
            }
        }
    } catch (const std::exception& error) {
        std::printf("[alias] STATUS FAILED: %s\n", error.what());
        ++failures;
    }

    router.stop();
    std::printf("[alias] RESULT %s\n", failures == 0 ? "OK" : "FAILED");
    return failures == 0 ? 0 : 1;
}
