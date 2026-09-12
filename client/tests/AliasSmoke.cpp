// Bazarish project (c) 2026
//
// Live end-to-end against a running alias resolver, over real I2P. Not a unit
// test - it needs the network and a resolver that is actually up - so it is
// built but never registered with ctest, like i2p_smoke beside it.
//
// What no automated layer can reach is exactly this: that the coordinate a build
// ships with names a daemon that answers, that the frame survives the real
// transport, and that what comes back verifies against the root the client was
// built with rather than against a root the test handed itself.
//
// Run:  alias_smoke [alias-to-resolve]
// The coordinate is the compiled-in one unless BAZARISH_RESOLVER_ROOT and
// BAZARISH_RESOLVER_DEST are set.

#include "Client.hpp"
#include "FederationFetch.hpp"
#include "ResolverConfig.hpp"

#include <bazarish/AliasMaintenance.hpp>
#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Resolve.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
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

ResolverCoordinate coordinate()
{
    ResolverCoordinate resolver = defaultResolverCoordinate();
    if (const char* const root = std::getenv("BAZARISH_RESOLVER_ROOT");
        root != nullptr && root[0] != '\0') {
        resolver.rootFingerprint = root;
    }
    if (const char* const dest = std::getenv("BAZARISH_RESOLVER_DEST");
        dest != nullptr && dest[0] != '\0') {
        resolver.dest = dest;
    }
    return resolver;
}

}  // namespace

int main(const int argc, const char** argv)
{
    const std::string alias = argc > 1 ? argv[1] : "nobodyhasthis";
    const ResolverCoordinate resolver = coordinate();
    if (!resolver.configured()) {
        std::printf("[alias] no resolver coordinate compiled in or in the environment\n");
        return 2;
    }
    std::printf("[alias] root=%s\n[alias] dest=%s\n", resolver.rootFingerprint.c_str(),
        resolver.dest.c_str());

    bazarish::i2p::Router router({});
    router.start();
    for (int waited = 0; waited < kRouterWaitSeconds && !router.ready(); ++waited) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    if (!router.ready()) {
        std::printf("[alias] router never became ready\n");
        return 1;
    }
    std::printf("[alias] router ready\n");

    // The transport a client really uses: a throwaway destination per exchange,
    // dialled straight at the resolver, with our own server nowhere in it.
    const FetchTransport transport = [&router](const std::string& toDest, const std::string& op,
                                         const Bytes& body) {
        return federationFetchOverI2p(router, toDest, op, body, bazarish::i2p::Privacy::eMinimal,
            "alias-smoke");
    };

    int failures = 0;

    // --- A resolve, over the real thing ---
    // A name nobody holds is the useful negative here: a typed ALIAS_UNKNOWN can
    // only come from a daemon that received the frame, parsed it and answered.
    try {
        const Descriptor descriptor
            = Client::resolveAlias(alias, resolver, nowSeconds(), transport);
        std::printf("[alias] RESOLVE ok: %s -> %s at %s\n", alias.c_str(),
            descriptor.fingerprint.c_str(), descriptor.dest.c_str());
    } catch (const std::exception& error) {
        const std::string what = error.what();
        if (what.find("ALIAS_UNKNOWN") != std::string::npos) {
            std::printf("[alias] RESOLVE reached the daemon: %s is not registered\n",
                alias.c_str());
        } else {
            std::printf("[alias] RESOLVE FAILED: %s\n", what.c_str());
            ++failures;
        }
    }

    // --- A signed status, verified against the compiled-in root ---
    // This is the whole trust path in one exchange: our signature names us, the
    // answer is signed by a key the root delegated, and the chain is checked
    // against the root this binary was built with. No name and no money needed.
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
