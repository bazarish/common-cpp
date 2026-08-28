// Bazarish project (c) 2026
#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include "WarmDestPool.hpp"

#include <atomic>
#include <cstddef>
#include <memory>
#include <map>
#include <mutex>

namespace bazarish::client {

namespace {
// A small, fixed warm pool of single-use throwaway dests (no demand-driven sizing),
// with a small tunnel quantity - enough to cover the two direct fetches that want a
// one-time dest (card + resolve) without paying cold tunnel-build latency.
constexpr std::size_t kWarmPoolSize = 2;
constexpr int kWarmPoolTunnelQuantity = 3;

// Whether spares are wanted at all; see setWarmDestsWanted.
std::atomic<bool> g_warmDestsWanted{true};

std::mutex& routerMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::unique_ptr<bazarish::i2p::Router>& routerSlot()
{
    static std::unique_ptr<bazarish::i2p::Router> router;
    return router;
}

// Owned in this TU and constructed after routerSlot (its slot is first touched only
// after the router exists), so at process exit it is destroyed first - its warmer
// thread is joined while the router is still alive.
std::unique_ptr<WarmDestPool>& warmPoolSlot()
{
    static std::unique_ptr<WarmDestPool> pool;
    return pool;
}

// Brings the warm pool up alongside a running router. Call under routerMutex.
void ensureWarmPool(bazarish::i2p::Router& router)
{
    if (!g_warmDestsWanted.load()) {
        return;
    }
    std::unique_ptr<WarmDestPool>& pool = warmPoolSlot();
    if (!pool) {
        pool = std::make_unique<WarmDestPool>(
            router, kWarmPoolSize, kWarmPoolTunnelQuantity);
        pool->start();
    }
}

// Tears the warm pool down (joins its warmer) before the router stops. Call under
// routerMutex.
void stopWarmPool()
{
    std::unique_ptr<WarmDestPool>& pool = warmPoolSlot();
    if (pool) {
        pool->stop();
        pool.reset();
    }
}

std::atomic<bool> g_i2pEnabled{true};
std::atomic<bazarish::i2p::Privacy> g_tunnelPrivacy{bazarish::i2p::Privacy::eMinimal};
// Strict by default: the netDb comes from our own server, not a public host.
std::atomic<bool> g_publicReseedAllowed{false};
// The SOCKS5 proxy the router's clearnet side goes through, empty by default.
// A string needs a mutex where a flag needs none.
std::string g_proxyHost;
// Where the external router is, when one is used at all. Empty means the engine
// in this process. Shares the proxy mutex: both are settings read when a router
// is built.
std::string g_samHost;
int g_samPort = 0;
int g_proxyPort = 0;

std::mutex& proxyMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::mutex& progressMutex()
{
    static std::mutex mutex;
    return mutex;
}

ConnectProgressFn& progressSink()
{
    static ConnectProgressFn sink;
    return sink;
}
// Full privacy mode (default off): when on, the transport refuses every clearnet
// facade, so all traffic runs over I2P (and an account with no I2P facade is
// explicitly offline). Consulted at request time, like g_i2pEnabled.
}  // namespace

namespace {
std::mutex& noticeMutex()
{
    static std::mutex mutex;
    return mutex;
}
BootstrapNoticeFn& noticeSink()
{
    static BootstrapNoticeFn sink;
    return sink;
}
}  // namespace

void setBootstrapNoticeSink(BootstrapNoticeFn sink)
{
    const std::lock_guard<std::mutex> lock(noticeMutex());
    noticeSink() = std::move(sink);
}

void reportBootstrapNotice(const std::string& message)
{
    BootstrapNoticeFn sink;
    {
        const std::lock_guard<std::mutex> lock(noticeMutex());
        sink = noticeSink();
    }
    if (sink) {
        sink(message);
    }
}

namespace {
std::mutex& facadesMutex()
{
    static std::mutex mutex;
    return mutex;
}
std::vector<std::string>& facadesSlot()
{
    static std::vector<std::string> facades;
    return facades;
}
}  // namespace

void setReseedFacades(std::vector<std::string> urls)
{
    const std::lock_guard<std::mutex> lock(facadesMutex());
    facadesSlot() = std::move(urls);
}

std::vector<std::string> reseedFacades()
{
    const std::lock_guard<std::mutex> lock(facadesMutex());
    return facadesSlot();
}

std::size_t knownRouterCount(const std::filesystem::path& dataDir, const std::size_t limit)
{
    std::error_code ec;
    const std::filesystem::path netDb = dataDir / "netDb";
    if (!std::filesystem::exists(netDb, ec)) {
        return 0;
    }
    // i2pd files them under one directory per leading character, so the count
    // is of the leaves, not of the buckets.
    std::size_t count = 0;
    std::filesystem::recursive_directory_iterator entries(netDb, ec);
    if (ec) {
        return 0;
    }
    for (const std::filesystem::directory_entry& entry : entries) {
        if (entry.is_regular_file(ec)) {
            ++count;
            if (count >= limit) {
                break;
            }
        }
    }
    return count;
}

void setSamTransport(std::string host, const int port)
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_samHost = std::move(host);
    g_samPort = port;
}

bool usingSamTransport()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return !g_samHost.empty();
}

std::string samTransportHost()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return g_samHost;
}

int samTransportPort()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return g_samPort;
}

bool seedRouterOnce(
    const std::filesystem::path& dataDir, const std::function<std::vector<Bytes>()>& fetch)
{
    if (!fetch) {
        return false;
    }
    if (usingSamTransport()) {
        return true;  // an external router keeps its own netDb
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    // Answered once: this sits on the path of every request that may go over I2P.
    static bool netDbReady = false;
    if (netDbReady) {
        return true;
    }
    // Not "is there a netDb" but "is there enough of one": a directory with a
    // handful of stale routers is a router that cannot build a tunnel and will
    // sit there trying. A running engine answers nothing here - it may well be
    // the one sitting there with an empty netDb.
    if (knownRouterCount(dataDir) >= kMinKnownRouters) {
        netDbReady = true;
        return true;
    }
    std::size_t written = 0;
    try {
        written = bazarish::i2p::seedRouterInfos(dataDir, fetch());
        bazarish::log::info("private reseed: {} routers", written);
    } catch (const std::exception& error) {
        bazarish::log::info("private reseed unavailable: {}", error.what());
        return false;
    }
    if (written == 0) {
        return false;
    }
    // The engine reads its netDb when its network starts, so one that is already
    // up knows nothing of the files just written until it is cycled.
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (router && router->running()) {
        stopWarmPool();
        router->stop();
        router->start();
        ensureWarmPool(*router);
    }
    netDbReady = true;
    return true;
}

// Everything a router needs to know about which transport it is, in one place:
// two call sites build one, and they must not drift apart.
bazarish::i2p::RouterConfig routerConfigFor(const std::filesystem::path& dataDir)
{
    bazarish::i2p::RouterConfig config;
    config.dataDir = dataDir;
    config.role = bazarish::i2p::Role::eClient;
    config.allowPublicReseed = g_publicReseedAllowed.load();
    config.socksProxyHost = i2pSocksProxyHost();
    config.socksProxyPort = i2pSocksProxyPort();
    if (usingSamTransport()) {
        config.backend = bazarish::i2p::Backend::eSam;
        config.samHost = samTransportHost();
        config.samControlPort = samTransportPort();
    }
    return config;
}

bazarish::i2p::Router& sharedI2pRouter(const std::filesystem::path& dataDir)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router) {
        router = std::make_unique<bazarish::i2p::Router>(routerConfigFor(dataDir));
    } else if (!router->running()) {
        router->start();
    }
    ensureWarmPool(*router);  // keep a couple of throwaway dests warm for direct fetches
    return *router;
}

bazarish::i2p::Router* sharedI2pRouterIfRunning()
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    bazarish::i2p::Router* const router = routerSlot().get();
    return (router != nullptr && router->running()) ? router : nullptr;
}

std::shared_ptr<bazarish::i2p::Endpoint> facadeLinkFor(
    const std::string& owner, const bazarish::i2p::Privacy privacy)
{
    static std::mutex linksMutex;
    static std::map<std::string, std::weak_ptr<bazarish::i2p::Endpoint>> links;

    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr) {
        return nullptr;  // the caller starts the router first
    }
    const auto build = [router, &owner, privacy]() {
        return router->createEndpoint(bazarish::i2p::EndpointConfig{
            router->generateKeys(), bazarish::i2p::LeaseSetKind::eEncrypted, privacy,
            bazarish::i2p::kDefaultTunnelQuantity, /*published=*/false, "Facade link", owner});
    };
    // One per account. Both of an account's clients - the transport and the request
    // parked waiting for news - dial through it; they need their own request
    // queues, not their own addresses, and a destination carries many streams at
    // once. Held by weak_ptr, so it goes down with its last user.
    if (owner.empty()) {
        return build();  // nothing to share it with
    }
    const std::lock_guard<std::mutex> lock(linksMutex);
    if (const std::shared_ptr<bazarish::i2p::Endpoint> existing = links[owner].lock()) {
        return existing;
    }
    const std::shared_ptr<bazarish::i2p::Endpoint> link = build();
    links[owner] = link;
    return link;
}

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest()
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    WarmDestPool* const pool = warmPoolSlot().get();
    return pool != nullptr ? pool->acquire() : nullptr;
}

void setI2pSocksProxy(std::string host, const int port)
{
    {
        const std::lock_guard<std::mutex> lock(proxyMutex());
        g_proxyHost = std::move(host);
        g_proxyPort = port;
    }
    if (usingSamTransport()) {
        return;  // the clearnet side of an external router is its operator's
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    if (const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot(); router) {
        // Written into the engine now; the transports read it as they come up.
        router->setSocksProxy(i2pSocksProxyHost(), i2pSocksProxyPort());
    }
}

std::string i2pSocksProxyHost()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return g_proxyHost;
}

int i2pSocksProxyPort()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return g_proxyPort;
}

std::optional<bazarish::i2p::ProxyState> i2pProxyState()
{
    if (usingSamTransport()) {
        return std::nullopt;
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router || !router->running()) {
        return std::nullopt;
    }
    return router->proxyState();
}

void restartI2pRouter(const std::filesystem::path& dataDir)
{
    (void)dataDir;
    if (usingSamTransport()) {
        return;  // there is no engine here to cycle
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router) {
        return;  // nothing running: the next start reads the setting
    }
    stopWarmPool();  // join the warmer before the router's network stops
    router->stop();
    router->setSocksProxy(i2pSocksProxyHost(), i2pSocksProxyPort());
    router->start();
    ensureWarmPool(*router);
}

void reconcileI2pRouter(const std::filesystem::path& dataDir)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (g_i2pEnabled.load()) {
        // An engine started on an empty netDb has nobody to learn the network
        // from: it builds no tunnel, and every destination it is asked for dies
        // waiting. Left down until an account hands it a netDb (or public reseeds
        // are allowed), which is also what starts it.
        // The gate below is about this process's own netDb, which an external
        // router does not have and does not need.
        if (!router && !usingSamTransport() && !g_publicReseedAllowed.load()
            && knownRouterCount(dataDir) < kMinKnownRouters) {
            bazarish::log::info(
                "i2p: not starting on {} known routers - waiting for a bootstrap",
                knownRouterCount(dataDir));
            return;
        }
        if (!router) {
            try {
                router = std::make_unique<bazarish::i2p::Router>(routerConfigFor(dataDir));
            } catch (const std::exception& error) {
                // An external router that is not answering leaves this process
                // with no transport at all, which is worth saying rather than
                // retrying silently on every reconcile.
                bazarish::log::warn("i2p: no transport: {}", error.what());
                return;
            }
        } else {
            router->start();
        }
        ensureWarmPool(*router);
    } else if (router) {
        stopWarmPool();  // join the warmer before the router's network stops
        router->stop();
    }
}

void setConnectProgressSink(ConnectProgressFn sink)
{
    const std::lock_guard<std::mutex> lock(progressMutex());
    progressSink() = std::move(sink);
}

void reportConnectProgress(const int percent, const std::string& text)
{
    ConnectProgressFn sink;
    {
        const std::lock_guard<std::mutex> lock(progressMutex());
        sink = progressSink();
    }
    if (sink) {
        sink(percent, text);
    }
}

void setPublicReseedAllowed(bool allowed)
{
    g_publicReseedAllowed.store(allowed);
}

bool publicReseedAllowed()
{
    return g_publicReseedAllowed.load();
}

void setI2pEnabled(bool enabled)
{
    g_i2pEnabled.store(enabled);
}

bool i2pEnabled()
{
    return g_i2pEnabled.load();
}

void setTunnelPrivacy(const bazarish::i2p::Privacy privacy)
{
    g_tunnelPrivacy.store(privacy);
}

bazarish::i2p::Privacy tunnelPrivacy()
{
    return g_tunnelPrivacy.load();
}

void setWarmDestsWanted(const bool wanted)
{
    g_warmDestsWanted.store(wanted);
    const std::lock_guard<std::mutex> lock(routerMutex());
    bazarish::i2p::Router* const router = routerSlot().get();
    if (!wanted) {
        stopWarmPool();
    } else if (router != nullptr && router->running()) {
        ensureWarmPool(*router);
    }
}

void flushWarmDests()
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    if (WarmDestPool* const pool = warmPoolSlot().get(); pool != nullptr) {
        pool->flush();
    }
}

}  // namespace bazarish::client
