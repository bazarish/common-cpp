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

void setReseedUrls(std::vector<std::string> urls)
{
    const std::lock_guard<std::mutex> lock(facadesMutex());
    facadesSlot() = std::move(urls);
}

std::vector<std::string> reseedUrls()
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

// Everything a router needs to know about which transport it is, in one place:
// two call sites build one, and they must not drift apart.
bazarish::i2p::RouterConfig routerConfigFor(const std::filesystem::path& dataDir)
{
    bazarish::i2p::RouterConfig config;
    config.dataDir = dataDir;
    config.role = bazarish::i2p::Role::eClient;
    config.reseedUrls = reseedUrls();
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
        // The engine bootstraps itself now: it is given the reseed addresses this
        // account's server named, or - with none - the ones it carries. There is
        // nothing to wait for before starting it, and waiting was what left a
        // client with an empty netDb sitting there forever.
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
