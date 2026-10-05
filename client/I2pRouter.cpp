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
constexpr std::size_t kWarmPoolSize = 2;
constexpr int kWarmPoolTunnelQuantity = 3;

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

std::unique_ptr<WarmDestPool>& warmPoolSlot()
{
    static std::unique_ptr<WarmDestPool> pool;
    return pool;
}

std::mutex& facadeLinksMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, std::weak_ptr<bazarish::i2p::Endpoint>>& facadeLinks()
{
    static std::map<std::string, std::weak_ptr<bazarish::i2p::Endpoint>> links;
    return links;
}

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
std::string g_proxyHost;
std::string g_samHost;
std::optional<GatewayAddress> g_gateway;
std::string g_gatewayPin;
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

void setGatewayTransport(const GatewayAddress& address, std::string pin)
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_gateway = address;
    g_gatewayPin = std::move(pin);
}

bool usingGatewayTransport()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return g_gateway.has_value();
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

bazarish::i2p::RouterConfig routerConfigFor(const std::filesystem::path& dataDir)
{
    bazarish::i2p::RouterConfig config;
    config.dataDir = dataDir;
    config.role = bazarish::i2p::Role::eClient;
    config.reseedUrls = reseedUrls();
    config.socksProxyHost = i2pSocksProxyHost();
    config.socksProxyPort = i2pSocksProxyPort();
    if (usingGatewayTransport()) {
        const std::lock_guard<std::mutex> lock(proxyMutex());
        config.backend = bazarish::i2p::Backend::eGateway;
        config.gatewayHost = g_gateway->host;
        config.gatewayPort = g_gateway->port;
        config.gatewayPath = g_gateway->path;
        config.gatewayToken = g_gateway->token;
        config.gatewayTls = g_gateway->tls;
        config.gatewayPin = g_gatewayPin;
        return config;
    }
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
    ensureWarmPool(*router);
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
    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr) {
        return nullptr;
    }
    const auto build = [router, &owner, privacy]() {
        bazarish::i2p::EndpointConfig config;
        config.privacy = privacy;
        config.published = false;
        config.label = "Facade link";
        config.owner = owner;
        return router->createEndpoint(config);
    };
    if (owner.empty()) {
        return build();
    }
    const std::lock_guard<std::mutex> lock(facadeLinksMutex());
    if (const std::shared_ptr<bazarish::i2p::Endpoint> existing = facadeLinks()[owner].lock()) {
        if (!existing->lost()) {
            return existing;
        }
        facadeLinks().erase(owner);
    }
    const std::shared_ptr<bazarish::i2p::Endpoint> link = build();
    facadeLinks()[owner] = link;
    return link;
}

void stopFacadeLinkFor(const std::string& owner)
{
    std::shared_ptr<bazarish::i2p::Endpoint> link;
    {
        const std::lock_guard<std::mutex> lock(facadeLinksMutex());
        const auto found = facadeLinks().find(owner);
        if (found == facadeLinks().end()) {
            return;
        }
        link = found->second.lock();
        facadeLinks().erase(found);
    }
    if (link) {
        link->stop();
    }
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
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router || !router->capabilities().proxy) {
        return;
    }
    router->setSocksProxy(i2pSocksProxyHost(), i2pSocksProxyPort());
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
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router || !router->running()) {
        return std::nullopt;
    }
    if (!router->capabilities().proxy) {
        return std::nullopt;
    }
    return router->proxyState();
}

void restartI2pRouter(const std::filesystem::path& dataDir)
{
    (void)dataDir;
    if (usingSamTransport() || usingGatewayTransport()) {
        return;
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (!router) {
        return;
    }
    stopWarmPool();
    router->stop();
    if (router->capabilities().proxy) {
        router->setSocksProxy(i2pSocksProxyHost(), i2pSocksProxyPort());
    }
    router->start();
    ensureWarmPool(*router);
}

void reconcileI2pRouter(const std::filesystem::path& dataDir)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (g_i2pEnabled.load()) {
        if (!router) {
            try {
                router = std::make_unique<bazarish::i2p::Router>(routerConfigFor(dataDir));
            } catch (const std::exception& error) {
                bazarish::log::warn("i2p: no transport: {}", error.what());
                return;
            }
        } else {
            router->start();
        }
        ensureWarmPool(*router);
    } else if (router) {
        stopWarmPool();
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
