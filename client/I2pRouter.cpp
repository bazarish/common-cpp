// Bazarish project (c) 2026
#include "I2pRouter.hpp"

#include <bazarish/Log.hpp>

#include "Presence.hpp"
#include "WarmDestPool.hpp"

#include <chrono>
#include <thread>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <map>
#include <mutex>
#include <set>
#include <stdexcept>
#include <utility>
#include <vector>

namespace bazarish::client {

namespace {
constexpr std::size_t kWarmPoolSize = 2;
constexpr std::size_t kWarmWatcherPoolSize = 1;

std::atomic<bool> g_warmDestsWanted{true};

std::mutex& routerMutex()
{
    static std::mutex mutex;
    return mutex;
}

// Taken before routerMutex: starting and stopping a router can take a minute.
std::mutex& lifecycleMutex()
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

std::unique_ptr<WarmDestPool>& warmWatcherPoolSlot()
{
    static std::unique_ptr<WarmDestPool> pool;
    return pool;
}

std::set<std::uint64_t>& presenceWanters()
{
    static std::set<std::uint64_t> wanters;
    return wanters;
}

bazarish::i2p::EndpointConfig warmStreamShape()
{
    bazarish::i2p::EndpointConfig config;
    config.privacy = tunnelPrivacy();
    config.tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
    config.published = false;
    config.label = "Warm reserve";
    return config;
}

bazarish::i2p::EndpointConfig warmWatcherShape()
{
    bazarish::i2p::EndpointConfig config = presenceEndpointShape();
    config.label = "Warm watcher";
    return config;
}

// True when there was a pool to visit.
bool forEachWarmPool(const std::function<void(WarmDestPool&)>& visit)
{
    bool any = false;
    for (const std::reference_wrapper<std::unique_ptr<WarmDestPool>> slot :
        {std::ref(warmPoolSlot()), std::ref(warmWatcherPoolSlot())}) {
        if (slot.get() != nullptr) {
            visit(*slot.get());
            any = true;
        }
    }
    return any;
}

std::mutex& facadeLinksMutex()
{
    static std::mutex mutex;
    return mutex;
}

using FacadeLinkKey = std::pair<std::string, std::string>;

std::map<FacadeLinkKey, std::weak_ptr<bazarish::i2p::Endpoint>>& facadeLinks()
{
    static std::map<FacadeLinkKey, std::weak_ptr<bazarish::i2p::Endpoint>> links;
    return links;
}

void ensureWarmPool(bazarish::i2p::Router& router)
{
    if (!g_warmDestsWanted.load() || router.capabilities().warmPool) {
        return;
    }
    std::unique_ptr<WarmDestPool>& pool = warmPoolSlot();
    if (!pool) {
        pool = std::make_unique<WarmDestPool>(router, kWarmPoolSize, warmStreamShape);
        pool->start();
    }
    std::unique_ptr<WarmDestPool>& watchers = warmWatcherPoolSlot();
    if (!watchers && router.capabilities().lateReaderKey && !presenceWanters().empty()) {
        watchers = std::make_unique<WarmDestPool>(router, kWarmWatcherPoolSize, warmWatcherShape);
        watchers->start();
    }
}

void stopWarmPool()
{
    for (const std::reference_wrapper<std::unique_ptr<WarmDestPool>> slot :
        {std::ref(warmPoolSlot()), std::ref(warmWatcherPoolSlot())}) {
        if (slot.get() != nullptr) {
            slot.get()->stop();
            slot.get().reset();
        }
    }
}

std::atomic<bazarish::i2p::Privacy> g_tunnelPrivacy{bazarish::i2p::Privacy::eMinimal};
std::string g_proxyHost;
std::string g_samHost;
std::optional<GatewayAddress> g_gateway;
std::string g_transportRefusal;
bool g_routerRetired = false;
int g_samPort = 0;
bool g_transit = false;
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

std::map<std::string, ConnectProgressFn>& progressSinks()
{
    static std::map<std::string, ConnectProgressFn> sinks;
    return sinks;
}

std::mutex& reseedsMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::vector<std::string>& reseedsSlot()
{
    static std::vector<std::string> reseeds;
    return reseeds;
}

std::filesystem::path& reseedFileSlot()
{
    static std::filesystem::path file;
    return file;
}

bool usingSamTransport()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    return !g_samHost.empty();
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
}  // namespace

void setReseedUrls(std::vector<std::string> urls)
{
    const std::lock_guard<std::mutex> lock(reseedsMutex());
    reseedsSlot() = std::move(urls);
}

std::vector<std::string> reseedUrls()
{
    const std::lock_guard<std::mutex> lock(reseedsMutex());
    return reseedsSlot();
}

void setReseedFile(std::filesystem::path file)
{
    const std::lock_guard<std::mutex> lock(reseedsMutex());
    reseedFileSlot() = std::move(file);
}

std::size_t knownRouterCount(const std::filesystem::path& dataDir)
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
            if (count >= kMinKnownRouters) {
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

void setRouterTransit(const bool transit)
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_transit = transit;
}

void setGatewayTransport(const GatewayAddress& address)
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_gateway = address;
    g_transportRefusal.clear();
}

void clearGatewayTransport()
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_gateway.reset();
    g_transportRefusal.clear();
}

void refuseI2pTransport(std::string reason)
{
    const std::lock_guard<std::mutex> lock(proxyMutex());
    g_gateway.reset();
    g_transportRefusal = std::move(reason);
}

bool applyI2pTransport(const std::function<void()>& set)
{
    const std::lock_guard<std::mutex> lifecycle(lifecycleMutex());
    {
        const std::lock_guard<std::mutex> lock(routerMutex());
        if (routerSlot() != nullptr || g_routerRetired) {
            return false;
        }
    }
    set();
    return true;
}

void retireI2pRouter()
{
    const std::lock_guard<std::mutex> lifecycle(lifecycleMutex());
    std::optional<std::reference_wrapper<bazarish::i2p::Router>> router;
    {
        const std::lock_guard<std::mutex> lock(routerMutex());
        g_routerRetired = true;
        if (routerSlot() == nullptr) {
            return;
        }
        router = std::ref(*routerSlot());
        stopWarmPool();
    }
    router->get().stop();
}

bool repointGatewayTransport(const GatewayAddress& address)
{
    const std::lock_guard<std::mutex> lifecycle(lifecycleMutex());
    std::optional<std::reference_wrapper<bazarish::i2p::Router>> running;
    {
        const std::lock_guard<std::mutex> lock(routerMutex());
        if (g_routerRetired) {
            return false;
        }
        if (routerSlot() != nullptr) {
            running = std::ref(*routerSlot());
        }
    }
    if (running.has_value() && !usingGatewayTransport()) {
        return false;
    }
    setGatewayTransport(address);
    if (running.has_value()) {
        running->get().repointGateway(
            {address.host, address.port, address.path, address.fingerprint, address.tls});
    }
    return true;
}

bazarish::i2p::RouterConfig routerConfigFor(const std::filesystem::path& dataDir)
{
    {
        const std::lock_guard<std::mutex> lock(proxyMutex());
        if (!g_transportRefusal.empty()) {
            throw std::runtime_error(g_transportRefusal);
        }
    }
    bazarish::i2p::RouterConfig config;
    config.dataDir = dataDir;
    {
        const std::lock_guard<std::mutex> lock(proxyMutex());
        config.role = g_transit ? bazarish::i2p::Role::eServer : bazarish::i2p::Role::eClient;
    }
    config.reseedUrls = reseedUrls();
    {
        const std::lock_guard<std::mutex> lock(reseedsMutex());
        config.reseedFile = reseedFileSlot();
    }
    config.socksProxyHost = i2pSocksProxyHost();
    config.socksProxyPort = i2pSocksProxyPort();
    if (usingGatewayTransport()) {
        const std::lock_guard<std::mutex> lock(proxyMutex());
        config.backend = bazarish::i2p::Backend::eGateway;
        config.gatewayHost = g_gateway->host;
        config.gatewayPort = g_gateway->port;
        config.gatewayPath = g_gateway->path;
        config.gatewayFingerprint = g_gateway->fingerprint;
        config.gatewayTls = g_gateway->tls;
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
    const std::lock_guard<std::mutex> lifecycle(lifecycleMutex());
    std::optional<std::reference_wrapper<bazarish::i2p::Router>> held;
    {
        const std::lock_guard<std::mutex> lock(routerMutex());
        if (g_routerRetired) {
            throw std::runtime_error("the I2P transport changed: start the application again");
        }
        if (routerSlot() != nullptr) {
            held = std::ref(*routerSlot());
        }
    }
    if (!held.has_value()) {
        auto made = std::make_unique<bazarish::i2p::Router>(routerConfigFor(dataDir));
        const std::lock_guard<std::mutex> lock(routerMutex());
        routerSlot() = std::move(made);
        held = std::ref(*routerSlot());
    }
    bazarish::i2p::Router& router = held->get();
    if (!router.running()) {
        router.start();
    }
    const std::lock_guard<std::mutex> lock(routerMutex());
    ensureWarmPool(router);
    return router;
}

std::optional<std::reference_wrapper<bazarish::i2p::Router>> sharedI2pRouterIfRunning()
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (router == nullptr || !router->running()) {
        return std::nullopt;
    }
    return std::ref(*router);
}

bazarish::i2p::Router& readySharedI2pRouter()
{
    const auto running = sharedI2pRouterIfRunning();
    if (!running.has_value() || !running->get().ready()) {
        throw std::runtime_error("the I2P router is still building tunnels");
    }
    return running->get();
}

std::shared_ptr<bazarish::i2p::Endpoint> facadeLinkFor(const std::string& account,
    const std::string& owner, const bazarish::i2p::Privacy privacy, const std::string& facadeHost)
{
    const auto running = sharedI2pRouterIfRunning();
    if (!running.has_value()) {
        return nullptr;
    }
    bazarish::i2p::Router& router = running->get();
    const auto build = [&router, &owner, privacy, &facadeHost]() {
        bazarish::i2p::EndpointConfig config;
        config.privacy = privacy;
        config.published = false;
        config.label = "Facade link";
        config.owner = owner;
        config.target = facadeHost;
        return router.createEndpoint(config);
    };
    if (account.empty()) {
        return build();
    }
    const FacadeLinkKey key{account, facadeHost};
    const std::lock_guard<std::mutex> lock(facadeLinksMutex());
    if (const std::shared_ptr<bazarish::i2p::Endpoint> existing = facadeLinks()[key].lock()) {
        if (!existing->lost()) {
            return existing;
        }
        facadeLinks().erase(key);
    }
    const std::shared_ptr<bazarish::i2p::Endpoint> link = build();
    facadeLinks()[key] = link;
    return link;
}

void stopFacadeLinkFor(const std::string& account)
{
    std::vector<std::shared_ptr<bazarish::i2p::Endpoint>> links;
    {
        const std::lock_guard<std::mutex> lock(facadeLinksMutex());
        for (auto at = facadeLinks().begin(); at != facadeLinks().end();) {
            if (at->first.first != account) {
                ++at;
                continue;
            }
            if (std::shared_ptr<bazarish::i2p::Endpoint> link = at->second.lock()) {
                links.push_back(std::move(link));
            }
            at = facadeLinks().erase(at);
        }
    }
    for (const std::shared_ptr<bazarish::i2p::Endpoint>& link : links) {
        link->stop();
    }
}

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest(const bazarish::i2p::Privacy privacy)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<WarmDestPool>& pool = warmPoolSlot();
    return pool != nullptr ? pool->acquire(privacy) : nullptr;
}

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmWatcher(const bazarish::i2p::Privacy privacy)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    const std::unique_ptr<WarmDestPool>& pool = warmWatcherPoolSlot();
    return pool != nullptr ? pool->acquire(privacy) : nullptr;
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

void restartI2pRouter()
{
    const std::lock_guard<std::mutex> lifecycle(lifecycleMutex());
    std::optional<std::reference_wrapper<bazarish::i2p::Router>> held;
    {
        const std::lock_guard<std::mutex> lock(routerMutex());
        if (routerSlot() == nullptr || g_routerRetired
            || !routerSlot()->capabilities().reseed) {
            return;
        }
        held = std::ref(*routerSlot());
        stopWarmPool();
    }
    bazarish::i2p::Router& router = held->get();
    router.stop();
    if (router.capabilities().proxy) {
        router.setSocksProxy(i2pSocksProxyHost(), i2pSocksProxyPort());
    }
    router.start();
    const std::lock_guard<std::mutex> lock(routerMutex());
    ensureWarmPool(router);
}

namespace {

// i2pd's RESEED_GIVEUP_TIMEOUT.
constexpr int kReseedWaitSeconds = 180;
constexpr int kReseedPollSeconds = 3;

bool g_bootstrapFailed = false;

std::mutex& bootstrapMutex()
{
    static std::mutex mutex;
    return mutex;
}

// The router writes netDb out on its own schedule: the live count is the one to wait on.
bool knownEnough(const bazarish::i2p::Router& router)
{
    return static_cast<std::size_t>(router.knownRouters()) >= kMinKnownRouters;
}

bool waitForNetDb(const bazarish::i2p::Router& router)
{
    const auto deadline
        = std::chrono::steady_clock::now() + std::chrono::seconds(kReseedWaitSeconds);
    while (std::chrono::steady_clock::now() < deadline) {
        if (knownEnough(router)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::seconds(kReseedPollSeconds));
    }
    return knownEnough(router);
}

I2pBootstrap reseedPass(bazarish::i2p::Router& router)
{
    // i2pd reseeds only as its netDb starts and gives up for good: a failed pass needs a restart.
    if (g_bootstrapFailed) {
        router.setReseedUrls(reseedUrls());
        restartI2pRouter();
    }
    if (reseedUrls().empty()) {
        return waitForNetDb(router) ? I2pBootstrap::eBuiltIn : I2pBootstrap::eEmpty;
    }
    if (waitForNetDb(router)) {
        return I2pBootstrap::eReseeded;
    }
    bazarish::log::warn(
        "i2p: the configured reseed produced no network database; starting with the built-in list");
    reportConnectProgressToAll(ConnectMilestone::eBuiltInReseeds);
    setReseedUrls({});
    router.setReseedUrls({});
    restartI2pRouter();
    return waitForNetDb(router) ? I2pBootstrap::eBuiltIn : I2pBootstrap::eEmpty;
}

}  // namespace

I2pBootstrap bootstrapI2pRouter(const std::filesystem::path& dataDir)
{
    bazarish::i2p::Router& router = sharedI2pRouter(dataDir);
    const bazarish::i2p::Capabilities what = router.capabilities();
    if (!what.reseed || !what.routerCounters) {
        return I2pBootstrap::eKnown;
    }
    const std::lock_guard<std::mutex> pass(bootstrapMutex());
    if (knownEnough(router)) {
        g_bootstrapFailed = false;
        return I2pBootstrap::eKnown;
    }
    const I2pBootstrap outcome = reseedPass(router);
    g_bootstrapFailed = outcome == I2pBootstrap::eEmpty;
    return outcome;
}

void setConnectProgressSink(const std::string& account, ConnectProgressFn sink)
{
    const std::lock_guard<std::mutex> lock(progressMutex());
    if (sink) {
        progressSinks()[account] = std::move(sink);
    } else {
        progressSinks().erase(account);
    }
}

int connectPercent(const ConnectMilestone milestone)
{
    // The interface filters progress as monotonic: a retry must not report less than its start.
    switch (milestone) {
    case ConnectMilestone::eRouterStarting: return 30;
    case ConnectMilestone::eBuiltInReseeds: return 30;
    case ConnectMilestone::eTunnelsBuilding: return 40;
    case ConnectMilestone::eTunnelsStillBuilding: return 40;
    case ConnectMilestone::eServerLookup: return 55;
    case ConnectMilestone::eRegistering: return 60;
    case ConnectMilestone::eServerReached: return 65;
    case ConnectMilestone::eRegisteringDevice: return 70;
    case ConnectMilestone::eCheckingAddress: return 83;
    case ConnectMilestone::ePublishingDestination: return 85;
    case ConnectMilestone::eDelegating: return 88;
    case ConnectMilestone::ePublishingCard: return 92;
    case ConnectMilestone::eSyncingDevices: return 96;
    }
    throw std::logic_error("no share of the connection for this milestone");
}

void reportConnectProgress(const std::string& account, const ConnectMilestone milestone)
{
    ConnectProgressFn sink;
    {
        const std::lock_guard<std::mutex> lock(progressMutex());
        const auto found = progressSinks().find(account);
        if (found != progressSinks().end()) {
            sink = found->second;
        }
    }
    if (sink) {
        sink(milestone);
    }
}

void reportConnectProgressToAll(const ConnectMilestone milestone)
{
    std::vector<ConnectProgressFn> sinks;
    {
        const std::lock_guard<std::mutex> lock(progressMutex());
        for (const auto& [owner, sink] : progressSinks()) {
            sinks.push_back(sink);
        }
    }
    for (const ConnectProgressFn& sink : sinks) {
        sink(milestone);
    }
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
    (void)forEachWarmPool([wanted](WarmDestPool& pool) { pool.setWanted(wanted); });
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (wanted && router != nullptr && router->running()) {
        ensureWarmPool(*router);
    }
}

void flushWarmDests()
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    (void)forEachWarmPool([](WarmDestPool& pool) { pool.flush(); });
}

void setPresenceWanted(const std::uint64_t presenceId, const bool wanted)
{
    const std::lock_guard<std::mutex> lock(routerMutex());
    if (wanted) {
        presenceWanters().insert(presenceId);
    } else {
        presenceWanters().erase(presenceId);
    }
    if (presenceWanters().empty()) {
        std::unique_ptr<WarmDestPool>& watchers = warmWatcherPoolSlot();
        if (watchers != nullptr) {
            watchers->stop();
            watchers.reset();
        }
        return;
    }
    const std::unique_ptr<bazarish::i2p::Router>& router = routerSlot();
    if (router != nullptr && router->running()) {
        ensureWarmPool(*router);
    }
}

}  // namespace bazarish::client
