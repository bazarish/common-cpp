// Bazarish project (c) 2026
#pragma once

#include "GatewayAddress.hpp"

#include <bazarish/I2p.hpp>

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

bazarish::i2p::Router& sharedI2pRouter(const std::filesystem::path& dataDir);

// How long a fresh destination may take to build its tunnels, and a dial to another one.
inline constexpr int kOwnTunnelsSeconds = 180;
inline constexpr int kDialSeconds = 90;

std::optional<std::reference_wrapper<bazarish::i2p::Router>> sharedI2pRouterIfRunning();
// Throws while the shared router is not running or still builds its tunnels.
bazarish::i2p::Router& readySharedI2pRouter();

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest(bazarish::i2p::Privacy privacy);
// A published datagram destination for presence watching; it gets its reader key when taken.
std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmWatcher(bazarish::i2p::Privacy privacy);

std::shared_ptr<bazarish::i2p::Endpoint> facadeLinkFor(
    const std::string& owner, bazarish::i2p::Privacy privacy, const std::string& facadeHost);

void stopFacadeLinkFor(const std::string& owner);

void setReseedUrls(std::vector<std::string> urls);
std::vector<std::string> reseedUrls();

inline constexpr std::size_t kMinKnownRouters = 10;

enum class I2pBootstrap {
    eKnown,
    eReseeded,
    eBuiltIn,
    eEmpty,
};

I2pBootstrap bootstrapI2pRouter(const std::filesystem::path& dataDir);
std::size_t knownRouterCount(const std::filesystem::path& dataDir);

// In the order a first connection passes them; the interface words each one itself.
enum class ConnectMilestone {
    eRouterStarting,
    eBuiltInReseeds,
    eTunnelsBuilding,
    eTunnelsStillBuilding,
    eServerLookup,
    eServerReached,
    eRegistering,
    eRegisteringDevice,
    eCheckingAddress,
    ePublishingDestination,
    eDelegating,
    ePublishingCard,
    eSyncingDevices,
};
int connectPercent(ConnectMilestone milestone);

using ConnectProgressFn = std::function<void(ConnectMilestone milestone)>;
// Keyed by the owner the account's destinations carry: each account sees its own progress.
void setConnectProgressSink(const std::string& owner, ConnectProgressFn sink);
void reportConnectProgress(const std::string& owner, ConnectMilestone milestone);
// For the router itself, which every account connecting through it waits on.
void reportConnectProgressToAll(ConnectMilestone milestone);

void setSamTransport(std::string host, int port);

void setRouterTransit(bool transit);

void setGatewayTransport(const GatewayAddress& address);
void clearGatewayTransport();
// The chosen gateway cannot be used: no router starts until another choice is made.
void refuseI2pTransport(std::string reason);

// The transport holds from this process's first router on: false, and nothing set, once one exists.
bool applyI2pTransport(const std::function<void()>& set);
// A changed transport takes the router down for good; the process has to start again.
void retireI2pRouter();

void setI2pSocksProxy(std::string host, int port);
void restartI2pRouter();
std::optional<bazarish::i2p::ProxyState> i2pProxyState();

void setTunnelPrivacy(bazarish::i2p::Privacy privacy);
bazarish::i2p::Privacy tunnelPrivacy();

void flushWarmDests();

void setWarmDestsWanted(bool wanted);

}  // namespace bazarish::client
