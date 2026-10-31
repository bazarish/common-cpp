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

bazarish::i2p::Router* sharedI2pRouterIfRunning();

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest();
// A published datagram destination for presence watching; it gets its reader key when taken.
std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmWatcher();

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

using ConnectProgressFn = std::function<void(int percent, const std::string& text)>;
void setConnectProgressSink(ConnectProgressFn sink);
void reportConnectProgress(int percent, const std::string& text);

void setSamTransport(std::string host, int port);

void setRouterTransit(bool transit);

void setGatewayTransport(const GatewayAddress& address, std::string pin);

void setI2pSocksProxy(std::string host, int port);
void restartI2pRouter();
std::optional<bazarish::i2p::ProxyState> i2pProxyState();

void setTunnelPrivacy(bazarish::i2p::Privacy privacy);
bazarish::i2p::Privacy tunnelPrivacy();

void flushWarmDests();

void setWarmDestsWanted(bool wanted);

}  // namespace bazarish::client
