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

// The process-wide embedded I2P router.
bazarish::i2p::Router& sharedI2pRouter(const std::filesystem::path& dataDir);

bazarish::i2p::Router* sharedI2pRouterIfRunning();

std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest();

std::shared_ptr<bazarish::i2p::Endpoint> facadeLinkFor(
    const std::string& owner, bazarish::i2p::Privacy privacy);

void stopFacadeLinkFor(const std::string& owner);

void reconcileI2pRouter(const std::filesystem::path& dataDir);

void setReseedUrls(std::vector<std::string> urls);
std::vector<std::string> reseedUrls();

inline constexpr std::size_t kMinKnownRouters = 10;
std::size_t knownRouterCount(
    const std::filesystem::path& dataDir, std::size_t limit = kMinKnownRouters);

using BootstrapNoticeFn = std::function<void(const std::string& message)>;
void setBootstrapNoticeSink(BootstrapNoticeFn sink);

void reportBootstrapNotice(const std::string& message);

using ConnectProgressFn = std::function<void(int percent, const std::string& text)>;
void setConnectProgressSink(ConnectProgressFn sink);
void reportConnectProgress(int percent, const std::string& text);

void setI2pEnabled(bool enabled);
bool i2pEnabled();

void setSamTransport(std::string host, int port);
bool usingSamTransport();

void setGatewayTransport(const GatewayAddress& address, std::string pin);
bool usingGatewayTransport();
std::string samTransportHost();
int samTransportPort();

void setI2pSocksProxy(std::string host, int port);
std::string i2pSocksProxyHost();
int i2pSocksProxyPort();
void restartI2pRouter(const std::filesystem::path& dataDir);
std::optional<bazarish::i2p::ProxyState> i2pProxyState();

void setTunnelPrivacy(bazarish::i2p::Privacy privacy);
bazarish::i2p::Privacy tunnelPrivacy();

void flushWarmDests();

void setWarmDestsWanted(bool wanted);

}  // namespace bazarish::client
