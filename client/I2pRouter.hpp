// Bazarish project (c) 2026
#pragma once

#include <bazarish/I2p.hpp>

#include <bazarish/Bytes.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

// The process-wide embedded I2P router. The i2pd engine is process-global, so a
// process may hold only one router; every session shares this single instance
// (the GUI keeps several accounts open at once, and they all route over it -
// blob fetch, calls, and i2p facades). It is created and started lazily on first
// use under dataDir; the first caller's dataDir wins and later arguments are
// ignored. If it exists but was stopped (I2P toggled off), this starts it again.
// Thread-safe. The object lives until process exit; its network is started and
// stopped to match the enable flag.
bazarish::i2p::Router& sharedI2pRouter(const std::filesystem::path& dataDir);

// The shared router if it exists and is currently running, else nullptr - never
// starts it. Lets a read-only caller (the router status view) poll diagnostics
// without forcing a heavyweight startup on its (e.g. the GUI) thread, and reports
// a stopped (disabled) router honestly as not running.
bazarish::i2p::Router* sharedI2pRouterIfRunning();

// A warm throwaway destination from the process-wide pool kept ready while the
// router runs, or nullptr when none is warm yet (the caller then builds a fresh
// dest cold), so nothing pays cold tunnel-build latency on a user's action. A
// federation fetch (card / resolve) drops it when the answer is in; an outgoing
// message holds it for one correspondent's term. It is never given out twice.
std::shared_ptr<bazarish::i2p::Endpoint> acquireWarmDest();

// The one outbound destination an account talks to its facade through, shared by
// everything that dials for it: the session's transport and the request that
// waits for news each keep their own request queue (a wait must never sit in
// front of a send), but a destination multiplexes streams, so one is enough.
// Kept alive by its users; `owner` is the account it belongs to, and an empty
// one gets a destination of its own rather than sharing a nameless bucket.
std::shared_ptr<bazarish::i2p::Endpoint> facadeLinkFor(
    const std::string& owner, bazarish::i2p::Privacy privacy);

// Brings the embedded router into line with the current enable flag: starts it
// (creating it under dataDir on first use) when enabled, stops its network when
// disabled. Reads the flag itself, so concurrent toggles converge on the final
// state. Heavyweight (start/stop join engine threads); call off the GUI thread.
void reconcileI2pRouter(const std::filesystem::path& dataDir);

// Installs a private reseed for a router data directory that has no netDb yet:
// the routers are written straight into the netDb the engine loads at start, so
// a first I2P start never reaches for a public reseed host. A no-op once the
// directory has a netDb (the router reseeds itself from what it knows) or once
// the router is running. Must run before the router for dataDir is created.
// Returns whether the router will start with a netDb of its own - false means
// the fetch failed and there is nothing to start from.
bool seedRouterOnce(
    const std::filesystem::path& dataDir, const std::function<std::vector<Bytes>()>& fetch);

// Whether the embedded router may bootstrap from i2pd's built-in reseed hosts.
// Default FALSE: the netDb comes from the user's own server over its clearnet
// facade, and contacting a public reseed host would announce the bootstrap to a
// third party. It is turned on only for the one case where there is nobody to
// ask - the server descriptor carries no clearnet facade, or none answered.
void setPublicReseedAllowed(bool allowed);

// A router that knows fewer peers than this cannot build a tunnel on its own and
// has to be handed a slice of somebody's netDb first. Ten is enough to start
// asking the network for more.
inline constexpr std::size_t kMinKnownRouters = 10;
// How many routers this data directory already knows.
// Routers in the data directory's netDb, counted no further than limit: every
// caller only asks whether there are enough, and a netDb that has been warming
// for a while holds thousands of files.
std::size_t knownRouterCount(
    const std::filesystem::path& dataDir, std::size_t limit = kMinKnownRouters);

// Told when the bootstrap has to fall back to the public reseed hosts, so the
// app can say so where the user will see it: the fallback reaches outside the
// network the user chose, and that is not something to leave in a log.
using BootstrapNoticeFn = std::function<void(const std::string& message)>;
void setBootstrapNoticeSink(BootstrapNoticeFn sink);

// Clearnet facades this application knows of, from every account it has open.
// Bootstrapping I2P belongs to the application, not to one account: a client
// that holds three accounts should ask all three servers before it reaches for a
// public reseed host. Each entry is a facade URL.
void setReseedFacades(std::vector<std::string> urls);
std::vector<std::string> reseedFacades();
void reportBootstrapNotice(const std::string& message);
bool publicReseedAllowed();

// Connect progress: the core reports named milestones of a connect (reseed,
// router start, tunnel build, dial, subscribe) so the UI can show what is
// actually happening during the minutes a first I2P connect takes. percent is a
// coarse 0..100 for a progress bar; text is one short human-readable line. The
// sink is process-wide, set by whoever drives a connect and cleared afterwards;
// it is called from worker threads, so the implementation must be thread-safe.
using ConnectProgressFn = std::function<void(int percent, const std::string& text)>;
void setConnectProgressSink(ConnectProgressFn sink);
void reportConnectProgress(int percent, const std::string& text);

// Process-wide I2P enable flag (default true). When turned off the transport
// treats every i2p facade as unreachable, so the network runs on clearnet
// facades only (and fails explicitly when none is reachable), and the embedded
// router's network is stopped (see reconcileI2pRouter). The flag is consulted at
// request time, so it also takes effect on the next request without rebuilding
// any session.
void setI2pEnabled(bool enabled);
bool i2pEnabled();

// Which transport this process uses. An empty host is the engine inside this
// process; anything else is a router outside it, reached over SAM at that
// address. Read when the router is built, so it has to be set before anything
// asks for one - and changing it afterwards takes an application restart,
// because the embedded engine cannot be initialised twice in one process.
void setSamTransport(std::string host, int port);
bool usingSamTransport();
std::string samTransportHost();
int samTransportPort();

// A SOCKS5 proxy for the embedded router's clearnet side - NTCP2, SSU2 and the
// built-in reseeds. Empty host (the default) means straight out. Read when the
// router's network starts, so a change reaches a running router only through
// restartI2pRouter below; setting it while none is up is enough on its own.
void setI2pSocksProxy(std::string host, int port);
std::string i2pSocksProxyHost();
int i2pSocksProxyPort();
// Stops the router's network and starts it again, so the transports come up
// reading whatever the proxy setting says now. A no-op when no router is up -
// the next start reads it anyway.
void restartI2pRouter(const std::filesystem::path& dataDir);
// What the engine made of the proxy setting: the options in force and whether it
// considers itself proxied. Nothing when no router is running.
std::optional<bazarish::i2p::ProxyState> i2pProxyState();

// Process-wide tunnel privacy profile (default eMax), the hop length every
// destination this process builds is given. Read when a destination is created,
// so a change applies to the next one built and never disturbs tunnels already
// carrying traffic. Call media is the one exception and always runs eMinimal:
// three hops each way would put audible delay into a live call.
void setTunnelPrivacy(bazarish::i2p::Privacy privacy);
bazarish::i2p::Privacy tunnelPrivacy();

// Throws away the warm spares (built at whatever account was in force) so the
// pool refills at the current one.
void flushWarmDests();

// Whether the process should keep warm spare destinations at all (default true).
// The spares exist to save a contact-card fetch or an alias lookup the cold
// tunnel-build wait; with every account offline nothing will ask for one, and
// the pool would only hold tunnels open for nobody. Takes effect at once.
void setWarmDestsWanted(bool wanted);

}  // namespace bazarish::client
