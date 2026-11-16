// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Devices.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/PairLink.hpp>

#include "FailureCause.hpp"
#include "I2pRouter.hpp"
#include "PacedSend.hpp"
#include "WatchedStream.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::client {

inline constexpr std::size_t kPairCodeDigits = 4;
inline constexpr int kMaxWrongCodes = 10;
inline constexpr std::size_t kMaxPairBundleBytes = 32 * 1024 * 1024;
// The code and the new device's public keys, sealed under the link's key.
inline constexpr std::size_t kMaxPairHelloBytes = 8 * 1024;

inline constexpr int kPairAcceptPollSeconds = 5;
inline constexpr int kPairRequestQuietSeconds = 60;
inline constexpr int kPairPeerQuietSeconds = 120;
inline constexpr int kPairDrainSeconds = 60;
inline constexpr char kPairingAccountLabel[] = "pairing";

// The account bundle's device block: the certificate, and the keys only the device itself holds.
inline constexpr char kBundleDeviceField[] = "device";
inline constexpr char kBundleDeviceCertField[] = "cert";
inline constexpr char kBundleDeviceSigningField[] = "signing";
inline constexpr char kBundleDeviceSealingField[] = "sealing";

void notePairingTrouble(const std::string& reason);

std::string newPairCode();
bool isPairCode(const std::string& text);

struct PairVerdict {
    int status = kI2pHttpNotFound;
    bool counted = false;
    // The device asking, once its code is right.
    std::optional<DevicePublic> device;
};

// A hello that does not open under the link's key is not counted: without the key no guess is.
PairVerdict pairVerdict(const std::string& method, const std::string& target, const Bytes& hello,
    const std::string& code, const Bytes& key);

std::string pairRequest(
    const std::string& dest, const std::string& code, const Bytes& key, const DevicePublic& device);
Bytes sealPairBundle(const Bytes& key, const Bytes& bundle);
SecretBytes openPairBundle(const Bytes& key, const Bytes& sealed);
std::string pairRefusal(int status, int triesLeft);
std::string pairBundleHead(std::size_t size);
int pairTriesLeft(const std::map<std::string, std::string>& headers);

using PairProgressFn = std::function<void(std::uint64_t done, std::uint64_t total)>;
using PairRefusedFn = std::function<void(int wrongCodes)>;
// The sealed bundle for the device that gave the right code.
using PairBundleFn = std::function<Bytes(const DevicePublic& device)>;

// Puts the keys this device made into the bundle the other device made for them; sealed again.
Bytes completePairBundle(const Bytes& key, const Bytes& sealed, const DeviceKeys& made);

struct PairServeResult {
    bool delivered = false;
    int wrongCodes = 0;
};

struct PairFetchResult {
    Bytes bundle;
    bool wrongCode = false;
    int triesLeft = 0;
};

template <class Stream>
bool writePairBundle(Stream& stream, const Bytes& bundle, const PairProgressFn& onProgress,
    const std::atomic<bool>& cancel)
{
    const std::uint64_t total = bundle.size();
    const std::function<void(std::uint64_t)> progress
        = [&onProgress, total](const std::uint64_t done) {
              if (onProgress) {
                  onProgress(done, total);
              }
          };
    const std::function<bool()> stopped = [&cancel]() { return cancel.load(); };
    stream.writeAll(viewOf(pairBundleHead(bundle.size())));
    std::uint64_t sent = 0;
    while (sent < total) {
        if (stopped()) {
            return false;
        }
        const std::size_t chunk
            = static_cast<std::size_t>(std::min<std::uint64_t>(kPacedChunkBytes, total - sent));
        stream.writeAll(ByteView(bundle).subspan(static_cast<std::size_t>(sent), chunk));
        sent += chunk;
        progress(onTheWire(sent, stream.pendingBytes()));
    }
    std::string brokenBecause;
    const DrainOutcome drained = drainUntilClosed(
        stream, sent, std::chrono::seconds(kPairDrainSeconds), progress, brokenBecause);
    if (drained == DrainOutcome::eTimedOut) {
        return false;
    }
    if (drained == DrainOutcome::eBroken) {
        notePairingTrouble("the other device did not close: " + brokenBecause);
    }
    progress(total);
    return true;
}

template <class Stream>
Bytes readPairHello(Stream& stream, const I2pHttpRequestHead& head)
{
    const auto length = head.headers.find("content-length");
    if (length == head.headers.end()) {
        return {};
    }
    const std::uint64_t total = std::stoull(length->second);
    if (total > kMaxPairHelloBytes) {
        return {};
    }
    Bytes hello(head.leftover.begin(), head.leftover.end());
    std::array<unsigned char, kMaxPairHelloBytes> buffer{};
    while (hello.size() < total) {
        const std::size_t got = stream.readSome(buffer);
        if (got == 0) {
            return {};
        }
        hello.insert(hello.end(), buffer.data(), buffer.data() + got);
    }
    hello.resize(static_cast<std::size_t>(total));
    return hello;
}

template <class Endpoint>
PairServeResult servePairBundle(Endpoint& endpoint, const PairBundleFn& makeBundle,
    const std::string& code, const Bytes& key, const PairProgressFn& onProgress,
    const PairRefusedFn& onWrongCode, const std::atomic<bool>& cancel)
{
    PairServeResult result;
    while (!cancel.load()) {
        std::string peer;
        const auto stream = endpoint.accept(peer, std::chrono::seconds(kPairAcceptPollSeconds));
        if (!stream) {
            continue;
        }
        try {
            stream->setReadTimeout(std::chrono::seconds(kPairRequestQuietSeconds));
            const I2pHttpRequestHead head = readI2pHttpRequestHead(*stream);
            const PairVerdict verdict
                = pairVerdict(head.method, head.target, readPairHello(*stream, head), code, key);
            if (verdict.status != kI2pHttpOk) {
                if (verdict.counted) {
                    ++result.wrongCodes;
                    if (onWrongCode) {
                        onWrongCode(result.wrongCodes);
                    }
                }
                const std::string refusal
                    = pairRefusal(verdict.status, kMaxWrongCodes - result.wrongCodes);
                stream->writeAll(viewOf(refusal));
                stream->close();
                if (result.wrongCodes >= kMaxWrongCodes) {
                    return result;
                }
                continue;
            }
            if (writePairBundle(*stream, makeBundle(*verdict.device), onProgress, cancel)) {
                stream->close();
                result.delivered = true;
                return result;
            }
            stream->close();
        } catch (const std::exception& error) {
            notePairingTrouble(std::string("attempt failed: ") + error.what());
        }
    }
    return result;
}

template <class Stream>
Bytes readPairBundle(Stream& stream, const I2pHttpHead& head, const PairProgressFn& onProgress,
    const std::atomic<bool>& cancel)
{
    const auto length = head.headers.find("content-length");
    if (length == head.headers.end()) {
        throw LinkError(
            LinkFailure::eServerMalformed, "the other device did not say how long the account is");
    }
    const std::uint64_t total = std::stoull(length->second);
    if (total == 0 || total > kMaxPairBundleBytes) {
        std::string reason = "the other device offered ";
        reason += std::to_string(total);
        reason += " bytes, and the limit is ";
        reason += std::to_string(kMaxPairBundleBytes);
        throw LinkError(LinkFailure::eServerMalformed, reason);
    }
    Bytes bundle;
    bundle.reserve(static_cast<std::size_t>(total));
    bundle.insert(bundle.end(), head.leftover.begin(), head.leftover.end());
    if (onProgress) {
        onProgress(bundle.size(), total);
    }
    std::vector<unsigned char> buffer(kPacedChunkBytes);
    while (bundle.size() < total) {
        if (cancel.load()) {
            throw LocalError(LocalFailure::eStopped, "pairing stopped");
        }
        const std::size_t got = stream.readSome(buffer);
        if (got == 0) {
            std::string reason = "the other device closed after ";
            reason += std::to_string(bundle.size());
            reason += " of ";
            reason += std::to_string(total);
            reason += " bytes";
            throw LinkError(LinkFailure::eServerUnreachable, reason);
        }
        bundle.insert(bundle.end(), buffer.data(), buffer.data() + got);
        if (onProgress) {
            onProgress(bundle.size(), total);
        }
    }
    bundle.resize(static_cast<std::size_t>(total));
    return bundle;
}

template <class Endpoint>
PairFetchResult fetchPairBundle(Endpoint& endpoint, const std::string& dest,
    const std::string& code, const Bytes& key, const DevicePublic& device,
    const PairProgressFn& onProgress, const std::atomic<bool>& cancel)
{
    if (!endpoint.waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
        throw LinkError(LinkFailure::eTunnelsBuilding, "this device could not build I2P tunnels");
    }
    const auto stream = endpoint.connect(dest, std::chrono::seconds(kDialSeconds));
    if (!stream) {
        throw LinkError(LinkFailure::eServerUnreachable, "cannot reach the other device");
    }
    stream->setReadTimeout(std::chrono::seconds(kPairPeerQuietSeconds));
    BasicWatchedStream watched(*stream);
    PairFetchResult got;
    try {
        const std::string request = pairRequest(dest, code, key, device);
        watched.writeAll(viewOf(request));
        const I2pHttpHead head = readI2pHttpHead(watched);
        if (head.status == kI2pHttpForbidden) {
            got.wrongCode = true;
            got.triesLeft = pairTriesLeft(head.headers);
        } else if (head.status != kI2pHttpOk) {
            std::string reason = "the other device answered ";
            reason += std::to_string(head.status);
            throw LinkError(LinkFailure::eServerRefused, reason);
        } else {
            got.bundle = readPairBundle(watched, head, onProgress, cancel);
        }
    } catch (const LinkError&) {
        throw;
    } catch (const LocalError&) {
        throw;
    } catch (const std::exception& error) {
        std::string reason = "the other device's answer: ";
        reason += error.what();
        throw LinkError(
            watched.failed() ? LinkFailure::eServerUnreachable : LinkFailure::eServerMalformed,
            reason);
    }
    stream->close();
    return got;
}

// Makes this device's keys, asks for the account with them and keeps them in what comes back.
template <class Endpoint>
PairFetchResult fetchPairBundle(Endpoint& endpoint, const std::string& dest,
    const std::string& code, const Bytes& key, const PairProgressFn& onProgress,
    const std::atomic<bool>& cancel)
{
    const DeviceKeys made = DeviceKeys::generate();
    PairFetchResult got
        = fetchPairBundle(endpoint, dest, code, key, DevicePublic::of(made), onProgress, cancel);
    if (!got.wrongCode) {
        got.bundle = completePairBundle(key, got.bundle, made);
    }
    return got;
}

bool applyLinkReseed(
    const std::filesystem::path& i2pDataDir, const std::vector<std::string>& reseeds);

std::shared_ptr<bazarish::i2p::Endpoint> publishPairDest(
    bazarish::i2p::Router& router, bazarish::i2p::Privacy privacy, const std::string& accountLabel);

std::shared_ptr<bazarish::i2p::Endpoint> openPairLink(
    bazarish::i2p::Router& router, bazarish::i2p::Privacy privacy, const std::string& accountLabel);

}  // namespace bazarish::client
