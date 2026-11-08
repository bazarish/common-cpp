// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/I2pHttp.hpp>
#include <bazarish/PairLink.hpp>

#include "I2pRouter.hpp"
#include "PacedSend.hpp"

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
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace bazarish::client {

inline constexpr std::size_t kPairCodeDigits = 4;
inline constexpr int kMaxWrongCodes = 10;
inline constexpr std::size_t kMaxPairBundleBytes = 32 * 1024 * 1024;
inline constexpr std::size_t kMaxPairHelloBytes = 256;

inline constexpr int kPairAcceptPollSeconds = 5;
inline constexpr int kPairRequestQuietSeconds = 60;
inline constexpr int kPairPeerQuietSeconds = 120;
inline constexpr int kPairDrainSeconds = 60;
inline constexpr char kPairingOwner[] = "pairing";

void notePairingTrouble(const std::string& reason);

std::string newPairCode();
bool isPairCode(const std::string& text);

struct PairVerdict {
    int status = kI2pHttpNotFound;
    bool counted = false;
};

// A hello that does not open under the link's key is not counted: without the key no guess is.
PairVerdict pairVerdict(const std::string& method, const std::string& target, const Bytes& hello,
    const std::string& code, const Bytes& key);

std::string pairRequest(const std::string& dest, const std::string& code, const Bytes& key);
Bytes sealPairBundle(const Bytes& key, const Bytes& bundle);
Bytes openPairBundle(const Bytes& key, const Bytes& sealed);
std::string pairRefusal(int status, int triesLeft);
std::string pairBundleHead(std::size_t size);
int pairTriesLeft(const std::map<std::string, std::string>& headers);

using PairProgressFn = std::function<void(std::uint64_t done, std::uint64_t total)>;
using PairRefusedFn = std::function<void(int wrongCodes)>;

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
        if (!waitForRoom(stream, sent, stopped, progress)) {
            return false;
        }
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
PairServeResult servePairBundle(Endpoint& endpoint, const Bytes& bundle, const std::string& code,
    const Bytes& key, const PairProgressFn& onProgress, const PairRefusedFn& onWrongCode,
    const std::atomic<bool>& cancel)
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
            if (writePairBundle(*stream, bundle, onProgress, cancel)) {
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
        throw std::runtime_error("the other device did not say how long the account is");
    }
    const std::uint64_t total = std::stoull(length->second);
    if (total == 0 || total > kMaxPairBundleBytes) {
        throw std::runtime_error("the other device offered " + std::to_string(total)
            + " bytes, and the limit is " + std::to_string(kMaxPairBundleBytes));
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
            throw std::runtime_error("pairing stopped");
        }
        const std::size_t got = stream.readSome(buffer);
        if (got == 0) {
            throw std::runtime_error("the other device closed after "
                + std::to_string(bundle.size()) + " of " + std::to_string(total) + " bytes");
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
    const std::string& code, const Bytes& key, const PairProgressFn& onProgress,
    const std::atomic<bool>& cancel)
{
    if (!endpoint.waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
        throw std::runtime_error("this device could not build I2P tunnels");
    }
    const auto stream = endpoint.connect(dest, std::chrono::seconds(kDialSeconds));
    if (!stream) {
        throw std::runtime_error("cannot reach the other device");
    }
    stream->setReadTimeout(std::chrono::seconds(kPairPeerQuietSeconds));
    const std::string request = pairRequest(dest, code, key);
    stream->writeAll(viewOf(request));
    const I2pHttpHead head = readI2pHttpHead(*stream);
    if (head.status == kI2pHttpForbidden) {
        PairFetchResult refused;
        refused.wrongCode = true;
        refused.triesLeft = pairTriesLeft(head.headers);
        stream->close();
        return refused;
    }
    if (head.status != kI2pHttpOk) {
        throw std::runtime_error(
            "the other device answered " + std::to_string(head.status));
    }
    PairFetchResult got;
    got.bundle = readPairBundle(*stream, head, onProgress, cancel);
    stream->close();
    return got;
}

bool applyLinkReseed(
    const std::filesystem::path& i2pDataDir, const std::vector<std::string>& reseeds);

std::shared_ptr<bazarish::i2p::Endpoint> publishPairDest(
    bazarish::i2p::Router& router, bazarish::i2p::Privacy privacy, const std::string& owner);

std::shared_ptr<bazarish::i2p::Endpoint> openPairLink(
    bazarish::i2p::Router& router, bazarish::i2p::Privacy privacy, const std::string& owner);

}  // namespace bazarish::client
