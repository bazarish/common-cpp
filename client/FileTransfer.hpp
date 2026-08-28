// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/I2p.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

namespace bazarish::client {

// Direct client-to-client file transfer over I2P. A file message carries only
// its name, size and digest; the bytes stay on the sender's disk until the
// recipient asks for them, at which point the sender raises a one-time
// destination and serves that one file over it. No storage service is involved,
// so nothing is ever parked on a third party's disk - the cost is that the
// sender must be online, which the UI has to show honestly.
//
// The wire protocol on the stream is deliberately tiny (no HTTP): the fetcher
// writes an 8-byte big-endian offset, the server answers with an 8-byte
// big-endian total ciphertext length followed by every byte from that offset on.
// A dropped stream is resumed by reconnecting with the next offset.

// What the sender prepared for one transfer: the whole file encrypted under a
// fresh key into a temp file, so ranges can be served (and resumed) without
// re-encrypting, and the digest is known before the first byte moves.
struct PreparedFile {
    std::filesystem::path ciphertextPath;
    std::string key;     // per-transfer CMS password, sent only in the sealed offer
    std::string sha256;  // ciphertext digest, verified by the recipient before decrypting
    std::uint64_t size = 0;
};

// Encrypts path into a temp ciphertext beside it. The caller owns the temp file
// and must remove it when the transfer is over.
PreparedFile prepareFile(
    const std::filesystem::path& path, const std::filesystem::path& ciphertextPath);

// The offer the sender seals back to the recipient once it is ready to serve.
struct FileOffer {
    std::string fileId;
    std::string host;  // one-time b33 the sender listens on
    std::string key;
    std::string sha256;
    std::uint64_t size = 0;
};

nlohmann::json fileOfferToJson(const FileOffer& offer);
FileOffer fileOfferFromJson(const nlohmann::json& json);

// Where a fetch attempt puts what it reads. Bytes go straight to disk, so a
// file far larger than memory transfers fine.
class TransferSink {
public:
    virtual ~TransferSink() = default;
    // The total ciphertext length the sender declares for this attempt.
    virtual void total(std::uint64_t bytes) = 0;
    virtual void append(const void* data, std::size_t size) = 0;
};

// One fetch attempt: read from `offset` into the sink until the stream ends. A
// short attempt (a dropped stream) is normal - the driver reconnects and
// continues from where the sink stopped. Throws on a transport failure.
using FetchAttemptFn = std::function<void(std::uint64_t offset, TransferSink& sink)>;

// Progress over the ciphertext byte stream, for the progress bar in the message
// block: (received, total).
using TransferProgressFn = std::function<void(std::uint64_t, std::uint64_t)>;

// Drives fetch() until the ciphertext is complete, verifies its digest, then
// decrypts it file-to-file into destPath. Neither the ciphertext nor the
// cleartext is ever held whole in memory, and a tampered or truncated transfer
// is rejected before any cleartext exists. The partial file is kept across
// attempts and removed on failure. The transport is injected so the
// resume/verify/decrypt logic is testable without a router.
void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer,
    const std::filesystem::path& destPath, const TransferProgressFn& onProgress = {},
    const std::atomic<bool>* cancel = nullptr);

// Serves one prepared ciphertext to a single peer on an already-built endpoint:
// accepts one stream, answers the offset request, and streams the rest. Returns
// whether a transfer completed. Blocks until it does, the cancel flag is set, or
// the window elapses.
bool serveFile(bazarish::i2p::Endpoint& endpoint, const std::filesystem::path& ciphertextPath,
    std::chrono::seconds window, const TransferProgressFn& onProgress = {},
    const std::atomic<bool>* cancel = nullptr);

// Fetches over I2P: dials the offer's host from a one-time destination of our
// own and drives receiveFile.
void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const std::filesystem::path& destPath,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const TransferProgressFn& onProgress = {}, const std::atomic<bool>* cancel = nullptr,
    const std::string& owner = {});

}  // namespace bazarish::client
