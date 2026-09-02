// Bazarish project (c) 2026
#include "FileTransfer.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <fstream>
#include <thread>
#include <stdexcept>

namespace bazarish::client {

namespace {

namespace fs = std::filesystem;

constexpr std::size_t kChunkBytes = 64 * 1024;
// Consecutive attempts that move no bytes before a transfer is abandoned.
constexpr int kMaxStalledAttempts = 5;

void encodeBigEndian64(const std::uint64_t value, std::array<std::uint8_t, 8>& out)
{
    for (std::size_t i = 0; i < 8; ++i) {
        out[i] = static_cast<std::uint8_t>((value >> (56 - 8 * i)) & 0xFF);
    }
}

std::uint64_t decodeBigEndian64(const std::array<std::uint8_t, 8>& in)
{
    std::uint64_t value = 0;
    for (const std::uint8_t byte : in) {
        value = (value << 8) | byte;
    }
    return value;
}

// Appends to a partial ciphertext file, tracking its length so a resumed
// transfer knows where it stopped.
class PartialFile {
public:
    explicit PartialFile(fs::path path)
        : path_(std::move(path))
        , out_(path_, std::ios::binary | std::ios::trunc)
    {
        if (!out_) {
            throw std::runtime_error("failed to open " + path_.string());
        }
    }

    void append(const void* data, const std::size_t size)
    {
        if (size == 0) {
            return;
        }
        out_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!out_) {
            throw std::runtime_error("failed to write " + path_.string());
        }
        size_ += size;
    }

    std::uint64_t size() const { return size_; }

    void finish()
    {
        out_.flush();
        if (!out_) {
            throw std::runtime_error("failed to flush " + path_.string());
        }
        out_.close();
    }

private:
    fs::path path_;
    std::ofstream out_;
    std::uint64_t size_ = 0;
};

}  // namespace

PreparedFile prepareFile(const fs::path& path, const fs::path& ciphertextPath)
{
    PreparedFile prepared;
    prepared.key = toHex(randomBytes(32));
    cms::sealWithPasswordToFile(path, ciphertextPath, prepared.key);
    prepared.ciphertextPath = ciphertextPath;
    prepared.sha256 = toHex(sha256File(ciphertextPath));
    prepared.size = fs::file_size(ciphertextPath);
    return prepared;
}

nlohmann::json fileOfferToJson(const FileOffer& offer)
{
    return {
        {"fileId", offer.fileId},
        {"host", offer.host},
        {"key", offer.key},
        {"sha256", offer.sha256},
        {"size", offer.size},
    };
}

FileOffer fileOfferFromJson(const nlohmann::json& json)
{
    FileOffer offer;
    offer.fileId = json.at("fileId").get<std::string>();
    offer.host = json.at("host").get<std::string>();
    offer.key = json.at("key").get<std::string>();
    offer.sha256 = json.at("sha256").get<std::string>();
    offer.size = json.at("size").get<std::uint64_t>();
    return offer;
}

namespace {

// Appends a fetch attempt's bytes to the partial file and records the total the
// sender declared, so the driver can tell progress from a stall.
class PartialSink : public TransferSink {
public:
    PartialSink(PartialFile& part, TransferProgressFn onProgress)
        : part_(part)
        , onProgress_(std::move(onProgress))
    {
    }

    void total(const std::uint64_t bytes) override { declaredTotal = bytes; }

    void append(const void* data, const std::size_t size) override
    {
        part_.append(data, size);
        if (onProgress_ && declaredTotal != 0) {
            onProgress_(part_.size(), declaredTotal);
        }
    }

    std::uint64_t declaredTotal = 0;

private:
    PartialFile& part_;
    TransferProgressFn onProgress_;
};

}  // namespace

void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer, const fs::path& destPath,
    const TransferProgressFn& onProgress, const std::atomic<bool>* cancel)
{
    const fs::path partPath = destPath.string() + ".part";
    try {
        PartialFile part(partPath);
        int stalled = 0;
        while (part.size() < offer.size) {
            if (cancel != nullptr && cancel->load()) {
                throw std::runtime_error("transfer cancelled");
            }
            const std::uint64_t before = part.size();
            PartialSink sink(part, onProgress);
            try {
                fetch(before, sink);
            } catch (const std::exception& error) {
                // A dropped stream is what this loop exists for: the next attempt
                // resumes from the bytes already on disk. Only a run of attempts
                // that moves nothing at all ends the transfer.
                log::warn("file-fetch: attempt failed: {}", error.what());
                if (++stalled >= kMaxStalledAttempts) {
                    throw;
                }
                continue;
            }
            if (sink.declaredTotal != 0 && sink.declaredTotal != offer.size) {
                throw std::runtime_error("sender declares a different size than it offered");
            }
            if (part.size() > offer.size) {
                throw std::runtime_error("sender sent more than it offered");
            }
            if (part.size() == before) {
                if (++stalled >= kMaxStalledAttempts) {
                    throw std::runtime_error("transfer stalled");
                }
            } else {
                stalled = 0;
            }
        }
        part.finish();

        // Verify-then-decrypt: a tampered or truncated transfer never yields
        // cleartext.
        if (toHex(sha256File(partPath)) != offer.sha256) {
            throw std::runtime_error("file digest mismatch");
        }
        cms::unsealWithPasswordToFile(partPath, destPath, offer.key);
    } catch (...) {
        std::error_code ec;
        fs::remove(partPath, ec);
        throw;
    }
    std::error_code ec;
    fs::remove(partPath, ec);
}

// How long the serving side waits for the receiver to close after the last byte
// is written, so nothing is torn down with data still queued.
constexpr int kDrainSeconds = 120;
// How much of the file may sit in the router's send queue at once. A write
// returns as soon as the bytes are queued, so without this the whole file is
// "sent" in milliseconds and the sender's progress bar is a lie that sits at
// 100% for the length of the transfer.
constexpr std::size_t kMaxQueuedBytes = 128 * 1024;
constexpr int kQueuePollMillis = 100;

namespace {
// Bytes that have actually left the device. The queue also holds the framing
// this counter never saw, so the subtraction saturates instead of wrapping.
std::uint64_t onTheWire(const std::uint64_t written, const std::size_t queued)
{
    return written > queued ? written - queued : 0;
}
}  // namespace

bool serveFile(bazarish::i2p::Endpoint& endpoint, const fs::path& ciphertextPath,
    const std::chrono::seconds window, const TransferProgressFn& onProgress,
    const std::atomic<bool>* cancel)
{
    const std::uint64_t total = fs::file_size(ciphertextPath);
    const auto deadline = std::chrono::steady_clock::now() + window;

    while (std::chrono::steady_clock::now() < deadline) {
        if (cancel != nullptr && cancel->load()) {
            return false;
        }
        std::string peer;
        const std::unique_ptr<bazarish::i2p::Stream> stream
            = endpoint.accept(peer, std::chrono::seconds(5));
        if (!stream) {
            continue;
        }
        try {
            // A peer that opens a stream and then says nothing must not hold this
            // thread: every wait on this side is bounded by the same span the
            // drain below is given.
            stream->setReadTimeout(std::chrono::seconds(kDrainSeconds));
            std::array<std::uint8_t, 8> header{};
            stream->readExact(header.data(), header.size());
            const std::uint64_t offset = decodeBigEndian64(header);
            if (offset > total) {
                stream->close();
                continue;
            }
            encodeBigEndian64(total, header);
            stream->writeAll(header.data(), header.size());

            std::ifstream in(ciphertextPath, std::ios::binary);
            if (!in) {
                throw std::runtime_error("failed to open " + ciphertextPath.string());
            }
            in.seekg(static_cast<std::streamoff>(offset));
            std::vector<char> buffer(kChunkBytes);
            std::uint64_t sent = offset;
            while (sent < total) {
                if (cancel != nullptr && cancel->load()) {
                    return false;
                }
                in.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
                const std::streamsize got = in.gcount();
                if (got <= 0) {
                    break;
                }
                stream->writeAll(buffer.data(), static_cast<std::size_t>(got));
                sent += static_cast<std::uint64_t>(got);
                // Wait for the queue to drain below the cap before reading more,
                // so progress follows what has actually left the device.
                while (stream->pendingBytes() > kMaxQueuedBytes) {
                    if (cancel != nullptr && cancel->load()) {
                        return false;
                    }
                    if (onProgress) {
                        onProgress(onTheWire(sent, stream->pendingBytes()), total);
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(kQueuePollMillis));
                }
                if (onProgress) {
                    onProgress(onTheWire(sent, stream->pendingBytes()), total);
                }
            }
            // Closing straight after the last write throws away whatever i2pd has
            // not put on the wire yet - with a file that is the whole transfer.
            // Wait for the receiver to close its side (it does when it has the
            // bytes), which is the only signal that they arrived.
            if (sent >= total) {
                // Everything is written; what is left is the queue emptying and
                // the receiver closing. Keep reporting the real figure.
                std::array<char, 64> drain{};
                const auto until = std::chrono::steady_clock::now()
                    + std::chrono::seconds(kDrainSeconds);
                while (std::chrono::steady_clock::now() < until) {
                    if (onProgress) {
                        onProgress(onTheWire(sent, stream->pendingBytes()), total);
                    }
                    try {
                        if (stream->readSome(drain.data(), drain.size()) == 0) {
                            break;  // the receiver closed: everything was delivered
                        }
                    } catch (const std::exception& error) {
                        // The receiver never closed. The bytes are written either
                        // way, and it is the receiver that decides the transfer is
                        // complete, so this is the end of the wait and not of the
                        // attempt.
                        log::debug("file-serve: the receiver did not close: {}", error.what());
                        break;
                    }
                }
                if (onProgress) {
                    onProgress(total, total);
                }
                stream->close();
                return true;
            }
            stream->close();
        } catch (const std::exception& error) {
            // A dropped peer is normal: it reconnects with the next offset.
            log::debug("file-serve: attempt failed: {}", error.what());
        }
    }
    return false;
}

// A fetch dials from a one-time destination built for the attempt, so it waits
// for its own tunnels before deciding the sender is unreachable.
constexpr int kOwnTunnelsSeconds = 180;
constexpr int kDialSeconds = 90;
// How long the sender may go without sending a byte before the attempt is given
// up on. A transfer that is running sends continuously; one that has stopped
// would otherwise hold this thread for as long as the stream looks open.
constexpr int kSenderQuietSeconds = 120;

void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const fs::path& destPath, const bazarish::i2p::Privacy privacy,
    const TransferProgressFn& onProgress, const std::atomic<bool>* cancel,
    const std::string& owner)
{
    // Each attempt dials from a fresh one-time destination, so a resumed transfer
    // is not linkable to the attempt it continues.
    const FetchAttemptFn fetch
        = [&router, &offer, privacy, &owner](const std::uint64_t offset, TransferSink& sink) {
              bazarish::i2p::EndpointConfig config{router.generateKeys()};
              config.privacy = privacy;
              config.tunnelQuantity = 2;
              config.published = false;
              config.label = "File download";
              config.owner = owner;
              const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                  = router.createEndpoint(config);
              // Our own tunnels first. Dialing from a destination that is still
              // building them fails for a reason that has nothing to do with the
              // sender, and was reported as "cannot reach the sender".
              if (!endpoint->waitReady(std::chrono::seconds(kOwnTunnelsSeconds))) {
                  throw std::runtime_error("this device could not build I2P tunnels");
              }
              const std::unique_ptr<bazarish::i2p::Stream> stream
                  = endpoint->connect(offer.host, std::chrono::seconds(kDialSeconds));
              if (!stream) {
                  throw std::runtime_error("cannot reach the sender");
              }

              stream->setReadTimeout(std::chrono::seconds(kSenderQuietSeconds));
              std::array<std::uint8_t, 8> header{};
              encodeBigEndian64(offset, header);
              stream->writeAll(header.data(), header.size());
              stream->readExact(header.data(), header.size());
              const std::uint64_t declared = decodeBigEndian64(header);
              sink.total(declared);

              // Stop at the length the sender declared rather than waiting for it
              // to close: it is waiting for US to close, so that nothing is torn
              // down with bytes still queued. Both sides waiting is a deadlock
              // that ends only when one of the timeouts does.
              std::vector<std::uint8_t> buffer(kChunkBytes);
              std::uint64_t received = offset;
              while (declared == 0 || received < declared) {
                  const std::size_t got = stream->readSome(buffer.data(), buffer.size());
                  if (got == 0) {
                      break;  // the sender ended the attempt; the driver resumes
                  }
                  sink.append(buffer.data(), got);
                  received += got;
              }
              stream->close();
          };
    receiveFile(fetch, offer, destPath, onProgress, cancel);
}

}  // namespace bazarish::client
