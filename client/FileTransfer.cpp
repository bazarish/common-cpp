// Bazarish project (c) 2026
#include "FileTransfer.hpp"

#include <bazarish/Cms.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Log.hpp>
#include <bazarish/PathText.hpp>

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

class PartialFile {
public:
    explicit PartialFile(fs::path path)
        : path_(std::move(path))
        , out_(path_, std::ios::binary | std::ios::trunc)
    {
        if (!out_) {
            throw std::runtime_error("failed to open " + utf8OfPath(path_));
        }
    }

    void append(const ByteView data)
    {
        if (data.empty()) {
            return;
        }
        out_.write(
            reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out_) {
            throw std::runtime_error("failed to write " + utf8OfPath(path_));
        }
        size_ += data.size();
    }

    std::uint64_t size() const { return size_; }

    void finish()
    {
        out_.flush();
        if (!out_) {
            throw std::runtime_error("failed to flush " + utf8OfPath(path_));
        }
        out_.close();
    }

private:
    fs::path path_;
    std::ofstream out_;
    std::uint64_t size_ = 0;
};

}  // namespace

PreparedFile prepareFile(FileInput& input, const fs::path& ciphertextPath, TransferStop& stop)
{
    PreparedFile prepared;
    prepared.key = toHex(randomBytes(32));
    prepared.header = cms::sealWithPasswordDetached(
        [&input, &stop](const ByteBuffer buffer) {
            if (stop.requested()) {
                throw std::runtime_error("transfer cancelled");
            }
            return input.read(buffer);
        },
        ciphertextPath, prepared.key);
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
        {"header", toBase64(offer.header)},
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
    offer.header = fromBase64(json.at("header").get<std::string>());
    offer.key = json.at("key").get<std::string>();
    offer.sha256 = json.at("sha256").get<std::string>();
    offer.size = json.at("size").get<std::uint64_t>();
    return offer;
}

namespace {

class OfferBroken : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class PartialSink : public TransferSink {
public:
    PartialSink(PartialFile& part, const std::uint64_t offered, TransferProgressFn onProgress)
        : part_(part)
        , offered_(offered)
        , onProgress_(std::move(onProgress))
    {
    }

    void total(const std::uint64_t bytes) override
    {
        if (bytes != offered_) {
            throw OfferBroken("sender declares a different size than it offered");
        }
    }

    void append(const ByteView data) override
    {
        if (part_.size() > offered_ || data.size() > offered_ - part_.size()) {
            throw OfferBroken("sender sent more than it offered");
        }
        part_.append(data);
        if (onProgress_) {
            onProgress_(part_.size(), offered_);
        }
    }

private:
    PartialFile& part_;
    const std::uint64_t offered_;
    TransferProgressFn onProgress_;
};

class LocalFileOutput : public FileOutput {
public:
    explicit LocalFileOutput(fs::path path)
        : path_(std::move(path))
        , out_(path_, std::ios::binary | std::ios::trunc)
    {
        if (!out_) {
            throw std::runtime_error("failed to open " + utf8OfPath(path_));
        }
    }

    void write(const ByteView data) override
    {
        out_.write(
            reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!out_) {
            throw std::runtime_error("failed to write " + utf8OfPath(path_));
        }
    }

    void finish() override
    {
        out_.close();
        if (!out_) {
            throw std::runtime_error("failed to close " + utf8OfPath(path_));
        }
    }

    void discard() noexcept override
    {
        out_.close();
        std::error_code ec;
        if (!fs::remove(path_, ec) && ec) {
            log::warn("a broken download stays at {}: {}", utf8OfPath(path_), ec.message());
        }
    }

private:
    fs::path path_;
    std::ofstream out_;
};

class LocalFileInput : public FileInput {
public:
    explicit LocalFileInput(fs::path path)
        : path_(std::move(path))
        , in_(path_, std::ios::binary)
    {
        if (!in_) {
            throw std::runtime_error("failed to open " + utf8OfPath(path_));
        }
    }

    std::size_t read(const ByteBuffer buffer) override
    {
        in_.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()));
        if (in_.bad()) {
            throw std::runtime_error("failed to read " + utf8OfPath(path_));
        }
        return static_cast<std::size_t>(in_.gcount());
    }

private:
    fs::path path_;
    std::ifstream in_;
};

class LocalFiles : public FileSource {
public:
    bool exists(const std::string& location) const override
    {
        return fs::exists(pathFromUtf8(location));
    }

    std::string name(const std::string& location) const override
    {
        return utf8OfPath(pathFromUtf8(location).filename());
    }

    std::unique_ptr<FileInput> open(const std::string& location) const override
    {
        return std::make_unique<LocalFileInput>(pathFromUtf8(location));
    }
};

}  // namespace

std::shared_ptr<const FileSource> localFiles()
{
    return std::make_shared<const LocalFiles>();
}

FileTarget fileTargetAt(const fs::path& dest)
{
    fs::path part = dest;
    part += ".part";
    return FileTarget{part,
        [dest]() { return std::make_unique<LocalFileOutput>(dest); }};
}

void TransferStop::request()
{
    std::vector<std::weak_ptr<bazarish::i2p::Endpoint>> watched;
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        requested_.store(true);
        watched.swap(watched_);
    }
    for (const std::weak_ptr<bazarish::i2p::Endpoint>& held : watched) {
        if (const std::shared_ptr<bazarish::i2p::Endpoint> endpoint = held.lock()) {
            endpoint->stop();
        }
    }
}

bool TransferStop::requested() const
{
    return requested_.load();
}

void TransferStop::watch(const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint)
{
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        if (!requested_.load()) {
            std::erase_if(watched_, [](const auto& held) { return held.expired(); });
            watched_.push_back(endpoint);
            return;
        }
    }
    endpoint->stop();
}

void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target, TransferStop& stop,
    const TransferProgressFn& onProgress)
{
    const fs::path& partPath = target.part;
    try {
        PartialFile part(partPath);
        int stalled = 0;
        while (part.size() < offer.size) {
            if (stop.requested()) {
                throw std::runtime_error("transfer cancelled");
            }
            const std::uint64_t before = part.size();
            PartialSink sink(part, offer.size, onProgress);
            try {
                fetch(before, sink);
            } catch (const OfferBroken&) {
                throw;
            } catch (const std::exception& error) {
                log::warn("file-fetch: attempt failed: {}", error.what());
                if (++stalled >= kMaxStalledAttempts) {
                    throw;
                }
                continue;
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

        if (toHex(sha256File(partPath)) != offer.sha256) {
            throw std::runtime_error("file digest mismatch");
        }
        const std::unique_ptr<FileOutput> out = target.open();
        try {
            Sha256 plain;
            cms::unsealWithPasswordDetached(offer.header, partPath, offer.key,
                [&out, &plain](const ByteView data) {
                    plain.update(data);
                    out->write(data);
                });
            out->finish();
            if (toHex(plain.digest()) != announcedSha256) {
                throw std::runtime_error("the file differs from the one announced");
            }
        } catch (...) {
            out->discard();
            throw;
        }
    } catch (...) {
        std::error_code ec;
        fs::remove(partPath, ec);
        throw;
    }
    std::error_code ec;
    fs::remove(partPath, ec);
}

constexpr int kDrainSeconds = 120;
constexpr std::size_t kDrainReadBytes = 64;
constexpr std::size_t kMaxQueuedBytes = 128 * 1024;
constexpr int kQueuePollMillis = 100;

namespace {
std::uint64_t onTheWire(const std::uint64_t written, const std::size_t queued)
{
    return written > queued ? written - queued : 0;
}
}  // namespace

bool serveFile(bazarish::i2p::Endpoint& endpoint, const fs::path& ciphertextPath,
    const std::chrono::seconds window, TransferStop& stop, const TransferProgressFn& onProgress)
{
    const std::uint64_t total = fs::file_size(ciphertextPath);
    const auto deadline = std::chrono::steady_clock::now() + window;

    while (std::chrono::steady_clock::now() < deadline) {
        if (stop.requested()) {
            return false;
        }
        std::string peer;
        const std::unique_ptr<bazarish::i2p::Stream> stream
            = endpoint.accept(peer, std::chrono::seconds(5));
        if (!stream) {
            continue;
        }
        try {
            stream->setReadTimeout(std::chrono::seconds(kDrainSeconds));
            std::array<std::uint8_t, 8> header{};
            stream->readExact(header);
            const std::uint64_t offset = decodeBigEndian64(header);
            if (offset > total) {
                stream->close();
                continue;
            }
            encodeBigEndian64(total, header);
            stream->writeAll(header);

            std::ifstream in(ciphertextPath, std::ios::binary);
            if (!in) {
                throw std::runtime_error("failed to open " + ciphertextPath.string());
            }
            in.seekg(static_cast<std::streamoff>(offset));
            Bytes buffer(kChunkBytes);
            std::uint64_t sent = offset;
            while (sent < total) {
                if (stop.requested()) {
                    return false;
                }
                in.read(reinterpret_cast<char*>(buffer.data()),
                    static_cast<std::streamsize>(buffer.size()));
                const std::streamsize got = in.gcount();
                if (got <= 0) {
                    break;
                }
                stream->writeAll(ByteView(buffer).first(static_cast<std::size_t>(got)));
                sent += static_cast<std::uint64_t>(got);
                while (stream->pendingBytes() > kMaxQueuedBytes) {
                    if (stop.requested()) {
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
            if (sent >= total) {
                std::array<unsigned char, kDrainReadBytes> drain{};
                const auto until = std::chrono::steady_clock::now()
                    + std::chrono::seconds(kDrainSeconds);
                while (std::chrono::steady_clock::now() < until) {
                    if (onProgress) {
                        onProgress(onTheWire(sent, stream->pendingBytes()), total);
                    }
                    try {
                        if (stream->readSome(drain) == 0) {
                            break;
                        }
                    } catch (const std::exception& error) {
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
            log::debug("file-serve: attempt failed: {}", error.what());
        }
    }
    return false;
}

constexpr int kOwnTunnelsSeconds = 180;
constexpr int kDialSeconds = 90;
constexpr int kSenderQuietSeconds = 120;
constexpr int kReadyPollSeconds = 1;

void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target,
    const bazarish::i2p::Privacy privacy, TransferStop& stop, const TransferProgressFn& onProgress,
    const std::string& owner)
{
    const FetchAttemptFn fetch
        = [&router, &offer, privacy, &owner, &stop](
              const std::uint64_t offset, TransferSink& sink) {
              bazarish::i2p::EndpointConfig config;
              config.privacy = privacy;
              config.tunnelQuantity = bazarish::i2p::kDefaultTunnelQuantity;
              config.published = false;
              config.label = "File download";
              config.bulk = true;
              config.owner = owner;
              config.target = offer.host;
              const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                  = router.createEndpoint(config);
              stop.watch(endpoint);
              const auto tunnelsBy = std::chrono::steady_clock::now()
                  + std::chrono::seconds(kOwnTunnelsSeconds);
              while (!endpoint->waitReady(std::chrono::seconds(kReadyPollSeconds))) {
                  if (stop.requested()) {
                      throw std::runtime_error("transfer cancelled");
                  }
                  if (std::chrono::steady_clock::now() >= tunnelsBy) {
                      throw std::runtime_error("this device could not build I2P tunnels");
                  }
              }
              const std::unique_ptr<bazarish::i2p::Stream> stream
                  = endpoint->connect(offer.host, std::chrono::seconds(kDialSeconds));
              if (!stream) {
                  throw std::runtime_error("cannot reach the sender");
              }

              stream->setReadTimeout(std::chrono::seconds(kSenderQuietSeconds));
              std::array<std::uint8_t, 8> header{};
              encodeBigEndian64(offset, header);
              stream->writeAll(header);
              stream->readExact(header);
              const std::uint64_t declared = decodeBigEndian64(header);
              sink.total(declared);

              std::vector<std::uint8_t> buffer(kChunkBytes);
              std::uint64_t received = offset;
              while (declared == 0 || received < declared) {
                  const std::size_t got = stream->readSome(buffer);
                  if (got == 0) {
                      break;
                  }
                  sink.append(ByteView(buffer).first(got));
                  received += got;
              }
              stream->close();
          };
    receiveFile(fetch, offer, announcedSha256, target, stop, onProgress);
}

}  // namespace bazarish::client
