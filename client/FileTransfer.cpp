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

    void append(const void* data, const std::size_t size)
    {
        if (size == 0) {
            return;
        }
        out_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!out_) {
            throw std::runtime_error("failed to write " + utf8OfPath(path_));
        }
        size_ += size;
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

PreparedFile prepareFile(FileInput& input, const fs::path& ciphertextPath)
{
    PreparedFile prepared;
    prepared.key = toHex(randomBytes(32));
    prepared.header = cms::sealWithPasswordDetached(
        [&input](void* const buffer, const std::size_t size) { return input.read(buffer, size); },
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

    void write(const void* data, const std::size_t size) override
    {
        out_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
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

    std::size_t read(void* const buffer, const std::size_t size) override
    {
        in_.read(static_cast<char*>(buffer), static_cast<std::streamsize>(size));
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

void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target,
    const TransferProgressFn& onProgress, const std::atomic<bool>* cancel)
{
    const fs::path& partPath = target.part;
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

        if (toHex(sha256File(partPath)) != offer.sha256) {
            throw std::runtime_error("file digest mismatch");
        }
        const std::unique_ptr<FileOutput> out = target.open();
        try {
            Sha256 plain;
            cms::unsealWithPasswordDetached(offer.header, partPath, offer.key,
                [&out, &plain](const void* data, const std::size_t size) {
                    plain.update(data, size);
                    out->write(data, size);
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
constexpr std::size_t kMaxQueuedBytes = 128 * 1024;
constexpr int kQueuePollMillis = 100;

namespace {
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
            if (sent >= total) {
                std::array<char, 64> drain{};
                const auto until = std::chrono::steady_clock::now()
                    + std::chrono::seconds(kDrainSeconds);
                while (std::chrono::steady_clock::now() < until) {
                    if (onProgress) {
                        onProgress(onTheWire(sent, stream->pendingBytes()), total);
                    }
                    try {
                        if (stream->readSome(drain.data(), drain.size()) == 0) {
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

void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target,
    const bazarish::i2p::Privacy privacy,
    const TransferProgressFn& onProgress, const std::atomic<bool>* cancel,
    const std::string& owner)
{
    const FetchAttemptFn fetch
        = [&router, &offer, privacy, &owner](const std::uint64_t offset, TransferSink& sink) {
              bazarish::i2p::EndpointConfig config;
              config.privacy = privacy;
              config.tunnelQuantity = 2;
              config.published = false;
              config.label = "File download";
              config.bulk = true;
              config.owner = owner;
              config.target = offer.host;
              const std::shared_ptr<bazarish::i2p::Endpoint> endpoint
                  = router.createEndpoint(config);
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

              std::vector<std::uint8_t> buffer(kChunkBytes);
              std::uint64_t received = offset;
              while (declared == 0 || received < declared) {
                  const std::size_t got = stream->readSome(buffer.data(), buffer.size());
                  if (got == 0) {
                      break;
                  }
                  sink.append(buffer.data(), got);
                  received += got;
              }
              stream->close();
          };
    receiveFile(fetch, offer, announcedSha256, target, onProgress, cancel);
}

}  // namespace bazarish::client
