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
#include <mutex>
#include <string>
#include <vector>

namespace bazarish::client {

// The plaintext of a file being sent, read from its start.
class FileInput {
public:
    virtual ~FileInput() = default;
    // Fills up to the whole buffer and answers 0 only at the end.
    virtual std::size_t read(ByteBuffer buffer) = 0;
};

// Where sent files are read from. A location is a path on this device, or something
// only the platform can open, such as an Android document.
class FileSource {
public:
    virtual ~FileSource() = default;
    virtual bool exists(const std::string& location) const = 0;
    virtual std::string name(const std::string& location) const = 0;
    virtual std::unique_ptr<FileInput> open(const std::string& location) const = 0;
};

std::shared_ptr<const FileSource> localFiles();

// Ends a transfer from another thread. The destinations it watches are stopped too, which ends
// whatever wait an attempt is in on them.
class TransferStop {
public:
    void request();
    bool requested() const;
    void watch(const std::shared_ptr<bazarish::i2p::Endpoint>& endpoint);

private:
    std::atomic<bool> requested_{false};
    std::mutex mutex_;
    std::vector<std::weak_ptr<bazarish::i2p::Endpoint>> watched_;
};

struct PreparedFile {
    std::filesystem::path ciphertextPath;
    Bytes header;
    std::string key;
    std::string sha256;
    std::uint64_t size = 0;
};

PreparedFile prepareFile(
    FileInput& input, const std::filesystem::path& ciphertextPath, TransferStop& stop);

struct FileOffer {
    std::string fileId;
    std::string host;
    Bytes header;
    std::string key;
    std::string sha256;
    std::uint64_t size = 0;
};

nlohmann::json fileOfferToJson(const FileOffer& offer);
FileOffer fileOfferFromJson(const nlohmann::json& json);

class TransferSink {
public:
    virtual ~TransferSink() = default;
    virtual void total(std::uint64_t bytes) = 0;
    virtual void append(ByteView data) = 0;
};

using FetchAttemptFn = std::function<void(std::uint64_t offset, TransferSink& sink)>;

using TransferProgressFn = std::function<void(std::uint64_t, std::uint64_t)>;

// The plaintext of a received file, written once its ciphertext is whole and verified.
class FileOutput {
public:
    virtual ~FileOutput() = default;
    virtual void write(ByteView data) = 0;
    virtual void finish() = 0;
    // Takes away what was written, open or finished: it must not be left as the file.
    virtual void discard() noexcept = 0;
};

// Where a received file lands: the ciphertext gathers in part, the plaintext goes to open().
struct FileTarget {
    std::filesystem::path part;
    std::function<std::unique_ptr<FileOutput>()> open;
};

FileTarget fileTargetAt(const std::filesystem::path& dest);

void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target, TransferStop& stop,
    const TransferProgressFn& onProgress = {});

bool serveFile(bazarish::i2p::Endpoint& endpoint, const std::filesystem::path& ciphertextPath,
    std::chrono::seconds window, TransferStop& stop, const TransferProgressFn& onProgress = {});

void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const std::string& announcedSha256, const FileTarget& target, bazarish::i2p::Privacy privacy,
    TransferStop& stop, const TransferProgressFn& onProgress, const std::string& owner);

}  // namespace bazarish::client
