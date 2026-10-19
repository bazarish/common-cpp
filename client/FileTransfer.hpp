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

struct PreparedFile {
    std::filesystem::path ciphertextPath;
    Bytes header;
    std::string key;
    std::string sha256;
    std::uint64_t size = 0;
};

PreparedFile prepareFile(
    const std::filesystem::path& path, const std::filesystem::path& ciphertextPath);

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
    virtual void append(const void* data, std::size_t size) = 0;
};

using FetchAttemptFn = std::function<void(std::uint64_t offset, TransferSink& sink)>;

using TransferProgressFn = std::function<void(std::uint64_t, std::uint64_t)>;

// The plaintext of a received file, written once its ciphertext is whole and verified.
class FileOutput {
public:
    virtual ~FileOutput() = default;
    virtual void write(const void* data, std::size_t size) = 0;
    virtual void finish() = 0;
};

// Where a received file lands: the ciphertext gathers in part, the plaintext goes to open().
struct FileTarget {
    std::filesystem::path part;
    std::function<std::unique_ptr<FileOutput>()> open;
};

FileTarget fileTargetAt(const std::filesystem::path& dest);

void receiveFile(const FetchAttemptFn& fetch, const FileOffer& offer, const FileTarget& target,
    const TransferProgressFn& onProgress = {}, const std::atomic<bool>* cancel = nullptr);

bool serveFile(bazarish::i2p::Endpoint& endpoint, const std::filesystem::path& ciphertextPath,
    std::chrono::seconds window, const TransferProgressFn& onProgress = {},
    const std::atomic<bool>* cancel = nullptr);

void fetchFileOverI2p(bazarish::i2p::Router& router, const FileOffer& offer,
    const FileTarget& target,
    bazarish::i2p::Privacy privacy = bazarish::i2p::Privacy::eMax,
    const TransferProgressFn& onProgress = {}, const std::atomic<bool>* cancel = nullptr,
    const std::string& owner = {});

}  // namespace bazarish::client
