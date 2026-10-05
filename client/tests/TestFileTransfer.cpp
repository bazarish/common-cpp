// Bazarish project (c) 2026
#include "FileTransfer.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace fs = std::filesystem;

namespace {

void writeFile(const fs::path& path, const Bytes& bytes)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
        static_cast<std::streamsize>(bytes.size()));
}

Bytes readFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return Bytes(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

FetchAttemptFn servingFrom(const Bytes& ciphertext, const std::size_t limit)
{
    return [&ciphertext, limit](const std::uint64_t offset, TransferSink& sink) {
        sink.total(ciphertext.size());
        const std::size_t from = static_cast<std::size_t>(offset);
        const std::size_t count = std::min(limit, ciphertext.size() - from);
        sink.append(ciphertext.data() + from, count);
    };
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    const fs::path root = fs::temp_directory_path() / ("bazarish-xfer-" + toHex(randomBytes(8)));
    fs::create_directories(root);

    const Bytes original = randomBytes(300 * 1024);
    const fs::path source = root / "source.bin";
    writeFile(source, original);

    const PreparedFile prepared = prepareFile(source, root / "source.enc");
    CHECK(prepared.size == fs::file_size(prepared.ciphertextPath));
    CHECK(prepared.sha256.size() == 64);
    CHECK(!prepared.key.empty());

    const Bytes ciphertext = readFile(prepared.ciphertextPath);
    CHECK(ciphertext.size() == prepared.size);

    FileOffer offer;
    offer.fileId = "msg-1";
    offer.host = "example.b32.i2p";
    offer.key = prepared.key;
    offer.sha256 = prepared.sha256;
    offer.size = prepared.size;

    const FileOffer roundTripped = fileOfferFromJson(fileOfferToJson(offer));
    CHECK(roundTripped.fileId == offer.fileId);
    CHECK(roundTripped.host == offer.host);
    CHECK(roundTripped.key == offer.key);
    CHECK(roundTripped.sha256 == offer.sha256);
    CHECK(roundTripped.size == offer.size);

    {
        const fs::path dest = root / "received.bin";
        std::uint64_t lastSeen = 0;
        std::uint64_t lastTotal = 0;
        receiveFile(servingFrom(ciphertext, 40 * 1024), offer, dest,
            [&lastSeen, &lastTotal](const std::uint64_t got, const std::uint64_t total) {
                CHECK(got >= lastSeen);
                lastSeen = got;
                lastTotal = total;
            });
        CHECK(readFile(dest) == original);
        CHECK(lastSeen == prepared.size);
        CHECK(lastTotal == prepared.size);
        CHECK(!fs::exists(dest.string() + ".part"));
    }

    {
        const fs::path dest = root / "received-oneshot.bin";
        receiveFile(servingFrom(ciphertext, ciphertext.size()), offer, dest);
        CHECK(readFile(dest) == original);
    }

    {
        Bytes tampered = ciphertext;
        tampered[tampered.size() / 2] ^= 0xFF;
        const fs::path dest = root / "tampered.bin";
        bool threw = false;
        try {
            receiveFile(servingFrom(tampered, tampered.size()), offer, dest);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
        CHECK(!fs::exists(dest));
        CHECK(!fs::exists(dest.string() + ".part"));
    }

    {
        const fs::path dest = root / "wrongsize.bin";
        bool threw = false;
        try {
            receiveFile(
                [&ciphertext](const std::uint64_t, TransferSink& sink) {
                    sink.total(ciphertext.size() + 1);
                    sink.append(ciphertext.data(), ciphertext.size());
                },
                offer, dest);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
        CHECK(!fs::exists(dest));
    }

    {
        const fs::path dest = root / "stalled.bin";
        int attempts = 0;
        bool threw = false;
        try {
            receiveFile([&attempts](const std::uint64_t, TransferSink& sink) {
                ++attempts;
                sink.total(0);
            }, offer, dest);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
        CHECK(attempts > 0 && attempts < 100);
        CHECK(!fs::exists(dest));
    }

    {
        const fs::path dest = root / "cancelled.bin";
        std::atomic<bool> cancel{true};
        bool threw = false;
        try {
            receiveFile(servingFrom(ciphertext, 1024), offer, dest, {}, &cancel);
        } catch (const std::exception&) {
            threw = true;
        }
        CHECK(threw);
        CHECK(!fs::exists(dest));
        CHECK(!fs::exists(dest.string() + ".part"));
    }

    fs::remove_all(root);
    std::printf("TestFileTransfer: all checks passed\n");
    return 0;
}
