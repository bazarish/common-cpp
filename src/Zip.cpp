// Bazarish project (c) 2026
#include "bazarish/Zip.hpp"

#include <zlib.h>

#include <cstdint>
#include <limits>
#include <stdexcept>

namespace bazarish {

namespace {

// APPNOTE.TXT 4.3.7, 4.3.12, 4.3.16.
constexpr std::uint32_t kLocalSignature = 0x04034b50;
constexpr std::uint32_t kCentralSignature = 0x02014b50;
constexpr std::uint32_t kEndSignature = 0x06054b50;
constexpr std::uint16_t kVersionNeeded = 20;
constexpr std::uint16_t kMadeOnUnix = 3 << 8;
constexpr std::uint16_t kUtf8Names = 0x0800;
constexpr std::uint16_t kStored = 0;
constexpr std::uint32_t kRegularFile = 0100000;
constexpr std::uint32_t kPermissionBits = 0777;
constexpr int kModeShift = 16;
constexpr std::size_t kLocalHeaderBytes = 30;
constexpr std::size_t kCentralHeaderBytes = 46;
constexpr std::size_t kEndRecordBytes = 22;
constexpr std::size_t kMaxCommentBytes = 0xffff;
constexpr std::size_t kMaxEntries = 0xffff;

void put16(Bytes& out, const std::uint32_t value)
{
    out.push_back(static_cast<unsigned char>(value & 0xff));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xff));
}

void put32(Bytes& out, const std::uint32_t value)
{
    put16(out, value & 0xffff);
    put16(out, value >> 16);
}

std::uint32_t get16(const Bytes& in, const std::size_t at)
{
    if (at + 2 > in.size()) {
        throw std::runtime_error("zip: the archive ends inside a record");
    }
    return static_cast<std::uint32_t>(in[at]) | (static_cast<std::uint32_t>(in[at + 1]) << 8);
}

std::uint32_t get32(const Bytes& in, const std::size_t at)
{
    return get16(in, at) | (get16(in, at + 2) << 16);
}

std::uint32_t crcOf(const Bytes& data)
{
    return static_cast<std::uint32_t>(
        crc32(0L, data.data(), static_cast<uInt>(data.size())));
}

std::uint32_t narrowed(const std::size_t value)
{
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("zip: an entry or the archive is over 4 GiB");
    }
    return static_cast<std::uint32_t>(value);
}

}  // namespace

Bytes zipStored(const std::vector<ZipEntry>& entries)
{
    if (entries.size() > kMaxEntries) {
        throw std::runtime_error("zip: too many entries for an archive without zip64");
    }
    Bytes out;
    Bytes central;
    for (const ZipEntry& entry : entries) {
        const std::uint32_t offset = narrowed(out.size());
        const std::uint32_t crc = crcOf(entry.data);
        const std::uint32_t size = narrowed(entry.data.size());
        put32(out, kLocalSignature);
        put16(out, kVersionNeeded);
        put16(out, kUtf8Names);
        put16(out, kStored);
        put32(out, 0);
        put32(out, crc);
        put32(out, size);
        put32(out, size);
        put16(out, narrowed(entry.name.size()));
        put16(out, 0);
        out.insert(out.end(), entry.name.begin(), entry.name.end());
        out.insert(out.end(), entry.data.begin(), entry.data.end());

        put32(central, kCentralSignature);
        put16(central, kMadeOnUnix | kVersionNeeded);
        put16(central, kVersionNeeded);
        put16(central, kUtf8Names);
        put16(central, kStored);
        put32(central, 0);
        put32(central, crc);
        put32(central, size);
        put32(central, size);
        put16(central, narrowed(entry.name.size()));
        put16(central, 0);
        put16(central, 0);
        put16(central, 0);
        put16(central, 0);
        put32(central, (kRegularFile | (entry.mode & kPermissionBits)) << kModeShift);
        put32(central, offset);
        central.insert(central.end(), entry.name.begin(), entry.name.end());
    }
    const std::uint32_t centralAt = narrowed(out.size());
    out.insert(out.end(), central.begin(), central.end());
    put32(out, kEndSignature);
    put16(out, 0);
    put16(out, 0);
    put16(out, static_cast<std::uint32_t>(entries.size()));
    put16(out, static_cast<std::uint32_t>(entries.size()));
    put32(out, narrowed(central.size()));
    put32(out, centralAt);
    put16(out, 0);
    return out;
}

std::vector<ZipEntry> unzipStored(const Bytes& archive)
{
    if (archive.size() < kEndRecordBytes) {
        throw std::runtime_error("zip: this is not an archive");
    }
    std::size_t end = archive.size() - kEndRecordBytes;
    const std::size_t lowest
        = archive.size() > kEndRecordBytes + kMaxCommentBytes
        ? archive.size() - kEndRecordBytes - kMaxCommentBytes
        : 0;
    while (get32(archive, end) != kEndSignature) {
        if (end == lowest) {
            throw std::runtime_error("zip: no end of central directory");
        }
        --end;
    }
    const std::uint32_t count = get16(archive, end + 10);
    std::size_t at = get32(archive, end + 16);

    std::vector<ZipEntry> entries;
    for (std::uint32_t index = 0; index < count; ++index) {
        if (get32(archive, at) != kCentralSignature) {
            throw std::runtime_error("zip: a broken central directory");
        }
        const std::uint32_t method = get16(archive, at + 10);
        const std::uint32_t crc = get32(archive, at + 16);
        const std::uint32_t size = get32(archive, at + 20);
        const std::uint32_t nameLength = get16(archive, at + 28);
        const std::uint32_t extraLength = get16(archive, at + 30);
        const std::uint32_t commentLength = get16(archive, at + 32);
        const std::uint32_t external = get32(archive, at + 38);
        const std::uint32_t local = get32(archive, at + 42);
        if (method != kStored) {
            throw std::runtime_error("zip: only stored entries are read");
        }
        if (at + kCentralHeaderBytes + nameLength > archive.size()) {
            throw std::runtime_error("zip: a name runs past the archive");
        }
        ZipEntry entry;
        entry.mode = (external >> kModeShift) & kPermissionBits;
        entry.name.assign(archive.begin() + static_cast<std::ptrdiff_t>(at + kCentralHeaderBytes),
            archive.begin() + static_cast<std::ptrdiff_t>(at + kCentralHeaderBytes + nameLength));
        if (get32(archive, local) != kLocalSignature) {
            throw std::runtime_error("zip: an entry has no local header");
        }
        const std::size_t data = local + kLocalHeaderBytes + get16(archive, local + 26)
            + get16(archive, local + 28);
        if (data + size > archive.size()) {
            throw std::runtime_error("zip: an entry runs past the archive");
        }
        entry.data.assign(archive.begin() + static_cast<std::ptrdiff_t>(data),
            archive.begin() + static_cast<std::ptrdiff_t>(data + size));
        if (crcOf(entry.data) != crc) {
            throw std::runtime_error("zip: " + entry.name + " does not match its checksum");
        }
        entries.push_back(std::move(entry));
        at += kCentralHeaderBytes + nameLength + extraLength + commentLength;
    }
    return entries;
}

}  // namespace bazarish
