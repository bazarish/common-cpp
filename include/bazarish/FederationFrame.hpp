// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <string>

namespace bazarish {

constexpr std::size_t kMaxFederationHeaderLineBytes = 64 * 1024;
constexpr std::size_t kFrameReadChunkBytes = 8 * 1024;

struct FederationDeliverResult {
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
    std::string deliveryId;
    Bytes signerPublicDer;
    Bytes signature;
};

struct FederationFetchResult {
    bool ok = false;
    Bytes sealed;
    std::string errorCode;
    std::string errorMessage;
};

namespace detail {

template <class Stream>
class FrameReader {
public:
    explicit FrameReader(Stream& stream)
        : stream_(stream)
    {
    }

    std::string line()
    {
        std::string out;
        for (;;) {
            while (at_ < buffer_.size()) {
                const char c = buffer_[at_++];
                if (c == '\n') {
                    return out;
                }
                out.push_back(c);
                if (out.size() > kMaxFederationHeaderLineBytes) {
                    throw std::runtime_error("federation header line too long");
                }
            }
            fill();
        }
    }

    void read(void* const out, const std::size_t size)
    {
        auto* const bytes = static_cast<unsigned char*>(out);
        std::size_t done = 0;
        while (done < size) {
            if (at_ >= buffer_.size()) {
                fill();
            }
            const std::size_t take = std::min(size - done, buffer_.size() - at_);
            std::memcpy(bytes + done, buffer_.data() + at_, take);
            at_ += take;
            done += take;
        }
    }

private:
    void fill()
    {
        buffer_.resize(kFrameReadChunkBytes);
        const std::size_t got = stream_.readSome(buffer_.data(), buffer_.size());
        if (got == 0) {
            throw std::runtime_error("the stream ended mid-frame");
        }
        buffer_.resize(got);
        at_ = 0;
    }

    Stream& stream_;
    std::string buffer_;
    std::size_t at_ = 0;
};

template <class Stream>
std::string readFederationHeaderLine(Stream& stream)
{
    std::string line;
    char c = 0;
    while (true) {
        stream.readExact(&c, 1);
        if (c == '\n') {
            break;
        }
        line.push_back(c);
        if (line.size() > kMaxFederationHeaderLineBytes) {
            throw std::runtime_error("federation header line too long");
        }
    }
    return line;
}

template <class Stream>
void writeFederationHeaderLine(Stream& stream, const std::string& line)
{
    const std::string framed = line + "\n";
    stream.writeAll(framed.data(), framed.size());
}

}  // namespace detail

std::string buildFederationDeliverHeader(const Bytes& sealed, std::size_t payloadLen);
FederationDeliverResult parseFederationDeliverReply(const std::string& line);
std::string buildFederationFetchHeader(const std::string& op, const Bytes& sealed);
FederationFetchResult parseFederationFetchReply(const std::string& line);

template <class Stream>
FederationDeliverResult federationSendDeliver(
    Stream& stream, const Bytes& sealed, const Bytes& payload)
{
    detail::writeFederationHeaderLine(stream, buildFederationDeliverHeader(sealed, payload.size()));
    if (!payload.empty()) {
        stream.writeAll(payload.data(), payload.size());
    }
    return parseFederationDeliverReply(detail::readFederationHeaderLine(stream));
}

template <class Stream>
FederationFetchResult federationSendFetch(
    Stream& stream, const std::string& op, const Bytes& sealed)
{
    detail::writeFederationHeaderLine(stream, buildFederationFetchHeader(op, sealed));
    return parseFederationFetchReply(detail::readFederationHeaderLine(stream));
}

}  // namespace bazarish
