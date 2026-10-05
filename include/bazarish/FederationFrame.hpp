// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <stdexcept>
#include <cstring>
#include <algorithm>
#include <string>

namespace bazarish {

// Framing for one delivery leg over an I2P stream (any type exposing
// readExact/writeAll, e.g. bazarish::i2p::Stream or a test double):
//   deliver request: one JSON header line "{op:deliver,sealed,len}\n" + len bytes
//   deliver reply:   one JSON line "{delivered,errorCode,errorMessage}\n"
//   fetch request:   one JSON header line "{op,sealed}\n" (no payload)
//   fetch reply:     one JSON line "{ok,sealed,errorCode,errorMessage}\n"
// JSON control + raw binary body, matching the system-wide wire format.
//
// The dialling half lives here, in common, because both a client delivering its
// own messages and a server fetching a card speak it; the serving half stays
// with the server, where the admission policy is.

// A header line is control, not content: past this it is not a header any more,
// and reading on would be an unbounded allocation on a peer's say-so.
constexpr std::size_t kMaxFederationHeaderLineBytes = 64 * 1024;
// How much of a frame is taken from the stream at once.
constexpr std::size_t kFrameReadChunkBytes = 8 * 1024;

struct FederationDeliverResult {
    bool delivered = false;
    std::string errorCode;
    std::string errorMessage;
    // The recipient's signature over the deliveryId, made with the signing key of
    // the destination that took the delivery, and that key. Empty when the store
    // did not happen. This rides the reply because the sender dialled from a
    // one-time destination that nobody can dial back: the confirmation has to
    // come home on the leg that is already open.
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

// A reader that takes what the stream gives it and keeps the surplus.
//
// A frame is a header line and, for a delivery, the payload after it. Read a
// byte at a time - which is what readExact of one byte is - a 2 KB header costs
// one cross-thread round trip per byte on the router's own lane: measured tens
// to hundreds of milliseconds per delivery, all of it waiting. Read in whatever
// pieces arrive, it costs two or three.
template <class Stream>
class FrameReader {
public:
    explicit FrameReader(Stream& stream)
        : stream_(stream)
    {
    }

    // Up to and not including the newline. Throws when the line outgrows what a
    // header may be, or when the stream ends first.
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

// Reads a newline-terminated header line from the stream.
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

// Non-template framing helpers (the JSON), defined in the .cpp.
std::string buildFederationDeliverHeader(const Bytes& sealed, std::size_t payloadLen);
FederationDeliverResult parseFederationDeliverReply(const std::string& line);
std::string buildFederationFetchHeader(const std::string& op, const Bytes& sealed);
FederationFetchResult parseFederationFetchReply(const std::string& line);

// Send one deliver request and read the result.
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

// Send one sealed fetch request {op, sealed} (no payload).
template <class Stream>
FederationFetchResult federationSendFetch(
    Stream& stream, const std::string& op, const Bytes& sealed)
{
    detail::writeFederationHeaderLine(stream, buildFederationFetchHeader(op, sealed));
    return parseFederationFetchReply(detail::readFederationHeaderLine(stream));
}

}  // namespace bazarish
