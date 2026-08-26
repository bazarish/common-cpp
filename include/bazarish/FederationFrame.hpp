// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>

#include <cstddef>
#include <stdexcept>
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
