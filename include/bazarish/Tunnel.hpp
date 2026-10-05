// Bazarish project (c) 2026
#pragma once

#include "bazarish/Auth.hpp"
#include "bazarish/Bytes.hpp"
#include "bazarish/Padding.hpp"
#include "bazarish/Crypto.hpp"

#include <cstdint>
#include <map>
#include <string>

namespace bazarish::tunnel {

// The client-to-server tunnel: what a facade carries and may not read.
//
// A facade stands between every client and its server, and it is the least
// trusted thing in the system - it may be somebody else's machine. Everything
// that used to travel it in the open (the caller's public keys, which are their
// identity; the device they speak for; their destination; the tokens that admit
// mail to their mailbox; the private transient that operates their address; how
// many messages are waiting and of what kind) travels inside this envelope
// instead. What is left outside is one URL and a length.
//
// Two frames:
//
//   hello  - opens a tunnel. Sealed to the server's sealing key, which the
//            client takes from the server card and trusts because that card is
//            signed by the fingerprint the user already had. It carries a fresh
//            secret, a one-time key for the answer, and the signature that says
//            who is opening it. This is the only place an identity is presented,
//            and a tunnel can never open another one: a carried frame is opened
//            with a tunnel key, and this one never is.
//
//   carry  - everything after that. The request rides under AES-256-GCM with a
//            key derived from the same secret, addressed by a per-request handle
//            that says nothing to anyone without it. No asymmetric work per
//            request, which matters when a client polls every few seconds.
//
// What this does NOT hide, and the documentation must say so: the facade still
// sees a stable source (one destination per client), when a request happens, and
// its length to the nearest step of the padding ladder below.

inline constexpr int kFrameVersion = 1;

// The one path a facade routes on, and the only one it ever sees a client use.
inline constexpr const char* kTunnelPath = "/t";
// The far end of the tunnel. An account call arrives sealed, is authenticated
// here, and is passed to the service node under this server's own signature with
// the user named in the path - signed, therefore, rather than asserted in a
// header the link between the two could rewrite. The node authorises it against
// the server card it is already bound to.
inline constexpr const char* kVouchedPrefix = "/v1/vouched/";

// Where the server card is fetched from, in the open: it is public, identical
// for every caller, and signed, so reading it tells a facade nothing and
// forging it is not open to one.
inline constexpr const char* kServerCardPath = "/v1/server/card";

// The signed statement a hello carries, in place of a request line. Its own
// method and path so a hello can never be replayed as anything else.
inline constexpr const char* kHelloMethod = "BZ-TUNNEL";
inline constexpr const char* kHelloPath = "/hello";

// A list of waiting mail grows by an entry at a time, so without padding its
// length would still count them. The ladder itself is shared with the E2E body,
// which is padded for the same reason against a different observer.

// One HTTP exchange as it travels inside the tunnel.
struct Request {
    std::string method;
    // The server-visible path: no facade base path, no query string.
    std::string path;
    std::string query;
    std::map<std::string, std::string> headers;
    Bytes body;
    std::string contentType;
};

struct Response {
    int status = 0;
    std::string contentType;
    Bytes body;
};

// What opens a tunnel.
struct Hello {
    Bytes secret;               // the tunnel secret; the session id derives from it
    Bytes replyKeyDer;          // SPKI of the one-time key the answer is sealed to
    auth::Headers signature;    // over (kHelloMethod, kHelloPath, secret)
};

// The answer to a hello, sealed to its reply key.
struct Welcome {
    std::int64_t expiresUnix = 0;
};

// Derives the key the carried frames are encrypted under. Separate from the MAC
// key of the same session: one secret, two purposes, and neither derivation may
// hand out the other's key.
Bytes deriveTunnelKey(const Bytes& secret, const std::string& sessionId);

// hello frame. sealHello throws if the key cannot seal (it must be hybrid).
Bytes sealHello(const Hello& hello, const Key& serverSealingPublic);
Hello openHello(const Bytes& frame, const Key& serverSealingPrivate);

// The answer to a hello.
Bytes sealWelcome(const Welcome& welcome, const Key& replyKeyPublic);
Welcome openWelcome(const Bytes& sealed, const Key& replyKeyPrivate);

// carry frame. The handle is the session handle for this request's sequence
// number; the server reads it without any key to find the tunnel it belongs to.
// The payload is padded to a step of the ladder before it is encrypted.
Bytes carry(const std::string& handle, const Bytes& tunnelKey, const Bytes& plaintext);
// The handle a carried frame is addressed to, read without opening it. Throws
// when the frame is not a carry frame at all.
std::string handleOf(const Bytes& frame);
// Whether a frame opens a tunnel rather than riding in one.
bool isHello(const Bytes& frame);
// Opens a carried frame. Throws when the key is wrong or anything was changed.
Bytes open(const Bytes& frame, const Bytes& tunnelKey);

// The inner exchange, encoded. Padding is the frame's business, not this one's:
// carry() pads what it is given, so every path onto the wire is padded once.
Bytes encodeRequest(const Request& request);
Request decodeRequest(const Bytes& plaintext);
Bytes encodeResponse(const Response& response);
Response decodeResponse(const Bytes& plaintext);

}  // namespace bazarish::tunnel
