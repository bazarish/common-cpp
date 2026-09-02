// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <string>

namespace bazarish::service {

// Sign-in-with-key wire contract - must stay in lockstep with the client
// (Session::signLogin). The challenge is signed as the body of a canonical
// request under this fixed method/path (so a login blob can never be replayed as
// a real API call); the four hybrid-auth headers are packed into
// base64(JSON {k,t,c,p}).
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// The challenge envelope: base64(JSON {v, nonce, ts, consumer, tag}).
inline constexpr int kLoginChallengeVersion = 1;

// Who consumes the signature - the part of a challenge the user is shown before
// signing. Binding a blob to one verifier stops it being reused elsewhere, but
// not the capture itself: someone signing on site N and handed site X's
// challenge has, unless this is on screen, no way to notice.
//
// name:  the resource as it calls itself, in the words on its own pages.
// place: where it lives, as the user reached it - URL, b32, host:port.
// role:  what is being signed into ("Administrator", "Account owner").
//
// Nothing here is proof, and the client says nothing about it that sounds like
// proof: the guarantee comes from the other end. A verifier accepts only
// challenges labelled with its own consumer, and the tag covers the label, so a
// challenge that can buy a session anywhere carries that place's true words. A
// label somebody made up buys its author nothing.
struct LoginConsumer {
    std::string name;
    std::string place;
    std::string role;

    friend bool operator==(const LoginConsumer&, const LoginConsumer&) = default;
};

// What each field may hold. These are display limits: a window shows this much
// honestly, and a longer field is a place to hide text in.
inline constexpr std::size_t kConsumerNameMax = 96;
inline constexpr std::size_t kConsumerPlaceMax = 256;
inline constexpr std::size_t kConsumerRoleMax = 48;

// Throws unless every required field is there, within its limit and free of
// control characters (a name carrying a newline could forge the line below it).
void requireUsableConsumer(const LoginConsumer& consumer);

// The exact bytes a consumer is bound by: what the challenge carries and what
// the HMAC tag covers, so re-labelling a captured challenge breaks the tag.
std::string canonicalConsumer(const LoginConsumer& consumer);

// The consumer a challenge names, validated. Throws when the challenge does not
// decode, is of another version, or names nobody - which is the point: a
// challenge that will not say who it is for is not signed.
LoginConsumer readLoginConsumer(const std::string& challenge);

// Verifies a login blob against the challenge it was issued for (the request
// auth freshness window contains replay) and returns the signer's fingerprint.
// Throws on any failure. The challenge's own semantics (consumer, single-use,
// issuance freshness) are the portal's concern; this proves only "the holder of
// fingerprint X signed this exact challenge recently".
std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

// Produces a login blob for a given identity. The client normally does this;
// the portal keeps it for issuing/testing and to hold the format in one place.
std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

}  // namespace bazarish::service
