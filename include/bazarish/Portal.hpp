// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bazarish::service {

// Sign-in-with-key wire contract - must stay in lockstep with the client (Session::signLogin).
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// The challenge envelope: base64(JSON {v, nonce, ts, consumer, tag}).
inline constexpr int kLoginChallengeVersion = 1;

struct LoginConsumer {
    std::string name;
    // Every address this place answers at, in the order it publishes them: the
    // signature covers the list, so the order is part of what is signed.
    std::vector<std::string> place;
    std::string role;

    friend bool operator==(const LoginConsumer&, const LoginConsumer&) = default;
};

inline constexpr std::size_t kConsumerNameMax = 96;
inline constexpr std::size_t kConsumerPlaceMax = 256;
inline constexpr std::size_t kConsumerRoleMax = 48;
// A list nobody reads is not a check: a reader has to be able to find their own
// address in it at a glance.
inline constexpr std::size_t kConsumerPlacesMax = 4;

void requireUsableConsumer(const LoginConsumer& consumer);

std::string canonicalConsumer(const LoginConsumer& consumer);

LoginConsumer readLoginConsumer(const std::string& challenge);

std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

}  // namespace bazarish::service
