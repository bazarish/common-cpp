// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

// Sign-in-with-key wire contract - must stay in lockstep with the client (Session::signLogin).
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// A challenge is bazarish://sign?c=base64url(JSON {v, nonce, ts, consumer, tag[, callback]}).
inline constexpr int kLoginChallengeVersion = 1;
inline constexpr char kLoginChallengeField[] = "c=";

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

struct LoginCallback {
    std::string host;
    std::string path;
};

inline constexpr std::size_t kLoginCallbackMax = 256;
inline constexpr char kLoginCallbackScheme[] = "http://";

std::string encodeLoginChallenge(const std::string& envelope);
std::string decodeLoginChallenge(const std::string& challenge);

void requireUsableConsumer(const LoginConsumer& consumer);

// Only http to a .b32.i2p host that the consumer lists among its own places.
LoginCallback parseLoginCallback(const std::string& callback, const LoginConsumer& consumer);

std::optional<LoginCallback> readLoginCallback(const std::string& challenge);

std::string canonicalConsumer(const LoginConsumer& consumer);

LoginConsumer readLoginConsumer(const std::string& challenge);

std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

}  // namespace bazarish::service
