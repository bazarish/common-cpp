// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

// The sign-in-with-key wire contract (docs-main api/SignInWithKey.md).
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// A challenge is bazarish://sign?c=base64url(JSON {v, nonce, ts, consumer, tag[, callback]}).
inline constexpr int kLoginChallengeVersion = 1;
// SignInWithKey.md, "The challenge": ts is honoured this long either side.
inline constexpr std::int64_t kLoginWindowSeconds = 300;
inline constexpr char kLoginChallengeField[] = "c=";

struct LoginConsumer {
    std::string name;
    // The signature covers the list, so its order is part of what is signed.
    std::vector<std::string> place;
    std::string role;

    friend bool operator==(const LoginConsumer&, const LoginConsumer&) = default;
};

inline constexpr std::size_t kConsumerNameMax = 96;
inline constexpr std::size_t kConsumerPlaceMax = 256;
inline constexpr std::size_t kConsumerRoleMax = 48;
// A reader has to find their own address in the list at a glance.
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

// SignInWithKey.md, "A link to a challenge": bazarish://sign?at=<.b32.i2p host><path>.
inline constexpr char kLoginLinkField[] = "at=";
// SignInWithKey.md: the most a client reads of a challenge it fetched by link.
inline constexpr std::size_t kLoginChallengeMax = 4096;

// Where a link says its challenge waits; empty when the text is not such a link.
std::optional<LoginCallback> readLoginChallengeLink(const std::string& link);

// A challenge fetched by link has to send its signature back to the host it came from.
void requireChallengeReturnsTo(const std::string& challenge, const std::string& host);

// Seconds since the epoch, by the clock of the site that minted it.
std::int64_t loginChallengeExpiresAt(const std::string& challenge);

std::string canonicalConsumer(const LoginConsumer& consumer);

LoginConsumer readLoginConsumer(const std::string& challenge);

std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

}  // namespace bazarish::service
