// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::service {

// docs-main api/SignInWithKey.md.
inline constexpr const char* kLoginMethod = "BZ-LOGIN";
inline constexpr const char* kLoginPath = "/portal/login";

// A challenge is bazarish://sign?c=base64url(JSON {v, nonce, ts, consumer, tag[, callback]}).
inline constexpr int kLoginChallengeVersion = 1;
// SignInWithKey.md, "The challenge": ts is honoured this long either side.
inline constexpr std::int64_t kLoginWindowSeconds = 300;
inline constexpr char kLoginChallengeField[] = "c=";

struct LoginConsumer {
    std::string name;
    // Signed, so the order matters.
    std::vector<std::string> place;
    std::string role;

    friend bool operator==(const LoginConsumer&, const LoginConsumer&) = default;
};

inline constexpr std::size_t kConsumerNameMax = 96;
inline constexpr std::size_t kConsumerPlaceMax = 256;
inline constexpr std::size_t kConsumerRoleMax = 48;
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

// Only http to a .b32.i2p host.
LoginCallback parseLoginCallback(const std::string& callback);

std::optional<LoginCallback> readLoginCallback(const std::string& challenge);

// SignInWithKey.md, "A link to a challenge": bazarish://sign?at=<.b32.i2p host><path>.
inline constexpr char kLoginLinkField[] = "at=";
// SignInWithKey.md: the most a client reads of a challenge it fetched by link.
inline constexpr std::size_t kLoginChallengeMax = 4096;

// Empty when the text is not a challenge link.
std::optional<LoginCallback> readLoginChallengeLink(const std::string& link);

void requireChallengeReturnsTo(const std::string& challenge, const std::string& host);

// Unix seconds, by the clock of the site that minted it.
std::int64_t loginChallengeExpiresAt(const std::string& challenge);

std::string canonicalConsumer(const LoginConsumer& consumer);

LoginConsumer readLoginConsumer(const std::string& challenge);

std::string verifyLoginBlob(const std::string& blob, std::int64_t now, const std::string& challenge);

std::string signLoginBlob(
    const Identity& identity, std::int64_t timestamp, const std::string& challenge);

// SignInWithKey.md, "The key": a link that hands a challenge over I2P ends in &key=, the key
// its fetch and its callback are sealed under. It is not part of the challenge and not signed.
inline constexpr char kLoginKeyField[] = "&key=";
inline constexpr char kLoginChallengeLabel[] = "bazarish sign-in challenge v1";
inline constexpr char kLoginAnswerLabel[] = "bazarish sign-in answer v1";

struct KeyedLoginLink {
    std::string link;
    std::optional<Bytes> key;
};

KeyedLoginLink splitLoginKey(const std::string& link);
std::string withLoginKey(const std::string& link, const Bytes& key);

Bytes sealLoginChallenge(const Bytes& key, const std::string& challenge);
std::string openLoginChallenge(const Bytes& key, const Bytes& sealed);

struct LoginAnswer {
    std::string challenge;
    std::string blob;
};

// The callback's body: {"nonce": <the challenge's nonce>, "sealed": <base64 of the answer>}.
std::string sealLoginAnswer(const Bytes& key, const LoginAnswer& answer);
std::string loginAnswerNonce(const std::string& body);
// None when the body does not open under the key or answers another challenge than its nonce.
std::optional<LoginAnswer> openLoginAnswer(const Bytes& key, const std::string& body);

}  // namespace bazarish::service
