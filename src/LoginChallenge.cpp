// Bazarish project (c) 2026
#include "bazarish/LoginChallenge.hpp"

#include "bazarish/Hmac.hpp"
#include "bazarish/Portal.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

std::string tagFor(const std::string& secret, const std::string& nonce, const std::int64_t ts,
    const std::string& audience)
{
    return hmacSha256Hex(secret, nonce + "\n" + std::to_string(ts) + "\n" + audience);
}

}  // namespace

LoginChallenge::LoginChallenge(
    std::string secret, std::string audience, const std::int64_t windowSeconds)
    : secret_(std::move(secret))
    , audience_(std::move(audience))
    , windowSeconds_(windowSeconds)
{
}

std::string LoginChallenge::issue(const std::int64_t now)
{
    const std::string nonce = toHex(randomBytes(16));
    const nlohmann::json challenge = {
        {"nonce", nonce},
        {"ts", now},
        {"aud", audience_},
        {"tag", tagFor(secret_, nonce, now, audience_)},
    };
    const std::string text = challenge.dump();
    return toBase64(Bytes(text.begin(), text.end()));
}

void LoginChallenge::pruneExpired(const std::int64_t now)
{
    for (auto it = consumed_.begin(); it != consumed_.end();) {
        if (it->second < now - windowSeconds_) {
            it = consumed_.erase(it);
        } else {
            ++it;
        }
    }
}

std::string LoginChallenge::verify(
    const std::string& challenge, const std::string& loginBlob, const std::int64_t now)
{
    // 1. Decode and validate the challenge envelope.
    const Bytes raw = fromBase64(challenge);
    const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
    const std::string nonce = parsed.at("nonce").get<std::string>();
    const std::int64_t ts = parsed.at("ts").get<std::int64_t>();
    const std::string audience = parsed.at("aud").get<std::string>();
    const std::string tag = parsed.at("tag").get<std::string>();

    if (audience != audience_) {
        throw std::runtime_error("login challenge: wrong audience");
    }
    if (ts < now - windowSeconds_ || ts > now + windowSeconds_) {
        throw std::runtime_error("login challenge: expired");
    }
    if (!constantTimeEqual(tag, tagFor(secret_, nonce, ts, audience))) {
        throw std::runtime_error("login challenge: bad tag (not issued here)");
    }

    // 2. Verify the user's signature over the whole challenge string. Throws on
    // a bad signature, before any nonce is consumed (so a failed attempt cannot
    // burn a valid challenge).
    const std::string fingerprint = verifyLoginBlob(loginBlob, now, challenge);

    // 3. Enforce single use: consume the nonce on success.
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        pruneExpired(now);
        if (!consumed_.emplace(nonce, ts).second) {
            throw std::runtime_error("login challenge: already used");
        }
    }
    return fingerprint;
}

}  // namespace bazarish::service
