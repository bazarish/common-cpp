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
    const std::string& canonicalConsumer)
{
    return hmacSha256Hex(secret, nonce + "\n" + std::to_string(ts) + "\n" + canonicalConsumer);
}

}  // namespace

LoginChallenge::LoginChallenge(
    std::string secret, LoginConsumer consumer, const std::int64_t windowSeconds)
    : secret_(std::move(secret))
    , consumer_(std::move(consumer))
    , canonicalConsumer_(canonicalConsumer(consumer_))
    , windowSeconds_(windowSeconds)
{
}

LoginConsumer LoginChallenge::consumer() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return consumer_;
}

void LoginChallenge::setConsumer(LoginConsumer consumer)
{
    std::string canonical = canonicalConsumer(consumer);
    const std::lock_guard<std::mutex> lock(mutex_);
    consumer_ = std::move(consumer);
    canonicalConsumer_ = std::move(canonical);
}

std::string LoginChallenge::currentCanonical() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return canonicalConsumer_;
}

std::string LoginChallenge::issue(const std::int64_t now)
{
    const std::string canonical = currentCanonical();
    const std::string nonce = toHex(randomBytes(16));
    const nlohmann::json challenge = {
        {"v", kLoginChallengeVersion},
        {"nonce", nonce},
        {"ts", now},
        {"consumer", nlohmann::json::parse(canonical)},
        {"tag", tagFor(secret_, nonce, now, canonical)},
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
    const std::string canonical = currentCanonical();
    if (canonicalConsumer(readLoginConsumer(challenge)) != canonical) {
        throw std::runtime_error("login challenge: it names another consumer");
    }
    const Bytes raw = fromBase64(challenge);
    const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
    const std::string nonce = parsed.at("nonce").get<std::string>();
    const std::int64_t ts = parsed.at("ts").get<std::int64_t>();
    const std::string tag = parsed.at("tag").get<std::string>();

    if (ts < now - windowSeconds_ || ts > now + windowSeconds_) {
        throw std::runtime_error("login challenge: expired");
    }
    if (!constantTimeEqual(tag, tagFor(secret_, nonce, ts, canonical))) {
        throw std::runtime_error("login challenge: unknown here");
    }

    const std::string fingerprint = verifyLoginBlob(loginBlob, now, challenge);

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
