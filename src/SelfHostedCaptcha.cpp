// Bazarish project (c) 2026
#include "bazarish/SelfHostedCaptcha.hpp"

#include "bazarish/Hmac.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <stdexcept>
#include <utility>

namespace bazarish::service {

namespace {

// No ambiguous glyphs (no I, L, O, 0, 1).
const char* const kAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

std::string randomCode(const int length)
{
    const Bytes random = randomBytes(static_cast<std::size_t>(length));
    std::string code;
    code.reserve(static_cast<std::size_t>(length));
    for (int i = 0; i < length; ++i) {
        code.push_back(kAlphabet[random[static_cast<std::size_t>(i)] % 32]);
    }
    return code;
}

std::string normalize(const std::string& input)
{
    std::string out;
    for (char c : input) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
        out.push_back(c);
    }
    return out;
}

std::string tagFor(const std::string& secret, const std::string& normalized, const std::int64_t ts)
{
    return hmacSha256Hex(secret, normalized + "\n" + std::to_string(ts));
}

// A distorted SVG of the code (no JavaScript). Noise lines and per-character
// rotation are derived from sha256(code), so rendering is deterministic per
// code yet varies across codes.
std::string renderSvg(const std::string& code)
{
    const Bytes h = sha256(Bytes(code.begin(), code.end()));
    std::string svg
        = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"180\" height=\"60\" "
          "viewBox=\"0 0 180 60\">";
    svg += "<rect width=\"180\" height=\"60\" fill=\"#eeeeee\"/>";
    for (std::size_t i = 0; i < 4; ++i) {
        svg += "<line x1=\"" + std::to_string(h[i * 4] % 180) + "\" y1=\""
            + std::to_string(h[i * 4 + 1] % 60) + "\" x2=\"" + std::to_string(h[i * 4 + 2] % 180)
            + "\" y2=\"" + std::to_string(h[i * 4 + 3] % 60)
            + "\" stroke=\"#999999\" stroke-width=\"1\"/>";
    }
    for (std::size_t i = 0; i < code.size(); ++i) {
        const int deg = static_cast<int>(h[16 + (i % 16)]) % 41 - 20;
        const int x = 18 + static_cast<int>(i) * 28;
        const int y = 40 + static_cast<int>(h[i % 16]) % 9 - 4;
        svg += "<text x=\"" + std::to_string(x) + "\" y=\"" + std::to_string(y)
            + "\" font-size=\"32\" font-family=\"monospace\" transform=\"rotate("
            + std::to_string(deg) + " " + std::to_string(x) + " " + std::to_string(y) + ")\">";
        svg.push_back(code[i]);
        svg += "</text>";
    }
    svg += "</svg>";
    return svg;
}

}  // namespace

SelfHostedCaptcha::SelfHostedCaptcha(
    std::string secret, const int length, const std::int64_t windowSeconds)
    : secret_(std::move(secret))
    , length_(length)
    , windowSeconds_(windowSeconds)
{
}

std::string SelfHostedCaptcha::name() const
{
    return "selfhosted";
}

CaptchaChallenge SelfHostedCaptcha::issue(const std::int64_t now)
{
    const std::string code = randomCode(length_);
    const nlohmann::json id = {{"ts", now}, {"tag", tagFor(secret_, normalize(code), now)}};
    const std::string idText = id.dump();

    CaptchaChallenge challenge;
    challenge.id = toBase64(Bytes(idText.begin(), idText.end()));
    challenge.contentType = "image/svg+xml";
    challenge.body = renderSvg(code);
    return challenge;
}

bool SelfHostedCaptcha::verify(
    const std::string& id, const std::string& answer, const std::int64_t now)
{
    std::int64_t ts = 0;
    std::string tag;
    try {
        const Bytes raw = fromBase64(id);
        const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
        ts = parsed.at("ts").get<std::int64_t>();
        tag = parsed.at("tag").get<std::string>();
    } catch (const std::exception&) {
        return false;  // malformed id
    }
    if (ts < now - windowSeconds_ || ts > now + windowSeconds_) {
        return false;
    }
    if (!constantTimeEqual(tag, tagFor(secret_, normalize(answer), ts))) {
        return false;
    }
    const std::lock_guard<std::mutex> lock(mutex_);
    pruneExpired(now);
    return consumed_.emplace(tag, ts).second;  // false when already used
}

void SelfHostedCaptcha::pruneExpired(const std::int64_t now)
{
    for (auto it = consumed_.begin(); it != consumed_.end();) {
        if (it->second < now - windowSeconds_) {
            it = consumed_.erase(it);
        } else {
            ++it;
        }
    }
}

std::unique_ptr<Captcha> makeSelfHostedCaptcha(const std::map<std::string, std::string>& params)
{
    const auto secret = params.find("secret");
    if (secret == params.end() || secret->second.empty()) {
        throw std::runtime_error("selfhosted captcha requires a 'secret' parameter");
    }
    int length = 5;
    if (const auto it = params.find("length"); it != params.end()) {
        length = std::stoi(it->second);
    }
    std::int64_t window = 300;
    if (const auto it = params.find("window"); it != params.end()) {
        window = std::stoll(it->second);
    }
    return std::make_unique<SelfHostedCaptcha>(secret->second, length, window);
}

}  // namespace bazarish::service
