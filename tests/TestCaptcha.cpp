// Bazarish project (c) 2026
#include <bazarish/Bytes.hpp>
#include <bazarish/Captcha.hpp>
#include <bazarish/Hmac.hpp>
#include <bazarish/SelfHostedCaptcha.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>

using namespace bazarish::service;

namespace {

const char* const kAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const std::string kSecret = "captcha-secret";
constexpr std::int64_t kNow = 9000;
constexpr std::int64_t kWindowSeconds = 300;
constexpr std::int64_t kOutsideWindow = 100000;
// Short enough for the test to walk the whole code space; deployments use the
// longer default.
constexpr int kSolvableLength = 2;
// A two-character code repeats often, and the single-use ledger is keyed by the
// tag - which is the code and the second it was drawn at. Cases after the first
// therefore issue at a second of their own, or one of them would be refused as
// already spent.
constexpr std::int64_t kSecondIssue = kNow + 1;
constexpr std::int64_t kThirdIssue = kNow + 2;
constexpr std::int64_t kFourthIssue = kNow + 3;
constexpr int kDeployedLength = 5;

// Recovers a challenge's code by re-deriving the tag its id carries. Only a
// holder of the captcha secret can do this - which is how the test drives the
// flow now that the image no longer spells the answer out. It costs the
// challenge nothing, so the same challenge can then be verified for real.
std::string solve(const std::string& secret, const std::string& id, const int length)
{
    const bazarish::Bytes raw = bazarish::fromBase64(id);
    const nlohmann::json parsed = nlohmann::json::parse(raw.begin(), raw.end());
    const auto ts = parsed.at("ts").get<std::int64_t>();
    const auto tag = parsed.at("tag").get<std::string>();
    const std::size_t alphabet = std::strlen(kAlphabet);

    std::string code(static_cast<std::size_t>(length), kAlphabet[0]);
    for (;;) {
        if (hmacSha256Hex(secret, code + "\n" + std::to_string(ts)) == tag) {
            return code;
        }
        std::size_t position = 0;
        for (; position < code.size(); ++position) {
            const char* const at = std::strchr(kAlphabet, code[position]);
            CHECK(at != nullptr);
            const std::size_t next = static_cast<std::size_t>(at - kAlphabet) + 1;
            if (next < alphabet) {
                code[position] = kAlphabet[next];
                break;
            }
            code[position] = kAlphabet[0];
        }
        if (position == code.size()) {
            return std::string();  // the whole space walked, nothing matched
        }
    }
}

std::string lowered(std::string text)
{
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

// The point of the rewrite: the answer must not be readable in the markup.
void testImageHidesTheCode()
{
    SelfHostedCaptcha captcha(kSecret, kDeployedLength, kWindowSeconds);
    const CaptchaChallenge challenge = captcha.issue(kNow);
    CHECK(challenge.contentType == "image/svg+xml");
    CHECK(challenge.body.find("<text") == std::string::npos);
    CHECK(challenge.body.find("font") == std::string::npos);

    // Nothing but the canvas and stroked paths - no element that could carry a
    // character, and no character to carry.
    for (std::size_t at = challenge.body.find('<'); at != std::string::npos;
         at = challenge.body.find('<', at + 1)) {
        const std::string tail = challenge.body.substr(at);
        CHECK(tail.rfind("<svg ", 0) == 0 || tail.rfind("<path ", 0) == 0
            || tail.rfind("</svg>", 0) == 0);
    }
}

// The same code drawn twice must not produce the same drawing, or a table of
// renderings would answer every challenge.
void testDrawingIsRandomised()
{
    SelfHostedCaptcha captcha(kSecret, 1, kWindowSeconds);
    std::map<std::string, std::string> drawings;  // code -> first drawing seen
    for (int attempt = 0; attempt < 100; ++attempt) {
        const CaptchaChallenge challenge = captcha.issue(kNow);
        const std::string code = solve(kSecret, challenge.id, 1);
        CHECK(code.size() == 1);
        const auto seen = drawings.find(code);
        if (seen == drawings.end()) {
            drawings.emplace(code, challenge.body);
            continue;
        }
        CHECK(seen->second != challenge.body);
        return;
    }
    CHECK(false);  // no character repeated in 100 draws over a 32-character alphabet
}

void testFlow()
{
    SelfHostedCaptcha captcha(kSecret, kSolvableLength, kWindowSeconds);

    const CaptchaChallenge challenge = captcha.issue(kNow);
    CHECK(!challenge.id.empty());
    const std::string code = solve(kSecret, challenge.id, kSolvableLength);
    CHECK(code.size() == static_cast<std::size_t>(kSolvableLength));
    CHECK(captcha.verify(challenge.id, code, kNow));
    CHECK(!captcha.verify(challenge.id, code, kNow));  // single use

    // A wrong answer costs the challenge nothing; the right one still lands.
    const CaptchaChallenge second = captcha.issue(kSecondIssue);
    CHECK(!captcha.verify(second.id, "ZZZZZ", kSecondIssue));
    CHECK(captcha.verify(second.id, solve(kSecret, second.id, kSolvableLength), kSecondIssue));

    // Case-insensitive.
    const CaptchaChallenge third = captcha.issue(kThirdIssue);
    CHECK(captcha.verify(
        third.id, lowered(solve(kSecret, third.id, kSolvableLength)), kThirdIssue));

    // Outside the window it is dead, inside it still answers.
    const CaptchaChallenge fourth = captcha.issue(kFourthIssue);
    const std::string fourthCode = solve(kSecret, fourth.id, kSolvableLength);
    CHECK(!captcha.verify(fourth.id, fourthCode, kFourthIssue + kOutsideWindow));
    CHECK(captcha.verify(fourth.id, fourthCode, kFourthIssue));

    CHECK(!captcha.verify("not-a-valid-id", "AAAAA", kNow));  // malformed id
}

void testRegistry()
{
    const std::string secret = "registry-secret";
    const std::unique_ptr<Captcha> built = makeCaptcha({"selfhosted",
        {{"secret", secret}, {"length", std::to_string(kSolvableLength)}}});
    CHECK(built != nullptr);
    CHECK(built->name() == "selfhosted");

    const CaptchaChallenge challenge = built->issue(kNow);
    CHECK(built->verify(challenge.id, solve(secret, challenge.id, kSolvableLength), kNow));

    bool threwOnMissingSecret = false;
    try {
        (void)makeCaptcha({"selfhosted", {}});
    } catch (const std::exception&) {
        threwOnMissingSecret = true;
    }
    CHECK(threwOnMissingSecret);

    bool threwOnUnknownType = false;
    try {
        (void)makeCaptcha({"nonexistent", {}});
    } catch (const std::exception&) {
        threwOnUnknownType = true;
    }
    CHECK(threwOnUnknownType);
}

}  // namespace

int main()
{
    testImageHidesTheCode();
    testDrawingIsRandomised();
    testFlow();
    testRegistry();
    std::printf("TestCaptcha OK\n");
    return 0;
}
