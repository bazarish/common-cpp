// Bazarish project (c) 2026
#include <bazarish/Captcha.hpp>
#include <bazarish/SelfHostedCaptcha.hpp>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <regex>
#include <string>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish::service;

namespace {

// The code lives in the SVG markup (the documented baseline weakness), so the
// test reads it back the way the harness drives the flow.
std::string extractCode(const std::string& svg)
{
    std::string code;
    const std::regex re(">([A-Z2-9])</text>");
    for (auto it = std::sregex_iterator(svg.begin(), svg.end(), re); it != std::sregex_iterator();
         ++it) {
        code += (*it)[1].str();
    }
    return code;
}

void testSelfHosted()
{
    SelfHostedCaptcha captcha("captcha-secret", 5, 300);
    const std::int64_t t = 9000;

    const CaptchaChallenge challenge = captcha.issue(t);
    CHECK(!challenge.id.empty());
    CHECK(challenge.contentType == "image/svg+xml");
    CHECK(challenge.body.find("<svg") != std::string::npos);

    const std::string code = extractCode(challenge.body);
    CHECK(code.size() == 5);

    // Correct answer (case-insensitive) verifies, exactly once.
    CHECK(captcha.verify(challenge.id, code, t));
    CHECK(!captcha.verify(challenge.id, code, t));  // single use

    // Wrong answer and stale answer fail (fresh challenges).
    const CaptchaChallenge other = captcha.issue(t);
    const std::string otherCode = extractCode(other.body);
    CHECK(!captcha.verify(other.id, "ZZZZZ", t));
    CHECK(captcha.verify(other.id, otherCode, t));  // still good after a wrong attempt

    const CaptchaChallenge lower = captcha.issue(t);
    std::string lowered = extractCode(lower.body);
    for (char& c : lowered) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    CHECK(captcha.verify(lower.id, lowered, t));  // case-insensitive

    const CaptchaChallenge stale = captcha.issue(t);
    CHECK(!captcha.verify(stale.id, extractCode(stale.body), t + 100000));  // outside window

    CHECK(!captcha.verify("not-a-valid-id", "AAAAA", t));  // malformed id
}

void testRegistry()
{
    const std::unique_ptr<Captcha> built
        = makeCaptcha({"selfhosted", {{"secret", "s"}, {"length", "4"}}});
    CHECK(built != nullptr);
    CHECK(built->name() == "selfhosted");
    CHECK(extractCode(built->issue(1).body).size() == 4);

    bool threw = false;
    try {
        (void)makeCaptcha({"selfhosted", {}});  // missing secret
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    threw = false;
    try {
        (void)makeCaptcha({"does-not-exist", {}});
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    // A self-written captcha plugs in by registering its type.
    registerCaptcha("custom", [](const std::map<std::string, std::string>&) {
        return std::unique_ptr<Captcha>(
            std::make_unique<SelfHostedCaptcha>("custom-secret", 6, 300));
    });
    CHECK(makeCaptcha({"custom", {}})->name() == "selfhosted");
}

}  // namespace

int main()
{
    testSelfHosted();
    testRegistry();
    std::printf("TestCaptcha: all checks passed\n");
    return 0;
}
