// Bazarish project (c) 2026
#pragma once

#include <bazarish/Captcha.hpp>

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <unordered_map>

namespace bazarish::service {

// The built-in self-hosted captcha: a short code from a non-ambiguous alphabet,
// drawn as a distorted SVG image (no JavaScript, no third party). The id is
// a stateless HMAC token binding the expected (normalised) answer and a
// timestamp, so verification needs no per-challenge storage beyond a small
// single-use set. Parameters: secret (HMAC key, required), length (code length,
// default 5), window (validity seconds, default 300).
//
// The image carries no text: every character is a set of stroked polylines,
// randomised per challenge and cut and shuffled so that neither the characters
// nor their order can be recovered from the markup. Reading it needs the same
// work a human does - rasterise, segment, recognise - which is the whole point
// of a captcha. It still does not stop an attacker willing to run an OCR model;
// a deployment that needs more can register a different backend.
class SelfHostedCaptcha : public Captcha {
public:
    SelfHostedCaptcha(std::string secret, int length, std::int64_t windowSeconds);

    std::string name() const override;
    CaptchaChallenge issue(std::int64_t now) override;
    bool verify(const std::string& id, const std::string& answer, std::int64_t now) override;

private:
    void pruneExpired(std::int64_t now);

    std::string secret_;
    int length_;
    std::int64_t windowSeconds_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> consumed_;  // token tag -> ts
};

std::unique_ptr<Captcha> makeSelfHostedCaptcha(const std::map<std::string, std::string>& params);

}  // namespace bazarish::service
