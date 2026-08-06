// Bazarish project (c) 2026
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace bazarish::service {

// A challenge to present to a human: an opaque id to pass back with the answer,
// plus a rendered body and its content type (JS-free - e.g. an SVG image).
struct CaptchaChallenge {
    std::string id;
    std::string contentType;
    std::string body;
};

// A pluggable captcha. The built-in default is self-hosted (no third party, no
// JavaScript); an operator can register a stronger provider. Implementations
// must be safe to call from multiple request threads.
class Captcha {
public:
    virtual ~Captcha() = default;

    virtual std::string name() const = 0;
    // Issues a new challenge. now is unix seconds (callers pass the clock so the
    // component stays deterministic and testable).
    virtual CaptchaChallenge issue(std::int64_t now) = 0;
    // Verifies an answer for a previously issued challenge id. Single-use:
    // a correct answer verifies at most once.
    virtual bool verify(const std::string& id, const std::string& answer, std::int64_t now) = 0;
};

// Backend configuration: a type name plus an opaque param bag - same shape as
// the payment-gateway registry so a self-written captcha needs no plumbing
// change.
struct CaptchaConfig {
    std::string type;
    std::map<std::string, std::string> params;
};

using CaptchaFactory
    = std::function<std::unique_ptr<Captcha>(const std::map<std::string, std::string>&)>;

// Registers a captcha backend under type (call before makeCaptcha to plug in a
// custom one; the built-in registers itself). Overwrites an existing type.
void registerCaptcha(const std::string& type, CaptchaFactory factory);

// Builds the captcha named by config.type. Throws when the type is unknown.
std::unique_ptr<Captcha> makeCaptcha(const CaptchaConfig& config);

}  // namespace bazarish::service
