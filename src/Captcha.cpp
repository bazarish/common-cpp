// Bazarish project (c) 2026
#include "bazarish/Captcha.hpp"

#include "bazarish/SelfHostedCaptcha.hpp"

#include <mutex>
#include <stdexcept>

namespace bazarish::service {

namespace {

std::mutex& registryMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, CaptchaFactory>& registry()
{
    static std::map<std::string, CaptchaFactory> entries;
    return entries;
}

// Caller must hold registryMutex().
void ensureBuiltins()
{
    static const bool kRegistered = []() {
        registry()["selfhosted"] = makeSelfHostedCaptcha;
        return true;
    }();
    (void)kRegistered;
}

}  // namespace

void registerCaptcha(const std::string& type, CaptchaFactory factory)
{
    const std::lock_guard<std::mutex> lock(registryMutex());
    ensureBuiltins();
    registry()[type] = std::move(factory);
}

std::unique_ptr<Captcha> makeCaptcha(const CaptchaConfig& config)
{
    const std::lock_guard<std::mutex> lock(registryMutex());
    ensureBuiltins();
    const auto it = registry().find(config.type);
    if (it == registry().end()) {
        throw std::runtime_error("unknown captcha type: " + config.type);
    }
    return it->second(config.params);
}

}  // namespace bazarish::service
