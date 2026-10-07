// Bazarish project (c) 2026
#include "AccountManager.hpp"
#include "DevicePairing.hpp"
#include "I2pRouter.hpp"
#include "Session.hpp"

#include <bazarish/Log.hpp>
#include <bazarish/PairLink.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using namespace bazarish;
using namespace bazarish::client;
using Clock = std::chrono::steady_clock;

namespace {

constexpr int kOfferWaitSeconds = 300;
constexpr int kTeardownWaitSeconds = 2;
constexpr char kWrongCode[] = "0000";
constexpr char kOtherWrongCode[] = "1111";

Clock::time_point gStart;

void say(const std::string& what)
{
    const long long ms
        = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - gStart).count();
    std::printf("[%7lld ms] %s\n", ms, what.c_str());
    std::fflush(stdout);
}

std::string wrongCodeFor(const std::string& code)
{
    return code == kWrongCode ? kOtherWrongCode : kWrongCode;
}

void sayDestinations(const std::string& when)
{
    bazarish::i2p::Router* const router = sharedI2pRouterIfRunning();
    if (router == nullptr) {
        say("pool " + when + ": no router");
        return;
    }
    for (const bazarish::i2p::LocalDestination& dest : router->localDestinations()) {
        say("pool " + when + ": " + dest.label + " " + dest.host + " in="
            + std::to_string(dest.inboundTunnels) + " out="
            + std::to_string(dest.outboundTunnels)
            + (dest.published ? " published" : " unpublished"));
    }
}

}  // namespace

int main()
{
    gStart = Clock::now();
    log::setLevel(log::Level::eInfo);
    setI2pEnabled(true);

    const fs::path root = fs::temp_directory_path() / ("bazarish-pair-smoke-" + toHex(randomBytes(8)));
    const fs::path second = root / "second";
    fs::create_directories(root);
    fs::create_directories(second);

    AccountManager first(root / "accounts");
    AccountManager joined(second / "accounts");
    const AccountInfo made = first.create("Pair Smoke");
    say("account " + made.id + " fingerprint " + made.fingerprint);

    Session session = first.open(made.id);
    std::atomic<bool> finished{false};
    std::atomic<bool> failed{false};
    const Session::PairingOffer offer
        = session.startPairing([&finished, &failed](const Session::PairingEvent& event) {
              switch (event.stage) {
              case Session::PairingStage::ePublishing: say("device 1: publishing"); break;
              case Session::PairingStage::eWaiting: say("device 1: waiting"); break;
              case Session::PairingStage::eWrongCode:
                  say("device 1: wrong code " + std::to_string(event.wrongCodes));
                  break;
              case Session::PairingStage::eSending:
                  say("device 1: sent " + std::to_string(event.done) + " of "
                      + std::to_string(event.total));
                  break;
              case Session::PairingStage::eDone:
                  say("device 1: handed over");
                  finished.store(true);
                  break;
              case Session::PairingStage::eRefused:
                  say("device 1: refused after " + std::to_string(event.wrongCodes));
                  failed.store(true);
                  break;
              case Session::PairingStage::eFailed:
                  say("device 1: failed: " + event.error);
                  failed.store(true);
                  break;
              }
          });
    say("link " + offer.uri);
    say("code " + offer.code);
    sayDestinations("while pairing");

    const PairLink link = parsePairLink(offer.uri);
    const std::atomic<bool> never{false};
    std::shared_ptr<bazarish::i2p::Endpoint> endpoint
        = openPairLink(sharedI2pRouter(root / "i2p"), bazarish::i2p::Privacy::eMinimal,
            kPairingOwner);

    const auto deadline = Clock::now() + std::chrono::seconds(kOfferWaitSeconds);
    PairFetchResult got;
    bool asked = false;
    while (Clock::now() < deadline && !failed.load()) {
        try {
            if (!asked) {
                say("device 2: trying a wrong code");
                const PairFetchResult refused = fetchPairBundle(
                    *endpoint, link.dest, wrongCodeFor(offer.code), nullptr, never);
                if (!refused.wrongCode) {
                    say("device 2: a wrong code was accepted");
                    return 1;
                }
                say("device 2: refused, tries left " + std::to_string(refused.triesLeft));
                asked = true;
            }
            say("device 2: trying the right code");
            got = fetchPairBundle(*endpoint, link.dest, offer.code,
                [](const std::uint64_t done, const std::uint64_t total) {
                    say("device 2: got " + std::to_string(done) + " of " + std::to_string(total));
                },
                never);
            break;
        } catch (const std::exception& error) {
            say(std::string("device 2: ") + error.what());
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    if (got.bundle.empty()) {
        say("device 2: nothing arrived");
        return 1;
    }
    say("device 2: bundle of " + std::to_string(got.bundle.size()) + " bytes");

    const AccountInfo restored = joined.import(std::string{}, got.bundle, offer.code);
    say("device 2: account " + restored.id + " fingerprint " + restored.fingerprint);
    if (restored.fingerprint != made.fingerprint) {
        say("the fingerprints differ");
        return 1;
    }
    if (restored.name != made.name) {
        say("the names differ");
        return 1;
    }
    for (int wait = 0; wait < kOfferWaitSeconds && !finished.load() && !failed.load(); ++wait) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    session.stopPairing();
    if (!finished.load()) {
        say("device 1 never reported the hand-over");
        return 1;
    }
    say("paired");

    endpoint.reset();
    std::this_thread::sleep_for(std::chrono::seconds(kTeardownWaitSeconds));
    sayDestinations("after both sides let go");

    const Session::PairingOffer again
        = session.startPairing([](const Session::PairingEvent&) {});
    say("second offer " + again.code);
    sayDestinations("a window nobody fetches from");
    session.stopPairing();
    std::this_thread::sleep_for(std::chrono::seconds(kTeardownWaitSeconds));
    sayDestinations("that window closed");
    return 0;
}
