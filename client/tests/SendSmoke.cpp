// Bazarish project (c) 2026
#include "GatewayAddress.hpp"
#include "I2pRouter.hpp"
#include "Session.hpp"

#include <bazarish/Bytes.hpp>
#include <bazarish/Log.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using namespace bazarish;
using namespace bazarish::client;
using Clock = std::chrono::steady_clock;

namespace {

Clock::time_point gStart;

long long sinceStart()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - gStart).count();
}

void say(const std::string& what)
{
    std::printf("[%7lld ms] %s\n", sinceStart(), what.c_str());
    std::fflush(stdout);
}

void useConfiguredTransport(const fs::path& settingsFile, const fs::path& i2pDir)
{
    std::ifstream in(settingsFile);
    if (!in) {
        throw std::runtime_error("no settings at " + settingsFile.string());
    }
    nlohmann::json settings;
    in >> settings;
    const nlohmann::json i2p = settings.value("i2p", nlohmann::json::object());
    const nlohmann::json gateway = i2p.value("gateway", nlohmann::json::object());
    setI2pEnabled(true);
    if (gateway.value("enabled", false)) {
        const std::optional<GatewayAddress> address
            = GatewayAddress::parse(gateway.value("address", std::string()));
        if (!address.has_value()) {
            throw std::runtime_error("the gateway address in settings.json does not read");
        }
        setGatewayTransport(*address, gateway.value("pin", std::string()));
        say("transport: the private gateway at " + address->host);
    } else if (i2p.value("sam", nlohmann::json::object()).value("enabled", false)) {
        const nlohmann::json sam = i2p.at("sam");
        setSamTransport(sam.value("host", std::string("127.0.0.1")), sam.value("port", 7656));
        say("transport: SAM");
    } else {
        say("transport: the engine inside this process");
    }
    (void)sharedI2pRouter(i2pDir);
}

}  // namespace

int main(int argc, char** argv)
{
    if (argc < 3) {
        std::fprintf(stderr, "usage: send_smoke <account.db> <peer-fingerprint> [text]\n");
        return 2;
    }
    gStart = Clock::now();
    const fs::path account(argv[1]);
    const std::string peer = argv[2];
    const std::string text = argc > 3 ? argv[3] : "a message from the send smoke";

    try {
        const fs::path root = account.parent_path().parent_path();
        useConfiguredTransport(root / "settings.json", root / "i2p");

        say("opening the account");
        Session session = Session::open(account, {});
        say("account open: " + session.fingerprint());
        say(session.isConnected() ? "the account says it is connected"
                                  : "the account says it is NOT connected");

        if (peer == "list") {
            for (const std::string& known : session.contactFingerprints()) {
                say("  contact " + known + "  " + session.contactDisplayName(known));
            }
            return 0;
        }

        say("first mailbox pass");
        const std::vector<IncomingMessage> mail = session.sync(false, 5);
        say("mailbox pass done, " + std::to_string(mail.size()) + " item(s)");

        DeliveryWatch watch;
        watch.onPhase = [](const std::string& phase) { say("  phase: " + phase); };
        watch.onOutcome = [](const OutboundCourier::Outcome& outcome) {
            say(std::string("  outcome: ") + (outcome.stored ? "stored by their server"
                                                             : "not stored"));
        };

        for (int round = 1; round <= 2; ++round) {
            say("sending " + std::to_string(round));
            session.sendMessage(peer, text + " (" + std::to_string(round) + ")", {}, watch);
            say("sendMessage " + std::to_string(round) + " returned");
            if (round == 1) {
                std::this_thread::sleep_for(std::chrono::seconds(20));
            }
        }

        for (int waited = 0; waited < 120; ++waited) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        say("done waiting");
    } catch (const std::exception& error) {
        say(std::string("FAILED: ") + error.what());
        return 1;
    }
    return 0;
}
