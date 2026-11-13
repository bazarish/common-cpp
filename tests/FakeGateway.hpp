// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/WebSocket.hpp>

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::test {

inline constexpr const char* kFakeGatewayPath = "/3b9e1f07c2d5";
inline constexpr const char* kFakeGatewayHost
    = "dlkbeyqjykssca6o7qlbwgq4fr2hry7kw2ursn2sh3lt3acox6gq.b32.i2p";

// A destination's status comes before the answer to its create.
class FakeGateway {
public:
    FakeGateway()
        : identity_(Identity::generate())
        , sealing_(Key::generateSealing())
        , card_(gateway::issueCard(identity_, sealing_))
        , cover_(identity_.fingerprint())
    {
    }

    std::string fingerprint() const { return identity_.fingerprint(); }

    std::vector<Bytes> received()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return received_;
    }

    void answerLookups(const i2p::LeaseSetRefresh& refresh)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        lookupAnswer_ = refresh;
    }

    std::vector<nlohmann::json> lookups()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return lookups_;
    }

    void closeOnHello()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        closeOnHello_ = true;
    }

    void acceptHellos()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        closeOnHello_ = false;
    }

    void dropSockets()
    {
        std::vector<std::shared_ptr<gateway::ChannelSocket>> held;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& [raw, channel] : channels_) {
                (void)raw;
                held.push_back(channel);
            }
        }
        for (const std::shared_ptr<gateway::ChannelSocket>& channel : held) {
            channel->close();
        }
    }

    std::vector<std::chrono::steady_clock::time_point> hellosClosed()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return hellosClosed_;
    }

    void askRenewals()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        renewDue_ = keyedEndpoints_;
    }

    int start(http::Server& server)
    {
        http::SocketRoutes routes;
        routes.admit
            = [](const http::Request&) -> std::optional<http::Response> { return std::nullopt; };
        routes.opened = [this](const http::SocketPtr& raw, const http::Request&) {
            const Bytes card = cover_.seal(gateway::padded(card_));
            raw->send(std::vector<unsigned char>(card.begin(), card.end()));
        };
        routes.message = [this](const http::SocketPtr& raw, const std::vector<unsigned char>& in) {
            arrived(raw, Bytes(in.begin(), in.end()));
        };
        routes.closed = [this](const http::SocketPtr& raw) {
            const std::lock_guard<std::mutex> lock(mutex_);
            channels_.erase(raw.get());
        };
        server.upgrade(kFakeGatewayPath, std::move(routes));
        return server.start();
    }

private:
    void arrived(const http::SocketPtr& raw, const Bytes& message)
    {
        std::shared_ptr<gateway::ChannelSocket> channel;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto found = channels_.find(raw.get());
            if (found != channels_.end()) {
                channel = found->second;
            }
        }
        if (channel == nullptr) {
            const std::optional<Key> client = gateway::openHello(cover_, message, sealing_);
            if (!client.has_value()) {
                raw->close();
                return;
            }
            gateway::Welcome welcome;
            welcome.sessionKey = randomBytes(gateway::kSessionKeyBytes);
            welcome.salt = randomBytes(gateway::kTicketBytes);
            const Bytes answer = gateway::makeWelcome(cover_, welcome, *client, identity_);
            raw->send(std::vector<unsigned char>(answer.begin(), answer.end()));
            const std::lock_guard<std::mutex> lock(mutex_);
            channels_[raw.get()] = std::make_shared<gateway::ChannelSocket>(raw,
                std::make_shared<gateway::Records>(
                    welcome.sessionKey, welcome.salt, gateway::Side::eGateway));
            return;
        }
        const std::optional<gateway::RecordBody> opened = channel->openRecord(message);
        if (!opened.has_value()) {
            raw->close();
            return;
        }
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            received_.push_back(opened->frame);
        }
        answer(channel, gateway::decode(opened->frame));
    }

    void answer(const http::SocketPtr& socket, const gateway::Frame& frame)
    {
        using gateway::FrameType;
        std::vector<std::uint32_t> renewing;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            renewing.swap(renewDue_);
        }
        for (const std::uint32_t endpoint : renewing) {
            socket->send(gateway::encode(FrameType::eEndpointRenew, endpoint));
        }
        if (frame.type == FrameType::eHello) {
            bool refuse = false;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                refuse = closeOnHello_;
                if (refuse) {
                    hellosClosed_.push_back(std::chrono::steady_clock::now());
                }
            }
            if (refuse) {
                socket->close();
                return;
            }
            socket->send(gateway::encodeJson(FrameType::eReady, frame.ref,
                {{"version", gateway::kProtocolVersion}, {"i2pd", "test"},
                    {"capabilities", {{"destinationCounters", true}, {"warmPool", true}}},
                    {"resumed", false}, {"endpoints", nlohmann::json::array()},
                    {"streams", nlohmann::json::array()}}));
            return;
        }
        if (frame.type == FrameType::eLeaseSetRefresh) {
            i2p::LeaseSetRefresh answer;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                lookups_.push_back(gateway::bodyJson(frame));
                answer = lookupAnswer_;
            }
            socket->send(gateway::encodeJson(
                FrameType::eOk, frame.ref, gateway::leaseSetRefreshJson(answer)));
            return;
        }
        if (frame.type == FrameType::eEndpointCreate) {
            socket->send(gateway::encodeJson(FrameType::eEndpointStatus, frame.ref,
                {{"ready", true}, {"host", kFakeGatewayHost}, {"tunnelsIn", 1}, {"tunnelsOut", 1},
                    {"leaseSets", 0}, {"localRoute", false}}));
            socket->send(gateway::encodeJson(
                FrameType::eOk, frame.ref, {{"host", kFakeGatewayHost}, {"kind", "stream"}}));
            if (gateway::bodyJson(frame).contains("keys")) {
                const std::lock_guard<std::mutex> lock(mutex_);
                keyedEndpoints_.push_back(frame.ref);
            }
        }
    }

    const Identity identity_;
    const Key sealing_;
    const Bytes card_;
    const gateway::Cover cover_;
    std::mutex mutex_;
    std::map<const http::Socket*, std::shared_ptr<gateway::ChannelSocket>> channels_;
    std::vector<Bytes> received_;
    std::vector<std::uint32_t> keyedEndpoints_;
    std::vector<std::uint32_t> renewDue_;
    i2p::LeaseSetRefresh lookupAnswer_;
    std::vector<nlohmann::json> lookups_;
    bool closeOnHello_ = false;
    std::vector<std::chrono::steady_clock::time_point> hellosClosed_;
};

}  // namespace bazarish::test
