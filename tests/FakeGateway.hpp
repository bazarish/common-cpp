// Bazarish project (c) 2026
#pragma once

#include <bazarish/Crypto.hpp>
#include <bazarish/GatewayChannel.hpp>
#include <bazarish/GatewayProtocol.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/WebSocket.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
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

    // Welcomes then carry tickets, which a later socket joins the session with.
    void issueTickets()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        issuingTickets_ = true;
    }

    void refuseJoins()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        refusingJoins_ = true;
    }

    // Fresh tickets for the session of the last hello, said on its socket.
    void sendTickets()
    {
        std::shared_ptr<gateway::ChannelSocket> control;
        nlohmann::json tickets = nlohmann::json::array();
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            control = control_.lock();
            for (const Bytes& ticket : freshTicketsLocked(controlSession_)) {
                tickets.push_back(toBase64(ticket));
            }
        }
        if (control == nullptr) {
            throw std::logic_error("no control socket to send the tickets on");
        }
        control->send(gateway::encodeJson(gateway::FrameType::eTickets, 0, {{"tickets", tickets}}));
    }

    std::size_t socketsOpened()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return socketsOpened_;
    }

    std::size_t joins()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        return joins_;
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

    // While held, nothing sent to the gateway is read.
    void holdReading(const bool held)
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            readingHeld_ = held;
        }
        readingMoved_.notify_all();
    }

    void answerStreams()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        answeringStreams_ = true;
    }

    void refuseStreams()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        refusingStreams_ = true;
    }

    // As the gateway gives up a dial: it resets the stream being opened and names why.
    void resetDials()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        resettingDials_ = true;
    }

    enum class StreamEnd { eClose, eReset };

    // What the far end says to the first bytes of each stream, and how it ends the stream then.
    void replyToStreams(Bytes reply, const StreamEnd end)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        answeringStreams_ = true;
        streamReply_ = StreamReply{std::move(reply), end};
    }

    void resetStreams()
    {
        std::vector<std::pair<std::shared_ptr<http::Socket>, std::uint32_t>> opened;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            opened.swap(streams_);
        }
        for (const auto& [socket, stream] : opened) {
            socket->send(gateway::encode(gateway::FrameType::eStreamReset, stream));
        }
    }

    std::size_t framesOf(const gateway::FrameType type)
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::size_t count = 0;
        for (const Bytes& frame : received_) {
            if (gateway::decode(frame).type == type) {
                ++count;
            }
        }
        return count;
    }

    std::size_t streamBytes()
    {
        const std::lock_guard<std::mutex> lock(mutex_);
        std::size_t total = 0;
        for (const Bytes& frame : received_) {
            const gateway::Frame decoded = gateway::decode(frame);
            if (decoded.type == gateway::FrameType::eStreamData) {
                total += decoded.body.size();
            }
        }
        return total;
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
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                ++socketsOpened_;
            }
            const Bytes card = cover_.seal(gateway::padded(card_));
            raw->send(std::vector<unsigned char>(card.begin(), card.end()));
        };
        routes.message = [this](const http::SocketPtr& raw, const std::vector<unsigned char>& in) {
            {
                std::unique_lock<std::mutex> lock(mutex_);
                readingMoved_.wait(lock, [this]() { return !readingHeld_; });
            }
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
                join(raw, message);
                return;
            }
            gateway::Welcome welcome;
            welcome.sessionKey = SecretBytes(randomBytes(gateway::kSessionKeyBytes));
            welcome.salt = randomBytes(gateway::kTicketBytes);
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                if (issuingTickets_) {
                    welcome.tickets = freshTicketsLocked(welcome.sessionKey);
                }
            }
            const Bytes answer = gateway::makeWelcome(cover_, welcome, *client, identity_);
            raw->send(std::vector<unsigned char>(answer.begin(), answer.end()));
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto made = std::make_shared<gateway::ChannelSocket>(raw,
                std::make_shared<gateway::Records>(
                    welcome.sessionKey, welcome.salt, gateway::Side::eGateway));
            channels_[raw.get()] = made;
            const std::shared_ptr<gateway::ChannelSocket> held = control_.lock();
            if (held == nullptr || !held->open()) {
                control_ = made;
                controlSession_ = welcome.sessionKey;
            }
            return;
        }
        const std::optional<gateway::RecordBody> opened = channel->openRecord(message);
        if (!opened.has_value()) {
            raw->close();
            return;
        }
        if (gateway::isFiller(*opened)) {
            return;
        }
        std::vector<Bytes> frames = {opened->frame};
        frames.insert(frames.end(), opened->following.begin(), opened->following.end());
        for (const Bytes& frame : frames) {
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                received_.push_back(frame);
            }
            answer(channel, gateway::decode(frame));
        }
    }

    // Under the lock.
    std::vector<Bytes> freshTicketsLocked(const SecretBytes& session)
    {
        std::vector<Bytes> made;
        for (std::size_t i = 0; i < gateway::kTicketsHeld; ++i) {
            made.push_back(randomBytes(gateway::kTicketBytes));
            ticketSessions_.emplace(std::string(made.back().begin(), made.back().end()), session);
        }
        return made;
    }

    void join(const http::SocketPtr& raw, const Bytes& message)
    {
        const Bytes ticket = gateway::ticketOf(message);
        std::optional<SecretBytes> session;
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            const auto found = ticketSessions_.find(std::string(ticket.begin(), ticket.end()));
            if (found != ticketSessions_.end() && !refusingJoins_) {
                session = found->second;
                ticketSessions_.erase(found);
            }
        }
        if (!session.has_value()) {
            const Bytes refused = gateway::refusedJoin();
            raw->send(std::vector<unsigned char>(refused.begin(), refused.end()));
            return;
        }
        const auto records = std::make_shared<gateway::Records>(*session, ticket, gateway::Side::eGateway);
        if (!records->open(gateway::joinRecordOf(message)).has_value()) {
            raw->close();
            return;
        }
        const Bytes joined = gateway::makeJoined(*records);
        const auto channel = std::make_shared<gateway::ChannelSocket>(raw, records);
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            channels_[raw.get()] = channel;
            ++joins_;
        }
        raw->send(std::vector<unsigned char>(joined.begin(), joined.end()));
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
        if (frame.type == FrameType::eStreamOpen) {
            bool refusing = false;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                if (resettingDials_) {
                    socket->send(gateway::encodeJson(FrameType::eStreamReset, frame.ref,
                        {{"code", "unreachable"}, {"message", "no lease set found"}}));
                    return;
                }
                refusing = refusingStreams_;
                if (!answeringStreams_ && !refusing) {
                    return;
                }
                if (!refusing) {
                    streams_.emplace_back(socket, frame.ref);
                }
            }
            socket->send(refusing ? gateway::encodeJson(FrameType::eError, frame.ref,
                                        {{"message", "no lease set found"}})
                                  : gateway::encode(FrameType::eStreamOpened, frame.ref));
            return;
        }
        if (frame.type == FrameType::eStreamData) {
            std::optional<StreamReply> reply;
            {
                const std::lock_guard<std::mutex> lock(mutex_);
                if (streamReply_.has_value() && repliedStreams_.insert(frame.ref).second) {
                    reply = streamReply_;
                }
            }
            if (!reply.has_value()) {
                return;
            }
            if (!reply->bytes.empty()) {
                socket->send(gateway::encode(FrameType::eStreamData, frame.ref, reply->bytes));
            }
            socket->send(gateway::encode(reply->end == StreamEnd::eClose ? FrameType::eStreamClose
                                                                         : FrameType::eStreamReset,
                frame.ref));
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
    bool issuingTickets_ = false;
    bool refusingJoins_ = false;
    std::map<std::string, SecretBytes> ticketSessions_;
    // Weak: a socket of the server must not outlive it.
    std::weak_ptr<gateway::ChannelSocket> control_;
    SecretBytes controlSession_;
    std::size_t socketsOpened_ = 0;
    std::size_t joins_ = 0;
    bool readingHeld_ = false;
    bool answeringStreams_ = false;
    bool refusingStreams_ = false;
    bool resettingDials_ = false;
    struct StreamReply {
        Bytes bytes;
        StreamEnd end = StreamEnd::eClose;
    };
    std::optional<StreamReply> streamReply_;
    std::set<std::uint32_t> repliedStreams_;
    std::condition_variable readingMoved_;
    std::vector<std::pair<std::shared_ptr<http::Socket>, std::uint32_t>> streams_;
    std::vector<std::chrono::steady_clock::time_point> hellosClosed_;
};

}  // namespace bazarish::test
