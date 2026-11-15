// Bazarish project (c) 2026
#include "bazarish/GatewayChannel.hpp"

#include "bazarish/Hybrid.hpp"
#include "bazarish/JsonRead.hpp"
#include "bazarish/Log.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cmath>
#include <condition_variable>
#include <deque>

namespace bazarish::gateway {

namespace {

constexpr char kCoverInfo[] = "bazarish gateway cover";
constexpr char kClientSendInfo[] = "bazarish gateway client to gateway";
constexpr char kGatewaySendInfo[] = "bazarish gateway gateway to client";
constexpr int kCardVersion = 1;
constexpr int kHelloVersion = 1;
constexpr std::size_t kCounterBytes = 8;
constexpr unsigned kBitsPerByte = 8;
constexpr unsigned char kJoinedMark = 1;
constexpr int kNoVersion = 0;
constexpr std::uint64_t kByteMask = 0xFF;

std::size_t drawPad()
{
    const Bytes random = randomBytes(sizeof(std::uint64_t));
    std::uint64_t value = 0;
    for (const unsigned char byte : random) {
        value = (value << kBitsPerByte) | byte;
    }
    const std::uint64_t span = kHandshakePadMax - kHandshakePadMin + 1;
    return kHandshakePadMin + static_cast<std::size_t>(value % span);
}

Bytes counterNonce(const std::uint64_t counter)
{
    Bytes nonce(kAeadNonceBytes, 0);
    for (std::size_t i = 0; i < kCounterBytes; ++i) {
        nonce[kAeadNonceBytes - 1 - i]
            = static_cast<unsigned char>((counter >> (kBitsPerByte * i)) & kByteMask);
    }
    return nonce;
}

Bytes bytesOfBinary(const nlohmann::json& value)
{
    const nlohmann::json::binary_t& binary = value.get_binary();
    return Bytes(binary.begin(), binary.end());
}

void mustFitRecord(const Bytes& frame)
{
    if (frame.size() > kMaxFrameBytes) {
        throw ProtocolError(Fault::eBadFrame, "a frame over the cap does not go in a record");
    }
}

Bytes recordOf(const Bytes& frame, const std::uint8_t flags, const std::size_t total)
{
    Bytes plaintext(total, 0);
    plaintext[0] = flags;
    putBigEndian(ByteBuffer(plaintext).subspan(kRecordFlagsBytes, kRecordLengthBytes),
        static_cast<std::uint16_t>(frame.size()));
    std::copy(frame.begin(), frame.end(), plaintext.begin() + kRecordHeaderBytes);
    return plaintext;
}

// uniformOpen rounds to 1 at its very top, which would land one step past `most`.
std::uint64_t drawIndex(const std::uint64_t count, shape::RandomSource& random)
{
    const auto index = static_cast<std::uint64_t>(
        std::floor(shape::uniformOpen(random) * static_cast<double>(count)));
    return std::min(index, count - 1);
}

std::size_t drawBetween(const std::size_t least, const std::size_t most, shape::RandomSource& random)
{
    return least + static_cast<std::size_t>(drawIndex(most - least + 1, random));
}

bool isDatagram(const std::vector<unsigned char>& message)
{
    if (message.empty()) {
        return false;
    }
    const std::optional<FrameType> type = frameTypeFromByte(message.front());
    return type == FrameType::eRawSend || type == FrameType::eRawRecv;
}

}  // namespace

Bytes issueCard(const Identity& identity, const Key& sealing)
{
    return hybrid::signJson({{"v", kCardVersion}, {"sealing", toBase64(sealing.publicDer())}},
        identity);
}

Key cardSealingKey(const Bytes& card, const std::string& fingerprint)
{
    const hybrid::VerifiedJson verified = hybrid::verifyJson(card);
    if (verified.identityFingerprint != fingerprint) {
        throw WrongGateway("the gateway's card is signed by another key than the link names");
    }
    if (verified.body.value("v", kNoVersion) != kCardVersion) {
        throw std::runtime_error("the gateway's card is of another version");
    }
    return Key::fromPublicDer(fromBase64(verified.body.at("sealing").get<std::string>()));
}

Cover::Cover(const std::string& fingerprint)
    : KeyedSeal(Bytes(fingerprint.begin(), fingerprint.end()), kCoverInfo)
{
}

Bytes padded(const Bytes& body)
{
    const nlohmann::json framed = nlohmann::json::array(
        {nlohmann::json::binary(body), nlohmann::json::binary(randomBytes(drawPad()))});
    const std::vector<std::uint8_t> encoded = nlohmann::json::to_cbor(framed);
    return Bytes(encoded.begin(), encoded.end());
}

Bytes unpadded(const Bytes& message)
{
    const nlohmann::json framed = parseCbor(message);
    if (!framed.is_array() || framed.size() != 2 || !framed.at(0).is_binary()) {
        throw std::runtime_error("a padded message is a body and its padding");
    }
    return bytesOfBinary(framed.at(0));
}

shape::LogNormal recordPad()
{
    return {kRecordPadMedian, kRecordPadSigma, kRecordPadFloor, kRecordPadCeiling};
}

shape::LogNormal bulkPad()
{
    return {kBulkPadMedian, kBulkPadSigma, 0, static_cast<double>(kBulkPadMax)};
}

std::chrono::milliseconds drawIdleKeepalive(shape::RandomSource& random)
{
    const std::chrono::milliseconds least = kIdleKeepaliveMin;
    const std::chrono::milliseconds span = kIdleKeepaliveMax - kIdleKeepaliveMin;
    return least
        + std::chrono::milliseconds(static_cast<std::chrono::milliseconds::rep>(
            std::floor(shape::uniformOpen(random) * static_cast<double>(span.count()))));
}

Bytes padRecord(const Bytes& frame, const std::uint8_t flags, shape::RandomSource& random)
{
    mustFitRecord(frame);
    const std::size_t needed = kRecordHeaderBytes + frame.size();
    const std::size_t total = static_cast<double>(needed) <= kRecordPadCeiling
        ? static_cast<std::size_t>(std::ceil(shape::drawAtLeast(
            recordPad(), static_cast<double>(needed), random)))
        : needed + static_cast<std::size_t>(shape::draw(bulkPad(), random));
    return recordOf(frame, flags, total);
}

Bytes mediaRecord(const Bytes& frame, const std::uint8_t flags, shape::RandomSource& random)
{
    mustFitRecord(frame);
    const std::size_t needed = kRecordHeaderBytes + frame.size();
    if (needed > kMediaPadCeiling) {
        return padRecord(frame, flags, random);
    }
    return recordOf(frame, flags, drawBetween(std::max(needed, kMediaPadFloor), kMediaPadCeiling, random));
}

Bytes fillerRecord(const std::uint8_t flags, shape::RandomSource& random)
{
    return recordOf({}, flags | kRecordFiller, drawBetween(kMediaPadFloor, kMediaPadCeiling, random));
}

std::optional<RecordBody> unpadRecord(const Bytes& plaintext)
{
    if (plaintext.size() < kRecordHeaderBytes || plaintext.size() > kMaxPaddedBytes) {
        return std::nullopt;
    }
    const std::size_t length = getBigEndian(
        ByteView(plaintext).subspan(kRecordFlagsBytes, kRecordLengthBytes));
    if (length > plaintext.size() - kRecordHeaderBytes) {
        return std::nullopt;
    }
    RecordBody body;
    body.flags = plaintext[0];
    const auto start = plaintext.begin() + kRecordHeaderBytes;
    body.frame.assign(start, start + static_cast<std::ptrdiff_t>(length));
    return body;
}

bool isFiller(const RecordBody& body)
{
    return (body.flags & kRecordFiller) != 0;
}

std::chrono::microseconds drawMediaGap(shape::RandomSource& random)
{
    const std::chrono::microseconds span = kMediaGapMax - kMediaGapMin;
    return kMediaGapMin
        + std::chrono::microseconds(static_cast<std::chrono::microseconds::rep>(
            drawIndex(static_cast<std::uint64_t>(span.count()) + 1, random)));
}

MediaPacer::MediaPacer(shape::RandomSource& random, const Clock::time_point start)
    : random_(random)
    , due_(start + drawMediaGap(random))
{
}

bool MediaPacer::queue(Bytes frame, const Clock::time_point at)
{
    bool kept = true;
    if (frames_.size() >= kMediaQueueLimit) {
        frames_.pop_front();
        ++dropped_;
        kept = false;
    }
    frames_.push_back(Queued{std::move(frame), at});
    return kept;
}

std::optional<MediaPacer::Queued> MediaPacer::take(const Clock::time_point now)
{
    due_ = now + drawMediaGap(random_);
    if (frames_.empty()) {
        return std::nullopt;
    }
    Queued oldest = std::move(frames_.front());
    frames_.pop_front();
    return oldest;
}

std::string pingCarrying(const std::uint8_t flags)
{
    return std::string(kRecordFlagsBytes, static_cast<char>(flags));
}

std::optional<std::uint8_t> flagsOfPing(const std::string& payload)
{
    if (payload.size() != kRecordFlagsBytes) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(payload.front());
}

Hello makeHello(const Cover& cover, const Key& gatewaySealing)
{
    Key ephemeral = Key::generateSealing();
    const nlohmann::json body
        = {{"v", kHelloVersion}, {"ephemeral", nlohmann::json::binary(ephemeral.publicDer())}};
    const std::vector<std::uint8_t> encoded = nlohmann::json::to_cbor(body);
    const Bytes message
        = cover.seal(hybrid::seal(padded(Bytes(encoded.begin(), encoded.end())), gatewaySealing, {}));
    return Hello{std::move(ephemeral), message};
}

std::optional<Key> openHello(const Cover& cover, const Bytes& message, const Key& gatewaySealing)
{
    const std::optional<Bytes> uncovered = cover.open(message);
    if (!uncovered.has_value()) {
        return std::nullopt;
    }
    try {
        const nlohmann::json body
            = parseCbor(unpadded(hybrid::unseal(*uncovered, gatewaySealing)));
        if (body.value("v", kNoVersion) != kHelloVersion || !body.at("ephemeral").is_binary()) {
            return std::nullopt;
        }
        return Key::fromPublicDer(bytesOfBinary(body.at("ephemeral")));
    } catch (const std::exception& error) {
        log::debug("gateway: a hello that does not open: {}", error.what());
        return std::nullopt;
    }
}

Bytes makeWelcome(const Cover& cover, const Welcome& welcome, const Key& clientEphemeral,
    const Identity& gateway)
{
    nlohmann::json tickets = nlohmann::json::array();
    for (const Bytes& ticket : welcome.tickets) {
        tickets.push_back(toBase64(ticket));
    }
    const nlohmann::json body = {{"key", toBase64(welcome.sessionKey)},
        {"salt", toBase64(welcome.salt)}, {"tickets", tickets},
        {"client", clientEphemeral.fingerprint()}};
    return cover.seal(hybrid::seal(padded(hybrid::signJson(body, gateway)), clientEphemeral, {}));
}

std::optional<Welcome> openWelcome(const Cover& cover, const Bytes& message,
    const Key& ephemeral, const std::string& fingerprint)
{
    const std::optional<Bytes> uncovered = cover.open(message);
    if (!uncovered.has_value()) {
        return std::nullopt;
    }
    const hybrid::VerifiedJson verified
        = hybrid::verifyJson(unpadded(hybrid::unseal(*uncovered, ephemeral)));
    if (verified.identityFingerprint != fingerprint) {
        throw WrongGateway("the gateway's welcome is signed by another key than the link names");
    }
    if (verified.body.at("client").get<std::string>() != ephemeral.fingerprint()) {
        throw std::runtime_error("the gateway's welcome was made for another hello");
    }
    Welcome welcome;
    welcome.sessionKey = fromBase64(verified.body.at("key").get<std::string>());
    welcome.salt = fromBase64(verified.body.at("salt").get<std::string>());
    for (const nlohmann::json& ticket : verified.body.at("tickets")) {
        welcome.tickets.push_back(fromBase64(ticket.get<std::string>()));
    }
    if (welcome.sessionKey.size() != kSessionKeyBytes) {
        throw std::runtime_error("the gateway's session key is of the wrong size");
    }
    return welcome;
}

Records::Records(const Bytes& sessionKey, const Bytes& salt, const Side side)
{
    const Bytes clientSends = hkdfSha256(sessionKey, salt, kClientSendInfo, kAeadKeyBytes);
    const Bytes gatewaySends = hkdfSha256(sessionKey, salt, kGatewaySendInfo, kAeadKeyBytes);
    sendKey_ = side == Side::eClient ? clientSends : gatewaySends;
    receiveKey_ = side == Side::eClient ? gatewaySends : clientSends;
}

Bytes Records::seal(const Bytes& plaintext)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return chachaSeal(sendKey_, counterNonce(sent_++), plaintext);
}

std::optional<Bytes> Records::open(const Bytes& record)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::optional<Bytes> opened = chachaOpen(receiveKey_, counterNonce(received_), record);
    if (opened.has_value()) {
        ++received_;
    }
    return opened;
}

Bytes makeJoin(const Bytes& ticket, Records& records)
{
    Bytes join = ticket;
    const Bytes record = records.seal(padded({}));
    join.insert(join.end(), record.begin(), record.end());
    return join;
}

Bytes ticketOf(const Bytes& join)
{
    if (join.size() < kTicketBytes) {
        return {};
    }
    return Bytes(join.begin(), join.begin() + kTicketBytes);
}

Bytes joinRecordOf(const Bytes& join)
{
    if (join.size() < kTicketBytes) {
        return {};
    }
    return Bytes(join.begin() + kTicketBytes, join.end());
}

Bytes makeJoined(Records& records)
{
    return records.seal(padded({kJoinedMark}));
}

bool isJoined(const Bytes& opened)
{
    return unpadded(opened) == Bytes{kJoinedMark};
}

Bytes refusedJoin()
{
    return randomBytes(padded({kJoinedMark}).size() + kAeadTagBytes);
}

ChannelSocket::ChannelSocket(
    http::SocketPtr raw, std::shared_ptr<Records> records, ChannelHooks hooks)
    : raw_(std::move(raw))
    , records_(std::move(records))
    , hooks_(std::move(hooks))
{
}

ChannelSocket::~ChannelSocket()
{
    stopPacing();
    if (pacerThread_.joinable()) {
        pacerThread_.join();
    }
}

void ChannelSocket::carryMedia()
{
    const std::lock_guard<std::mutex> lock(pacing_);
    if (pacer_.has_value() || stopping_) {
        return;
    }
    pacer_.emplace(random_, MediaPacer::Clock::now());
    pacerThread_ = std::thread([this]() { pace(); });
}

std::uint64_t ChannelSocket::mediaDropped() const
{
    const std::lock_guard<std::mutex> lock(pacing_);
    return pacer_.has_value() ? pacer_->dropped() : 0;
}

void ChannelSocket::sendSealed(const Bytes& plaintext)
{
    // The nonce is the record's place in the stream, so sealing and queueing are one step.
    const std::lock_guard<std::mutex> lock(sending_);
    const Bytes record = records_->seal(plaintext);
    raw_->send(std::vector<unsigned char>(record.begin(), record.end()));
}

void ChannelSocket::send(std::vector<unsigned char> message)
{
    const Bytes frame(message.begin(), message.end());
    mustFitRecord(frame);
    if (isDatagram(message)) {
        std::unique_lock<std::mutex> lock(pacing_);
        if (pacer_.has_value()) {
            const bool kept = pacer_->queue(frame, MediaPacer::Clock::now());
            const std::uint64_t dropped = pacer_->dropped();
            lock.unlock();
            if (!kept) {
                log::warn("gateway: media queue full; the oldest datagram dropped ({} so far)",
                    dropped);
            }
            if (hooks_.sent) {
                hooks_.sent();
            }
            return;
        }
    }
    const std::uint8_t flags = hooks_.flags ? hooks_.flags() : 0;
    sendSealed(padRecord(frame, flags, random_));
    if (hooks_.sent) {
        hooks_.sent();
    }
}

void ChannelSocket::pace()
{
    std::unique_lock<std::mutex> lock(pacing_);
    while (!stopping_) {
        const MediaPacer::Clock::time_point due = pacer_->due();
        if (paced_.wait_until(lock, due, [this]() { return stopping_; })) {
            break;
        }
        if (!raw_->open()) {
            break;
        }
        const bool backlogged = raw_->pending() > kMediaBacklogBytes;
        const std::optional<MediaPacer::Queued> carried = pacer_->take(MediaPacer::Clock::now());
        if (!carried.has_value() && backlogged) {
            continue;
        }
        lock.unlock();
        const std::uint8_t flags = hooks_.flags ? hooks_.flags() : 0;
        sendSealed(carried.has_value() ? mediaRecord(carried->frame, flags, random_)
                                       : fillerRecord(flags, random_));
        lock.lock();
    }
}

void ChannelSocket::stopPacing()
{
    {
        const std::lock_guard<std::mutex> lock(pacing_);
        stopping_ = true;
    }
    paced_.notify_all();
}

std::size_t ChannelSocket::pending() const
{
    return raw_->pending();
}

void ChannelSocket::close()
{
    stopPacing();
    raw_->close();
}

bool ChannelSocket::open() const
{
    return raw_->open();
}

std::optional<RecordBody> ChannelSocket::openRecord(const Bytes& record)
{
    const std::optional<Bytes> opened = records_->open(record);
    if (!opened.has_value()) {
        return std::nullopt;
    }
    return unpadRecord(*opened);
}

namespace {

struct Opening {
    std::mutex mutex;
    std::condition_variable arrived;
    std::deque<Bytes> early;
    // Weak: the socket's callbacks hold the opening, and the channel holds the socket.
    std::weak_ptr<ChannelSocket> channel;
    bool established = false;
    bool closed = false;
    ChannelMessageFn onMessage;
    ChannelClosedFn onClosed;
};

std::optional<Bytes> nextEarly(Opening& opening)
{
    std::unique_lock<std::mutex> lock(opening.mutex);
    if (!opening.arrived.wait_for(lock, kHandshakeTimeout,
            [&opening]() { return !opening.early.empty() || opening.closed; })) {
        return std::nullopt;
    }
    if (opening.early.empty()) {
        return std::nullopt;
    }
    Bytes message = std::move(opening.early.front());
    opening.early.pop_front();
    return message;
}

}  // namespace

ChannelOpened openChannel(const http::SocketDial& dial, const std::string& fingerprint,
    const std::optional<ChannelJoin>& join, ChannelMessageFn onMessage, ChannelClosedFn onClosed,
    ChannelHooks hooks)
{
    const std::shared_ptr<Opening> opening = std::make_shared<Opening>();
    opening->onMessage = std::move(onMessage);
    opening->onClosed = std::move(onClosed);
    const http::SocketDialResult dialled = http::openSocket(
        dial,
        [opening](const http::SocketPtr& raw, const std::vector<unsigned char>& message) {
            std::shared_ptr<ChannelSocket> channel;
            {
                const std::lock_guard<std::mutex> lock(opening->mutex);
                if (!opening->established) {
                    opening->early.emplace_back(message.begin(), message.end());
                    opening->arrived.notify_all();
                    return;
                }
                channel = opening->channel.lock();
            }
            if (channel == nullptr) {
                return;
            }
            const std::optional<RecordBody> opened
                = channel->openRecord(Bytes(message.begin(), message.end()));
            if (!opened.has_value()) {
                log::warn("gateway: a record that does not open; the socket is closed");
                raw->close();
                return;
            }
            if (isFiller(*opened)) {
                return;
            }
            opening->onMessage(
                channel, std::vector<unsigned char>(opened->frame.begin(), opened->frame.end()));
        },
        [opening](const http::SocketPtr&) {
            std::shared_ptr<ChannelSocket> channel;
            {
                const std::lock_guard<std::mutex> lock(opening->mutex);
                opening->closed = true;
                channel = opening->channel.lock();
            }
            opening->arrived.notify_all();
            if (channel != nullptr) {
                opening->onClosed(channel);
            }
        });
    ChannelOpened result;
    if (dialled.socket == nullptr) {
        result.error = dialled.error;
        return result;
    }
    const http::SocketPtr raw = dialled.socket;
    const auto fail = [&raw, &result](const std::string& why) {
        raw->close();
        result.error = why;
        return result;
    };
    const Cover cover(fingerprint);

    const std::optional<Bytes> first = nextEarly(*opening);
    if (!first.has_value()) {
        return fail("the gateway sent no card");
    }
    std::optional<Key> sealing;
    try {
        const std::optional<Bytes> card = cover.open(*first);
        if (!card.has_value()) {
            throw WrongGateway("the gateway's card is not sealed for this link");
        }
        sealing = cardSealingKey(unpadded(*card), fingerprint);
    } catch (const WrongGateway& error) {
        result.wrongGateway = true;
        return fail(error.what());
    } catch (const std::exception& error) {
        return fail(std::string("the gateway's card does not read: ") + error.what());
    }

    std::shared_ptr<Records> records;
    if (join.has_value()) {
        const std::shared_ptr<Records> joining
            = std::make_shared<Records>(join->sessionKey, join->ticket, Side::eClient);
        const Bytes asked = makeJoin(join->ticket, *joining);
        raw->send(std::vector<unsigned char>(asked.begin(), asked.end()));
        result.ticketSpent = true;
        const std::optional<Bytes> answer = nextEarly(*opening);
        if (!answer.has_value()) {
            return fail("the gateway did not answer a join");
        }
        const std::optional<Bytes> opened = joining->open(*answer);
        try {
            if (opened.has_value() && isJoined(*opened)) {
                records = joining;
            }
        } catch (const std::exception& error) {
            log::debug("gateway: a join answer that does not read: {}", error.what());
        }
    }
    if (records == nullptr) {
        Hello hello = makeHello(cover, *sealing);
        raw->send(std::vector<unsigned char>(hello.message.begin(), hello.message.end()));
        const std::optional<Bytes> answer = nextEarly(*opening);
        if (!answer.has_value()) {
            return fail("the gateway did not welcome this client");
        }
        try {
            result.welcome = openWelcome(cover, *answer, hello.ephemeral, fingerprint);
        } catch (const WrongGateway& error) {
            result.wrongGateway = true;
            return fail(error.what());
        } catch (const std::exception& error) {
            return fail(std::string("the gateway's welcome does not read: ") + error.what());
        }
        if (!result.welcome.has_value()) {
            return fail("the gateway's welcome is not sealed for this link");
        }
        records = std::make_shared<Records>(
            result.welcome->sessionKey, result.welcome->salt, Side::eClient);
    }

    const std::shared_ptr<ChannelSocket> channel
        = std::make_shared<ChannelSocket>(raw, records, std::move(hooks));
    bool outOfTurn = false;
    {
        const std::lock_guard<std::mutex> lock(opening->mutex);
        outOfTurn = !opening->early.empty();
        opening->channel = channel;
        opening->established = true;
    }
    if (outOfTurn) {
        return fail("the gateway spoke before the client's first frame");
    }
    result.socket = channel;
    return result;
}

}  // namespace bazarish::gateway
