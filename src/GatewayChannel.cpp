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

std::size_t neededFor(const std::vector<Bytes>& frames)
{
    std::size_t needed = kRecordFlagsBytes;
    for (const Bytes& frame : frames) {
        needed += kRecordLengthBytes + frame.size();
    }
    return needed;
}

Bytes recordOf(const std::vector<Bytes>& frames, const std::uint8_t flags, const std::size_t total)
{
    Bytes plaintext(std::max(total, kRecordHeaderBytes), 0);
    plaintext[0] = flags;
    std::size_t at = kRecordFlagsBytes;
    for (const Bytes& frame : frames) {
        putBigEndian(ByteBuffer(plaintext).subspan(at, kRecordLengthBytes),
            static_cast<std::uint16_t>(frame.size()));
        std::copy(frame.begin(), frame.end(), plaintext.begin() + static_cast<std::ptrdiff_t>(at + kRecordLengthBytes));
        at += kRecordLengthBytes + frame.size();
    }
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

std::chrono::microseconds drawWithin(const std::chrono::microseconds least,
    const std::chrono::microseconds most, shape::RandomSource& random)
{
    return least
        + std::chrono::microseconds(static_cast<std::chrono::microseconds::rep>(
            drawIndex(static_cast<std::uint64_t>((most - least).count()) + 1, random)));
}

std::size_t drawLogUniform(const std::size_t least, const std::size_t most, shape::RandomSource& random)
{
    const double ratio = static_cast<double>(most) / static_cast<double>(least);
    const double drawn
        = std::round(static_cast<double>(least) * std::exp(shape::uniformOpen(random) * std::log(ratio)));
    return std::min(static_cast<std::size_t>(drawn), most);
}

std::size_t paddedTotal(const std::size_t needed, shape::RandomSource& random)
{
    return static_cast<double>(needed) <= kRecordPadCeiling
        ? static_cast<std::size_t>(std::ceil(
            shape::drawAtLeast(recordPad(), static_cast<double>(needed), random)))
        : needed + static_cast<std::size_t>(shape::draw(bulkPad(), random));
}

std::size_t voiceBandFloor(const std::size_t frames)
{
    return frames * kMediaPadPerFrame;
}

std::optional<std::string> hostOf(const Bytes& frame)
{
    if (frame.size() < kFrameHeaderBytes + kHostLengthBytes
        || frame.front() != static_cast<std::uint8_t>(FrameType::eRawSend)) {
        return std::nullopt;
    }
    const std::size_t length
        = getBigEndian(ByteView(frame).subspan(kFrameHeaderBytes, kHostLengthBytes));
    const std::size_t at = kFrameHeaderBytes + kHostLengthBytes;
    if (length > frame.size() - at) {
        return std::nullopt;
    }
    const auto start = frame.begin() + static_cast<std::ptrdiff_t>(at);
    return std::string(start, start + static_cast<std::ptrdiff_t>(length));
}

Bytes withHost(const Bytes& frame, const std::string& present, const std::string& wanted)
{
    Bytes out(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(kFrameHeaderBytes));
    appendBigEndian(out, wanted.size(), kHostLengthBytes);
    out.insert(out.end(), wanted.begin(), wanted.end());
    const auto payload = frame.begin()
        + static_cast<std::ptrdiff_t>(kFrameHeaderBytes + kHostLengthBytes + present.size());
    out.insert(out.end(), payload, frame.end());
    return out;
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
    return recordOf({frame}, flags, paddedTotal(kRecordHeaderBytes + frame.size(), random));
}

std::optional<RecordBody> unpadRecord(const Bytes& plaintext)
{
    if (plaintext.size() < kRecordHeaderBytes || plaintext.size() > kMaxPaddedBytes) {
        return std::nullopt;
    }
    RecordBody body;
    body.flags = plaintext[0];
    std::size_t at = kRecordFlagsBytes;
    while (at + kRecordLengthBytes <= plaintext.size()) {
        const std::size_t length
            = getBigEndian(ByteView(plaintext).subspan(at, kRecordLengthBytes));
        if (length == 0) {
            break;
        }
        at += kRecordLengthBytes;
        if (length > plaintext.size() - at) {
            return std::nullopt;
        }
        const auto start = plaintext.begin() + static_cast<std::ptrdiff_t>(at);
        Bytes frame(start, start + static_cast<std::ptrdiff_t>(length));
        if (body.frame.empty()) {
            body.frame = std::move(frame);
        } else {
            body.following.push_back(std::move(frame));
        }
        at += length;
    }
    return body;
}

bool isFiller(const RecordBody& body)
{
    return body.frame.empty();
}

MediaRegime drawMediaRegime(shape::RandomSource& random)
{
    MediaRegime regime;
    regime.gapLeast = drawWithin(kMediaGapFloorLeast, kMediaGapFloorMost, random);
    regime.gapMost = drawWithin(regime.gapLeast + kMediaGapWidthLeast, kMediaGapCeiling, random);
    regime.fillerShare = shape::uniformOpen(random) * kMediaFillerShareMost;
    regime.padSpan = drawBetween(kMediaPadSpanLeast, kMediaPadSpanMost, random);
    return regime;
}

std::chrono::microseconds drawMediaGap(const MediaRegime& regime, shape::RandomSource& random)
{
    return drawWithin(regime.gapLeast, regime.gapMost, random);
}

Bytes mediaRecord(const std::vector<Bytes>& frames, const std::uint8_t flags,
    const MediaRegime& regime, shape::RandomSource& random)
{
    for (const Bytes& frame : frames) {
        mustFitRecord(frame);
    }
    const std::size_t needed = neededFor(frames);
    const std::size_t least = voiceBandFloor(frames.size());
    const std::size_t most = least + regime.padSpan;
    if (needed > most) {
        return recordOf(frames, flags, paddedTotal(needed, random));
    }
    return recordOf(frames, flags, drawBetween(std::max(needed, least), most, random));
}

Bytes fillerRecord(const std::uint8_t flags, const MediaRegime& regime, shape::RandomSource& random)
{
    if (shape::uniformOpen(random) < kFillerVoiceLike) {
        const std::size_t least
            = voiceBandFloor(1 + static_cast<std::size_t>(drawIndex(kMediaFramesPerRecord, random)));
        return recordOf({}, flags, drawBetween(least, least + regime.padSpan, random));
    }
    return recordOf({}, flags, drawLogUniform(kFillerLeast, kFillerMost, random));
}

MediaPacer::MediaPacer(shape::RandomSource& random, const Clock::time_point start)
    : random_(random)
{
    enter(start);
    due_ = start + drawMediaGap(regime_, random_);
}

void MediaPacer::enter(const Clock::time_point now)
{
    regime_ = drawMediaRegime(random_);
    regimeUntil_ = now + drawWithin(kMediaRegimeLeast, kMediaRegimeMost, random_);
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

MediaPacer::Slot MediaPacer::take(const Clock::time_point now)
{
    if (now >= regimeUntil_) {
        enter(now);
    }
    Slot slot;
    while (slot.frames.size() < kMediaFramesPerRecord && !frames_.empty()) {
        slot.frames.push_back(std::move(frames_.front()));
        frames_.pop_front();
    }
    slot.filler = slot.frames.empty() && shape::uniformOpen(random_) < regime_.fillerShare;
    due_ = now + drawMediaGap(regime_, random_);
    return slot;
}

Bytes HostElision::elide(const Bytes& frame)
{
    const std::optional<std::string> host = hostOf(frame);
    if (!host.has_value() || host->empty()) {
        return frame;
    }
    if (*host != last_) {
        last_ = *host;
        return frame;
    }
    return withHost(frame, *host, {});
}

std::optional<Bytes> HostElision::restore(const Bytes& frame)
{
    const std::optional<std::string> host = hostOf(frame);
    if (!host.has_value()) {
        return frame;
    }
    if (!host->empty()) {
        last_ = *host;
        return frame;
    }
    if (last_.empty()) {
        return std::nullopt;
    }
    return withHost(frame, {}, last_);
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
    const std::optional<SecretBytes> uncovered = cover.open(message);
    if (!uncovered.has_value()) {
        return std::nullopt;
    }
    try {
        const nlohmann::json body
            = parseCbor(unpadded(hybrid::unseal(uncovered->bytes(), gatewaySealing).bytes()));
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
    const nlohmann::json body = {{"key", toBase64(welcome.sessionKey.bytes())},
        {"salt", toBase64(welcome.salt)}, {"tickets", tickets},
        {"client", clientEphemeral.fingerprint()}};
    return cover.seal(hybrid::seal(padded(hybrid::signJson(body, gateway)), clientEphemeral, {}));
}

std::optional<Welcome> openWelcome(const Cover& cover, const Bytes& message,
    const Key& ephemeral, const std::string& fingerprint)
{
    const std::optional<SecretBytes> uncovered = cover.open(message);
    if (!uncovered.has_value()) {
        return std::nullopt;
    }
    const hybrid::VerifiedJson verified
        = hybrid::verifyJson(unpadded(hybrid::unseal(uncovered->bytes(), ephemeral).bytes()));
    if (verified.identityFingerprint != fingerprint) {
        throw WrongGateway("the gateway's welcome is signed by another key than the link names");
    }
    if (verified.body.at("client").get<std::string>() != ephemeral.fingerprint()) {
        throw std::runtime_error("the gateway's welcome was made for another hello");
    }
    Welcome welcome;
    welcome.sessionKey = SecretBytes(fromBase64(verified.body.at("key").get<std::string>()));
    welcome.salt = fromBase64(verified.body.at("salt").get<std::string>());
    for (const nlohmann::json& ticket : verified.body.at("tickets")) {
        welcome.tickets.push_back(fromBase64(ticket.get<std::string>()));
    }
    if (welcome.sessionKey.size() != kSessionKeyBytes) {
        throw std::runtime_error("the gateway's session key is of the wrong size");
    }
    return welcome;
}

Records::Records(const SecretBytes& sessionKey, const Bytes& salt, const Side side)
    : sendKey_(hkdfSha256(sessionKey.bytes(), salt,
        side == Side::eClient ? kClientSendInfo : kGatewaySendInfo, kAeadKeyBytes))
    , receiveKey_(hkdfSha256(sessionKey.bytes(), salt,
          side == Side::eClient ? kGatewaySendInfo : kClientSendInfo, kAeadKeyBytes))
{
}

Bytes Records::seal(const Bytes& plaintext)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    return chachaSeal(sendKey_.bytes(), counterNonce(sent_++), plaintext);
}

std::optional<Bytes> Records::open(const Bytes& record)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::optional<SecretBytes> opened = chachaOpen(receiveKey_.bytes(), counterNonce(received_), record);
    if (!opened.has_value()) {
        return std::nullopt;
    }
    ++received_;
    return opened->release();
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
        MediaPacer::Slot slot = pacer_->take(MediaPacer::Clock::now());
        const MediaRegime regime = pacer_->regime();
        if (slot.frames.empty() && (!slot.filler || backlogged)) {
            continue;
        }
        lock.unlock();
        const std::uint8_t flags = hooks_.flags ? hooks_.flags() : 0;
        if (slot.frames.empty()) {
            sendSealed(fillerRecord(flags, regime, random_));
        } else {
            std::vector<Bytes> frames;
            for (const MediaPacer::Queued& queued : slot.frames) {
                frames.push_back(sentHosts_.elide(queued.frame));
            }
            sendSealed(mediaRecord(frames, flags, regime, random_));
        }
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

void ChannelSocket::closeWhenSent()
{
    stopPacing();
    raw_->closeWhenSent();
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
    std::optional<RecordBody> body = unpadRecord(*opened);
    if (!body.has_value() || isFiller(*body)) {
        return body;
    }
    const std::lock_guard<std::mutex> lock(opening_);
    std::optional<Bytes> first = heardHosts_.restore(body->frame);
    if (!first.has_value()) {
        return std::nullopt;
    }
    body->frame = std::move(*first);
    for (Bytes& frame : body->following) {
        std::optional<Bytes> restored = heardHosts_.restore(frame);
        if (!restored.has_value()) {
            return std::nullopt;
        }
        frame = std::move(*restored);
    }
    return body;
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
            for (const Bytes& frame : opened->following) {
                opening->onMessage(channel, std::vector<unsigned char>(frame.begin(), frame.end()));
            }
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
        const std::optional<SecretBytes> card = cover.open(*first);
        if (!card.has_value()) {
            throw WrongGateway("the gateway's card is not sealed for this link");
        }
        sealing = cardSealingKey(unpadded(card->bytes()), fingerprint);
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
