// Bazarish project (c) 2026
#include "bazarish/GatewayChannel.hpp"
#include "bazarish/JsonRead.hpp"
#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <algorithm>
#include <limits>
#include <random>
#include <set>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr int kDraws = 16;
// CBOR heads and tags around a padded message.
constexpr std::size_t kFraming = 64;
constexpr std::uint64_t kSeed = 1112;
constexpr int kRecords = 4000;
// Two samples of kRecords from one distribution part by more than this once in a million.
constexpr double kSameDistribution = 0.06;
constexpr std::size_t kMailWaitBytes = 1300;
constexpr std::size_t kAnswerBytes = 500;
constexpr std::size_t kDistinctLengths = 200;
constexpr std::uint32_t kAnyRef = 7;
constexpr std::uint64_t kAnyCredit = 123456;
constexpr std::size_t kVoiceBytes = 160;

class SeededRandom final : public shape::RandomSource {
public:
    explicit SeededRandom(const std::uint64_t seed) : engine_(seed) {}
    std::uint64_t next() override { return engine_(); }

private:
    std::mt19937_64 engine_;
};

class Captured final : public http::Socket {
public:
    void send(std::vector<unsigned char> message) override { sent.push_back(std::move(message)); }
    std::size_t pending() const override { return 0; }
    void close() override {}
    bool open() const override { return true; }

    std::vector<std::vector<unsigned char>> sent;
};

double kolmogorovSmirnov(std::vector<std::size_t> one, std::vector<std::size_t> two)
{
    std::sort(one.begin(), one.end());
    std::sort(two.begin(), two.end());
    double widest = 0;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < one.size() && j < two.size()) {
        const std::size_t at = std::min(one[i], two[j]);
        while (i < one.size() && one[i] == at) {
            ++i;
        }
        while (j < two.size() && two[j] == at) {
            ++j;
        }
        const double gap = static_cast<double>(i) / static_cast<double>(one.size())
            - static_cast<double>(j) / static_cast<double>(two.size());
        widest = std::max(widest, gap < 0 ? -gap : gap);
    }
    return widest;
}

std::string anyHost()
{
    return std::string(52, 'a') + ".b32.i2p";
}

std::vector<Bytes> datagrams()
{
    return {encodeRawSend(kAnyRef, anyHost(), randomBytes(kVoiceBytes)),
        encode(FrameType::eRawRecv, kAnyRef, randomBytes(kVoiceBytes))};
}

std::vector<Bytes> frameClasses()
{
    return {encodeCredit(kAnyRef, kAnyCredit),
        encodeJson(FrameType::eEndpointStatus, kAnyRef,
            {{"ready", true}, {"host", anyHost()}, {"tunnelsIn", 3},
                {"tunnelsOut", 3}, {"leaseSets", 1}, {"localRoute", false}}),
        encode(FrameType::eStreamData, kAnyRef, randomBytes(kAnswerBytes)),
        encode(FrameType::eStreamData, kAnyRef, randomBytes(kMailWaitBytes)),
        datagrams().front(), datagrams().back()};
}

void checkMediaBare(const Bytes& sessionKey, const Bytes& salt)
{
    for (const Bytes& datagram : datagrams()) {
        const Bytes bare = bareRecord(datagram, kRecordActive);
        CHECK(bare.size() == kRecordHeaderBytes + datagram.size());
        CHECK(unpadRecord(bare)->frame == datagram);
        CHECK(unpadRecord(bare)->flags == kRecordActive);
    }
    CHECK_THROWS(bareRecord(Bytes(kMaxFrameBytes + 1, 0), 0));

    const std::shared_ptr<Captured> captured = std::make_shared<Captured>();
    ChannelSocket lane(captured, std::make_shared<Records>(sessionKey, salt, Side::eClient),
        ChannelHooks{[]() { return kRecordActive; }, {}});
    lane.carryMedia();
    Records far(sessionKey, salt, Side::eGateway);
    for (const Bytes& frame : frameClasses()) {
        lane.send(std::vector<unsigned char>(frame.begin(), frame.end()));
        const std::vector<unsigned char>& wire = captured->sent.back();
        const std::optional<Bytes> opened = far.open(Bytes(wire.begin(), wire.end()));
        CHECK(opened.has_value());
        CHECK(unpadRecord(*opened)->frame == frame);
        CHECK(unpadRecord(*opened)->flags == kRecordActive);
        const FrameType type = static_cast<FrameType>(frame.front());
        if (type == FrameType::eRawSend || type == FrameType::eRawRecv) {
            CHECK(wire.size() == kRecordHeaderBytes + frame.size() + kAeadTagBytes);
        } else {
            CHECK(wire.size() >= static_cast<std::size_t>(kRecordPadFloor) + kAeadTagBytes);
        }
    }
}

void checkRecordPadding(const Bytes& sessionKey, const Bytes& salt)
{
    Records clientSide(sessionKey, salt, Side::eClient);
    Records gatewaySide(sessionKey, salt, Side::eGateway);
    SeededRandom random(kSeed);
    const std::vector<Bytes> classes = frameClasses();
    std::vector<std::vector<std::size_t>> lengths(classes.size());
    for (std::size_t kind = 0; kind < classes.size(); ++kind) {
        CHECK(kRecordHeaderBytes + classes[kind].size() <= kRecordPadFloor);
        std::set<std::size_t> distinct;
        for (int i = 0; i < kRecords; ++i) {
            const Bytes record
                = clientSide.seal(padRecord(classes[kind], kRecordActive, random));
            CHECK(record.size() >= static_cast<std::size_t>(kRecordPadFloor) + kAeadTagBytes);
            CHECK(record.size() <= static_cast<std::size_t>(kRecordPadCeiling) + kAeadTagBytes);
            lengths[kind].push_back(record.size());
            distinct.insert(record.size());
            const std::optional<Bytes> opened = gatewaySide.open(record);
            CHECK(opened.has_value());
            const std::optional<RecordBody> body = unpadRecord(*opened);
            CHECK(body.has_value());
            CHECK(body->frame == classes[kind]);
            CHECK(body->flags == kRecordActive);
        }
        CHECK(distinct.size() > kDistinctLengths);
    }
    for (std::size_t one = 0; one < classes.size(); ++one) {
        for (std::size_t two = one + 1; two < classes.size(); ++two) {
            const double distance = kolmogorovSmirnov(lengths[one], lengths[two]);
            std::printf("record lengths, class %zu against %zu: KS %.4f\n", one, two, distance);
            CHECK(distance < kSameDistribution);
        }
    }

    const Bytes bulk = encode(FrameType::eStreamData, kAnyRef, randomBytes(kMaxBodyBytes));
    std::set<std::size_t> bulkLengths;
    for (int i = 0; i < kDraws; ++i) {
        const Bytes plaintext = padRecord(bulk, 0, random);
        CHECK(plaintext.size() >= kRecordHeaderBytes + bulk.size());
        CHECK(plaintext.size() <= kMaxPaddedBytes);
        bulkLengths.insert(plaintext.size());
        CHECK(unpadRecord(plaintext)->frame == bulk);
    }
    CHECK(bulkLengths.size() > 1);
    CHECK_THROWS(padRecord(Bytes(kMaxFrameBytes + 1, 0), 0, random));

    CHECK(!unpadRecord(Bytes{}).has_value());
    CHECK(!unpadRecord(Bytes{0, 0}).has_value());
    Bytes lying = padRecord(classes.front(), 0, random);
    std::fill_n(lying.begin() + kRecordFlagsBytes, kRecordLengthBytes,
        std::numeric_limits<std::uint8_t>::max());
    CHECK(!unpadRecord(lying).has_value());
    CHECK(flagsOfPing(pingCarrying(kRecordActive)) == kRecordActive);
    CHECK(flagsOfPing(pingCarrying(0)) == 0);
    CHECK(!flagsOfPing(std::string()).has_value());

    const std::shared_ptr<Captured> captured = std::make_shared<Captured>();
    std::size_t told = 0;
    ChannelSocket channel(captured,
        std::make_shared<Records>(sessionKey, salt, Side::eClient),
        ChannelHooks{[]() { return kRecordActive; }, [&told]() { ++told; }});
    Records far(sessionKey, salt, Side::eGateway);
    std::vector<std::vector<std::size_t>> sentLengths(classes.size());
    for (int i = 0; i < kRecords; ++i) {
        for (std::size_t kind = 0; kind < classes.size(); ++kind) {
            channel.send(std::vector<unsigned char>(classes[kind].begin(), classes[kind].end()));
            const std::vector<unsigned char>& wire = captured->sent.back();
            sentLengths[kind].push_back(wire.size());
            const std::optional<Bytes> opened = far.open(Bytes(wire.begin(), wire.end()));
            CHECK(opened.has_value());
            CHECK(unpadRecord(*opened)->frame == classes[kind]);
            CHECK(unpadRecord(*opened)->flags == kRecordActive);
        }
    }
    CHECK(told == classes.size() * static_cast<std::size_t>(kRecords));
    for (std::size_t kind = 1; kind < classes.size(); ++kind) {
        const double distance = kolmogorovSmirnov(sentLengths.front(), sentLengths[kind]);
        std::printf("sent records, class 0 against %zu: KS %.4f\n", kind, distance);
        CHECK(distance < kSameDistribution);
    }
}

std::size_t widest(const Bytes& sent, const Bytes& paddedBody)
{
    const nlohmann::json framed = bazarish::parseCbor(paddedBody);
    return sent.size() - framed.at(1).get_binary().size() + kHandshakePadMax + kFraming;
}

}  // namespace

int main()
{
    const Identity gatewayIdentity = Identity::generate();
    const Key gatewaySealing = Key::generateSealing();
    const std::string fingerprint = gatewayIdentity.fingerprint();
    const Cover cover(fingerprint);

    const Bytes card = issueCard(gatewayIdentity, gatewaySealing);
    CHECK(cardSealingKey(card, fingerprint).publicDer() == gatewaySealing.publicDer());
    CHECK_THROWS(cardSealingKey(card, Identity::generate().fingerprint()));
    const Bytes coveredCard = cover.seal(padded(card));
    CHECK(!Cover(Identity::generate().fingerprint()).open(coveredCard).has_value());
    CHECK(unpadded(*cover.open(coveredCard)) == card);

    std::set<std::size_t> lengths;
    for (int i = 0; i < kDraws; ++i) {
        lengths.insert(cover.seal(padded(card)).size());
    }
    CHECK(lengths.size() > 1);
    CHECK(widest(coveredCard, *cover.open(coveredCard)) <= kMaxRecordBytes);

    const Hello hello = makeHello(cover, gatewaySealing);
    const std::optional<Key> client = openHello(cover, hello.message, gatewaySealing);
    CHECK(client.has_value());
    CHECK(client->publicDer() == hello.ephemeral.publicDer());
    CHECK(!openHello(Cover(Identity::generate().fingerprint()), hello.message, gatewaySealing));
    CHECK(!openHello(cover, hello.message, Key::generateSealing()));

    Welcome welcome;
    welcome.sessionKey = randomBytes(kSessionKeyBytes);
    welcome.salt = randomBytes(kTicketBytes);
    for (std::size_t i = 0; i < kTicketsHeld; ++i) {
        welcome.tickets.push_back(randomBytes(kTicketBytes));
    }
    const Bytes answer = makeWelcome(cover, welcome, *client, gatewayIdentity);
    CHECK(widest(hello.message, hybrid::unseal(*cover.open(hello.message), gatewaySealing))
        <= kMaxRecordBytes);
    CHECK(widest(answer, hybrid::unseal(*cover.open(answer), hello.ephemeral)) <= kMaxRecordBytes);
    const std::optional<Welcome> taken = openWelcome(cover, answer, hello.ephemeral, fingerprint);
    CHECK(taken.has_value());
    CHECK(taken->sessionKey == welcome.sessionKey);
    CHECK(taken->tickets == welcome.tickets);
    const Hello other = makeHello(cover, gatewaySealing);
    CHECK_THROWS(openWelcome(cover, answer, other.ephemeral, fingerprint));
    const Identity impostor = Identity::generate();
    const Bytes forged = makeWelcome(cover, welcome, *client, impostor);
    CHECK_THROWS(openWelcome(cover, forged, hello.ephemeral, fingerprint));

    Records clientSide(welcome.sessionKey, welcome.salt, Side::eClient);
    Records gatewaySide(welcome.sessionKey, welcome.salt, Side::eGateway);
    const Bytes frame = {1, 2, 3, 4};
    const Bytes first = clientSide.seal(frame);
    const Bytes second = clientSide.seal(frame);
    CHECK(first != second);
    CHECK(gatewaySide.open(first) == frame);
    Bytes tampered = second;
    tampered.back() ^= 1;
    CHECK(!gatewaySide.open(tampered).has_value());
    CHECK(gatewaySide.open(second) == frame);
    CHECK(clientSide.open(gatewaySide.seal(frame)) == frame);

    const Bytes ticket = welcome.tickets.front();
    Records joining(welcome.sessionKey, ticket, Side::eClient);
    Records joined(welcome.sessionKey, ticket, Side::eGateway);
    const Bytes join = makeJoin(ticket, joining);
    CHECK(ticketOf(join) == ticket);
    const std::optional<Bytes> asked = joined.open(joinRecordOf(join));
    CHECK(asked.has_value() && unpadded(*asked).empty());
    const std::optional<Bytes> told = joining.open(makeJoined(joined));
    CHECK(told.has_value() && isJoined(*told));
    Records otherSocket(welcome.sessionKey, welcome.tickets.back(), Side::eGateway);
    CHECK(!otherSocket.open(joining.seal(frame)).has_value());

    std::set<std::size_t> refusals;
    std::set<std::size_t> answers;
    for (int i = 0; i < kDraws; ++i) {
        Records any(welcome.sessionKey, ticket, Side::eGateway);
        refusals.insert(refusedJoin().size());
        answers.insert(makeJoined(any).size());
    }
    for (const std::set<std::size_t>* const sizes : {&refusals, &answers}) {
        CHECK(sizes->size() > 1);
        CHECK(*sizes->begin() >= kHandshakePadMin);
        CHECK(*sizes->rbegin() <= kHandshakePadMax + kFraming);
    }

    checkRecordPadding(welcome.sessionKey, welcome.salt);
    checkMediaBare(welcome.sessionKey, welcome.salt);
    std::printf("TestGatewayChannel ok\n");
    return 0;
}
