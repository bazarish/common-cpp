// Bazarish project (c) 2026
#include "bazarish/GatewayChannel.hpp"
#include "bazarish/Hybrid.hpp"

#include "TestUtil.hpp"

#include <set>
#include <string>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

constexpr int kDraws = 16;
// CBOR heads and tags around a padded message.
constexpr std::size_t kFraming = 64;

std::size_t widest(const Bytes& sent, const Bytes& paddedBody)
{
    const nlohmann::json framed = nlohmann::json::from_cbor(paddedBody);
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
    return 0;
}
