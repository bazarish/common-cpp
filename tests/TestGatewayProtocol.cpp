// Bazarish project (c) 2026
#include "bazarish/GatewayProtocol.hpp"

#include "TestUtil.hpp"

#include <set>
#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::gateway;

namespace {

const std::vector<FrameType> kAllTypes = {FrameType::eHello, FrameType::eReady, FrameType::eOk,
    FrameType::eError, FrameType::eResume, FrameType::eAttach, FrameType::eEndpointCreate,
    FrameType::eEndpointStop, FrameType::eEndpointStatus, FrameType::eStreamOpen,
    FrameType::eStreamOpened, FrameType::eStreamInbound, FrameType::eStreamData,
    FrameType::eStreamCredit, FrameType::eStreamClose, FrameType::eStreamReset,
    FrameType::eRawSend, FrameType::eRawRecv};

const std::vector<Fault> kAllFaults = {Fault::eVersion, Fault::eBadFrame, Fault::eUnknownId,
    Fault::eNoEndpoint, Fault::eUnsupported, Fault::eRefused, Fault::eUnreachable, Fault::eTimeout,
    Fault::eClosed, Fault::eWrongLane, Fault::eInternal};

Frame roundTrip(const Bytes& wire)
{
    return decode(wire.data(), wire.size());
}

}  // namespace

int main()
{
    // Every type has a name of its own and survives the byte it travels as.
    std::set<std::string> names;
    for (const FrameType type : kAllTypes) {
        const std::string name(frameTypeName(type));
        CHECK(!name.empty());
        CHECK(name != "unknown");
        CHECK(names.insert(name).second);
        const std::optional<FrameType> back
            = frameTypeFromByte(static_cast<std::uint8_t>(type));
        CHECK(back.has_value());
        CHECK(back.value() == type);
    }
    // A byte nobody assigned is not quietly accepted.
    CHECK(!frameTypeFromByte(0x00).has_value());
    CHECK(!frameTypeFromByte(0x13).has_value());
    CHECK(!frameTypeFromByte(0x40).has_value());
    CHECK(!frameTypeFromByte(0xFF).has_value());

    // Every fault has a name of its own.
    std::set<std::string> faultNames;
    for (const Fault fault : kAllFaults) {
        const std::string name(faultName(fault));
        CHECK(!name.empty());
        CHECK(faultNames.insert(name).second);
    }

    // The header is five bytes and the reference is big endian, because a
    // reader on another machine has to agree about which byte comes first.
    const Bytes empty = encode(FrameType::eHello, 0x01020304);
    CHECK(empty.size() == kFrameHeaderBytes);
    CHECK(empty[0] == static_cast<unsigned char>(FrameType::eHello));
    CHECK(empty[1] == 0x01);
    CHECK(empty[2] == 0x02);
    CHECK(empty[3] == 0x03);
    CHECK(empty[4] == 0x04);
    const Frame decodedEmpty = roundTrip(empty);
    CHECK(decodedEmpty.type == FrameType::eHello);
    CHECK(decodedEmpty.ref == 0x01020304);
    CHECK(decodedEmpty.body.empty());

    // A body of bytes travels untouched, at the largest size the cap allows.
    const Bytes payload(kMaxBodyBytes, 0xA5);
    const Bytes full = encode(FrameType::eStreamData, 8, payload);
    CHECK(full.size() == kMaxFrameBytes);
    const Frame decodedFull = roundTrip(full);
    CHECK(decodedFull.body == payload);

    // One byte more is a frame that does not exist.
    const Bytes tooLong(kMaxBodyBytes + 1, 0);
    CHECK_THROWS(encode(FrameType::eStreamData, 8, tooLong));
    Bytes oversized = full;
    oversized.push_back(0);
    CHECK_THROWS(decode(oversized.data(), oversized.size()));

    // A message shorter than its own header, and one naming a type that does
    // not exist, are both refused rather than half read.
    CHECK_THROWS(decode(empty.data(), kFrameHeaderBytes - 1));
    Bytes unknownType = empty;
    unknownType[0] = 0x7F;
    CHECK_THROWS(decode(unknownType.data(), unknownType.size()));

    // A document round trips; anything that is not one is refused.
    const nlohmann::json body = {{"version", kProtocolVersion}, {"resumed", true}};
    const Frame ready = roundTrip(encodeJson(FrameType::eReady, 3, body));
    CHECK(bodyJson(ready) == body);
    const std::string notADocument = "[1,2,3]";
    const Frame array = roundTrip(
        encode(FrameType::eReady, 3, notADocument.data(), notADocument.size()));
    CHECK_THROWS(bodyJson(array));
    const std::string broken = "{\"a\":";
    const Frame malformed
        = roundTrip(encode(FrameType::eReady, 3, broken.data(), broken.size()));
    CHECK_THROWS(bodyJson(malformed));
    CHECK_THROWS(bodyJson(decodedFull));

    // A credit is one count and nothing else.
    const Frame credit = roundTrip(encodeCredit(6, kStreamWindowBytes));
    CHECK(credit.type == FrameType::eStreamCredit);
    CHECK(credit.ref == 6);
    CHECK(decodeCredit(credit) == kStreamWindowBytes);
    Frame shortCredit = credit;
    shortCredit.body.pop_back();
    CHECK_THROWS(decodeCredit(shortCredit));
    CHECK_THROWS(decodeCredit(ready));

    // A datagram going out names its destination and carries the rest.
    const std::string host = "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p";
    const Bytes media = {0xDE, 0xAD, 0xBE, 0xEF};
    const Frame raw = roundTrip(encodeRawSend(4, host, media.data(), media.size()));
    CHECK(raw.type == FrameType::eRawSend);
    CHECK(raw.ref == 4);
    const RawSend sent = decodeRawSend(raw);
    CHECK(sent.host == host);
    CHECK(sent.payload == media);

    // An empty payload is a datagram too; an unnamed destination is not.
    const Frame bare = roundTrip(encodeRawSend(4, host, nullptr, 0));
    CHECK(decodeRawSend(bare).host == host);
    CHECK(decodeRawSend(bare).payload.empty());
    CHECK_THROWS(encodeRawSend(4, std::string(), media.data(), media.size()));
    Frame truncated = raw;
    truncated.body.resize(3);
    CHECK_THROWS(decodeRawSend(truncated));
    CHECK_THROWS(decodeRawSend(ready));

    // The two sides never collide, and neither ever hands out the same
    // identifier twice or the zero that means "no subject".
    Ids client(false);
    Ids gateway(true);
    std::set<std::uint32_t> issued;
    for (int i = 0; i < 100; ++i) {
        const std::uint32_t mine = client.next();
        const std::uint32_t theirs = gateway.next();
        CHECK(mine % 2 == 0);
        CHECK(theirs % 2 == 1);
        CHECK(mine != 0);
        CHECK(issued.insert(mine).second);
        CHECK(issued.insert(theirs).second);
    }

    std::printf("TestGatewayProtocol ok\n");
    return 0;
}
