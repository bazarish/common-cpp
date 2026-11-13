// Bazarish project (c) 2026
#include "EpochRing.hpp"

#include <bazarish/Epochs.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/JsonRead.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

constexpr EpochNumber kEpoch = 10;
constexpr EpochGeneration kLaterGeneration = 1;
constexpr std::int64_t kIntoEpoch = 100;

std::int64_t inside(const EpochNumber n)
{
    return epochStart(n) + kIntoEpoch;
}

}  // namespace

int main()
{
    CHECK(epochAt(kEpochOriginSeconds) == 0);
    CHECK(epochAt(kEpochOriginSeconds - 1) == -1);
    CHECK(epochAt(epochEnd(kEpoch) - 1) == kEpoch);
    CHECK(epochAt(epochEnd(kEpoch)) == kEpoch + 1);
    CHECK(epochEnd(kEpoch) - epochStart(kEpoch) == kEpochSeconds);
    CHECK(lessThanAnEpochAhead(kEpoch, inside(kEpoch)));
    CHECK(!lessThanAnEpochAhead(kEpoch + 1, inside(kEpoch)));

    const Bytes kid = epochKid(kEpoch, kFirstEpochGeneration, "devaaaaaaa");
    CHECK(kid
        == (Bytes{kEpochKidTag, 0, 0, 0, kEpoch, 0, 0, 0, 0, 'd', 'e', 'v', 'a', 'a', 'a', 'a', 'a',
            'a', 'a'}));
    CHECK(kid.size() == hybrid::kMaxSealKidBytes);
    CHECK_THROWS(epochKid(kEpoch, kFirstEpochGeneration, std::string(kDeviceIdLength + 1, 'z')));
    CHECK_THROWS(epochKid(kEpoch, kFirstEpochGeneration, "devaaaaaa1"));
    CHECK_THROWS(epochKid(kEpoch, kFirstEpochGeneration, ""));
    CHECK_THROWS(epochKid(kEpoch, kFirstEpochGeneration, "dev/1"));
    CHECK_THROWS(epochKid(-1, kFirstEpochGeneration, "devaaaaaaa"));

    EpochRing ring;
    Key early = Key::generateSealing();
    const Bytes earlyDer = early.publicDer();
    CHECK(ring.add(kEpoch, kFirstEpochGeneration, "devbbbbbbb", std::move(early)));
    CHECK(!ring.add(kEpoch, kFirstEpochGeneration, "devbbbbbbb", Key::generateSealing()));
    CHECK(ring.inUse(kEpoch).front().by == "devbbbbbbb");
    Key smaller = Key::generateSealing();
    const Bytes smallerDer = smaller.publicDer();
    CHECK(ring.add(kEpoch, kFirstEpochGeneration, "devaaaaaaa", std::move(smaller)));
    CHECK(ring.inUse(kEpoch).size() == 1);
    CHECK(ring.inUse(kEpoch).front().by == "devaaaaaaa");
    CHECK(ring.add(kEpoch, kLaterGeneration, "devddddddd", Key::generateSealing()));
    CHECK(ring.inUse(kEpoch).front().by == "devddddddd");
    CHECK(ring.inUse(kEpoch).front().g == kLaterGeneration);
    CHECK(ring.add(kEpoch + 1, kFirstEpochGeneration, "devbbbbbbb", Key::generateSealing()));
    CHECK(ring.inUse(kEpoch).size() == 2);
    CHECK(ring.inUse(kEpoch + 1).size() == 1);
    CHECK(ring.last() == kEpoch + 1);
    CHECK(ring.holds(kEpoch) && !ring.holds(kEpoch + 2));

    const std::vector<EpochPublic> offered = ring.inUse(kEpoch);
    CHECK(epochFor(offered, inside(kEpoch))->by == "devddddddd");
    CHECK(epochFor(offered, inside(kEpoch + 1))->n == kEpoch + 1);
    CHECK(!epochFor(offered, inside(kEpoch + 2)).has_value());
    const std::vector<EpochPublic> both{{kEpoch, kFirstEpochGeneration, "devbbbbbbb", earlyDer},
        {kEpoch, kFirstEpochGeneration, "devaaaaaaa", smallerDer}};
    CHECK(epochFor(both, inside(kEpoch))->by == "devaaaaaaa");
    CHECK(chosenEpochs(both).size() == 1);
    CHECK(mergedEpochs(both, offered, inside(kEpoch + 1)).size() == 1);
    CHECK(mergedEpochs(both, offered, inside(kEpoch)).size() == 4);
    CHECK(epochsFromJson(epochsJson(mergedEpochs(both, offered, inside(kEpoch))))
        == mergedEpochs(both, offered, inside(kEpoch)));

    const Bytes plain{'h', 'i'};
    for (const EpochPublic& epoch : both) {
        CHECK(ring.open(sealToEpoch(plain, epoch)) == plain);
    }
    {
        const Bytes sealed = sealToEpoch(plain, both.front());
        nlohmann::json frame = parseCbor(sealed);
        frame["kid"] = nlohmann::json::binary(both.back().kid());
        CHECK_THROWS(ring.open(nlohmann::json::to_cbor(frame)));
        frame["kid"] = nlohmann::json::binary(epochKid(kEpoch, kFirstEpochGeneration, "devccccccc"));
        CHECK_THROWS(ring.open(nlohmann::json::to_cbor(frame)));
    }
    const EpochPublic stranger{kEpoch, kFirstEpochGeneration, "devbbbbbbb", Key::generateSealing().publicDer()};
    CHECK_THROWS(ring.open(sealToEpoch(plain, stranger)));

    EpochRing copy;
    CHECK(copy.addAll(ring.toJson()));
    CHECK(!copy.addAll(ring.toJson()));
    CHECK(copy.inUse(kEpoch) == ring.inUse(kEpoch));
    CHECK(copy.open(sealToEpoch(plain, both.front())) == plain);
    CHECK(copy.toJson({kEpoch + 1}).size() == 1);
    {
        nlohmann::json extra = ring.toJson();
        extra[0]["note"] = "x";
        EpochRing refused;
        CHECK_THROWS(refused.addAll(extra));
        nlohmann::json publicOnly = ring.toJson();
        publicOnly[0]["pem"] = "not a key";
        CHECK_THROWS(refused.addAll(publicOnly));
    }

    const Bytes oldMail = sealToEpoch(plain, both.back());
    CHECK(!ring.eraseEnded(epochEnd(kEpoch) + kEpochKeptAfterEndSeconds - 1));
    CHECK(ring.open(oldMail) == plain);
    CHECK(ring.eraseEnded(epochEnd(kEpoch) + kEpochKeptAfterEndSeconds));
    CHECK(!ring.holds(kEpoch));
    CHECK(ring.holds(kEpoch + 1));
    CHECK_THROWS(ring.open(oldMail));
    CHECK(ring.open(sealToEpoch(plain, ring.inUse(kEpoch + 1).front())) == plain);

    return 0;
}
