// Bazarish project (c) 2026
#include "EpochTestRing.hpp"
#include "MailWaitGate.hpp"
#include "OutboundCourier.hpp"
#include "OutboundLeases.hpp"

#include <bazarish/Crypto.hpp>
#include <bazarish/DeliveryEnvelope.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/I2p.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Log.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

constexpr std::chrono::seconds kQuickDial{1};
constexpr std::chrono::seconds kQuickReply{1};
// Long enough that nothing in a test reaches it unless the test waits for it.
constexpr std::chrono::seconds kFarRecheck{3600};
constexpr std::chrono::seconds kNearRecheck{2};
// What a gate that must stay closed is given to prove it does.
constexpr std::chrono::milliseconds kStaysClosed{4000};
constexpr std::int64_t kPublishedStep = 100;
constexpr std::int64_t kLeaseSeconds = 600;
constexpr std::size_t kPayloadBytes = 64;
constexpr std::int64_t kPastMs = 1;

std::string deliveredReply(const Key& signing, const std::string& deliveryId);

class ScriptedStream final : public DeliveryStream {
public:
    explicit ScriptedStream(std::string reply)
        : reply_(std::move(reply) + "\n")
    {
    }

    void writeAll(const ByteView) override {}

    std::size_t readSome(const ByteBuffer buffer) override
    {
        const ByteView from
            = viewOf(reply_).subspan(sent_, std::min(buffer.size(), reply_.size() - sent_));
        std::copy(from.begin(), from.end(), buffer.begin());
        sent_ += from.size();
        return from.size();
    }

    bool answered() const override { return true; }

    void close() override {}

private:
    std::string reply_;
    std::size_t sent_ = 0;
};

// A recipient's server: opens the envelope with its serving key and signs what it names.
class ServerStream final : public DeliveryStream {
public:
    ServerStream(const Key& signing, const Key& serving)
        : signing_(signing)
        , serving_(serving)
    {
    }

    void writeAll(const ByteView data) override { written_.append(data.begin(), data.end()); }

    std::size_t readSome(const ByteBuffer buffer) override
    {
        if (reply_.empty()) {
            const nlohmann::json header
                = nlohmann::json::parse(written_.substr(0, written_.find('\n')));
            const DeliveryEnvelope envelope = openDeliveryEnvelope(
                fromBase64(header.at("sealed").get<std::string>()), serving_);
            reply_ = deliveredReply(signing_, envelope.deliveryId) + "\n";
        }
        const ByteView from
            = viewOf(reply_).subspan(sent_, std::min(buffer.size(), reply_.size() - sent_));
        std::copy(from.begin(), from.end(), buffer.begin());
        sent_ += from.size();
        return from.size();
    }

    bool answered() const override { return true; }

    void close() override {}

private:
    const Key& signing_;
    const Key& serving_;
    std::string written_;
    std::string reply_;
    std::size_t sent_ = 0;
};

// What a stream into a lease set whose tunnels are gone does: takes everything, answers nothing.
class SilentStream final : public DeliveryStream {
public:
    void writeAll(ByteView) override {}

    std::size_t readSome(ByteBuffer) override
    {
        std::unique_lock<std::mutex> lock(mutex_);
        closedCv_.wait(lock, [this]() { return closed_; });
        throw std::runtime_error("closed before an answer");
    }

    bool answered() const override { return false; }

    void close() override
    {
        {
            const std::lock_guard<std::mutex> lock(mutex_);
            closed_ = true;
        }
        closedCv_.notify_all();
    }

private:
    std::mutex mutex_;
    std::condition_variable closedCv_;
    bool closed_ = false;
};

// What a stream to a live recipient that lost it on the way does: answered, then ended.
class BrokenStream final : public DeliveryStream {
public:
    void writeAll(ByteView) override {}

    std::size_t readSome(ByteBuffer) override { return 0; }

    bool answered() const override { return true; }

    void close() override {}
};

constexpr std::size_t kStallAtBytes = 40 * 1024;
constexpr std::size_t kBigPayloadBytes = 64 * 1024;
constexpr std::size_t kTracedChunkBytes = 16 * 1024;

class StalledStream final : public DeliveryStream {
public:
    void writeAll(const ByteView data) override
    {
        if (taken_ + data.size() > kStallAtBytes) {
            throw std::runtime_error("write on a closed stream");
        }
        taken_ += data.size();
    }

    std::size_t readSome(ByteBuffer) override { return 0; }

    bool answered() const override { return true; }

    void close() override {}

private:
    std::size_t taken_ = 0;
};

struct TestKeys {
    Key signing = Key::generateSigning();
    Key serving = Key::generateSealing();
    std::shared_ptr<EpochRing> recipient = epochtest::ringAround(nowSeconds(), "rrrrrrrrrr");
};

std::string deliveredReply(const Key& signing, const std::string& deliveryId)
{
    return nlohmann::json({
                              {"delivered", true},
                              {"deliveryId", deliveryId},
                              {"signerPub", toBase64(signing.publicDer())},
                              {"sig",
                                  toBase64(bazarish::sign(signing, deliveryAckInput(deliveryId)))},
                          })
        .dump();
}

Letter letterTo(const TestKeys& keys, const std::string& route, const std::uint64_t seq)
{
    Letter letter;
    letter.seq = seq;
    letter.route = route;
    letter.mailbox = "mailbox-" + route;
    letter.deliveryClass = kContentDeliveryClass;
    letter.deliveryId = "d-" + std::to_string(seq);
    letter.pass = Bytes{1, 2, 3};
    letter.servingSealingDer = keys.serving.publicDer();
    letter.plain = Bytes(kPayloadBytes, 0x41);
    letter.sealTo = keys.recipient->inUse(0);
    letter.kind = "text";
    return letter;
}

CourierTimings quick(const std::chrono::seconds recheck)
{
    CourierTimings timings;
    timings.dial = kQuickDial;
    timings.reply = kQuickReply;
    timings.recheck = recheck;
    return timings;
}

OutboundCourier::Links dialling(
    std::function<std::shared_ptr<DeliveryStream>(const std::string& toDest)> open)
{
    OutboundCourier::Links links;
    links.prepare = [](const std::string&, const std::string&) { return true; };
    links.openStream = [open = std::move(open)](const std::string& toDest, std::chrono::seconds) {
        return open(toDest);
    };
    return links;
}

// Outcomes and phases as the courier reported them, by letter.
struct Record {
    std::mutex mutex;
    std::map<std::uint64_t, DeliveryOutcome> outcomes;
    std::map<std::uint64_t, std::vector<std::string>> phases;
    std::map<std::uint64_t, std::thread::id> reportedOn;
    std::vector<std::uint64_t> settled;

    DeliveryWatch watchFor(const std::uint64_t seq)
    {
        DeliveryWatch watch;
        watch.onPhase = [this, seq](const std::string& phase) {
            const std::lock_guard<std::mutex> lock(mutex);
            phases[seq].push_back(phase);
        };
        watch.onOutcome = [this, seq](const DeliveryOutcome& outcome) {
            const std::lock_guard<std::mutex> lock(mutex);
            outcomes[seq] = outcome;
            reportedOn[seq] = std::this_thread::get_id();
        };
        return watch;
    }

    OutboundCourier::SettledFn settledFn()
    {
        return [this](const std::uint64_t seq, const DeliveryOutcome&) {
            const std::lock_guard<std::mutex> lock(mutex);
            settled.push_back(seq);
        };
    }

    std::optional<DeliveryOutcome> outcome(const std::uint64_t seq)
    {
        const std::lock_guard<std::mutex> lock(mutex);
        const auto found = outcomes.find(seq);
        return found == outcomes.end() ? std::nullopt
                                       : std::optional<DeliveryOutcome>(found->second);
    }

    bool saw(const std::uint64_t seq, const std::string& phase)
    {
        const std::lock_guard<std::mutex> lock(mutex);
        const std::vector<std::string>& seen = phases[seq];
        return std::find(seen.begin(), seen.end(), phase) != seen.end();
    }

    std::size_t settledCount()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return settled.size();
    }
};

bool settles(Record& record, const std::uint64_t seq)
{
    return testutil::waitFor([&record, seq]() { return record.outcome(seq).has_value(); });
}

bool staysUnsettled(Record& record, const std::uint64_t seq)
{
    return !testutil::waitFor(
        [&record, seq]() { return record.outcome(seq).has_value(); }, kStaysClosed);
}

bool waits(Record& record, const std::uint64_t seq)
{
    return testutil::waitFor([&record, seq]() { return record.saw(seq, kPhaseWaiting); });
}

i2p::LeaseSetSeen version(const int number)
{
    const std::int64_t published = number * kPublishedStep;
    return i2p::LeaseSetSeen{published, published + kLeaseSeconds};
}

// One recipient's lease sets: what its live router answers on, what the closest floodfill
// serves, and what the sender's address holds.
struct FakeNet {
    std::mutex mutex;
    int live = 1;
    int floodfill = 1;
    std::optional<int> cached;
    int lookups = 0;
    std::vector<int> dialledOn;
    const TestKeys& keys;

    explicit FakeNet(const TestKeys& held)
        : keys(held)
    {
    }

    OutboundCourier::Links links(const bool refreshes)
    {
        OutboundCourier::Links links = dialling(
            [this](const std::string&) -> std::shared_ptr<DeliveryStream> {
            const std::lock_guard<std::mutex> lock(mutex);
            if (!cached.has_value()) {
                cached = floodfill;
            }
            dialledOn.push_back(*cached);
            if (*cached != live) {
                return std::make_shared<SilentStream>();
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        });
        links.lookup = [this, refreshes](
                           const std::string&) -> std::optional<i2p::LeaseSetRefresh> {
            if (!refreshes) {
                return std::nullopt;
            }
            const std::lock_guard<std::mutex> lock(mutex);
            ++lookups;
            i2p::LeaseSetRefresh refresh;
            if (cached.has_value()) {
                refresh.before = version(*cached);
            }
            cached = floodfill;
            refresh.after = version(floodfill);
            return refresh;
        };
        return links;
    }

    int lookupsMade()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return lookups;
    }

    std::vector<int> dialled()
    {
        const std::lock_guard<std::mutex> lock(mutex);
        return dialledOn;
    }
};

std::int64_t utcMillisIn(const std::chrono::seconds from)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        (std::chrono::system_clock::now() + from).time_since_epoch())
        .count();
}

}  // namespace

int main()
try {
    const TestKeys keys;
    const std::string dest = "recipient.b32.i2p";
    const std::string other = "another.b32.i2p";

    {
        const std::chrono::steady_clock::time_point made{};
        const std::chrono::seconds tick{1};
        CHECK(!leaseSpent(made, made, made + kLeaseIdleLife - tick));
        CHECK(leaseSpent(made, made, made + kLeaseIdleLife));
        const std::chrono::steady_clock::time_point busy = made + kLeaseMaxLife - tick;
        CHECK(!leaseSpent(made, busy, made + kLeaseMaxLife - tick));
        CHECK(leaseSpent(made, busy, made + kLeaseMaxLife));
        CHECK(leaseKeyFor(OutboundAddressing::eOnePerCorrespondent, false, dest) == dest);
        CHECK(leaseKeyFor(OutboundAddressing::eOneForAll, false, dest)
            == leaseKeyFor(OutboundAddressing::eOneForAll, false, other));
        CHECK(leaseKeyFor(OutboundAddressing::eOneForAll, true, dest)
            != leaseKeyFor(OutboundAddressing::eOneForAll, false, dest));
    }

    {
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        }),
            record.settledFn(), quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(dials.load() == 1);
        CHECK(record.reportedOn[1] != std::this_thread::get_id());
        CHECK(record.saw(1, kPhasePreparing) && record.saw(1, kPhaseDialing)
            && record.saw(1, kPhaseSending));
        CHECK(testutil::waitFor([&record]() { return record.settledCount() == 1; }));

        Letter keyless = letterTo(keys, other, 2);
        keyless.sealTo = {keyless.sealTo.front()};
        CHECK(keyless.sealTo.front().n < epochAt(nowSeconds()));
        courier.submit(keyless, record.watchFor(2));
        CHECK(waits(record, 2));
        CHECK(staysUnsettled(record, 2));
        CHECK(dials.load() == 1);
        courier.rekey(keyless.mailbox, keys.recipient->inUse(0));
        CHECK(settles(record, 2));
        CHECK(record.outcome(2)->stored);
        CHECK(dials.load() == 2);

        Record late;
        CHECK(courier.attach(1, late.watchFor(1)));
        CHECK(settles(late, 1));
        CHECK(late.outcome(1)->stored);
        courier.forget(1);
        CHECK(!courier.attach(1, late.watchFor(1)));
    }

    {
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            return std::make_shared<ScriptedStream>(
                nlohmann::json({{"delivered", false}, {"errorCode", "DELIVERY_REJECTED"},
                                   {"errorMessage", "delivery rejected"}})
                    .dump());
        }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(!record.outcome(1)->stored);
        CHECK(record.outcome(1)->errorCode == "DELIVERY_REJECTED");
        CHECK(dials.load() == 1);
    }

    {
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            if (++dials == 1) {
                return std::make_shared<BrokenStream>();
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(!record.saw(1, kPhaseWaiting));
        CHECK(dials.load() == 2);
        std::printf("TestOutboundCourier: a stream the recipient answered and lost is sent again"
                    " at once\n");
    }

    {
        std::vector<std::string> told;
        std::mutex toldMutex;
        log::setTap([&](log::Level, std::string_view, const std::string_view message) {
            if (message.find("did not complete") != std::string_view::npos) {
                const std::lock_guard<std::mutex> lock(toldMutex);
                told.emplace_back(message);
            }
        });
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            if (dials == 1) {
                return std::make_shared<StalledStream>();
            }
            if (dials == 2) {
                return std::make_shared<BrokenStream>();
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        }),
            {}, quick(kFarRecheck));
        Letter big = letterTo(keys, dest, 1);
        big.plain = Bytes(kBigPayloadBytes, 'p');
        courier.submit(big, record.watchFor(1));
        CHECK(settles(record, 1));
        log::setTap({});
        CHECK(told.size() == 2);
        const std::string tookMark = "the stream took ";
        const std::size_t tookAt = told.empty() ? std::string::npos : told[0].find(tookMark);
        CHECK(tookAt != std::string::npos);
        const std::size_t took = std::stoul(told[0].substr(tookAt + tookMark.size()));
        CHECK(took > kStallAtBytes - kTracedChunkBytes && took <= kStallAtBytes);
        CHECK(told[0].find("no reply was awaited yet") != std::string::npos);
        CHECK(told[1].find("the reply was awaited for") != std::string::npos);
        CHECK(told[1].find("0 bytes of it came") != std::string::npos);
        std::printf("TestOutboundCourier: a broken delivery tells how far it got: %s\n",
            told.empty() ? "" : told[0].c_str());
    }

    {
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            return std::make_shared<ScriptedStream>(nlohmann::json({{"delivered", true}}).dump());
        }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(waits(record, 1));
        CHECK(staysUnsettled(record, 1));
        CHECK(dials.load() == 1);
        courier.stop();
        CHECK(!record.outcome(1).has_value());
        CHECK_THROWS(courier.submit(letterTo(keys, dest, 2)));
    }

    {
        Record record;
        FakeNet net(keys);
        net.floodfill = 2;
        net.cached = 1;
        std::mutex toldMutex;
        std::vector<std::string> told;
        OutboundCourier::Links links = net.links(true);
        links.newerLeaseSet = [&](const std::string& toDest) {
            const std::lock_guard<std::mutex> lock(toldMutex);
            told.push_back(toDest);
        };
        const auto toldOf = [&]() {
            const std::lock_guard<std::mutex> lock(toldMutex);
            return told;
        };
        OutboundCourier courier(links, {}, quick(kFarRecheck));
        Letter keyless = letterTo(keys, dest, 1);
        keyless.sealTo = {keyless.sealTo.front()};
        courier.submit(keyless, record.watchFor(1));
        CHECK(waits(record, 1));
        courier.unreachable(dest);
        CHECK(testutil::waitFor([&]() { return toldOf().size() == 1; }));
        CHECK(toldOf().front() == dest);
        courier.unreachable(dest);
        CHECK(testutil::waitFor([&net]() { return net.lookupsMade() == 2; }));
        CHECK(staysUnsettled(record, 1));
        CHECK(toldOf().size() == 1);
        CHECK(net.dialled().empty());
        std::printf("TestOutboundCourier: a letter that waits for a key still has its route looked"
                    " up, and a newer lease set is told once\n");
    }

    {
        Record record;
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            if (++dials == 1) {
                i2p::networkChanged();
                return std::make_shared<SilentStream>();
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(dials.load() == 2);
        CHECK(!record.saw(1, kPhaseWaiting));
        std::printf("TestOutboundCourier: silence while this device moved network is sent again"
                    " at once\n");
    }

    {
        Record record;
        std::atomic<bool> tunnels{false};
        OutboundCourier::Links links = dialling([&](const std::string&) {
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        });
        links.prepare = [&tunnels](const std::string&, const std::string&) {
            return tunnels.load();
        };
        OutboundCourier courier(links, {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(testutil::waitFor([&record]() { return record.saw(1, kPhaseOffline); }));
        CHECK(!record.saw(1, kPhaseWaiting));
        CHECK(!record.saw(1, kPhaseDialing));
        tunnels = true;
        courier.heard(kOwnMailboxRoute);
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        std::printf("TestOutboundCourier: no address with tunnels to send from waits for this"
                    " device, not for the recipient\n");
    }

    {
        Record record;
        FakeNet net(keys);
        net.live = 2;
        net.floodfill = 2;
        net.cached = 1;
        OutboundCourier courier(net.links(true), {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(record.saw(1, kPhaseWaiting));
        CHECK(net.lookupsMade() == 1);
        CHECK(net.dialled() == std::vector<int>({1, 2}));
        std::printf("TestOutboundCourier: a restarted holder is reached on its new lease set"
                    " right after the first silence\n");
    }

    {
        Record record;
        FakeNet net(keys);
        net.live = 2;
        net.floodfill = 2;
        net.cached = 1;
        OutboundCourier courier(net.links(false), {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(waits(record, 1));
        CHECK(staysUnsettled(record, 1));
        CHECK(net.dialled() == std::vector<int>({1}));
        std::printf("TestOutboundCourier: with no lookup the stale lease set is not dialled"
                    " again before the recheck\n");
    }

    {
        Record record;
        FakeNet net(keys);
        net.live = 2;
        net.floodfill = 2;
        net.cached = 1;
        OutboundCourier courier(net.links(false), {}, quick(kNearRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(waits(record, 1));
        {
            const std::lock_guard<std::mutex> lock(net.mutex);
            net.cached.reset();
        }
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(net.dialled() == std::vector<int>({1, 2}));
        std::printf("TestOutboundCourier: with no lookup the route is dialled again at the"
                    " recheck\n");
    }

    {
        Record record;
        FakeNet net(keys);
        net.live = 2;
        net.floodfill = 1;
        net.cached = 1;
        OutboundCourier courier(net.links(true), {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(testutil::waitFor([&net]() { return net.lookupsMade() == 1; }));
        CHECK(staysUnsettled(record, 1));
        CHECK(net.dialled() == std::vector<int>({1}));
        {
            const std::lock_guard<std::mutex> lock(net.mutex);
            net.floodfill = 2;
        }
        courier.heard(dest);
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(net.lookupsMade() == 2);
        CHECK(net.dialled() == std::vector<int>({1, 2}));
    }

    {
        Record record;
        FakeNet net(keys);
        net.live = 2;
        net.floodfill = 1;
        net.cached = 1;
        OutboundCourier courier(net.links(true), {}, quick(kNearRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(testutil::waitFor([&net]() { return net.lookupsMade() == 2; }));
        CHECK(!record.outcome(1).has_value());
        CHECK(net.dialled() == std::vector<int>({1}));
        {
            const std::lock_guard<std::mutex> lock(net.mutex);
            net.floodfill = 2;
        }
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(net.lookupsMade() == 3);
        CHECK(net.dialled() == std::vector<int>({1, 2}));
        std::printf("TestOutboundCourier: a closed route is looked up again at every recheck"
                    " and dialled once a newer lease set is published\n");
    }

    {
        Record record;
        std::atomic<bool> answers{false};
        std::atomic<int> dials{0};
        OutboundCourier courier(
            dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            if (!answers.load()) {
                return nullptr;
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        }),
            {}, quick(kFarRecheck));
        MailWaitGate mailGate;
        mailGate.onAnswered([&courier]() { courier.heard(kOwnMailboxRoute); });
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        courier.submit(letterTo(keys, other, 2), record.watchFor(2));
        CHECK(waits(record, 1) && waits(record, 2));
        CHECK(testutil::waitFor([&dials]() { return dials.load() == 2; }));
        answers = true;
        i2p::networkChanged();
        CHECK(staysUnsettled(record, 1) && staysUnsettled(record, 2));
        CHECK(dials.load() == 2);
        mailGate.asking();
        mailGate.answered();
        CHECK(settles(record, 1) && settles(record, 2));
        CHECK(record.outcome(1)->stored && record.outcome(2)->stored);
        CHECK(dials.load() == 4);
        std::printf("TestOutboundCourier: after the link came back the outbox waited for the"
                    " mail wait's answer\n");
    }

    {
        Record record;
        std::atomic<bool> linkUp{false};
        std::atomic<int> dials{0};
        std::atomic<int> lookups{0};
        OutboundCourier::Links links = dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
            ++dials;
            if (!linkUp.load()) {
                i2p::networkLost();
                return std::make_shared<BrokenStream>();
            }
            return std::make_shared<ServerStream>(keys.signing, keys.serving);
        });
        links.lookup = [&lookups](const std::string&) -> std::optional<i2p::LeaseSetRefresh> {
            ++lookups;
            return std::nullopt;
        };
        OutboundCourier courier(links, {}, quick(kFarRecheck));
        MailWaitGate mailGate;
        mailGate.onAnswered([&courier]() { courier.heard(kOwnMailboxRoute); });
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(testutil::waitFor([&record]() { return record.saw(1, kPhaseOffline); }));
        CHECK(!record.saw(1, kPhaseWaiting));
        CHECK(staysUnsettled(record, 1));
        CHECK(dials.load() == 1);
        CHECK(lookups.load() == 0);
        linkUp = true;
        i2p::networkChanged();
        mailGate.asking();
        mailGate.answered();
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        CHECK(dials.load() == 2);
        CHECK(lookups.load() == 0);
        std::printf("TestOutboundCourier: a delivery our own lost link broke waited without blaming"
                    " the recipient and went once our server answered\n");
    }

    {
        Record record;
        std::atomic<bool> answers{false};
        OutboundCourier::Links links;
        links.ownMailbox = [&answers](const Letter&) -> std::optional<DeliveryOutcome> {
            if (!answers.load()) {
                return std::nullopt;
            }
            DeliveryOutcome stored;
            stored.stored = true;
            return stored;
        };
        OutboundCourier courier(links, {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, kOwnMailboxRoute, 1), record.watchFor(1));
        CHECK(waits(record, 1));
        CHECK(!record.saw(1, kPhasePreparing));
        courier.heard(dest);
        CHECK(staysUnsettled(record, 1));
        answers = true;
        courier.heard(kOwnMailboxRoute);
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
    }

    {
        Record record;
        OutboundCourier courier(
            dialling([](const std::string&) -> std::shared_ptr<DeliveryStream> { return nullptr; }),
            record.settledFn(), quick(kFarRecheck));
        Letter call = letterTo(keys, dest, 1);
        call.kind = "call.invite";
        call.notAfterMs = utcMillisIn(kNearRecheck);
        courier.submit(call, record.watchFor(1));
        courier.submit(letterTo(keys, other, 2), record.watchFor(2));
        Letter stale = letterTo(keys, other, 3);
        stale.notAfterMs = kPastMs;
        courier.submit(stale, record.watchFor(3));
        CHECK(settles(record, 3));
        CHECK(settles(record, 1));
        CHECK(!record.outcome(1)->stored);
        CHECK(record.outcome(1)->errorCode.empty());
        CHECK(!record.outcome(2).has_value());
        courier.withdraw("mailbox-" + other);
        CHECK(settles(record, 2));
        CHECK(record.outcome(2)->errorMessage == kWithdrawnMessage);
        CHECK(record.outcome(2)->reason == NotStored::eWithdrawn);
        CHECK(record.outcome(3)->reason == NotStored::eExpired);
        CHECK(record.reportedOn[2] != std::this_thread::get_id());
        CHECK(testutil::waitFor([&record]() { return record.settledCount() == 3; }));
    }

    {
        Record record;
        std::mutex mutex;
        std::vector<std::string> dialled;
        OutboundCourier courier(
            dialling([&](const std::string& toDest) -> std::shared_ptr<DeliveryStream> {
                const std::lock_guard<std::mutex> lock(mutex);
                dialled.push_back(toDest);
                if (toDest == dest) {
                    return nullptr;
                }
                return std::make_shared<ServerStream>(keys.signing, keys.serving);
            }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        CHECK(waits(record, 1));
        courier.readdress("mailbox-" + dest, other, keys.serving.publicDer());
        CHECK(settles(record, 1));
        CHECK(record.outcome(1)->stored);
        const std::lock_guard<std::mutex> lock(mutex);
        CHECK(dialled == std::vector<std::string>({dest, other}));
    }

    {
        Record record;
        std::mutex mutex;
        std::vector<std::string> told;
        OutboundCourier::Links links
            = dialling([&](const std::string&) -> std::shared_ptr<DeliveryStream> {
                  return std::make_shared<ServerStream>(keys.signing, keys.serving);
              });
        links.keepOwn = [&](const std::string& toDest) {
            const std::lock_guard<std::mutex> lock(mutex);
            told.push_back("keep " + toDest);
        };
        links.release = [&](const std::string& toDest) {
            const std::lock_guard<std::mutex> lock(mutex);
            told.push_back("release " + toDest);
        };
        OutboundCourier courier(links, {}, quick(kFarRecheck));
        Letter request = letterTo(keys, dest, 1);
        request.deliveryClass = kContactDeliveryClass;
        request.pass.clear();
        courier.submit(request, record.watchFor(1));
        CHECK(settles(record, 1));
        CHECK(testutil::waitFor([&]() {
            const std::lock_guard<std::mutex> lock(mutex);
            return told == std::vector<std::string>({"keep " + dest, "release " + dest});
        }));
    }

    {
        std::mutex mutex;
        std::condition_variable cv;
        int inFlightSame = 0;
        int maxInFlightSame = 0;
        int otherDials = 0;
        bool release = false;
        Record record;
        OutboundCourier courier(
            dialling([&](const std::string& toDest) -> std::shared_ptr<DeliveryStream> {
                std::unique_lock<std::mutex> lock(mutex);
                if (toDest == other) {
                    ++otherDials;
                    cv.notify_all();
                } else {
                    ++inFlightSame;
                    maxInFlightSame = std::max(maxInFlightSame, inFlightSame);
                    cv.notify_all();
                    cv.wait(lock, [&release]() { return release; });
                    --inFlightSame;
                }
                return std::make_shared<ServerStream>(keys.signing, keys.serving);
            }),
            {}, quick(kFarRecheck));
        courier.submit(letterTo(keys, dest, 1), record.watchFor(1));
        courier.submit(letterTo(keys, dest, 2), record.watchFor(2));
        courier.submit(letterTo(keys, other, 3), record.watchFor(3));
        {
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [&otherDials]() { return otherDials == 1; });
            release = true;
        }
        cv.notify_all();
        CHECK(settles(record, 1));
        CHECK(settles(record, 2));
        CHECK(settles(record, 3));
        CHECK(maxInFlightSame == 1);
    }

    std::printf("TestOutboundCourier ok\n");
    return 0;
} catch (...) {
    return testutil::failed();
}
