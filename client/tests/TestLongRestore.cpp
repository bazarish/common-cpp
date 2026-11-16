// Bazarish project (c) 2026
#include "AccountDb.hpp"
#include "Authorship.hpp"
#include "GatewayAddress.hpp"
#include "I2pKeys.hpp"
#include "I2pRouter.hpp"
#include "OutboundCourier.hpp"
#include "Session.hpp"

#include "FakeGateway.hpp"
#include "TunnelStub.hpp"

#include <bazarish/Certificates.hpp>
#include <bazarish/Clock.hpp>
#include <bazarish/Descriptor.hpp>
#include <bazarish/Epochs.hpp>
#include <bazarish/FederationFrame.hpp>
#include <bazarish/HttpServer.hpp>
#include <bazarish/Hybrid.hpp>
#include <bazarish/I2pAddress.hpp>
#include <bazarish/KeyedSeal.hpp>
#include <bazarish/Padding.hpp>
#include <bazarish/Limits.hpp>
#include <bazarish/Pass.hpp>
#include <bazarish/Resolve.hpp>
#include <bazarish/ServerDescriptor.hpp>

#include "TestUtil.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <deque>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace bazarish;
using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

constexpr std::int64_t kLongAbsenceDays = 182;
constexpr std::int64_t kShortAbsenceDays = 20;
constexpr std::int64_t kStaleBackupDays = 65;
constexpr std::int64_t kIdleDeleteDays = 180;
constexpr std::int64_t kFirstLettersDay = 10;
constexpr std::int64_t kSecondNewKeyDay = 40;
constexpr std::int64_t kLivedOnDays = 35;
constexpr std::int64_t kSecondLettersDay = 50;
constexpr std::int64_t kThirdLettersDay = 90;
constexpr std::int64_t kFourthLettersDay = 170;
constexpr std::int64_t kPastRandomPause = kSecondsPerHour + 1;
constexpr std::int64_t kRenewLeadSeconds = kMaxDelegationDays * kSecondsPerDay;
constexpr std::int64_t kWatchHours = 72;
constexpr std::int64_t kPromptHours = 3;
constexpr std::int64_t kRestoreHourOfDay = 12;
constexpr std::int64_t kSecondUserAskHour = 1;
constexpr int kQuietPasses = 3;
constexpr std::chrono::milliseconds kPassGap{20};
constexpr std::chrono::seconds kTestStaleBound{1};
constexpr int kForbidden = 403;
constexpr int kNotFound = 404;
constexpr int kConflict = 409;
constexpr std::uint64_t kQuotaBytes = 100u * 1024 * 1024;

struct Item {
    std::string id;
    std::string cls;
    Bytes payload;
    std::string forDevice;
    std::int64_t arrivedAt = 0;
    std::set<std::string> ackedBy;
};

struct Account {
    bool signedUp = false;
    bool approved = true;
    std::string card;
    Bytes cardKey;
    std::string dest;
    std::string sealingPem;
    std::int64_t delegatedUntil = 0;
    std::set<std::string> passes;
    std::map<std::string, std::string> installs;
    std::set<std::string> seen;
    std::vector<Item> mailbox;
};

struct Mock {
    std::mutex mu;
    std::atomic<std::int64_t> utc{0};
    std::map<std::string, Account> accounts;
    std::map<std::string, std::string> ownerOf;
    std::set<std::string> down;
    bool moderated = false;
    int nextId = 1;
    std::size_t stored = 0;
    // Grows with every pass and every send: asks made in one of them share its number.
    std::atomic<int> phase{0};
    // What a card fetch from an account fails with, in turn, before its card comes.
    std::map<std::string, std::deque<FetchFailure>> cardScript;
    struct CardAsk {
        int phase = 0;
        bool came = false;
    };
    std::map<std::string, std::vector<CardAsk>> cardAsks;
    // What the sending side holds of each lease set: the lookup's "before".
    std::map<std::string, i2p::LeaseSetSeen> leaseHeld;

    // Under the lock.
    const Account* servingAt(const std::string& dest) const
    {
        const auto owner = ownerOf.find(dest);
        if (owner == ownerOf.end() || down.contains(owner->second)) {
            return nullptr;
        }
        const auto account = accounts.find(owner->second);
        if (account == accounts.end() || !account->second.approved || account->second.dest != dest
            || utc.load() >= account->second.delegatedUntil) {
            return nullptr;
        }
        return &account->second;
    }

    // Under the lock.
    void purge()
    {
        const std::int64_t cut = utc.load() - kMailRetentionDays * kSecondsPerDay;
        for (auto& [fp, account] : accounts) {
            std::erase_if(account.mailbox, [cut](const Item& item) { return item.arrivedAt < cut; });
        }
    }

    // Under the lock.
    static void dropTaken(Account& account)
    {
        std::erase_if(account.mailbox, [&account](const Item& item) {
            if (!item.forDevice.empty()) {
                return item.ackedBy.contains(item.forDevice);
            }
            for (const auto& [device, install] : account.installs) {
                if (!item.ackedBy.contains(device)) {
                    return false;
                }
            }
            return true;
        });
    }
};

std::string requireCaller(const http::Request& request)
{
    const std::string caller = request.header(bazarish::teststub::kCallerHeader);
    if (caller.empty()) {
        throw std::runtime_error("no caller: this request did not come through the tunnel");
    }
    return caller;
}

std::string requireDevice(const http::Request& request)
{
    return request.header(bazarish::teststub::kCallerDeviceHeader);
}

using StubHandler = std::function<void(const http::Request&, http::Response&)>;

http::Handler stub(StubHandler handler)
{
    return [handler = std::move(handler)](const http::Request& request) {
        http::Response response;
        handler(request, response);
        return response;
    };
}

void respondJson(http::Response& response, const nlohmann::json& body)
{
    response.contentType = "application/json";
    response.body = body.dump();
}

void refuse(http::Response& response, const int status, const std::string& code)
{
    response.status = status;
    respondJson(response, {{"error", {{"code", code}, {"message", "refused by the stand-in server"}}}});
}

class MockStream final : public DeliveryStream {
public:
    MockStream(Mock& mock, const Key& signingKey, std::string dest)
        : mock_(mock)
        , signingKey_(signingKey)
        , dest_(std::move(dest))
    {
    }

    void writeAll(const ByteView data) override { written_.append(data.begin(), data.end()); }

    std::size_t readSome(const ByteBuffer buffer) override
    {
        if (!served_) {
            reply_ = serve();
            served_ = true;
        }
        const ByteView from
            = viewOf(reply_).subspan(sent_, std::min(buffer.size(), reply_.size() - sent_));
        std::copy(from.begin(), from.end(), buffer.begin());
        sent_ += from.size();
        return from.size();
    }

    void close() override {}

private:
    std::string serve()
    {
        const std::size_t lineEnd = written_.find('\n');
        CHECK(lineEnd != std::string::npos);
        const nlohmann::json header = nlohmann::json::parse(written_.substr(0, lineEnd));
        const std::size_t length = header.at("len").get<std::size_t>();
        const std::string payloadText = written_.substr(lineEnd + 1, length);
        const Bytes sealed = fromBase64(header.at("sealed").get<std::string>());
        const std::lock_guard<std::mutex> lock(mock_.mu);
        const Account* serving = mock_.servingAt(dest_);
        if (serving == nullptr) {
            throw std::runtime_error("the address went down mid-delivery");
        }
        const nlohmann::json inner = nlohmann::json::parse(
            hybrid::unseal(sealed, Key::fromPrivatePem(serving->sealingPem)).bytes());
        const std::string cls = inner.at("class").get<std::string>();
        const std::string mailbox = inner.at("mailbox").get<std::string>();
        const std::string deliveryId = inner.at("deliveryId").get<std::string>();
        Account& account = mock_.accounts.at(mock_.ownerOf.at(dest_));
        const auto refusal = [](const std::string& code) {
            return nlohmann::json{{"delivered", false}, {"errorCode", code},
                       {"errorMessage", "refused by the stand-in server"}}
                       .dump()
                + "\n";
        };
        if (mock_.ownerOf.at(dest_) != mailbox) {
            return refusal("DELIVERY_REJECTED");
        }
        if (!account.seen.contains(deliveryId)) {
            if (cls == "content"
                && !account.passes.contains(
                    toBase64(deliveryPassHandle(fromBase64(inner.at("pass").get<std::string>()))))) {
                return refusal("DELIVERY_REJECTED");
            }
            account.seen.insert(deliveryId);
            account.mailbox.push_back({"m" + std::to_string(mock_.nextId++), cls,
                Bytes(payloadText.begin(), payloadText.end()), {}, mock_.utc.load(), {}});
            ++mock_.stored;
        }
        return nlohmann::json{{"delivered", true}, {"deliveryId", deliveryId},
                   {"signerPub", toBase64(signingKey_.publicDer())},
                   {"sig", toBase64(bazarish::sign(signingKey_, deliveryAckInput(deliveryId)))}}
                   .dump()
            + "\n";
    }

    Mock& mock_;
    const Key& signingKey_;
    std::string dest_;
    std::string written_;
    std::string reply_;
    bool served_ = false;
    std::size_t sent_ = 0;
};

struct Track {
    std::mutex mutex;
    std::string label;
    std::string to;
    std::string id;
    std::string phase;
    std::optional<DeliveryOutcome> outcome;
    std::int64_t storedHour = -1;
};

struct Options {
    std::string tag;
    std::int64_t absenceDays = 0;
    bool deletedWhileAway = false;
    bool moderatedOnReturn = false;
    std::int64_t livedOnDays = 0;
    bool firstContactsDownAtRestore = false;
    bool reachesEveryContact = true;
    // After the restore C1's card breaks off twice and B's does not connect once.
    bool cardHiccups = false;
};

struct Verdict {
    std::string tag;
    std::int64_t t0 = 0;
    EpochNumber backupLast = 0;
    std::int64_t nextDayHour = 0;
    std::map<std::string, std::shared_ptr<Track>> byLabel;
    std::map<std::string, bool> sealsToLostDevice;
    std::function<std::optional<std::int64_t>(const std::shared_ptr<Track>&)> readHour;

    std::shared_ptr<Track> track(const std::string& what) const { return byLabel.at(tag + ": " + what); }
    std::optional<std::int64_t> read(const std::string& what) const { return readHour(track(what)); }
    bool readBy(const std::string& what, const std::int64_t hour) const
    {
        const std::optional<std::int64_t> at = read(what);
        return at.has_value() && *at <= hour;
    }
    bool stored(const std::string& what) const
    {
        const std::lock_guard<std::mutex> lock(track(what)->mutex);
        return track(what)->outcome.has_value() && track(what)->outcome->stored;
    }
    bool waiting(const std::string& what) const
    {
        const std::lock_guard<std::mutex> lock(track(what)->mutex);
        return !track(what)->outcome.has_value() && track(what)->phase == kPhaseWaiting;
    }
};

void restoreAfter(const Options& run, Mock& m, const ServerEndpoint& endpoint, const FetchTransport& dial,
    const std::function<OutboundCourier::Links()>& links, const fs::path& scratch,
    const std::function<void(const Verdict&)>& check)
{
    const std::int64_t t0 = nowSeconds();
    m.utc.store(t0);
    m.moderated = false;
    const UtcClock clock = [&m]() { return m.utc.load(); };
    CourierTimings timings;
    timings.staleBound = kTestStaleBound;
    const auto wire = [&](Session& session) {
        session.setEpochClock(clock);
        session.setPresenceClock(clock);
        session.setFetchTransport(dial);
        session.setOutboundLinks(links(), timings);
    };
    std::map<std::string, fs::path> dirOf;
    const auto made = [&](const std::string& name, const AccountKind kind) {
        const fs::path dir = scratch / (run.tag + "-" + name);
        std::unique_ptr<Session> session = Session::create(dir, kind, endpoint, std::string{});
        wire(*session);
        session->registerAccount();
        dirOf[session->fingerprint()] = dir;
        return session;
    };
    const auto dayAt = [t0](const std::int64_t day) { return t0 + day * kSecondsPerDay; };

    std::unique_ptr<Session> u = made("u", AccountKind::eUser);
    std::unique_ptr<Session> c1 = made("c1", AccountKind::eUser);
    std::unique_ptr<Session> c2 = made("c2", AccountKind::eUser);
    std::unique_ptr<Session> c3 = made("c3", AccountKind::eUser);
    std::unique_ptr<Session> bot = made("bot", AccountKind::eBot);
    const std::string uFp = u->fingerprint();
    std::vector<Session*> contacts{c1.get(), c2.get(), c3.get(), bot.get()};
    std::vector<Session*> live{u.get(), c1.get(), c2.get(), c3.get(), bot.get()};
    std::map<std::string, std::vector<IncomingMessage>> heard;
    std::map<std::string, std::string> nameOf{{uFp, "U"}, {c1->fingerprint(), "C1"},
        {c2->fingerprint(), "C2"}, {c3->fingerprint(), "C3"}, {bot->fingerprint(), "B"}};

    const auto pass = [&]() {
        ++m.phase;
        for (Session* session : live) {
            session->flushPendingEchoes();
            for (IncomingMessage& item : session->sync()) {
                heard[session->fingerprint()].push_back(std::move(item));
            }
        }
    };
    const auto quiet = [&]() {
        std::size_t lastStored = SIZE_MAX;
        std::size_t lastHeard = SIZE_MAX;
        int still = 0;
        while (still < kQuietPasses) {
            pass();
            std::this_thread::sleep_for(kPassGap);
            std::size_t heardNow = 0;
            for (const auto& [fp, items] : heard) {
                heardNow += items.size();
            }
            const std::size_t storedNow = [&]() {
                const std::lock_guard<std::mutex> lock(m.mu);
                return m.stored;
            }();
            still = storedNow == lastStored && heardNow == lastHeard ? still + 1 : 0;
            lastStored = storedNow;
            lastHeard = heardNow;
        }
    };
    const auto heardText = [&](const std::string& fp, const std::string& text) {
        const auto found = heard.find(fp);
        return found != heard.end()
            && std::any_of(found->second.begin(), found->second.end(),
                [&text](const IncomingMessage& item) { return item.text == text; });
    };
    const auto at = [&](const std::int64_t when) {
        m.utc.store(when);
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.purge();
        }
        for (Session* session : contacts) {
            static_cast<void>(session->refreshI2pTransientIfDue(when, kRenewLeadSeconds));
        }
        pass();
        m.utc.store(when + kPastRandomPause);
        quiet();
    };

    std::vector<std::shared_ptr<Track>> tracks;
    std::atomic<std::int64_t> watchHour{-1};
    const auto send = [&](Session& from, const std::string& to, const std::string& text) {
        auto track = std::make_shared<Track>();
        track->label = text;
        track->to = to;
        track->id = newMessageId();
        DeliveryWatch watch;
        watch.onPhase = [track](const std::string& phase) {
            const std::lock_guard<std::mutex> lock(track->mutex);
            track->phase = phase;
        };
        watch.onOutcome = [track, &watchHour](const DeliveryOutcome& outcome) {
            const std::lock_guard<std::mutex> lock(track->mutex);
            track->outcome = outcome;
            track->storedHour = watchHour.load();
        };
        tracks.push_back(track);
        ++m.phase;
        from.sendMessage(to, text, track->id, watch);
        return track;
    };
    const auto settledOf = [](const std::shared_ptr<Track>& track) {
        const std::lock_guard<std::mutex> lock(track->mutex);
        return track->outcome;
    };
    const auto phaseOf = [](const std::shared_ptr<Track>& track) {
        const std::lock_guard<std::mutex> lock(track->mutex);
        return track->phase;
    };

    for (Session* contact : contacts) {
        Session::ContactCardRequest request;
        request.uriOrAlias = contact->inviteUri();
        request.introText = "hi from U";
        const Session::ContactCardResolved resolved
            = Session::resolveContactCard(u->contactFetchContext(), request, [](Session::CardStep) {});
        if (!resolved.ok) {
            std::printf("%s: the card of %s did not resolve: %s\n", run.tag.c_str(),
                nameOf[contact->fingerprint()].c_str(), resolved.error.c_str());
        }
        CHECK(resolved.ok);
        u->commitContactAdd(resolved, {});
        CHECK(testutil::waitFor([&]() {
            pass();
            return contact->contactIsPending(uFp);
        }));
        contact->acceptContactRequest(uFp);
        CHECK(testutil::waitFor([&]() {
            pass();
            return u->canWriteTo(contact->fingerprint()) && contact->canWriteTo(uFp);
        }));
    }
    for (Session* contact : contacts) {
        const std::string hello = run.tag + ": hello " + nameOf[contact->fingerprint()];
        const std::string back = run.tag + ": hello U from " + nameOf[contact->fingerprint()];
        send(*u, contact->fingerprint(), hello);
        send(*contact, uFp, back);
        CHECK(testutil::waitFor([&]() {
            pass();
            return heardText(contact->fingerprint(), hello) && heardText(uFp, back);
        }));
    }
    quiet();

    const std::string lostDevice = u->deviceId();
    const std::string uAddress = u->i2pAddress();
    const std::string uDest = [&]() {
        const std::lock_guard<std::mutex> lock(m.mu);
        return m.accounts.at(uFp).dest;
    }();
    const std::vector<EpochPublic> backupEpochs = u->ownEpochs();
    const fs::path backup = scratch / (run.tag + "-u.backup");
    u->exportAccount(backup, "backup-password");

    if (run.livedOnDays > 0) {
        u->setDelegationDays(kMaxDelegationDays);
        static_cast<void>(u->refreshI2pTransientIfDue(m.utc.load(), kRenewLeadSeconds));
        at(dayAt(run.livedOnDays));
        static_cast<void>(u->refreshI2pTransientIfDue(m.utc.load(), kRenewLeadSeconds));
        at(m.utc.load());
        std::printf("%s: the lost device ran %lld days past the backup and made epoch %lld; "
                    "the backup holds epochs %lld..%lld\n",
            run.tag.c_str(), static_cast<long long>(run.livedOnDays),
            static_cast<long long>(u->ownEpochs().back().n), static_cast<long long>(backupEpochs.front().n),
            static_cast<long long>(backupEpochs.back().n));
    }
    live.erase(std::find(live.begin(), live.end(), u.get()));
    u.reset();

    struct Planned {
        std::int64_t day;
        std::function<void()> action;
    };
    std::vector<Planned> plan;
    const auto letters = [&](const std::int64_t day, const std::vector<Session*>& senders) {
        plan.push_back({day, [&, day, senders]() {
                            for (Session* from : senders) {
                                send(*from, uFp,
                                    run.tag + ": " + nameOf[from->fingerprint()] + " on day "
                                        + std::to_string(day));
                            }
                        }});
    };
    const std::int64_t firstDay = run.livedOnDays + kFirstLettersDay;
    plan.push_back({firstDay, [&]() {
                        c3->replaceOwnAddress();
                    }});
    letters(firstDay, {c1.get(), c2.get(), c3.get(), bot.get()});
    plan.push_back({kSecondNewKeyDay, [&]() {
                        c2->replaceOwnAddress();
                    }});
    letters(kSecondLettersDay, {c1.get(), c2.get(), c3.get()});
    letters(kThirdLettersDay, {c1.get(), c2.get(), c3.get(), bot.get()});
    letters(kFourthLettersDay, {c1.get(), c2.get(), c3.get()});
    if (run.deletedWhileAway) {
        plan.push_back({kIdleDeleteDays, [&]() {
                            const std::lock_guard<std::mutex> lock(m.mu);
                            m.accounts.erase(uFp);
                        }});
    }
    std::stable_sort(plan.begin(), plan.end(),
        [](const Planned& a, const Planned& b) { return a.day < b.day; });
    for (const Planned& step : plan) {
        if (step.day >= run.absenceDays) {
            continue;
        }
        at(std::max(dayAt(step.day), m.utc.load()));
        step.action();
        quiet();
    }

    std::printf("%s: before the restore, as the senders see their letters to U:\n", run.tag.c_str());
    for (const std::shared_ptr<Track>& track : tracks) {
        if (track->to != uFp) {
            continue;
        }
        const std::optional<DeliveryOutcome> outcome = settledOf(track);
        std::printf("  %-28s %s\n", track->label.c_str(),
            outcome.has_value()
                ? (outcome->stored ? "stored by U's server"
                                   : ("refused: " + outcome->errorCode).c_str())
                : ("in the outbox, phase " + phaseOf(track)).c_str());
        CHECK(!outcome.has_value() || outcome->stored);
    }
    const std::size_t heldForU = [&]() {
        const std::lock_guard<std::mutex> lock(m.mu);
        m.purge();
        const auto account = m.accounts.find(uFp);
        return account == m.accounts.end() ? std::size_t{0} : account->second.mailbox.size();
    }();
    std::printf("%s: U's server holds %zu item(s) for U at the restore\n", run.tag.c_str(), heldForU);

    std::int64_t restoreAt = dayAt(run.absenceDays) / kSecondsPerDay * kSecondsPerDay + kRestoreHourOfDay * kSecondsPerHour;
    while (restoreAt < m.utc.load()) {
        restoreAt += kSecondsPerDay;
    }
    m.utc.store(restoreAt);
    m.moderated = run.moderatedOnReturn;
    if (run.firstContactsDownAtRestore) {
        const std::lock_guard<std::mutex> lock(m.mu);
        m.down = {c1->fingerprint(), bot->fingerprint()};
    }
    if (run.cardHiccups) {
        const std::lock_guard<std::mutex> lock(m.mu);
        m.cardAsks.clear();
        m.cardScript[c1->fingerprint()] = {FetchFailure::eBrokeAfterOpen, FetchFailure::eBrokeAfterOpen};
        m.cardScript[bot->fingerprint()] = {FetchFailure::eNotConnected};
    }
    const fs::path restoredDir = scratch / (run.tag + "-restored");
    Session::importAccount(backup, restoredDir, "backup-password");
    CHECK(nlohmann::json::parse(AccountDb(restoredDir, std::string{}).text("meta")).at("reviewDevices").get<bool>());
    std::unique_ptr<Session> r = Session::open(restoredDir, std::string{});
    wire(*r);
    CHECK(r->fingerprint() == uFp);
    CHECK(r->isPrimary());
    CHECK(r->deviceId() != lostDevice);
    {
        const std::vector<OwnDevice> devices = r->ownDevices();
        CHECK(devices.size() == 2);
        CHECK(std::none_of(devices.begin(), devices.end(), [](const OwnDevice& d) { return d.revoked; }));
        CHECK(std::any_of(devices.begin(), devices.end(),
            [&](const OwnDevice& d) { return d.id == lostDevice; }));
    }
    const EpochNumber current = epochAt(restoreAt);
    std::printf("%s: restored device %s (lost %s); epoch now %lld, backup epochs %lld..%lld\n",
        run.tag.c_str(), r->deviceId().c_str(), lostDevice.c_str(), static_cast<long long>(current),
        static_cast<long long>(backupEpochs.front().n), static_cast<long long>(backupEpochs.back().n));
    const auto ringNumbers = [&]() {
        std::set<EpochNumber> numbers;
        for (const nlohmann::json& entry :
            nlohmann::json::parse(AccountDb(restoredDir, std::string{}).text("epochs"))) {
            numbers.insert(entry.at("n").get<EpochNumber>());
        }
        return numbers;
    };
    r->flushPendingEchoes();
    for (const EpochNumber n : ringNumbers()) {
        CHECK(epochEnd(n) + kEpochKeptAfterEndSeconds > restoreAt);
    }

    std::string registerError;
    try {
        r->registerAccount();
    } catch (const std::exception& error) {
        registerError = error.what();
    }
    std::printf("%s: first registerAccount on the restored device: %s\n", run.tag.c_str(),
        registerError.empty() ? (r->approvalState().pending ? "pending approval" : "ok")
                              : registerError.c_str());
    CHECK(registerError.empty());
    if (run.moderatedOnReturn) {
        CHECK(r->approvalState().pending);
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            CHECK(m.servingAt(uDest) == nullptr);
        }
        at(m.utc.load() + kSecondsPerHour);
        for (const std::shared_ptr<Track>& track : tracks) {
            const std::optional<DeliveryOutcome> outcome = settledOf(track);
            CHECK(!outcome.has_value() || outcome->stored);
        }
        {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.accounts.at(uFp).approved = true;
        }
        r->registerAccount();
        CHECK(!r->approvalState().pending);
    }
    live.push_back(r.get());
    {
        const std::lock_guard<std::mutex> lock(m.mu);
        CHECK(m.accounts.at(uFp).dest == uDest);
        CHECK(m.servingAt(uDest) != nullptr);
        const ContactCard card = ContactCard::verify(fromBase64(m.accounts.at(uFp).card));
        CHECK(card.epochs.size() == kCardEpochs);
        std::printf("%s: published card names epochs %lld (by %s) and %lld; dest %s\n", run.tag.c_str(),
            static_cast<long long>(card.epochs.front().n), card.epochs.front().by.c_str(),
            static_cast<long long>(card.epochs.back().n), card.dest.substr(0, 8).c_str());
        CHECK(card.epochs.front().n == current);
        CHECK(card.devices.active(lostDevice).has_value());
    }
    CHECK(r->i2pAddress() == uAddress);

    const auto contactHoldsOurEpoch = [&](Session& contact) {
        const nlohmann::json held = nlohmann::json::parse(
            AccountDb(dirOf.at(contact.fingerprint()), std::string{}).text("contacts"));
        for (const nlohmann::json& epoch : held.at(uFp).at("epochs")) {
            if (epoch.at("n").get<EpochNumber>() == epochAt(m.utc.load())
                && epoch.at("by").get<std::string>() == r->deviceId()) {
                return true;
            }
        }
        return false;
    };

    Verdict verdict;
    const auto sealedToBy = [&](Session& contact) -> std::string {
        const nlohmann::json held = nlohmann::json::parse(
            AccountDb(dirOf.at(contact.fingerprint()), std::string{}).text("contacts"));
        const std::optional<EpochPublic> chosen = epochFor(epochsFromJson(held.at(uFp).at("epochs")), m.utc.load());
        return chosen.has_value() ? chosen->by : std::string();
    };
    if (run.cardHiccups) {
        const auto holdsEpochOf = [&](Session& contact) {
            const nlohmann::json held
                = nlohmann::json::parse(AccountDb(restoredDir, std::string{}).text("contacts"));
            return epochFor(epochsFromJson(held.at(contact.fingerprint()).at("epochs")), m.utc.load())
                .has_value();
        };
        const bool failedFirst = [&]() {
            const std::lock_guard<std::mutex> lock(m.mu);
            const std::vector<Mock::CardAsk>& asks = m.cardAsks[bot->fingerprint()];
            return !asks.empty() && !asks.front().came;
        }();
        const bool onTheLeaseSet = testutil::waitFor([&]() {
            r->flushPendingEchoes();
            return holdsEpochOf(*bot);
        });
        std::printf("%s: B's card %s; with B's lease set looked up it %s before U wrote to B\n",
            run.tag.c_str(), failedFirst ? "did not connect" : "was not asked",
            onTheLeaseSet ? "came" : "did not come");
        CHECK(failedFirst);
        CHECK(onTheLeaseSet);
    }
    for (Session* contact : contacts) {
        send(*r, contact->fingerprint(), run.tag + ": restored U to " + nameOf[contact->fingerprint()]);
        const std::string by = sealedToBy(*contact);
        std::printf("  %s writes to U sealed to %s\n", nameOf[contact->fingerprint()].c_str(),
            by.empty() ? "no key it holds (waits for one)" : by == lostDevice ? "the lost device's key" : "the restored device's key");
        verdict.sealsToLostDevice[nameOf[contact->fingerprint()]] = by == lostDevice;
        send(*contact, uFp, run.tag + ": " + nameOf[contact->fingerprint()] + " after the restore");
    }
    {
        const std::lock_guard<std::mutex> lock(m.mu);
        m.down.clear();
    }
    const std::int64_t watchFrom = m.utc.load();
    const std::int64_t nextDayHour
        = ((watchFrom / kSecondsPerDay + 1) * kSecondsPerDay - watchFrom + kSecondsPerHour - 1) / kSecondsPerHour;
    std::map<std::string, std::int64_t> heardAt;
    std::map<std::string, std::int64_t> keysAt;
    for (std::int64_t hour = 0; hour <= kWatchHours; ++hour) {
        watchHour.store(hour);
        if (run.firstContactsDownAtRestore && hour == kSecondUserAskHour) {
            send(*r, c1->fingerprint(), run.tag + ": restored U to C1 again");
        }
        at(watchFrom + hour * kSecondsPerHour);
        for (const auto& [fp, items] : heard) {
            for (const IncomingMessage& item : items) {
                heardAt.try_emplace(nameOf[fp] + " <- " + item.text, hour);
            }
        }
        for (Session* contact : contacts) {
            if (contactHoldsOurEpoch(*contact)) {
                keysAt.try_emplace(nameOf[contact->fingerprint()], hour);
            }
        }
    }

    if (run.cardHiccups) {
        const std::lock_guard<std::mutex> lock(m.mu);
        const std::vector<Mock::CardAsk>& asks = m.cardAsks[c1->fingerprint()];
        std::printf("%s: C1's card was asked %zu time(s) after the restore; the first in phase %d\n",
            run.tag.c_str(), asks.size(), asks.empty() ? -1 : asks.front().phase);
        CHECK(asks.size() >= 3);
        CHECK(!asks[0].came && !asks[1].came && asks[2].came);
        CHECK(asks[1].phase == asks[0].phase && asks[2].phase == asks[0].phase);
    }
    std::printf("%s: after the restore (hours from registration, test clock; next UTC day at hour %lld):\n",
        run.tag.c_str(), static_cast<long long>(nextDayHour));
    for (const auto& [name, hour] : keysAt) {
        std::printf("  %s holds the restored device's epoch key from hour %lld\n", name.c_str(),
            static_cast<long long>(hour));
    }
    const auto readHour = [&](const std::shared_ptr<Track>& track) -> std::optional<std::int64_t> {
        const std::string receiver = track->to == uFp ? std::string("U") : nameOf[track->to];
        const auto read = heardAt.find(receiver + " <- " + track->label);
        if (read == heardAt.end()) {
            return std::nullopt;
        }
        return read->second;
    };
    for (const std::shared_ptr<Track>& track : tracks) {
        const std::optional<DeliveryOutcome> outcome = settledOf(track);
        const std::optional<std::int64_t> read = readHour(track);
        std::string state = "waiting (" + phaseOf(track) + ")";
        if (outcome.has_value()) {
            const std::lock_guard<std::mutex> lock(track->mutex);
            state = outcome->stored ? (track->storedHour < 0 ? std::string("stored before the restore")
                                                             : "stored at hour " + std::to_string(track->storedHour))
                                    : "refused " + outcome->errorCode;
        }
        std::printf("  %-34s %-28s %s\n", track->label.c_str(), state.c_str(),
            read.has_value() ? ("read at hour " + std::to_string(*read)).c_str() : "not read");
        CHECK(!outcome.has_value() || outcome->stored);
    }
    for (Session* contact : contacts) {
        const std::string by = sealedToBy(*contact);
        std::printf("  %s now seals to U with %s\n", nameOf[contact->fingerprint()].c_str(),
            by == lostDevice ? "the lost device's key" : "the restored device's key");
    }
    for (Session* session : live) {
        for (const WireEvent& event : session->connectionLog()) {
            if (!event.outgoing && event.status == "dropped") {
                std::printf("  %s dropped: %s (%s)\n", nameOf[session->fingerprint()].c_str(),
                    event.what.c_str(), event.detail.c_str());
            }
        }
    }
    verdict.tag = run.tag;
    verdict.t0 = t0;
    verdict.backupLast = backupEpochs.back().n;
    verdict.nextDayHour = nextDayHour;
    verdict.readHour = readHour;
    for (const std::shared_ptr<Track>& track : tracks) {
        verdict.byLabel.emplace(track->label, track);
    }
    check(verdict);

    for (Session* contact : contacts) {
        const std::vector<ContactDevice> devices = contact->contactDevices(uFp);
        std::printf("%s: before the revocation %s lists the lost device as %s\n", run.tag.c_str(),
            nameOf[contact->fingerprint()].c_str(),
            std::any_of(devices.begin(), devices.end(), [&](const ContactDevice& d) { return d.id == lostDevice && !d.revoked; })
                ? "active"
                : "absent or revoked");
    }
    {
        const auto injected = [&](const nlohmann::json& inner, const EpochPublic& epoch) {
            const std::lock_guard<std::mutex> lock(m.mu);
            m.accounts.at(uFp).mailbox.push_back({"x" + std::to_string(m.nextId++), "content",
                sealToEpoch(padToLadder(nlohmann::json::to_cbor(nlohmann::json::array({inner}))), epoch), {},
                m.utc.load(), {}});
        };
        const Identity c1Root = Identity::fromPrivatePem(AccountDb(dirOf.at(c1->fingerprint()), std::string{}).text("root.pem"));
        const DeviceKeys stray = DeviceKeys::generate();
        const DeviceCredential strayKey(Identity::fromPrivatePem(stray.signingPem()),
            DeviceCertificate::issue(c1Root, DevicePublic::of(stray), DeviceRole::ePrimary, nowSeconds()));
        nlohmann::json letter = {{"v", 1}, {"type", "text"}, {"id", newMessageId()}, {"from", c1->fingerprint()},
            {"sentAt", nowMillis()}, {"text", run.tag + ": from a device C1's card does not name"}};
        signAuthorship(letter, strayKey, false);
        injected(letter, r->ownEpochs().front());
        nlohmann::json elsewhere = letter;
        elsewhere["id"] = newMessageId();
        injected(elsewhere, EpochPublic{r->ownEpochs().front().n, kFirstEpochGeneration, "zzzzzzzzzz",
                                Key::generateSealing().publicDer()});
        const auto notesFrom = [&](const std::string& fp) {
            return std::count_if(heard[uFp].begin(), heard[uFp].end(), [&fp](const IncomingMessage& item) {
                return item.contentType == kTypeUnreadable && item.fromFingerprint == fp;
            });
        };
        const auto notesBefore = notesFrom(c1->fingerprint());
        const auto strayBefore = notesFrom(std::string());
        quiet();
        std::printf("%s: a letter of an unknown device of C1 left %ld note(s) in C1's chat, a letter sealed to "
                    "a key U never held left %ld anywhere\n",
            run.tag.c_str(), static_cast<long>(notesFrom(c1->fingerprint()) - notesBefore),
            static_cast<long>(notesFrom(std::string()) - strayBefore));
        CHECK(notesFrom(c1->fingerprint()) == notesBefore + 1);
        CHECK(notesFrom(std::string()) == strayBefore);
        CHECK(!heardText(uFp, run.tag + ": from a device C1's card does not name"));
    }
    {
        const std::vector<OwnDevice> asked = r->devicesToReview();
        CHECK(asked.size() == 1);
        CHECK(asked.front().id == lostDevice && asked.front().role == DeviceRole::ePrimary);
        CHECK(asked.front().issuedAt > 0);
        CHECK_THROWS(r->reviewDevices({r->deviceId()}));
    }
    r->reviewDevices({lostDevice});
    CHECK(r->devicesToReview().empty());
    CHECK(!nlohmann::json::parse(AccountDb(restoredDir, std::string{}).text("meta")).at("reviewDevices").get<bool>());
    at(m.utc.load() + kSecondsPerHour);
    at(m.utc.load() + kSecondsPerHour);
    {
        const std::lock_guard<std::mutex> lock(m.mu);
        CHECK(ContactCard::verify(fromBase64(m.accounts.at(uFp).card)).devices.revoked(lostDevice));
        CHECK(!m.accounts.at(uFp).installs.contains(lostDevice));
    }
    for (Session* contact : contacts) {
        const std::vector<ContactDevice> devices = contact->contactDevices(uFp);
        const bool revokedThere = std::any_of(devices.begin(), devices.end(),
            [&](const ContactDevice& d) { return d.id == lostDevice && d.revoked; });
        std::printf("%s: after the revocation %s lists the lost device as %s\n", run.tag.c_str(),
            nameOf[contact->fingerprint()].c_str(), revokedThere ? "revoked" : "active");
        CHECK(revokedThere || (!run.reachesEveryContact && contact == c3.get()));
        send(*contact, uFp, run.tag + ": " + nameOf[contact->fingerprint()] + " after the revocation");
    }
    for (std::int64_t hour = 0; hour < kPromptHours; ++hour) {
        at(m.utc.load() + kSecondsPerHour);
    }
    for (Session* contact : contacts) {
        const std::string text = run.tag + ": " + nameOf[contact->fingerprint()] + " after the revocation";
        const bool read = heardText(uFp, text);
        std::printf("  %s %s\n", text.c_str(), read ? "read" : "not read");
        CHECK(read || (!run.reachesEveryContact && contact == c3.get()));
    }
}

}  // namespace

int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    http::Server gatewayServer(http::Server::Options{});
    test::FakeGateway gateway;
    const int gatewayPort = gateway.start(gatewayServer);
    CHECK(gatewayPort > 0);
    const std::optional<GatewayAddress> gatewayAt
        = GatewayAddress::parse("http://127.0.0.1:" + std::to_string(gatewayPort)
            + test::kFakeGatewayPath + "#" + gateway.fingerprint());
    CHECK(gatewayAt.has_value());
    CHECK(applyI2pTransport([&gatewayAt]() { setGatewayTransport(*gatewayAt); }));

    Mock m;
    http::Server::Options options;
    options.port = 0;
    options.threads = 16;
    http::Server server(options);

    const auto known = [&m](const std::string& caller) -> Account* {
        const auto found = m.accounts.find(caller);
        if (found == m.accounts.end() || !found->second.signedUp || found->second.card.empty()
            || !found->second.approved) {
            return nullptr;
        }
        return &found->second;
    };
    const auto revokedHere = [](const Account& account, const std::string& device) {
        return !account.card.empty() && ContactCard::verify(fromBase64(account.card)).devices.revoked(device);
    };

    server.get("/v1/messaging/destination", stub([&](const http::Request& request, http::Response& response) {
        const std::lock_guard<std::mutex> lock(m.mu);
        const Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        respondJson(response, {{"dest", account->dest}});
    }));
    server.post("/v1/account/card", stub([&](const http::Request& request, http::Response& response) {
        const std::string caller = requireCaller(request);
        const nlohmann::json body = nlohmann::json::parse(request.body);
        const std::string cardB64 = body.at("card").get<std::string>();
        const ContactCard card = ContactCard::verify(fromBase64(cardB64));
        CHECK(card.fingerprint() == caller);
        const std::lock_guard<std::mutex> lock(m.mu);
        const auto found = m.accounts.find(caller);
        if (found == m.accounts.end() || !found->second.signedUp) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        Account& account = found->second;
        if (!account.card.empty() && card.issuedAt <= ContactCard::verify(fromBase64(account.card)).issuedAt) {
            refuse(response, kConflict, "REQUEST_FAILED");
            return;
        }
        account.card = cardB64;
        account.cardKey = linkKeyFromText(body.at("cardKey").get<std::string>());
        for (auto device = account.installs.begin(); device != account.installs.end();) {
            device = card.devices.revoked(device->first) ? account.installs.erase(device) : std::next(device);
        }
        Mock::dropTaken(account);
        respondJson(response, {{"quotaBytes", kQuotaBytes},
            {"approval", account.approved ? "approved" : kApprovalPending}, {"registrationMessage", ""}});
    }));
    server.post("/v1/account/registration", stub([&](const http::Request& request, http::Response& response) {
        const std::lock_guard<std::mutex> lock(m.mu);
        Account& account = m.accounts[requireCaller(request)];
        if (!account.signedUp) {
            account.signedUp = true;
            account.approved = !m.moderated;
        }
        respondJson(response, {{"ok", true}, {"requiresApproval", !account.approved}});
    }));
    server.get("/v1/account/i2p-status", stub([&](const http::Request& request, http::Response& response) {
        const std::lock_guard<std::mutex> lock(m.mu);
        const auto found = m.accounts.find(requireCaller(request));
        if (found == m.accounts.end() || !found->second.signedUp) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        respondJson(response, {{"approval", found->second.approved ? "approved" : kApprovalPending},
            {"registrationMessage", ""}, {"transientExpires", found->second.delegatedUntil}});
    }));
    server.post("/v1/account/i2p-dest", stub([&](const http::Request& request, http::Response& response) {
        const std::string caller = requireCaller(request);
        const nlohmann::json body = nlohmann::json::parse(request.body);
        const std::lock_guard<std::mutex> lock(m.mu);
        const auto found = m.accounts.find(caller);
        if (found == m.accounts.end() || !found->second.signedUp) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        Account& account = found->second;
        if (!account.approved) {
            refuse(response, kForbidden, "ACCOUNT_PENDING_APPROVAL");
            return;
        }
        const std::string transient = body.at("transient").get<std::string>();
        if (transient.empty()) {
            account.delegatedUntil = 0;
            respondJson(response, {{"dest", ""}});
            return;
        }
        const std::string address = i2pRoutingHost(fromBase64(transient));
        account.dest = address;
        account.sealingPem = body.at("sealingKey").get<std::string>();
        account.delegatedUntil = m.utc.load() + (body.at("expiresUnix").get<std::int64_t>() - nowSeconds());
        m.ownerOf[address] = caller;
        respondJson(response, {{"dest", address}});
    }));
    server.post("/v1/messaging/self", stub([&](const http::Request& request, http::Response& response) {
        const nlohmann::json body = nlohmann::json::parse(request.body);
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        account->mailbox.push_back({body.at("deliveryId").get<std::string>(), "device",
            fromBase64(body.at("payload").get<std::string>()), body.at("to").get<std::string>(),
            m.utc.load(), {}});
        respondJson(response, {{"ok", true}});
    }));
    server.post("/v1/messaging/clients", stub([&](const http::Request& request, http::Response& response) {
        const std::string device = requireDevice(request);
        const std::string install = nlohmann::json::parse(request.body).at("install").get<std::string>();
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        if (revokedHere(*account, device)) {
            refuse(response, kForbidden, "DEVICE_REVOKED");
            return;
        }
        const auto [held, added] = account->installs.emplace(device, install);
        if (!added && held->second != install) {
            refuse(response, kConflict, "DEVICE_TAKEN");
            return;
        }
        respondJson(response, {{"ok", true}});
    }));
    server.post("/v1/messaging/passes", stub([&](const http::Request& request, http::Response& response) {
        const nlohmann::json passes = nlohmann::json::parse(request.body).at("passes");
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        for (const nlohmann::json& handle : passes) {
            account->passes.insert(handle.get<std::string>());
        }
        respondJson(response, {{"ok", true}, {"held", account->passes.size()}});
    }));
    server.post("/v1/messaging/passes/revoke", stub([&](const http::Request& request, http::Response& response) {
        const nlohmann::json passes = nlohmann::json::parse(request.body).at("passes");
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        std::size_t dropped = 0;
        for (const nlohmann::json& handle : passes) {
            dropped += account->passes.erase(handle.get<std::string>());
        }
        respondJson(response, {{"revoked", dropped}});
    }));
    server.get("/v1/messaging/pending", stub([&](const http::Request& request, http::Response& response) {
        const std::string device = requireDevice(request);
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        if (revokedHere(*account, device)) {
            refuse(response, kForbidden, "DEVICE_REVOKED");
            return;
        }
        nlohmann::json pending = nlohmann::json::array();
        for (const Item& item : account->mailbox) {
            if ((!item.forDevice.empty() && item.forDevice != device) || item.ackedBy.contains(device)) {
                continue;
            }
            pending.push_back({{"id", item.id}, {"class", item.cls}, {"bytes", item.payload.size()}});
        }
        respondJson(response, {{"pending", pending}});
    }));
    server.post("/v1/messaging/fetch", stub([&](const http::Request& request, http::Response& response) {
        const std::string device = requireDevice(request);
        const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        nlohmann::json items = nlohmann::json::array();
        for (const nlohmann::json& id : ids) {
            for (const Item& item : account->mailbox) {
                if (item.id == id.get<std::string>() && (item.forDevice.empty() || item.forDevice == device)) {
                    items.push_back({{"id", item.id},
                        {"blob", nlohmann::json::binary(std::vector<std::uint8_t>(item.payload.begin(), item.payload.end()))}});
                }
            }
        }
        const std::vector<std::uint8_t> answer = nlohmann::json::to_cbor({{"items", items}});
        response.contentType = "application/cbor";
        response.body = std::string(answer.begin(), answer.end());
    }));
    server.post("/v1/messaging/ack", stub([&](const http::Request& request, http::Response& response) {
        const std::string device = requireDevice(request);
        const nlohmann::json ids = nlohmann::json::parse(request.body).at("ids");
        const std::lock_guard<std::mutex> lock(m.mu);
        Account* account = known(requireCaller(request));
        if (account == nullptr) {
            refuse(response, kNotFound, "ACCOUNT_UNKNOWN");
            return;
        }
        for (const nlohmann::json& id : ids) {
            for (Item& item : account->mailbox) {
                if (item.id == id.get<std::string>()) {
                    item.ackedBy.insert(device);
                }
            }
        }
        Mock::dropTaken(*account);
        respondJson(response, {{"ok", true}});
    }));

    const Identity stubServerIdentity = Identity::generate();
    const Key stubServerSealing = Key::generateSealing();
    const Key stubNodeSealing = Key::generateSealing();
    bazarish::teststub::Tunnel tunnelStub(
        server, stubServerIdentity, stubServerSealing, ServerCard::Service::eMessaging);
    bazarish::teststub::Tunnel nodeTunnelStub(
        server, stubServerIdentity, stubNodeSealing, ServerCard::Service::eServiceNode);
    const int port = server.start();
    CHECK(port > 0);
    ServerEndpoint endpoint;
    endpoint.serverFingerprint = stubServerIdentity.fingerprint();
    endpoint.facades = {Facade{"127.0.0.1", port}};

    const FetchTransport dial = [&m](const std::string& toDest, const std::string& op, const Bytes& query) {
        CHECK(op == "card");
        const std::lock_guard<std::mutex> lock(m.mu);
        const Account* serving = m.servingAt(toDest);
        if (serving == nullptr) {
            throw FetchFailed(FetchFailure::eLeaseSetNotFound, "no lease set for " + toDest.substr(0, 8));
        }
        const std::string owner = m.ownerOf.at(toDest);
        std::deque<FetchFailure>& script = m.cardScript[owner];
        m.cardAsks[owner].push_back({m.phase.load(), script.empty()});
        if (!script.empty()) {
            const FetchFailure failure = script.front();
            script.pop_front();
            throw FetchFailed(failure, "a scripted failure for " + toDest.substr(0, 8));
        }
        FetchOutcome outcome;
        const std::optional<SecretBytes> asked = KeyedSeal(serving->cardKey, kCardRequestLabel).open(query);
        if (!asked.has_value()
            || cardFetchQueryFromJson(nlohmann::json::parse(asked->bytes())).fingerprint != m.ownerOf.at(toDest)) {
            outcome.errorCode = "CARD_UNKNOWN";
            return outcome;
        }
        outcome.ok = true;
        outcome.sealed = KeyedSeal(serving->cardKey, kCardReplyLabel).seal(fromBase64(serving->card));
        return outcome;
    };
    const Key ackSigning = Key::generateSigning();
    const std::function<OutboundCourier::Links()> links = [&m, &ackSigning]() {
        OutboundCourier::Links made;
        made.prepare = [](const std::string&, const std::string&) { return true; };
        made.openStream = [&m, &ackSigning](
                              const std::string& toDest, std::chrono::seconds) -> std::shared_ptr<DeliveryStream> {
            const std::lock_guard<std::mutex> lock(m.mu);
            if (m.servingAt(toDest) == nullptr) {
                return nullptr;
            }
            return std::make_shared<MockStream>(m, ackSigning, toDest);
        };
        made.lookup = [&m](const std::string& toDest) {
            const std::lock_guard<std::mutex> lock(m.mu);
            i2p::LeaseSetRefresh found;
            if (const auto held = m.leaseHeld.find(toDest); held != m.leaseHeld.end()) {
                found.before = held->second;
            }
            const Account* serving = m.servingAt(toDest);
            if (serving != nullptr) {
                found.after = i2p::LeaseSetSeen{serving->delegatedUntil - kSecondsPerDay, serving->delegatedUntil};
                m.leaseHeld[toDest] = *found.after;
            }
            return std::optional<i2p::LeaseSetRefresh>(found);
        };
        return made;
    };

    const fs::path scratch = testutil::freshDir("longrestore");
    restoreAfter({"long", kLongAbsenceDays, true, true, 0, false, true, true}, m, endpoint, dial, links, scratch,
        [](const Verdict& v) {
            for (const std::string sender : {"C1", "C2", "C3", "B"}) {
                CHECK(v.stored(sender + " on day 10"));
                CHECK(!v.read(sender + " on day 10").has_value());
            }
            for (const std::string day : {"50", "90", "170"}) {
                CHECK(v.readBy("C1 on day " + day, kPromptHours));
                CHECK(v.readBy("C2 on day " + day, v.nextDayHour + kPromptHours));
                CHECK(v.readBy("C3 on day " + day, v.nextDayHour + kPromptHours));
            }
            CHECK(v.readBy("B on day 90", kPromptHours));
            CHECK(v.readBy("C1 after the restore", kPromptHours));
            CHECK(v.readBy("B after the restore", kPromptHours));
            CHECK(v.readBy("C2 after the restore", v.nextDayHour + kPromptHours));
            CHECK(v.readBy("C3 after the restore", v.nextDayHour + kPromptHours));
            CHECK(v.readBy("restored U to C1", kPromptHours));
            CHECK(v.readBy("restored U to B", kPromptHours));
            CHECK(v.readBy("restored U to C2", v.nextDayHour + kPromptHours));
            CHECK(v.readBy("restored U to C3", v.nextDayHour + kPromptHours));
        });
    restoreAfter({"short", kShortAbsenceDays, false, false, 0}, m, endpoint, dial, links, scratch,
        [](const Verdict& v) {
            for (const std::string sender : {"C1", "C2", "C3", "B"}) {
                CHECK(v.readBy(sender + " on day 10", kPromptHours));
                CHECK(v.readBy(sender + " after the restore", kPromptHours));
                CHECK(v.readBy("restored U to " + sender, kPromptHours));
            }
        });
    restoreAfter({"stale", kStaleBackupDays, false, false, kLivedOnDays, true, false}, m, endpoint, dial, links,
        scratch, [](const Verdict& v) {
            const std::int64_t lettersDay = kLivedOnDays + kFirstLettersDay;
            const bool lacking = epochAt(v.t0 + lettersDay * kSecondsPerDay) > v.backupLast;
            std::printf("stale: the letters of day %lld are sealed to an epoch the backup %s\n",
                static_cast<long long>(lettersDay), lacking ? "lacks" : "holds");
            for (const std::string sender : {"C1", "C2", "C3", "B"}) {
                const std::string what = sender + " on day " + std::to_string(lettersDay);
                CHECK(v.stored(what));
                CHECK(v.read(what).has_value() != lacking);
            }
            CHECK(v.readBy("restored U to C2", kPromptHours));
            CHECK(v.readBy("restored U to C1 again", kPromptHours));
            CHECK(v.readBy("restored U to C1", kPromptHours));
            const std::optional<std::int64_t> toBot = v.read("restored U to B");
            CHECK(toBot.has_value() && *toBot + 1 >= v.nextDayHour && *toBot <= v.nextDayHour + kPromptHours);
            CHECK(v.waiting("restored U to C3"));
            for (const auto& [sender, toLost] : v.sealsToLostDevice) {
                CHECK(v.stored(sender + " after the restore"));
                CHECK(v.read(sender + " after the restore").has_value() != toLost);
            }
        });

    server.stop();
    gatewayServer.stop();
    fs::remove_all(scratch);
    std::fprintf(stderr, "TestLongRestore passed\n");
    return 0;
}
