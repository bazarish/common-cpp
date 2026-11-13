// Bazarish project (c) 2026
#include "bazarish/Epochs.hpp"

#include "bazarish/Hybrid.hpp"

#include <algorithm>
#include <cctype>
#include <climits>
#include <limits>
#include <map>
#include <stdexcept>
#include <tuple>
#include <utility>

namespace bazarish {

namespace {

constexpr char kNumberField[] = "n";
constexpr char kFromField[] = "from";
constexpr char kGenerationField[] = "g";
constexpr char kByField[] = "by";
constexpr char kKeyField[] = "key";
constexpr std::size_t kEpochFields = 5;

void requireKidNumber(const std::int64_t n)
{
    if (n < 0 || n > static_cast<std::int64_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw std::runtime_error("an epoch number or generation is out of range: " + std::to_string(n));
    }
}

void appendBigEndian(Bytes& out, const std::int64_t value, const std::size_t bytes)
{
    for (std::size_t i = 0; i < bytes; ++i) {
        const unsigned shift = static_cast<unsigned>((bytes - 1 - i) * CHAR_BIT);
        out.push_back(static_cast<std::uint8_t>(static_cast<std::uint64_t>(value) >> shift));
    }
}

void requireCreator(const std::string& by)
{
    if (by.empty() || by.size() > kMaxEpochCreatorBytes
        || !std::all_of(by.begin(), by.end(),
            [](const char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0; })) {
        throw std::runtime_error("an epoch key names its maker by a short id of letters and digits");
    }
}

void requireSealingKey(const Bytes& keyDer)
{
    const Key key = Key::fromPublicDer(keyDer);
    if (!key.hasKem() || !key.isA(kClassicalSealingAlgorithm)) {
        throw std::runtime_error("an epoch carries a key that does not seal");
    }
}

bool before(const EpochPublic& a, const EpochPublic& b)
{
    return std::tie(a.n, a.g, a.by) < std::tie(b.n, b.g, b.by);
}

}  // namespace

EpochNumber epochAt(const std::int64_t utcSeconds)
{
    const std::int64_t since = utcSeconds - kEpochOriginSeconds;
    const std::int64_t whole = since / kEpochSeconds;
    return since % kEpochSeconds < 0 ? whole - 1 : whole;
}

std::int64_t epochStart(const EpochNumber n)
{
    return kEpochOriginSeconds + n * kEpochSeconds;
}

std::int64_t epochEnd(const EpochNumber n)
{
    return epochStart(n + 1);
}

bool lessThanAnEpochAhead(const EpochNumber last, const std::int64_t utcSeconds)
{
    return epochEnd(last) - utcSeconds < kEpochSeconds;
}

Bytes epochKid(const EpochNumber n, const EpochGeneration g, const std::string& by)
{
    requireKidNumber(n);
    requireKidNumber(g);
    requireCreator(by);
    Bytes kid{kEpochKidTag};
    appendBigEndian(kid, n, kEpochKidNumberBytes);
    appendBigEndian(kid, g, kEpochKidGenerationBytes);
    kid.insert(kid.end(), by.begin(), by.end());
    return kid;
}

bool chosenOver(const EpochGeneration g, const std::string& by, const EpochGeneration otherG,
    const std::string& otherBy)
{
    return g != otherG ? g > otherG : by < otherBy;
}

Bytes EpochPublic::kid() const
{
    return epochKid(n, g, by);
}

nlohmann::json epochsJson(const std::vector<EpochPublic>& epochs)
{
    nlohmann::json list = nlohmann::json::array();
    for (const EpochPublic& epoch : epochs) {
        list.push_back({
            {kNumberField, epoch.n},
            {kFromField, epochStart(epoch.n)},
            {kGenerationField, epoch.g},
            {kByField, epoch.by},
            {kKeyField, toBase64(epoch.keyDer)},
        });
    }
    return list;
}

std::vector<EpochPublic> epochsFromJson(const nlohmann::json& list)
{
    if (!list.is_array()) {
        throw std::runtime_error("epochs come as a list");
    }
    std::vector<EpochPublic> epochs;
    for (const nlohmann::json& entry : list) {
        if (!entry.is_object() || entry.size() != kEpochFields) {
            throw std::runtime_error(
                "an epoch carries exactly its number, start, generation, maker and key");
        }
        EpochPublic epoch;
        epoch.n = entry.at(kNumberField).get<EpochNumber>();
        requireKidNumber(epoch.n);
        if (entry.at(kFromField).get<std::int64_t>() != epochStart(epoch.n)) {
            throw std::runtime_error("an epoch names a start that is not its own");
        }
        epoch.g = entry.at(kGenerationField).get<EpochGeneration>();
        requireKidNumber(epoch.g);
        epoch.by = entry.at(kByField).get<std::string>();
        requireCreator(epoch.by);
        epoch.keyDer = fromBase64(entry.at(kKeyField).get<std::string>());
        requireSealingKey(epoch.keyDer);
        if (!epochs.empty() && !before(epochs.back(), epoch)) {
            throw std::runtime_error("epochs come in ascending order, each key once");
        }
        epochs.push_back(std::move(epoch));
    }
    return epochs;
}

std::vector<EpochPublic> chosenEpochs(const std::vector<EpochPublic>& epochs)
{
    std::map<EpochNumber, EpochPublic> chosen;
    for (const EpochPublic& epoch : epochs) {
        const auto found = chosen.find(epoch.n);
        if (found == chosen.end()
            || chosenOver(epoch.g, epoch.by, found->second.g, found->second.by)) {
            chosen[epoch.n] = epoch;
        }
    }
    std::vector<EpochPublic> list;
    for (auto& [n, epoch] : chosen) {
        list.push_back(std::move(epoch));
    }
    return list;
}

std::optional<EpochPublic> epochFor(
    const std::vector<EpochPublic>& epochs, const std::int64_t utcSeconds)
{
    const EpochNumber current = epochAt(utcSeconds);
    for (const EpochPublic& epoch : chosenEpochs(epochs)) {
        if (epoch.n == current) {
            return epoch;
        }
    }
    return std::nullopt;
}

std::vector<EpochPublic> mergedEpochs(const std::vector<EpochPublic>& held,
    const std::vector<EpochPublic>& offered, const std::int64_t utcSeconds)
{
    const EpochNumber current = epochAt(utcSeconds);
    std::map<std::tuple<EpochNumber, EpochGeneration, std::string>, Bytes> byKey;
    const auto take = [current, &byKey](const std::vector<EpochPublic>& source) {
        for (const EpochPublic& epoch : source) {
            if (epoch.n >= current) {
                byKey[{epoch.n, epoch.g, epoch.by}] = epoch.keyDer;
            }
        }
    };
    take(held);
    take(offered);
    std::vector<EpochPublic> merged;
    for (auto& [key, keyDer] : byKey) {
        merged.push_back(
            EpochPublic{std::get<0>(key), std::get<1>(key), std::get<2>(key), std::move(keyDer)});
    }
    return merged;
}

Bytes sealToEpoch(const Bytes& plaintext, const EpochPublic& epoch)
{
    return hybrid::seal(plaintext, Key::fromPublicDer(epoch.keyDer), epoch.kid());
}

}  // namespace bazarish
