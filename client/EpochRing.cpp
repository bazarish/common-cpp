// Bazarish project (c) 2026
#include "EpochRing.hpp"

#include <bazarish/Hybrid.hpp>

#include <stdexcept>
#include <utility>

namespace bazarish::client {

namespace {

constexpr char kNumberField[] = "n";
constexpr char kGenerationField[] = "g";
constexpr char kByField[] = "by";
constexpr char kPemField[] = "pem";
constexpr std::size_t kEntryFields = 4;

}  // namespace

nlohmann::json EpochRing::toJson() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json list = nlohmann::json::array();
    for (const auto& [kid, held] : byKid_) {
        list.push_back({{kNumberField, held.n}, {kGenerationField, held.g}, {kByField, held.by},
                    {kPemField, held.key.privatePem()}});
    }
    return list;
}

nlohmann::json EpochRing::toJson(const std::set<EpochNumber>& numbers) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json list = nlohmann::json::array();
    for (const auto& [kid, held] : byKid_) {
        if (numbers.contains(held.n)) {
            list.push_back(
                {{kNumberField, held.n}, {kGenerationField, held.g}, {kByField, held.by},
                    {kPemField, held.key.privatePem()}});
        }
    }
    return list;
}

bool EpochRing::add(const EpochNumber n, const EpochGeneration g, const std::string& by, Key key)
{
    if (by.empty()) {
        throw std::runtime_error("an epoch key names the device that made it");
    }
    if (!key.hasPrivate() || !key.hasKem() || !key.isA(kClassicalSealingAlgorithm)) {
        throw std::runtime_error("an epoch key is a private hybrid sealing key");
    }
    Bytes publicDer = key.publicDer();
    std::string kid = toHex(epochKid(n, g, by));
    const std::lock_guard<std::mutex> lock(mutex_);
    if (byKid_.contains(kid)) {
        return false;
    }
    byKid_.emplace(std::move(kid), Held{n, g, by, std::move(key), std::move(publicDer)});
    return true;
}

bool EpochRing::addAll(const nlohmann::json& list)
{
    if (!list.is_array()) {
        throw std::runtime_error("epoch keys come as a list");
    }
    bool added = false;
    for (const nlohmann::json& entry : list) {
        if (!entry.is_object() || entry.size() != kEntryFields) {
            throw std::runtime_error(
                "an epoch key carries exactly its number, generation, maker and key");
        }
        const bool fresh = add(entry.at(kNumberField).get<EpochNumber>(),
            entry.at(kGenerationField).get<EpochGeneration>(), entry.at(kByField).get<std::string>(),
            Key::fromPrivatePem(entry.at(kPemField).get<std::string>()));
        added = added || fresh;
    }
    return added;
}

std::map<EpochNumber, std::string> EpochRing::chosenKidsLocked() const
{
    std::map<EpochNumber, std::string> chosen;
    for (const auto& [kid, held] : byKid_) {
        const auto found = chosen.find(held.n);
        if (found == chosen.end()) {
            chosen[held.n] = kid;
            continue;
        }
        const Held& other = byKid_.at(found->second);
        if (chosenOver(held.g, held.by, other.g, other.by)) {
            chosen[held.n] = kid;
        }
    }
    return chosen;
}

std::vector<EpochPublic> EpochRing::inUse(const EpochNumber first) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::vector<EpochPublic> epochs;
    for (const auto& [n, kid] : chosenKidsLocked()) {
        if (n >= first) {
            const Held& held = byKid_.at(kid);
            epochs.push_back(EpochPublic{n, held.g, held.by, held.publicDer});
        }
    }
    return epochs;
}

std::optional<EpochNumber> EpochRing::last() const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    std::optional<EpochNumber> last;
    for (const auto& [kid, held] : byKid_) {
        if (!last.has_value() || held.n > *last) {
            last = held.n;
        }
    }
    return last;
}

bool EpochRing::holds(const EpochNumber n) const
{
    const std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [kid, held] : byKid_) {
        if (held.n == n) {
            return true;
        }
    }
    return false;
}

Bytes EpochRing::open(const Bytes& frame) const
{
    const std::string kid = toHex(hybrid::sealedKid(frame));
    const std::lock_guard<std::mutex> lock(mutex_);
    const auto found = byKid_.find(kid);
    if (found == byKid_.end()) {
        throw std::runtime_error(
            "sealed to key " + kid + ", which this account does not hold, or holds no longer");
    }
    return hybrid::unseal(frame, found->second.key);
}

bool EpochRing::eraseEnded(const std::int64_t utcSeconds)
{
    const std::lock_guard<std::mutex> lock(mutex_);
    const std::size_t before = byKid_.size();
    std::erase_if(byKid_, [utcSeconds](const auto& entry) {
        return utcSeconds >= epochEnd(entry.second.n) + kEpochKeptAfterEndSeconds;
    });
    return byKid_.size() != before;
}

}  // namespace bazarish::client
