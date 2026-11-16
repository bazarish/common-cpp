// Bazarish project (c) 2026
#pragma once

#include <bazarish/Bytes.hpp>
#include <bazarish/Crypto.hpp>
#include <bazarish/Epochs.hpp>
#include <bazarish/SecretBytes.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace bazarish::client {

// The account's epoch sealing keys; shared with the threads that open what was sealed to them.
class EpochRing {
public:
    EpochRing() = default;
    EpochRing(const EpochRing&) = delete;
    EpochRing& operator=(const EpochRing&) = delete;

    // [{n, g, by, pem}]: `by` is the device that made the key.
    nlohmann::json toJson() const;
    nlohmann::json toJson(const std::set<EpochNumber>& numbers) const;
    // The list as text; the copies of the keys made on the way are wiped.
    SecretBytes toText() const;

    // False when the ring held that key already.
    bool add(EpochNumber n, EpochGeneration g, const std::string& by, Key key);
    // False when the ring held every key of the list already.
    bool addAll(const nlohmann::json& list);
    bool addAll(const SecretBytes& text);

    std::vector<EpochPublic> inUse(EpochNumber first) const;
    bool holds(EpochNumber n) const;
    bool holdsKid(const Bytes& kid) const;
    std::optional<EpochNumber> first() const;
    std::optional<EpochNumber> last() const;

    // Throws when the frame names a key this ring does not hold.
    SecretBytes open(const Bytes& frame) const;

    // False when nothing was erased.
    bool eraseEnded(std::int64_t utcSeconds);

private:
    struct Held {
        EpochNumber n = 0;
        EpochGeneration g = 0;
        std::string by;
        Key key;
        Bytes publicDer;
    };

    // Keyed by the key id in hex.
    std::map<EpochNumber, std::string> chosenKidsLocked() const;

    mutable std::mutex mutex_;
    std::map<std::string, Held> byKid_;
};

}  // namespace bazarish::client
