// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"
#include "bazarish/Clock.hpp"
#include "bazarish/Crypto.hpp"
#include "bazarish/Limits.hpp"

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bazarish {

using EpochNumber = std::int64_t;
// The number of the revocation list a key was made under.
using EpochGeneration = std::int64_t;
inline constexpr EpochGeneration kFirstEpochGeneration = 0;

inline constexpr std::int64_t kEpochDays = 30;
inline constexpr std::int64_t kEpochSeconds = kEpochDays * kSecondsPerDay;
// 2026-01-01T00:00:00Z, the start of epoch 0.
inline constexpr std::int64_t kEpochOriginSeconds = 1767225600;
inline constexpr std::int64_t kEpochKeptAfterEndSeconds = kMailRetentionDays * kSecondsPerDay;
inline constexpr std::size_t kCardEpochs = 2;

inline constexpr std::uint8_t kEpochKidTag = 0x01;
inline constexpr std::size_t kEpochKidNumberBytes = 4;
inline constexpr std::size_t kEpochKidGenerationBytes = 4;
inline constexpr std::size_t kMaxEpochCreatorBytes = 16;

EpochNumber epochAt(std::int64_t utcSeconds);
std::int64_t epochStart(EpochNumber n);
std::int64_t epochEnd(EpochNumber n);
// True while what runs through epoch `last` leaves less than one epoch after `utcSeconds`.
bool lessThanAnEpochAhead(EpochNumber last, std::int64_t utcSeconds);

struct EpochPublic {
    EpochNumber n = 0;
    EpochGeneration g = 0;
    // The device that made the key.
    std::string by;
    Bytes keyDer;

    Bytes kid() const;
    bool operator==(const EpochPublic&) const = default;
};

Bytes epochKid(EpochNumber n, EpochGeneration g, const std::string& by);
// For one epoch: the key of the higher generation, then of the maker with the smaller id.
bool chosenOver(EpochGeneration g, const std::string& by, EpochGeneration otherG,
    const std::string& otherBy);

// [{n, from, g, by, key}] ascending by n, g and by; each `from` its epoch's start.
nlohmann::json epochsJson(const std::vector<EpochPublic>& epochs);
std::vector<EpochPublic> epochsFromJson(const nlohmann::json& list);

std::optional<EpochPublic> epochFor(const std::vector<EpochPublic>& epochs, std::int64_t utcSeconds);
std::vector<EpochPublic> chosenEpochs(const std::vector<EpochPublic>& epochs);
// The keys of both lists for epochs that have not ended; an offered key replaces a held one.
std::vector<EpochPublic> mergedEpochs(const std::vector<EpochPublic>& held,
    const std::vector<EpochPublic>& offered, std::int64_t utcSeconds);

Bytes sealToEpoch(const Bytes& plaintext, const EpochPublic& epoch);

}  // namespace bazarish
