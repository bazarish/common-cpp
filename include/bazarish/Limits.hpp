// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>

namespace bazarish {

constexpr std::size_t kMaxMessagePayloadBytes = 512 * 1024;
constexpr std::size_t kMaxPendingContactRequests = 30;

constexpr std::size_t kMaxContactRequestBytes = 17890;
constexpr std::size_t kMaxContactGreetingBytes = 100;
constexpr std::size_t kMaxAccountNameBytes = 64;

inline constexpr const char* kContentDeliveryClass = "content";
inline constexpr const char* kContactDeliveryClass = "contact";
inline constexpr const char* kDeviceDeliveryClass = "device";

inline constexpr std::size_t kContactRequestsPerMinute = 3;

inline constexpr std::int64_t kMinDelegationDays = 1;
inline constexpr std::int64_t kMaxDelegationDays = 30;
inline constexpr std::int64_t kDefaultDelegationDays = 14;
inline constexpr double kDelegationRenewAtFraction = 0.5;

inline constexpr std::size_t kMaxPassesPerRequest = 256;
inline constexpr std::size_t kMaxPassesPerMailbox = 4096;

inline constexpr std::size_t kMaxRequestBodyBytes = 2 * 1024 * 1024;

inline constexpr std::size_t kMaxResolverAnswerBytes = 256 * 1024;
inline constexpr std::size_t kMaxFacadeAnswerBytes = 16 * 1024 * 1024;

}  // namespace bazarish
