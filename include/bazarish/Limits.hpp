// Bazarish project (c) 2026
#pragma once

#include <cstddef>
#include <cstdint>

namespace bazarish {

constexpr std::size_t kMaxMessagePayloadBytes = 512 * 1024;
// What hybrid::seal adds to a body of 64 KiB or more, a few bytes less to a smaller one.
constexpr std::size_t kHybridSealOverheadBytes = 1176;
constexpr std::size_t kMaxSealedBodyBytes = kMaxMessagePayloadBytes - kHybridSealOverheadBytes;
constexpr std::size_t kMaxMessageIdBytes = 64;
constexpr std::size_t kMaxMediaNameBytes = 255;
constexpr std::size_t kMaxMediaMimeBytes = 255;
// All but the media of the heaviest picture or voice message, as TestDeliveryPass weighs it.
constexpr std::size_t kMediaMessageReserveBytes = 7755;
constexpr std::size_t kMaxMediaBytes = kMaxSealedBodyBytes - kMediaMessageReserveBytes;
constexpr std::size_t kMaxPendingContactRequests = 30;

constexpr std::size_t kMaxContactRequestBytes = 17590;
constexpr std::size_t kMaxContactGreetingBytes = 100;
constexpr std::size_t kMaxAccountNameBytes = 64;
constexpr std::size_t kAvatarMaxBytes = 500 * 1024;
constexpr std::size_t kMaxPictureBytes = kMaxMediaBytes;
constexpr std::size_t kMaxVoiceBytes = kMaxMediaBytes;

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

// Any one stored item fits.
inline constexpr std::size_t kMaxFetchBytes = 2 * kMaxMessagePayloadBytes;
inline constexpr std::size_t kMaxAckIdsPerRequest = 256;

inline constexpr std::size_t kMaxRequestBodyBytes = 2 * 1024 * 1024;

inline constexpr std::size_t kMaxResolverAnswerBytes = 256 * 1024;
inline constexpr std::size_t kMaxFacadeAnswerBytes = 16 * 1024 * 1024;

}  // namespace bazarish
