// Bazarish project (c) 2026
#pragma once

#include "bazarish/Bytes.hpp"

#include <string>

namespace bazarish {

// A delivery pass: what admits one correspondent's mail into a mailbox. It does
// not expire, and it is the same value for every device that correspondent
// writes from - so there is nothing to count, nothing to address to a device and
// nothing to refill. The account that issued it takes it back by asking its own
// server to drop it.
inline constexpr std::size_t kDeliveryPassSize = 32;
// The account's static delivery secret: minted with the account, carried through
// export and import unchanged, and never sent anywhere.
inline constexpr std::size_t kDeliverySecretSize = 32;

// The pass one correspondent is admitted by. Derived rather than drawn, so an
// account keeps no list of what it issued and every device of it arrives at the
// same value for the same correspondent.
//
// It is the same value for as long as the account lives: there is no way to hand
// a correspondent a different one, because removing and re-adding them derives
// this one back. Taking a pass away is what an account can do, and taking it
// away means parting with that correspondent.
Bytes deliveryPass(const Bytes& deliverySecret, const std::string& peerFingerprint);

// What the recipient's server holds and looks up. The pass itself is what a
// sender presents; only this is registered, so reading a node's disk does not
// yield the right to write to the mailboxes on it.
Bytes deliveryPassHandle(const Bytes& pass);

}  // namespace bazarish
