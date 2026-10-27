// Bazarish project (c) 2026
#pragma once

#include <string_view>

namespace bazarish {

enum class AccountKind { eUser, eBot, eChat };

std::string_view accountKindName(AccountKind kind);
// Throws on a name that is not one of the three.
AccountKind accountKindFromName(std::string_view name);

}  // namespace bazarish
