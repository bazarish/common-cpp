// Bazarish project (c) 2026
#pragma once

#include <string_view>

namespace bazarish {

enum class AccountKind { eUser, eBot, eChat };

std::string_view accountKindName(AccountKind kind);
AccountKind accountKindFromName(std::string_view name);

}  // namespace bazarish
