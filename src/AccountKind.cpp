// Bazarish project (c) 2026
#include "bazarish/AccountKind.hpp"

#include <stdexcept>
#include <string>

namespace {

constexpr std::string_view kUserName = "user";
constexpr std::string_view kBotName = "bot";
constexpr std::string_view kChatName = "chat";

}  // namespace

namespace bazarish {

std::string_view accountKindName(const AccountKind kind)
{
    switch (kind) {
    case AccountKind::eUser:
        return kUserName;
    case AccountKind::eBot:
        return kBotName;
    case AccountKind::eChat:
        return kChatName;
    }
    throw std::logic_error("unknown account kind");
}

AccountKind accountKindFromName(const std::string_view name)
{
    if (name == kUserName) {
        return AccountKind::eUser;
    }
    if (name == kBotName) {
        return AccountKind::eBot;
    }
    if (name == kChatName) {
        return AccountKind::eChat;
    }
    throw std::runtime_error("unknown account kind: " + std::string(name));
}

}  // namespace bazarish
