// Bazarish project (c) 2026
#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace bazarish::client {

inline constexpr char kTypeBotMenu[] = "bot.menu";
inline constexpr std::size_t kMaxBotMenuItems = 32;
inline constexpr std::size_t kMaxBotMenuTitleChars = 32;
inline constexpr std::size_t kMaxBotMenuCommandBytes = 32;
inline constexpr std::int64_t kMaxBotMenuId = std::numeric_limits<std::uint32_t>::max();

struct BotMenuItem {
    std::string title;
    std::string command;

    friend bool operator==(const BotMenuItem&, const BotMenuItem&) = default;
};

struct BotMenu {
    std::int64_t id = 0;
    std::vector<BotMenuItem> items;

    friend bool operator==(const BotMenu&, const BotMenu&) = default;
};

void requireBotMenu(const BotMenu& menu);

std::int64_t botMenuIdFromJson(const nlohmann::json& value);

BotMenu botMenuFromJson(const nlohmann::json& body);

nlohmann::json botMenuItemsJson(const std::vector<BotMenuItem>& items);

// The messages a person writes, which a bot answers and which name the menu they hold.
bool carriesMenuId(const std::string& type);

class BotMenuMarks {
public:
    // Refuses a menu sent before the one already held.
    bool admit(const std::string& peer, std::int64_t id, std::int64_t sentAt);

    std::optional<std::int64_t> idFor(const std::string& peer) const;

    bool forget(const std::string& peer);

    nlohmann::json toJson() const;

    static BotMenuMarks fromJson(const nlohmann::json& stored);

private:
    struct Mark {
        std::int64_t id = 0;
        std::int64_t sentAt = 0;
    };

    std::map<std::string, Mark> marks_;
};

}  // namespace bazarish::client
