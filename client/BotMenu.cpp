// Bazarish project (c) 2026
#include "BotMenu.hpp"

#include <bazarish/PlainText.hpp>

#include <algorithm>
#include <set>
#include <stdexcept>

namespace bazarish::client {

namespace {

bool commandByte(const char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

}  // namespace

void requireBotMenu(const BotMenu& menu)
{
    if (menu.id < 0 || menu.id > kMaxBotMenuId) {
        throw std::runtime_error("a bot menu id is an unsigned 32-bit integer");
    }
    if (menu.items.size() > kMaxBotMenuItems) {
        throw std::runtime_error(
            "a bot menu holds at most " + std::to_string(kMaxBotMenuItems) + " items");
    }
    for (const BotMenuItem& item : menu.items) {
        const std::optional<std::size_t> chars = plainCodePoints(item.title);
        if (!chars || *chars == 0 || *chars > kMaxBotMenuTitleChars) {
            throw std::runtime_error("a bot menu title is 1 to "
                + std::to_string(kMaxBotMenuTitleChars) + " characters of plain text");
        }
        if (item.command.empty() || item.command.size() > kMaxBotMenuCommandBytes
            || !std::all_of(item.command.begin(), item.command.end(), commandByte)) {
            throw std::runtime_error("a bot menu command is 1 to "
                + std::to_string(kMaxBotMenuCommandBytes) + " of a-z, 0-9 and _");
        }
    }
}

std::int64_t botMenuIdFromJson(const nlohmann::json& value)
{
    if (!value.is_number_integer() || value.get<std::int64_t>() < 0
        || value.get<std::int64_t>() > kMaxBotMenuId) {
        throw std::runtime_error("a bot menu id is an unsigned 32-bit integer");
    }
    return value.get<std::int64_t>();
}

BotMenu botMenuFromJson(const nlohmann::json& body)
{
    BotMenu menu;
    menu.id = botMenuIdFromJson(body.at("menuId"));
    const nlohmann::json& items = body.at("items");
    if (!items.is_array() || items.size() > kMaxBotMenuItems) {
        throw std::runtime_error(
            "a bot menu holds at most " + std::to_string(kMaxBotMenuItems) + " items");
    }
    for (const nlohmann::json& item : items) {
        menu.items.push_back(
            {item.at("title").get<std::string>(), item.at("command").get<std::string>()});
    }
    requireBotMenu(menu);
    return menu;
}

nlohmann::json botMenuItemsJson(const std::vector<BotMenuItem>& items)
{
    nlohmann::json out = nlohmann::json::array();
    for (const BotMenuItem& item : items) {
        out.push_back({{"title", item.title}, {"command", item.command}});
    }
    return out;
}

bool carriesMenuId(const std::string& type)
{
    static const std::set<std::string> kAnswered{
        "text", "image", "audio", "file", "bot.command", "bot.callback"};
    return kAnswered.find(type) != kAnswered.end();
}

bool BotMenuMarks::admit(const std::string& peer, const std::int64_t id, const std::int64_t sentAt)
{
    const auto held = marks_.find(peer);
    if (held != marks_.end() && sentAt < held->second.sentAt) {
        return false;
    }
    marks_[peer] = {id, sentAt};
    return true;
}

std::optional<std::int64_t> BotMenuMarks::idFor(const std::string& peer) const
{
    const auto held = marks_.find(peer);
    if (held == marks_.end()) {
        return std::nullopt;
    }
    return held->second.id;
}

bool BotMenuMarks::forget(const std::string& peer)
{
    return marks_.erase(peer) > 0;
}

nlohmann::json BotMenuMarks::toJson() const
{
    nlohmann::json out = nlohmann::json::object();
    for (const auto& [peer, mark] : marks_) {
        out[peer] = {{"id", mark.id}, {"sentAt", mark.sentAt}};
    }
    return out;
}

BotMenuMarks BotMenuMarks::fromJson(const nlohmann::json& stored)
{
    BotMenuMarks marks;
    for (const auto& [peer, mark] : stored.items()) {
        marks.marks_[peer]
            = {mark.at("id").get<std::int64_t>(), mark.at("sentAt").get<std::int64_t>()};
    }
    return marks;
}

}  // namespace bazarish::client
