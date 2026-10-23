// Bazarish project (c) 2026
#include "BotMenu.hpp"

#include "TestUtil.hpp"

#include <bazarish/PlainText.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <limits>
#include <string>

using namespace bazarish;
using namespace bazarish::client;

namespace {

nlohmann::json envelopeOf(const std::int64_t id, const nlohmann::json& items)
{
    return {{"type", kTypeBotMenu}, {"menuId", id}, {"items", items}};
}

nlohmann::json oneItem(const std::string& title, const std::string& command)
{
    return nlohmann::json::array({{{"title", title}, {"command", command}}});
}

}  // namespace

int main()
{
    const BotMenu menu = botMenuFromJson(envelopeOf(7, oneItem("Баланс", "balance")));
    CHECK(menu.id == 7 && menu.items.size() == 1);
    CHECK(menu.items.front().title == "Баланс" && menu.items.front().command == "balance");
    CHECK(botMenuFromJson(envelopeOf(7, botMenuItemsJson(menu.items))) == menu);
    CHECK(botMenuFromJson(envelopeOf(kMaxBotMenuId, nlohmann::json::array())).items.empty());

    CHECK_THROWS(botMenuFromJson(envelopeOf(kMaxBotMenuId + 1, oneItem("A", "a"))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(-1, oneItem("A", "a"))));
    CHECK_THROWS(botMenuFromJson(
        {{"menuId", std::numeric_limits<std::uint64_t>::max()}, {"items", oneItem("A", "a")}}));
    CHECK(botMenuFromJson(nlohmann::json::from_cbor(nlohmann::json::to_cbor(
                              envelopeOf(kMaxBotMenuId, oneItem("A", "a")))))
              .id
        == kMaxBotMenuId);
    CHECK_THROWS(botMenuFromJson({{"menuId", "7"}, {"items", oneItem("A", "a")}}));
    CHECK_THROWS(botMenuFromJson({{"menuId", 7}}));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, {{"title", "A"}, {"command", "a"}})));

    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("", "a"))));
    CHECK(botMenuFromJson(envelopeOf(7, oneItem(std::string(kMaxBotMenuTitleChars, 'A'), "a")))
              .items.size()
        == 1);
    CHECK_THROWS(botMenuFromJson(
        envelopeOf(7, oneItem(std::string(kMaxBotMenuTitleChars + 1, 'A'), "a"))));
    std::string wide;
    for (std::size_t i = 0; i < kMaxBotMenuTitleChars; ++i) {
        wide += "Ж";
    }
    CHECK(botMenuFromJson(envelopeOf(7, oneItem(wide, "a"))).items.size() == 1);
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A\nB", "a"))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A\xE2\x80\xAE" "B", "a"))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("\xC3", "a"))));

    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A", ""))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A", "/balance"))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A", "Balance"))));
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, oneItem("A", "xmr 25"))));
    CHECK(botMenuFromJson(envelopeOf(7, oneItem("A", std::string(kMaxBotMenuCommandBytes, 'a'))))
              .items.size()
        == 1);
    CHECK_THROWS(botMenuFromJson(
        envelopeOf(7, oneItem("A", std::string(kMaxBotMenuCommandBytes + 1, 'a')))));

    nlohmann::json full = nlohmann::json::array();
    for (std::size_t i = 0; i < kMaxBotMenuItems; ++i) {
        full.push_back({{"title", "A"}, {"command", "a"}});
    }
    CHECK(botMenuFromJson(envelopeOf(7, full)).items.size() == kMaxBotMenuItems);
    full.push_back({{"title", "A"}, {"command", "a"}});
    CHECK_THROWS(botMenuFromJson(envelopeOf(7, full)));
    BotMenu tooMany;
    tooMany.items.assign(kMaxBotMenuItems + 1, {"A", "a"});
    CHECK_THROWS(requireBotMenu(tooMany));

    CHECK(carriesMenuId("text") && carriesMenuId("bot.command") && carriesMenuId("bot.callback"));
    CHECK(!carriesMenuId("receipt") && !carriesMenuId("reaction") && !carriesMenuId(kTypeBotMenu));

    BotMenuMarks marks;
    CHECK(!marks.idFor("bob"));
    CHECK(marks.admit("bob", 7, 1000));
    CHECK(marks.idFor("bob") == 7);
    CHECK(!marks.admit("bob", 8, 999));
    CHECK(marks.idFor("bob") == 7);
    CHECK(marks.admit("bob", 7, 1000));
    CHECK(marks.admit("bob", 9, 1001));
    const BotMenuMarks kept = BotMenuMarks::fromJson(marks.toJson());
    CHECK(kept.idFor("bob") == 9);
    CHECK(marks.forget("bob") && !marks.idFor("bob") && !marks.forget("bob"));

    CHECK(plainCodePoints("Ж1") == 2u);
    CHECK(!plainCodePoints("\x7F"));

    std::printf("TestBotMenu: all checks passed\n");
    return 0;
}
