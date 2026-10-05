// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"

#include <cstddef>
#include <functional>
#include <map>
#include <string>

namespace bazarish::client {

class Bot {
public:
    using CommandHandler
        = std::function<void(Bot&, const std::string& peer, const std::string& args)>;
    using TextHandler
        = std::function<void(Bot&, const std::string& peer, const std::string& text)>;
    using CallbackHandler = std::function<void(
        Bot&, const std::string& peer, const std::string& data, const std::string& ref)>;

    explicit Bot(Session& session);

    void onCommand(const std::string& name, CommandHandler handler);
    void onText(TextHandler handler);
    void onCallback(CallbackHandler handler);
    void onUnknownCommand(CommandHandler handler);
    void onContact(TextHandler handler);

    void reply(const std::string& peer, const std::string& text);
    void replyWithKeyboard(
        const std::string& peer, const std::string& text, const InlineKeyboard& keyboard);
    void editMessage(const std::string& peer, const std::string& refId,
        const std::string& text, const InlineKeyboard& keyboard = {});

    Session& session() { return session_; }

    std::size_t poll();
    [[noreturn]] void run(int intervalMs = 2000);

    void dispatch(const IncomingMessage& update);

private:
    static bool parseSlashCommand(const std::string& text, std::string& name, std::string& args);
    void dispatchCommand(
        const std::string& peer, const std::string& name, const std::string& args);

    Session& session_;
    std::map<std::string, CommandHandler> commands_;
    TextHandler text_;
    CallbackHandler callback_;
    CommandHandler unknownCommand_;
    TextHandler contact_;
};

}  // namespace bazarish::client
