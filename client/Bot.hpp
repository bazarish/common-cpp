// Bazarish project (c) 2026
#pragma once

#include "Session.hpp"

#include <cstddef>
#include <functional>
#include <map>
#include <string>

namespace bazarish::client {

// A minimal chat-bot framework over a Session. A bot is an ordinary identity:
// it subscribes to a server like any other client, auto-accepts incoming
// contacts and answers commands, plain text and inline-keyboard callbacks. The
// server, facades and federation are unchanged - a bot is pure Layer-2 content,
// so the two-layer invariant (Messages.md) holds.
//
// Handlers receive the bot (for replies) and the peer fingerprint. Replies go
// through helper methods that proxy to the Session, so a handler never touches
// the wire format directly.
class Bot {
public:
    // For commands, args is the raw argument string; for callbacks, data is the
    // tapped button's payload and ref the keyboard message it belonged to; for
    // text, text is the received line; for a new contact, text is the intro.
    using CommandHandler
        = std::function<void(Bot&, const std::string& peer, const std::string& args)>;
    using TextHandler
        = std::function<void(Bot&, const std::string& peer, const std::string& text)>;
    using CallbackHandler = std::function<void(
        Bot&, const std::string& peer, const std::string& data, const std::string& ref)>;

    explicit Bot(Session& session);

    // Registers a handler for the command `name` (without the leading slash).
    // Both a bot.command message and a plain "/name ..." text line dispatch here.
    void onCommand(const std::string& name, CommandHandler handler);
    // Handler for plain text that is not a command.
    void onText(TextHandler handler);
    // Handler for an inline-keyboard button press (a bot.callback).
    void onCallback(CallbackHandler handler);
    // Handler for an unrecognized command (its name arrives as the args
    // parameter). Optional; without it unknown commands are ignored.
    void onUnknownCommand(CommandHandler handler);
    // Handler run when a new contact is established (the contact request, with
    // its intro text). Without it, a new contact dispatches the "start" command
    // if one is registered.
    void onContact(TextHandler handler);

    // --- Reply helpers (proxy to the Session) ---

    // Sends a plain text reply to peer.
    void reply(const std::string& peer, const std::string& text);
    // Sends an interactive reply: text plus an inline keyboard.
    void replyWithKeyboard(
        const std::string& peer, const std::string& text, const InlineKeyboard& keyboard);
    // Edits a message the bot previously sent in place (e.g. on a callback,
    // refId is the callback's ref): replaces its text and keyboard. An empty
    // keyboard removes the buttons.
    void editMessage(const std::string& peer, const std::string& refId,
        const std::string& text, const InlineKeyboard& keyboard = {});

    Session& session() { return session_; }

    // Pulls and dispatches one batch of pending updates; returns the count.
    std::size_t poll();
    // Polls forever, sleeping intervalMs between rounds (the CLI runtime). A
    // transient sync failure (server momentarily unreachable) is swallowed so
    // the bot keeps running.
    [[noreturn]] void run(int intervalMs = 2000);

    // Dispatches a single already-decrypted update to the registered handlers.
    // Separated from poll() so the routing is unit-testable without a server.
    void dispatch(const IncomingMessage& update);

private:
    // Splits a "/name rest" line into (name, args). Returns false when the line
    // is not a slash command.
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
