// Bazarish project (c) 2026
#include "Bot.hpp"

#include <bazarish/Log.hpp>

#include <chrono>
#include <thread>
#include <utility>

namespace bazarish::client {

Bot::Bot(Session& session)
    : session_(session)
{
}

void Bot::onCommand(const std::string& name, CommandHandler handler)
{
    commands_[name] = std::move(handler);
}

void Bot::onText(TextHandler handler)
{
    text_ = std::move(handler);
}

void Bot::onCallback(CallbackHandler handler)
{
    callback_ = std::move(handler);
}

void Bot::onUnknownCommand(CommandHandler handler)
{
    unknownCommand_ = std::move(handler);
}

void Bot::onContact(TextHandler handler)
{
    contact_ = std::move(handler);
}

void Bot::reply(const std::string& peer, const std::string& text)
{
    session_.sendMessage(peer, text);
}

void Bot::replyWithKeyboard(
    const std::string& peer, const std::string& text, const InlineKeyboard& keyboard)
{
    session_.sendInteractive(peer, text, keyboard);
}

void Bot::editMessage(const std::string& peer, const std::string& refId, const std::string& text,
    const InlineKeyboard& keyboard)
{
    session_.sendEdit(peer, refId, text, keyboard);
}

bool Bot::parseSlashCommand(const std::string& text, std::string& name, std::string& args)
{
    if (text.empty() || text.front() != '/') {
        return false;
    }
    const std::size_t space = text.find(' ');
    if (space == std::string::npos) {
        name = text.substr(1);
        args.clear();
        return !name.empty();
    }
    name = text.substr(1, space - 1);
    // Trim the single separating space; keep the rest verbatim.
    std::size_t start = space;
    while (start < text.size() && text[start] == ' ') {
        ++start;
    }
    args = text.substr(start);
    return !name.empty();
}

void Bot::dispatchCommand(
    const std::string& peer, const std::string& name, const std::string& args)
{
    const auto found = commands_.find(name);
    if (found != commands_.end()) {
        found->second(*this, peer, args);
        return;
    }
    if (unknownCommand_) {
        unknownCommand_(*this, peer, name);
    }
}

void Bot::dispatch(const IncomingMessage& update)
{
    if (update.contentType == "contact.request") {
        if (contact_) {
            contact_(*this, update.fromFingerprint, update.text);
        } else if (commands_.find("start") != commands_.end()) {
            dispatchCommand(update.fromFingerprint, "start", {});
        }
        return;
    }
    if (update.contentType == "bot.command") {
        dispatchCommand(update.fromFingerprint, update.commandName, update.commandArgs);
        return;
    }
    if (update.contentType == "bot.callback") {
        if (callback_) {
            callback_(*this, update.fromFingerprint, update.callbackData, update.refId);
        }
        return;
    }
    if (update.contentType == "text") {
        std::string name;
        std::string args;
        if (parseSlashCommand(update.text, name, args)) {
            dispatchCommand(update.fromFingerprint, name, args);
        } else if (text_) {
            text_(*this, update.fromFingerprint, update.text);
        }
        return;
    }
    // Control and media types (receipt, token-refill, file, unsupported, ...)
    // are not dispatched: a bot that cares about them can read poll()'s return
    // and the session directly. Ignoring them keeps the common case simple.
}

namespace {

// Whether an incoming type warrants a delivery receipt: user-visible lines the
// sender shows a tick for. Control content (receipt, edit, token-refill,
// callbacks/commands raised by silent button taps) does not.
bool warrantsReceipt(const std::string& contentType)
{
    // The names the protocol actually uses. This list carried "photo" and
    // "audio", which nothing sends, and omitted "image", which is what a picture
    // is - so the reference bot never acknowledged one.
    return contentType == "text" || contentType == "file" || contentType == "image"
        || contentType == "voice";
}

}  // namespace

std::size_t Bot::poll()
{
    const std::vector<IncomingMessage> updates = session_.sync();
    for (const IncomingMessage& update : updates) {
        dispatch(update);
        // Acknowledge receipt so the sender's tick advances to delivered (the
        // "green" state). Best-effort: a failed receipt must not stop the bot.
        if (warrantsReceipt(update.contentType) && !update.e2eId.empty()) {
            try {
                session_.sendReceipt(update.fromFingerprint, update.e2eId);
            } catch (const std::exception& error) {
                // Non-fatal: the sender simply stays at the "yellow" state.
                bazarish::log::warn("bot: receipt not sent: {}", error.what());
            }
        }
    }
    return updates.size();
}

void Bot::run(const int intervalMs)
{
    while (true) {
        try {
            poll();
        } catch (const std::exception& error) {
            // Transient (server momentarily unreachable, a handler throwing):
            // skip this round and try again. A bot must not die on one bad poll.
            bazarish::log::warn("bot: poll failed: {}", error.what());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
    }
}

}  // namespace bazarish::client
