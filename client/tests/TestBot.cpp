// Bazarish project (c) 2026
#include "Bot.hpp"
#include <bazarish/ServerDescriptor.hpp>
#include "Session.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <vector>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

using namespace bazarish::client;

namespace {

namespace fs = std::filesystem;

// Records what a handler saw, so dispatch routing can be asserted.
struct Trace {
    std::vector<std::string> commands;   // "name|args"
    std::vector<std::string> texts;      // received text
    std::vector<std::string> callbacks;  // "data|ref"
    std::vector<std::string> contacts;   // intro text of a new contact
    std::vector<std::string> unknown;    // unknown command names
};

IncomingMessage make(const std::string& type, const std::string& from)
{
    IncomingMessage message;
    message.contentType = type;
    message.fromFingerprint = from;
    return message;
}

void testKeyboardJson()
{
    const InlineKeyboard keyboard = {
        {{"Yes", "yes", {}}, {"No", "no", {}}},
        {{"Help", {}, "help"}},
    };
    const nlohmann::json json = nlohmann::json::parse(inlineKeyboardJson(keyboard));

    CHECK(json.is_array());
    CHECK(json.size() == 2);
    CHECK(json[0].size() == 2);
    CHECK(json[0][0].at("text") == "Yes");
    CHECK(json[0][0].at("data") == "yes");
    // A callback button carries no "command", and vice versa - minimal shape.
    CHECK(!json[0][0].contains("command"));
    CHECK(json[1][0].at("text") == "Help");
    CHECK(json[1][0].at("command") == "help");
    CHECK(!json[1][0].contains("data"));
}

void testDispatch()
{
    const fs::path accountDir = fs::temp_directory_path() / "bz-testbot-state";
    fs::remove_all(accountDir);
    // The account is removed once the session holding it is gone: an open
    // database file is not one every platform lets go of.
    {
        // A connection-less Session is enough to construct a Bot; dispatch never
        // touches the network, and the recording handlers never send a reply.
        Session session = Session::create(accountDir, std::string{}, "testbot");

        Trace trace;
        Bot bot(session);
        bot.onCommand("start", [&trace](Bot&, const std::string&, const std::string& args) {
            trace.commands.push_back("start|" + args);
        });
        bot.onCommand("echo", [&trace](Bot&, const std::string&, const std::string& args) {
            trace.commands.push_back("echo|" + args);
        });
        bot.onText([&trace](Bot&, const std::string&, const std::string& text) {
            trace.texts.push_back(text);
        });
        bot.onCallback(
            [&trace](Bot&, const std::string&, const std::string& data, const std::string& ref) {
                trace.callbacks.push_back(data + "|" + ref);
            });
        bot.onUnknownCommand([&trace](Bot&, const std::string&, const std::string& name) {
            trace.unknown.push_back(name);
        });
        bot.onContact([&trace](Bot&, const std::string&, const std::string& intro) {
            trace.contacts.push_back(intro);
        });

        // bot.command routes to the named command handler with its args.
        {
            IncomingMessage message = make("bot.command", "peer1");
            message.commandName = "echo";
            message.commandArgs = "hello world";
            bot.dispatch(message);
            CHECK(trace.commands.size() == 1);
            CHECK(trace.commands[0] == "echo|hello world");
        }

        // A plain "/command args" text line routes to the same command handler.
        {
            IncomingMessage message = make("text", "peer1");
            message.text = "/echo from text";
            bot.dispatch(message);
            CHECK(trace.commands.size() == 2);
            CHECK(trace.commands[1] == "echo|from text");
        }

        // A "/command" with no args dispatches with an empty argument string.
        {
            IncomingMessage message = make("text", "peer1");
            message.text = "/start";
            bot.dispatch(message);
            CHECK(trace.commands.size() == 3);
            CHECK(trace.commands[2] == "start|");
        }

        // Non-command text routes to the text handler verbatim.
        {
            IncomingMessage message = make("text", "peer1");
            message.text = "just chatting";
            bot.dispatch(message);
            CHECK(trace.texts.size() == 1);
            CHECK(trace.texts[0] == "just chatting");
        }

        // An unknown command routes to the unknown-command handler.
        {
            IncomingMessage message = make("text", "peer1");
            message.text = "/nope arg";
            bot.dispatch(message);
            CHECK(trace.unknown.size() == 1);
            CHECK(trace.unknown[0] == "nope");
        }

        // A callback carries the button data and the referenced keyboard message.
        {
            IncomingMessage message = make("bot.callback", "peer1");
            message.callbackData = "ping";
            message.refId = "kbmsg42";
            bot.dispatch(message);
            CHECK(trace.callbacks.size() == 1);
            CHECK(trace.callbacks[0] == "ping|kbmsg42");
        }

        // A new contact routes to the contact handler with the intro text.
        {
            IncomingMessage message = make("contact.request", "peer2");
            message.text = "hi bot";
            bot.dispatch(message);
            CHECK(trace.contacts.size() == 1);
            CHECK(trace.contacts[0] == "hi bot");
        }

        // Control/media types are ignored by dispatch (no handler fires).
        {
            const std::size_t commandsBefore = trace.commands.size();
            const std::size_t textsBefore = trace.texts.size();
            const std::size_t callbacksBefore = trace.callbacks.size();
            bot.dispatch(make("receipt", "peer1"));
            bot.dispatch(make("token-refill", "peer1"));
            bot.dispatch(make("file", "peer1"));
            bot.dispatch(make("edit", "peer1"));
            CHECK(trace.commands.size() == commandsBefore);
            CHECK(trace.texts.size() == textsBefore);
            CHECK(trace.callbacks.size() == callbacksBefore);
        }
    }

    fs::remove_all(accountDir);
}

// Without an explicit contact handler, a new contact falls back to the "start"
// command when one is registered.
void testContactFallsBackToStart()
{
    const fs::path accountDir = fs::temp_directory_path() / "bz-testbot-state2";
    fs::remove_all(accountDir);
    // Removed after the session, as above.
    {
        Session session = Session::create(accountDir, std::string{}, "testbot2");

        bool started = false;
        Bot bot(session);
        bot.onCommand("start", [&started](Bot&, const std::string&, const std::string&) {
            started = true;
        });
        bot.dispatch(make("contact.request", "peer3"));
        CHECK(started);
    }

    fs::remove_all(accountDir);
}

}  // namespace

// The stub server these tests talk to is a plain HTTP listener on localhost -
// the same shape as a stand on a LAN, and the reason that switch exists.
int main()
{
    bazarish::setAllowFacadeWithoutI2pForDevPurposes(true);
    testKeyboardJson();
    testDispatch();
    testContactFallsBackToStart();
    std::fprintf(stderr, "TestBot passed\n");
    return 0;
}
