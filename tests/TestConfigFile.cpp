// Bazarish project (c) 2026
#include <bazarish/ConfigFile.hpp>

#include "TestUtil.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

using namespace bazarish;

namespace {

// The file an operator wrote: their order, their spacing, their notes.
const char* const kConfig = R"({
  // how much every account gets
  "freeStorageBytes": 52428800,
  "portal": {
    "message": "Bazarish test stand.",   /* shown by the client */
    "facades": ["http://one.example", "http://two.example"]
  },
  "registration": {
    "requireApproval": false,
    "ttlDays": 7
  }
}
)";

void testPatchKeepsEverythingElse()
{
    const std::string patched
        = configWithValue(kConfig, {"registration", "requireApproval"}, true);
    CHECK(patched.find("\"requireApproval\": true") != std::string::npos);
    // The operator's notes, order and spacing are untouched.
    CHECK(patched.find("// how much every account gets") != std::string::npos);
    CHECK(patched.find("/* shown by the client */") != std::string::npos);
    CHECK(patched.find("\"ttlDays\": 7") != std::string::npos);
    CHECK(patched.find("\"http://two.example\"") != std::string::npos);
    CHECK(patched.find("\"freeStorageBytes\": 52428800") != std::string::npos);
    // Only the one value moved: everything before the change is byte for byte.
    const std::size_t at = kConfig ? std::string(kConfig).find("\"requireApproval\"") : 0;
    CHECK(patched.compare(0, at, kConfig, at) == 0);
}

void testPatchesAtTheTopLevel()
{
    const std::string patched = configWithValue(kConfig, {"freeStorageBytes"}, 20971520);
    CHECK(patched.find("\"freeStorageBytes\": 20971520") != std::string::npos);
    CHECK(patched.find("\"requireApproval\": false") != std::string::npos);
}

void testStringsAreEscaped()
{
    const std::string patched = configWithValue(
        kConfig, {"registration", "message"}, "He said \"no\", then left\n");
    CHECK(patched.find("\"message\": \"He said \\\"no\\\", then left\\n\"") != std::string::npos);
    // The portal's own message, which shares the key name, is not the one changed.
    CHECK(patched.find("\"message\": \"Bazarish test stand.\"") != std::string::npos);
}

void testWritesKeysTheFileDoesNotHave()
{
    const std::string added = configWithValue(kConfig, {"registration", "message"}, "Ping me");
    CHECK(added.find("\"message\": \"Ping me\"") != std::string::npos);
    CHECK(added.find("\"requireApproval\": false") != std::string::npos);
    CHECK(nlohmann::json::parse(added, nullptr, true, true)
              .at("registration")
              .at("message")
              .get<std::string>()
        == "Ping me");

    // A whole branch the file never had.
    const std::string branch = configWithValue(kConfig, {"limits", "maxDevices"}, 4);
    const nlohmann::json parsed = nlohmann::json::parse(branch, nullptr, true, true);
    CHECK(parsed.at("limits").at("maxDevices").get<int>() == 4);
    CHECK(parsed.at("freeStorageBytes").get<std::uint64_t>() == 52428800);

    // An empty object takes its first key.
    const std::string empty = configWithValue("{\n  \"registration\": {}\n}\n",
        {"registration", "ttlDays"}, 3);
    CHECK(nlohmann::json::parse(empty).at("registration").at("ttlDays").get<int>() == 3);
}

void testRefusesWhatItCannotPatch()
{
    bool threw = false;
    try {
        // freeStorageBytes is a number, so it holds no keys.
        (void)configWithValue(kConfig, {"freeStorageBytes", "inner"}, 1);
    } catch (const std::exception&) {
        threw = true;
    }
    CHECK(threw);

    bool notAnObject = false;
    try {
        (void)configWithValue("[1, 2]", {"a"}, 1);
    } catch (const std::exception&) {
        notAnObject = true;
    }
    CHECK(notAnObject);
}

// Reading a daemon's settings: what is there, what is missing, and what is of
// the wrong shape.
void testReadingSettings()
{
    const ConfigView view(nlohmann::json::parse(kConfig, nullptr, true, true));
    CHECK(view.number("freeStorageBytes", 0) == 52428800);
    CHECK(view.text("portal.message") == "Bazarish test stand.");
    CHECK(!view.flag("registration.requireApproval", true));
    CHECK(view.list("portal.facades").size() == 2);
    CHECK(view.has("registration.ttlDays"));
    CHECK(!view.has("registration.message"));

    // A missing value is the caller's default, not an error.
    CHECK(view.text("portal.nothing", "fallback") == "fallback");
    CHECK(view.number("nothing.at.all", 7) == 7);
    CHECK(view.list("nothing").empty());
    CHECK(!view.endpoint("listen").has_value());

    const ConfigView listening(nlohmann::json::parse(
        R"({"listen": {"host": "127.0.0.1", "port": 8420}, "half": {"host": "x"}})"));
    const std::optional<ConfigView::Endpoint> endpoint = listening.endpoint("listen");
    CHECK(endpoint.has_value());
    CHECK(endpoint->host == "127.0.0.1");
    CHECK(endpoint->port == 8420);

    // A value of the wrong shape is an error, not a default: a daemon that
    // silently ran on the default would be a daemon nobody configured.
    bool wrongShape = false;
    try {
        (void)view.number("portal.message", 0);
    } catch (const std::exception&) {
        wrongShape = true;
    }
    CHECK(wrongShape);

    bool halfAnEndpoint = false;
    try {
        (void)listening.endpoint("half");
    } catch (const std::exception&) {
        halfAnEndpoint = true;
    }
    CHECK(halfAnEndpoint);
}

}  // namespace

int main()
{
    testPatchKeepsEverythingElse();
    testPatchesAtTheTopLevel();
    testStringsAreEscaped();
    testWritesKeysTheFileDoesNotHave();
    testRefusesWhatItCannotPatch();
    testReadingSettings();
    std::printf("TestConfigFile: all checks passed\n");
    return 0;
}
